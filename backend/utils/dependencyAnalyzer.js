import fs from 'node:fs';
import path from 'node:path';

const OSV_QUERY_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULNERABILITY_URL = 'https://api.osv.dev/v1/vulns/';
const MAX_LOCKFILE_BYTES = 10 * 1024 * 1024;
const MAX_PACKAGES = 1000;
const MAX_BATCH_SIZE = 100;
const MAX_ADVISORIES = 500;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_INVENTORY_ENTRIES = 10000;
const MAX_INVENTORY_DEPTH = 32;
const MAX_TOTAL_DEPENDENCY_FILE_BYTES = 50 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10000;
const ANALYSIS_TIMEOUT_MS = 30000;
const NPM_SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const NPM_FILES = new Set(['package.json', 'package-lock.json', 'npm-shrinkwrap.json']);
const IGNORED_DIRECTORIES = new Set(['.git', 'node_modules']);
const matchesUnsupportedManifest = (name) =>
  name === 'go.mod' || name === 'go.sum' ? 'Go'
    : name === 'Cargo.toml' || name === 'Cargo.lock' ? 'Rust'
      : name === 'requirements.txt' || /^requirements-[^/]+\.txt$/i.test(name) ||
        ['Pipfile', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml', 'setup.py', 'setup.cfg'].includes(name)
        ? 'Python'
        : name === 'pom.xml' ? 'Maven'
          : ['gradle.lockfile', 'build.gradle', 'build.gradle.kts'].includes(name) ? 'Gradle'
            : name === 'Gemfile' || name === 'Gemfile.lock' ? 'Ruby'
              : name === 'composer.json' || name === 'composer.lock' ? 'PHP'
                : null;

const failure = (reason, metadata = {}) => ({
  status: 'failed',
  findings: [],
  metadata: { status: 'failed', reason, ...metadata }
});

const isContainedPath = (rootPath, candidatePath) => {
  const relativePath = path.relative(rootPath, candidatePath);
  return relativePath === '' ||
    (relativePath !== '..' && !relativePath.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relativePath));
};

const readBoundedFile = (fileSystem, filePath, rootPath) => {
  let descriptor;
  try {
    if (rootPath) {
      const canonicalPath = fileSystem.realpathSync(filePath);
      if (!isContainedPath(rootPath, canonicalPath) || canonicalPath === rootPath) {
        const error = new Error('Dependency file is outside the project root');
        error.code = 'DEPENDENCY_OUTSIDE_ROOT';
        throw error;
      }
    }
    descriptor = fileSystem.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
    );
    const stat = fileSystem.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > MAX_LOCKFILE_BYTES) {
      const error = new Error('Dependency lockfile exceeds its read limit');
      error.code = 'DEPENDENCY_FILE_LIMIT';
      throw error;
    }

    const chunks = [];
    const buffer = Buffer.alloc(64 * 1024);
    let totalBytes = 0;
    while (true) {
      const bytesRead = fileSystem.readSync(
        descriptor,
        buffer,
        0,
        Math.min(buffer.length, MAX_LOCKFILE_BYTES - totalBytes + 1),
        null
      );
      if (bytesRead === 0) break;
      totalBytes += bytesRead;
      if (totalBytes > MAX_LOCKFILE_BYTES) {
        const error = new Error('Dependency lockfile exceeds its read limit');
        error.code = 'DEPENDENCY_FILE_LIMIT';
        throw error;
      }
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    return Buffer.concat(chunks, totalBytes).toString('utf8');
  } finally {
    if (descriptor !== undefined) fileSystem.closeSync(descriptor);
  }
};

const discoverDependencyFiles = (fileSystem, projectRoot) => {
  let requestedRootStat;
  try {
    requestedRootStat = fileSystem.lstatSync(projectRoot);
  } catch {
    return {
      rootPath: projectRoot,
      files: [],
      unsupportedFormats: [],
      incompleteReason: 'dependency_inventory_incomplete',
      skippedSymlinkCount: 0
    };
  }
  if (!requestedRootStat.isDirectory() || requestedRootStat.isSymbolicLink()) {
    return {
      rootPath: projectRoot,
      files: [],
      unsupportedFormats: [],
      incompleteReason: requestedRootStat.isSymbolicLink()
        ? 'dependency_symlink_skipped'
        : 'dependency_inventory_incomplete',
      skippedSymlinkCount: requestedRootStat.isSymbolicLink() ? 1 : 0
    };
  }
  let rootPath;
  try {
    rootPath = fileSystem.realpathSync(projectRoot);
  } catch {
    return {
      rootPath: projectRoot,
      files: [],
      unsupportedFormats: [],
      incompleteReason: 'dependency_inventory_incomplete',
      skippedSymlinkCount: 0
    };
  }
  const rootStat = fileSystem.lstatSync(rootPath);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    return {
      rootPath,
      files: [],
      unsupportedFormats: [],
      incompleteReason: 'dependency_inventory_incomplete',
      skippedSymlinkCount: 0
    };
  }

  const files = [];
  const unsupportedFormats = new Set();
  const pending = [{ fullPath: rootPath, relativePath: '', depth: 0 }];
  let entriesVisited = 0;
  let totalFileBytes = 0;
  let skippedSymlinkCount = 0;
  let incompleteReason = null;

  while (pending.length > 0 && !incompleteReason) {
    const current = pending.pop();
    try {
      const currentStat = fileSystem.lstatSync(current.fullPath);
      const currentCanonicalPath = fileSystem.realpathSync(current.fullPath);
      if (!currentStat.isDirectory() || currentStat.isSymbolicLink() ||
          currentCanonicalPath !== current.fullPath ||
          !isContainedPath(rootPath, currentCanonicalPath)) {
        incompleteReason = currentStat.isSymbolicLink()
          ? 'dependency_symlink_skipped'
          : 'dependency_inventory_incomplete';
        if (currentStat.isSymbolicLink()) skippedSymlinkCount += 1;
        break;
      }
    } catch {
      incompleteReason = 'dependency_inventory_incomplete';
      break;
    }
    let entries;
    try {
      entries = fileSystem.readdirSync(current.fullPath, { withFileTypes: true });
    } catch {
      incompleteReason = 'dependency_inventory_incomplete';
      break;
    }
    for (const entry of entries) {
      entriesVisited += 1;
      if (entriesVisited > MAX_INVENTORY_ENTRIES) {
        incompleteReason = 'dependency_entry_limit_exceeded';
        break;
      }

      const fullPath = path.join(current.fullPath, entry.name);
      const relativePath = current.relativePath
        ? path.join(current.relativePath, entry.name)
        : entry.name;
      if (!isContainedPath(rootPath, fullPath)) {
        incompleteReason = 'dependency_inventory_incomplete';
        break;
      }
      if (entry.isSymbolicLink()) {
        skippedSymlinkCount += 1;
        incompleteReason = 'dependency_symlink_skipped';
        break;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) continue;
        let directoryStat;
        try {
          directoryStat = fileSystem.lstatSync(fullPath);
        } catch {
          incompleteReason = 'dependency_inventory_incomplete';
          break;
        }
        if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
          if (directoryStat.isSymbolicLink()) {
            skippedSymlinkCount += 1;
            incompleteReason = 'dependency_symlink_skipped';
          } else {
            incompleteReason = 'dependency_inventory_incomplete';
          }
          break;
        }
        if (current.depth >= MAX_INVENTORY_DEPTH) {
          incompleteReason = 'dependency_depth_limit_exceeded';
          break;
        }
        pending.push({
          fullPath,
          relativePath,
          depth: current.depth + 1
        });
        continue;
      }

      const npmFile = NPM_FILES.has(entry.name);
      const unsupportedEcosystem = matchesUnsupportedManifest(entry.name);
      if (!npmFile && !unsupportedEcosystem) continue;

      let stat;
      try {
        stat = fileSystem.lstatSync(fullPath);
      } catch {
        incompleteReason = 'dependency_inventory_incomplete';
        break;
      }
      if (!stat.isFile() || stat.isSymbolicLink()) {
        skippedSymlinkCount += stat.isSymbolicLink() ? 1 : 0;
        incompleteReason = stat.isSymbolicLink()
          ? 'dependency_symlink_skipped'
          : 'dependency_inventory_incomplete';
        break;
      }
      totalFileBytes += stat.size;
      if (stat.size > MAX_LOCKFILE_BYTES ||
          totalFileBytes > MAX_TOTAL_DEPENDENCY_FILE_BYTES) {
        incompleteReason = stat.size > MAX_LOCKFILE_BYTES
          ? 'lockfile_exceeds_size_limit'
          : 'dependency_total_size_limit_exceeded';
        break;
      }
      files.push({
        fullPath,
        relativePath: relativePath.replace(/\\/g, '/'),
        directory: current.relativePath.replace(/\\/g, '/'),
        name: entry.name,
        kind: npmFile ? 'npm' : 'unsupported'
      });
      if (unsupportedEcosystem) unsupportedFormats.add(unsupportedEcosystem);
    }
  }

  return {
    rootPath,
    files,
    unsupportedFormats: [...unsupportedFormats].sort(),
    incompleteReason,
    skippedSymlinkCount,
    entriesVisited,
    totalFileBytes
  };
};

const packageNameFromLockPath = (lockPath) => {
  if (typeof lockPath !== 'string' || lockPath.includes('\\') ||
      lockPath.startsWith('/') || lockPath.split('/').includes('..')) {
    throw new Error('Invalid npm lockfile package path');
  }
  const marker = 'node_modules/';
  const markerIndex = lockPath.lastIndexOf(marker);
  if (markerIndex < 0) return null;
  const packagePath = lockPath.slice(markerIndex + marker.length);
  const parts = packagePath.split('/');
  if (parts[0]?.startsWith('@')) {
    if (parts.length < 2 || !parts[1]) throw new Error('Invalid scoped npm package path');
    return `${parts[0]}/${parts[1]}`;
  }
  if (!parts[0]) throw new Error('Invalid npm package path');
  return parts[0];
};

const addPackage = (packages, name, version, direct) => {
  if (typeof name !== 'string' || !name.trim() ||
      typeof version !== 'string' || !version.trim()) {
    throw new Error('npm lockfile contains a dependency without a known version');
  }
  const normalizedName = name.trim();
  const normalizedVersion = version.trim();
  if (/[\u0000-\u001f\u007f]/.test(normalizedName + normalizedVersion)) {
    throw new Error('npm lockfile contains invalid dependency metadata');
  }
  if (!/^(@[^/@\s]+\/)?[^/@\s]+$/.test(normalizedName) ||
      !NPM_SEMVER_PATTERN.test(normalizedVersion)) {
    throw new Error('npm lockfile contains a dependency with an unsupported identity or version');
  }
  const key = `${normalizedName}\u0000${normalizedVersion}`;
  const existing = packages.get(key);
  if (existing) {
    existing.direct ||= direct;
    return;
  }
  packages.set(key, {
    name: normalizedName,
    version: normalizedVersion,
    direct
  });
  if (packages.size > MAX_PACKAGES) {
    const error = new Error('npm lockfile dependency count exceeds its limit');
    error.code = 'DEPENDENCY_PACKAGE_LIMIT';
    throw error;
  }
};

const parseV1Dependencies = (dependencies, packages) => {
  const pending = [{ dependencies, direct: true, depth: 0 }];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current.dependencies === undefined) continue;
    if (!current.dependencies || typeof current.dependencies !== 'object' ||
        Array.isArray(current.dependencies)) {
      throw new Error('Invalid npm lockfile dependency tree');
    }
    if (current.depth > 64) {
      throw new Error('npm lockfile dependency nesting exceeds its limit');
    }
    for (const [name, record] of Object.entries(current.dependencies)) {
      if (!record || typeof record !== 'object' || Array.isArray(record)) {
        throw new Error('Invalid npm lockfile dependency record');
      }
      if (record.link !== true) addPackage(packages, name, record.version, current.direct);
      if (record.dependencies !== undefined) {
        pending.push({
          dependencies: record.dependencies,
          direct: false,
          depth: current.depth + 1
        });
      }
    }
  }
};

const parseNpmLockfile = (lockfile, additionalDirectNames = []) => {
  if (!lockfile || typeof lockfile !== 'object' || Array.isArray(lockfile)) {
    throw new Error('Invalid npm lockfile');
  }
  const packages = new Map();
  if (lockfile.lockfileVersion === 1) {
    parseV1Dependencies(lockfile.dependencies, packages);
    const directNames = new Set(Object.keys(lockfile.dependencies || {}));
    const allDirectNames = new Set([...directNames, ...additionalDirectNames]);
    for (const dependency of packages.values()) {
      if (allDirectNames.has(dependency.name)) dependency.direct = true;
    }
    for (const name of directNames) {
      if (![...packages.values()].some((dependency) =>
        dependency.direct && dependency.name === name
      )) {
        throw new Error('npm lockfile is missing a direct dependency record');
      }
    }
    return {
      packages: [...packages.values()],
      directNames,
      allDirectNames,
      packageRecords: {}
    };
  }
  if (lockfile.lockfileVersion !== 2 && lockfile.lockfileVersion !== 3) {
    throw new Error('Unsupported or missing npm lockfile version');
  }
  if (!lockfile.packages || typeof lockfile.packages !== 'object' ||
      Array.isArray(lockfile.packages) ||
      !lockfile.packages[''] || typeof lockfile.packages[''] !== 'object' ||
      Array.isArray(lockfile.packages[''])) {
    throw new Error('npm lockfile is missing its root package metadata');
  }

  const root = lockfile.packages[''];
  const directNames = new Set([
    ...Object.keys(root.dependencies || {}),
    ...Object.keys(root.devDependencies || {}),
    ...Object.keys(root.optionalDependencies || {}),
    ...Object.keys(root.peerDependencies || {})
  ]);
  const allDirectNames = new Set([...directNames, ...additionalDirectNames]);
  if ([root.dependencies, root.devDependencies, root.optionalDependencies, root.peerDependencies]
    .some((value) => value !== undefined &&
      (!value || typeof value !== 'object' || Array.isArray(value)))) {
    throw new Error('npm lockfile contains invalid root dependency metadata');
  }

  const installedDirectNames = new Set();
  for (const [lockPath, record] of Object.entries(lockfile.packages)) {
    if (!lockPath) continue;
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('Invalid npm lockfile package record');
    }
    if (record.link === true) continue;
    const lockName = packageNameFromLockPath(lockPath);
    if (!lockName) continue;
    if (record.name !== undefined && typeof record.name !== 'string') {
      throw new Error('npm lockfile contains an invalid package name');
    }
    addPackage(packages, record.name || lockName, record.version, allDirectNames.has(lockName));
    if (directNames.has(lockName)) installedDirectNames.add(lockName);
  }

  if (packages.size > 0 && directNames.size === 0) {
    throw new Error('npm lockfile is missing direct dependency metadata');
  }
  for (const name of directNames) {
    if (!installedDirectNames.has(name)) {
      throw new Error('npm lockfile is missing a direct dependency record');
    }
  }
  return {
    packages: [...packages.values()],
    directNames,
    allDirectNames,
    packageRecords: lockfile.packages
  };
};

const readPackageManifest = (fileSystem, projectRoot, manifestPath) => {
  const manifest = JSON.parse(readBoundedFile(fileSystem, manifestPath, projectRoot));
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Invalid npm package manifest');
  }
  const manifestDirectNames = new Set();
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencyMap = manifest[key];
    if (dependencyMap === undefined) continue;
    if (!dependencyMap || typeof dependencyMap !== 'object' || Array.isArray(dependencyMap)) {
      throw new Error('Invalid npm package manifest dependency metadata');
    }
    for (const [name, versionRange] of Object.entries(dependencyMap)) {
      if (typeof versionRange !== 'string' || !versionRange.trim()) {
        throw new Error('Invalid npm package manifest dependency range');
      }
      manifestDirectNames.add(name);
    }
  }
  return { manifest, directNames: manifestDirectNames };
};

const validatePackageManifest = (fileSystem, projectRoot, lockDirectNames, manifestPath) => {
  const selectedManifestPath = manifestPath || path.join(projectRoot, 'package.json');
  if (!fileSystem.existsSync(selectedManifestPath)) return null;
  const { manifest, directNames: manifestDirectNames } = readPackageManifest(
    fileSystem,
    projectRoot,
    selectedManifestPath
  );
  if (manifestDirectNames.size !== lockDirectNames.size ||
      [...manifestDirectNames].some((name) => !lockDirectNames.has(name))) {
    throw new Error('npm manifest and lockfile direct dependencies are inconsistent');
  }
  return manifest;
};

const workspacePatterns = (manifest) => {
  if (!Object.hasOwn(manifest, 'workspaces')) return [];
  let workspaces;
  if (Array.isArray(manifest.workspaces)) {
    workspaces = manifest.workspaces;
  } else if (manifest.workspaces && typeof manifest.workspaces === 'object' &&
      !Array.isArray(manifest.workspaces)) {
    workspaces = manifest.workspaces.packages;
  }
  if (!Array.isArray(workspaces) ||
      workspaces.some((pattern) => typeof pattern !== 'string' || !pattern.trim())) {
    throw new Error('npm workspace declaration is invalid');
  }
  return workspaces;
};

const workspacePatternRegex = (pattern) => {
  const normalized = pattern.replace(/\\/g, '/').replace(/^\.\/+/, '');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) {
    throw new Error('npm workspace declaration is invalid');
  }
  const wildcard = normalized
    .replace(/\*\*/g, '\u0000')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*');
  return new RegExp(`^${wildcard}/?$`);
};

const isDeclaredWorkspace = (patterns, relativeDirectory) => {
  let included = false;
  for (const pattern of patterns) {
    const excluded = pattern.startsWith('!');
    const candidate = excluded ? pattern.slice(1) : pattern;
    if (workspacePatternRegex(candidate).test(relativeDirectory)) {
      included = !excluded;
    }
  }
  return included;
};

const normalizedWorkspaceTarget = (value) => {
  if (typeof value !== 'string' || value.includes('\u0000')) return null;
  const normalized = value.replace(/^file:/, '').replace(/\\/g, '/').replace(/^\.\/+/, '');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) {
    return null;
  }
  return path.posix.normalize(normalized);
};

const isLinkedWorkspace = (lockfile, relativeDirectory) => {
  if (!lockfile.packages?.[relativeDirectory]) return false;
  return Object.values(lockfile.packages).some((record) =>
    record?.link === true &&
    normalizedWorkspaceTarget(record.resolved) === relativeDirectory
  );
};

const validateWorkspaceManifest = (manifest, lockRecord) => {
  if (!lockRecord || typeof lockRecord !== 'object' || Array.isArray(lockRecord)) {
    throw new Error('npm lockfile is missing a declared workspace record');
  }
  const lockNames = new Set();
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = lockRecord[key];
    if (dependencies === undefined) continue;
    if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
      throw new Error('npm lockfile contains invalid workspace dependency metadata');
    }
    for (const name of Object.keys(dependencies)) lockNames.add(name);
  }
  const manifestNames = new Set();
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = manifest[key];
    if (dependencies === undefined) continue;
    for (const name of Object.keys(dependencies)) manifestNames.add(name);
  }
  if (manifestNames.size !== lockNames.size ||
      [...manifestNames].some((name) => !lockNames.has(name))) {
    throw new Error('npm workspace manifest and lockfile dependencies are inconsistent');
  }
};

const boundedJson = async (response) => {
  const declaredLength = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    const error = new Error('OSV response exceeds its size limit');
    error.code = 'OSV_RESPONSE_LIMIT';
    throw error;
  }

  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          const error = new Error('OSV response exceeds its size limit');
          error.code = 'OSV_RESPONSE_LIMIT';
          throw error;
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      reader.releaseLock();
    }
    return JSON.parse(Buffer.concat(chunks, totalBytes).toString('utf8'));
  }

  const text = await response.text();
  if (Buffer.byteLength(text) > MAX_RESPONSE_BYTES) {
    const error = new Error('OSV response exceeds its size limit');
    error.code = 'OSV_RESPONSE_LIMIT';
    throw error;
  }
  return JSON.parse(text);
};

const requestJson = async (
  fetchImpl,
  url,
  init,
  signal,
  timeoutMs = REQUEST_TIMEOUT_MS
) => {
  const controller = new AbortController();
  const onAbort = () => controller.abort(signal.reason);
  if (signal?.aborted) {
    controller.abort(signal.reason);
  } else {
    signal?.addEventListener('abort', onAbort, { once: true });
  }
  const timer = setTimeout(() => {
    const error = new Error('OSV request timed out');
    error.code = 'OSV_TIMEOUT';
    controller.abort(error);
  }, timeoutMs);
  try {
    const response = await fetchImpl(url, {
      ...init,
      redirect: 'error',
      signal: controller.signal
    });
    if (!response.ok) {
      const error = new Error('OSV request failed');
      error.code = 'OSV_HTTP_ERROR';
      throw error;
    }
    return await boundedJson(response);
  } catch (error) {
    if (controller.signal.aborted && controller.signal.reason?.code === 'OSV_TIMEOUT') {
      throw controller.signal.reason;
    }
    if (signal?.aborted) {
      const cancelled = new Error('Dependency analysis cancelled');
      cancelled.code = 'ABORT_ERR';
      throw cancelled;
    }
    if (error instanceof SyntaxError) {
      const malformed = new Error('OSV returned malformed JSON');
      malformed.code = 'OSV_MALFORMED_RESPONSE';
      throw malformed;
    }
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
};

const withAnalysisDeadline = async (
  signal,
  operation,
  timeoutMs = ANALYSIS_TIMEOUT_MS
) => {
  const controller = new AbortController();
  const onAbort = () => controller.abort(signal.reason);
  if (signal?.aborted) controller.abort(signal.reason);
  else signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => {
    const error = new Error('Dependency analysis timed out');
    error.code = 'DEPENDENCY_TIMEOUT';
    controller.abort(error);
  }, timeoutMs);
  try {
    return await operation(controller.signal);
  } catch (error) {
    if (controller.signal.reason?.code === 'DEPENDENCY_TIMEOUT') {
      throw controller.signal.reason;
    }
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
};

const normalizeSeverity = (vulnerability, affected) => {
  const raw = affected?.database_specific?.severity ||
    affected?.ecosystem_specific?.severity ||
    vulnerability.database_specific?.severity ||
    vulnerability.ecosystem_specific?.severity;
  if (typeof raw === 'string') {
    const normalized = raw.trim().toLowerCase();
    if (normalized === 'critical') return 'Critical';
    if (normalized === 'high') return 'High';
    if (normalized === 'moderate' || normalized === 'medium') return 'Medium';
    if (normalized === 'low') return 'Low';
  }
  for (const severity of vulnerability.severity || []) {
    const score = Number(severity.score);
    if (Number.isFinite(score) && score >= 0 && score <= 10) {
      if (score >= 9) return 'Critical';
      if (score >= 7) return 'High';
      if (score >= 4) return 'Medium';
      return 'Low';
    }
  }
  return 'Unknown';
};

const conciseSummary = (vulnerability) => {
  const summary = typeof vulnerability.summary === 'string' ? vulnerability.summary : '';
  return summary.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 400);
};

const fixedVersionFor = (affectedRecords) => {
  const rangeVersions = [];
  for (const affected of affectedRecords) {
    if (!Array.isArray(affected.ranges) || affected.ranges.length === 0) return null;
    for (const range of affected.ranges || []) {
      const versions = new Set();
      for (const event of range.events || []) {
        if (typeof event.fixed === 'string' && event.fixed.trim()) versions.add(event.fixed.trim());
      }
      if (versions.size !== 1) return null;
      rangeVersions.push([...versions][0]);
    }
  }
  const uniqueVersions = new Set(rangeVersions);
  return rangeVersions.length > 0 && uniqueVersions.size === 1
    ? [...uniqueVersions][0]
    : null;
};

const lookupAdvisories = async (packages, fetchImpl, signal, requestTimeoutMs) => {
  const matches = [];
  for (let offset = 0; offset < packages.length; offset += MAX_BATCH_SIZE) {
    const batch = packages.slice(offset, offset + MAX_BATCH_SIZE);
    const response = await requestJson(fetchImpl, OSV_QUERY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: batch.map(({ name, version }) => ({
          package: { name, ecosystem: 'npm' },
          version
        }))
      })
    }, signal, requestTimeoutMs);

    if (!response || !Array.isArray(response.results) ||
        response.results.length !== batch.length) {
      const error = new Error('OSV returned an incomplete query response');
      error.code = 'OSV_MALFORMED_RESPONSE';
      throw error;
    }
    response.results.forEach((result, index) => {
      if (!result || typeof result !== 'object' || Array.isArray(result) ||
          (result.vulns !== undefined && !Array.isArray(result.vulns))) {
        const error = new Error('OSV returned an invalid package result');
        error.code = 'OSV_MALFORMED_RESPONSE';
        throw error;
      }
      if (result.next_page_token) {
        const error = new Error('OSV advisory results were paginated beyond the supported bound');
        error.code = 'OSV_PAGINATION_LIMIT';
        throw error;
      }
      for (const vuln of result.vulns || []) {
        if (!vuln || typeof vuln.id !== 'string' || !vuln.id.trim() ||
            typeof vuln.modified !== 'string' || !Number.isFinite(Date.parse(vuln.modified))) {
          const error = new Error('OSV returned an invalid advisory reference');
          error.code = 'OSV_MALFORMED_RESPONSE';
          throw error;
        }
        matches.push({
          package: batch[index],
          id: vuln.id,
          modified: new Date(vuln.modified).toISOString()
        });
        if (matches.length > MAX_ADVISORIES) {
          const error = new Error('OSV advisory count exceeds its limit');
          error.code = 'OSV_ADVISORY_LIMIT';
          throw error;
        }
      }
    });
  }
  return matches;
};

const fetchVulnerabilityDetails = async (
  matches,
  fetchImpl,
  signal,
  requestTimeoutMs
) => {
  const results = [];
  for (let offset = 0; offset < matches.length; offset += 8) {
    const batch = matches.slice(offset, offset + 8);
    const details = await Promise.all(batch.map(async (match) => {
      const vulnerability = await requestJson(
        fetchImpl,
        `${OSV_VULNERABILITY_URL}${encodeURIComponent(match.id)}`,
        { method: 'GET' },
        signal,
        requestTimeoutMs
      );
      if (!vulnerability || vulnerability.id !== match.id ||
          !Array.isArray(vulnerability.affected)) {
        const error = new Error('OSV returned malformed vulnerability details');
        error.code = 'OSV_MALFORMED_RESPONSE';
        throw error;
      }
      const affectedRecords = vulnerability.affected.filter((item) =>
        item?.package?.ecosystem?.toLowerCase() === 'npm' &&
        item.package.name === match.package.name
      );
      if (affectedRecords.length === 0) {
        const error = new Error('OSV advisory did not match its queried package');
        error.code = 'OSV_MALFORMED_RESPONSE';
        throw error;
      }
      const affected = affectedRecords[0];
      return {
        severity: normalizeSeverity(vulnerability, affected),
        summary: conciseSummary(vulnerability) ||
          'OSV identifies this installed package version as affected.',
        fixedVersion: fixedVersionFor(affectedRecords),
        advisoryModified: match.modified,
        dependency: {
          ecosystem: 'npm',
          package: match.package.name,
          installedVersion: match.package.version,
          relationship: match.package.direct ? 'direct' : 'transitive',
          advisoryId: match.id
        }
      };
    }));
    results.push(...details);
  }
  return results;
};

export async function analyzeDependencies(
  projectRoot,
  {
    fs: fileSystem = fs,
    fetch: fetchImpl = globalThis.fetch,
    signal,
    now = () => new Date(),
    enabled = true,
    requestTimeoutMs = REQUEST_TIMEOUT_MS,
    analysisTimeoutMs = ANALYSIS_TIMEOUT_MS
  } = {}
) {
  const inventory = discoverDependencyFiles(fileSystem, projectRoot);
  const packageFiles = inventory.files.filter((file) => file.name === 'package.json');
  const packageLocks = inventory.files.filter((file) =>
    file.name === 'package-lock.json' || file.name === 'npm-shrinkwrap.json'
  );
  const npmDirectories = new Map();
  for (const file of inventory.files.filter((entry) => entry.kind === 'npm')) {
    const group = npmDirectories.get(file.directory) || { manifests: [], locks: [] };
    if (file.name === 'package.json') group.manifests.push(file);
    else group.locks.push(file);
    npmDirectories.set(file.directory, group);
  }
  const unsupportedFormats = inventory.unsupportedFormats;
  const queriedAt = now().toISOString();
  const baseMetadata = {
    source: 'OSV',
    queriedAt,
    freshness: 'No local advisory cache is used; OSV does not expose a database-wide freshness timestamp. Per-advisory modified times are reported.',
    unsupportedFormats,
    inventory: {
      entriesVisited: inventory.entriesVisited ?? 0,
      skippedSymlinkCount: inventory.skippedSymlinkCount,
      totalDependencyFileBytes: inventory.totalFileBytes ?? 0,
      limits: {
        entries: MAX_INVENTORY_ENTRIES,
        depth: MAX_INVENTORY_DEPTH,
        totalDependencyFileBytes: MAX_TOTAL_DEPENDENCY_FILE_BYTES
      }
    }
  };

  if (signal?.aborted) {
    return failure('analysis_cancelled', baseMetadata);
  }
  if (inventory.incompleteReason) {
    return failure(inventory.incompleteReason, baseMetadata);
  }
  if (packageLocks.length === 0) {
    if (packageFiles.length > 0) {
      return failure('npm_lockfile_missing', baseMetadata);
    }
    return {
      status: 'unsupported',
      findings: [],
      metadata: {
        ...baseMetadata,
        status: 'unsupported',
        reason: unsupportedFormats.length
          ? 'unsupported_dependency_formats'
          : 'no_supported_dependency_manifest'
      }
    };
  }

  try {
    const coveredWorkspaceDirectories = new Set();
    const analyzedLockDirectories = new Set();
    const packagesByIdentity = new Map();
    let analyzedLockCount = 0;
    for (const directory of [...npmDirectories.keys()].sort((left, right) =>
      left.split('/').length - right.split('/').length || left.localeCompare(right)
    )) {
      const group = npmDirectories.get(directory);
      if (coveredWorkspaceDirectories.has(directory)) continue;
      if (group.locks.length > 1) {
        return failure('multiple_npm_lockfiles', {
          ...baseMetadata,
          manifestCount: analyzedLockCount
        });
      }
      if (group.locks.length === 0) continue;

      const lockFile = group.locks[0];
      const lockPath = path.join(inventory.rootPath, ...lockFile.relativePath.split('/'));
      const lock = JSON.parse(readBoundedFile(fileSystem, lockPath, inventory.rootPath));
      const rootManifestFile = group.manifests[0];
      const rootManifestPath = rootManifestFile
        ? path.join(inventory.rootPath, ...rootManifestFile.relativePath.split('/'))
        : null;
      const rootManifestResult = rootManifestPath
        ? readPackageManifest(fileSystem, inventory.rootPath, rootManifestPath)
        : null;
      const patterns = rootManifestResult ? workspacePatterns(rootManifestResult.manifest) : [];
      const workspaceManifests = [];
      const additionalDirectNames = new Set();
      for (const childFile of packageFiles) {
        const childDirectory = childFile.directory;
        if (!childDirectory ||
            (directory && !childDirectory.startsWith(`${directory}/`))) continue;
        const relativeDirectory = path.posix.relative(directory, childDirectory);
        if (!isDeclaredWorkspace(patterns, relativeDirectory) ||
            !isLinkedWorkspace(lock, relativeDirectory)) continue;
        const manifestPath = path.join(
          inventory.rootPath,
          ...childFile.relativePath.split('/')
        );
        const workspaceManifest = readPackageManifest(
          fileSystem,
          inventory.rootPath,
          manifestPath
        );
        validateWorkspaceManifest(
          workspaceManifest.manifest,
          lock.packages[relativeDirectory]
        );
        workspaceManifests.push({ directory: childDirectory, relativeDirectory });
        for (const name of workspaceManifest.directNames) additionalDirectNames.add(name);
      }

      const parsed = parseNpmLockfile(lock, [...additionalDirectNames]);
      if (rootManifestResult) {
        validatePackageManifest(
          fileSystem,
          inventory.rootPath,
          parsed.directNames,
          rootManifestPath
        );
      }
      for (const workspace of workspaceManifests) {
        coveredWorkspaceDirectories.add(workspace.directory);
      }
      analyzedLockDirectories.add(directory);
      analyzedLockCount += 1;
      for (const dependency of parsed.packages) {
        const identity = `${dependency.name}\u0000${dependency.version}`;
        const existing = packagesByIdentity.get(identity);
        if (existing) existing.direct ||= dependency.direct;
        else packagesByIdentity.set(identity, dependency);
      }
    }

    for (const [directory, group] of npmDirectories) {
      if (group.manifests.length > 0 &&
          !analyzedLockDirectories.has(directory) &&
          !coveredWorkspaceDirectories.has(directory)) {
        return failure('npm_lockfile_missing', {
          ...baseMetadata,
          manifestCount: analyzedLockCount
        });
      }
    }

    const packages = [...packagesByIdentity.values()];
    if (!enabled && packages.length > 0) {
      return failure('advisory_query_disabled', {
        ...baseMetadata,
        manifest: analyzedLockCount === 1 ? packageLocks[0].name : 'multiple',
        manifestCount: analyzedLockCount,
        packageCount: packages.length,
        queriedPackageCount: 0,
        advisoryCount: null
      });
    }
    if (typeof fetchImpl !== 'function' && packages.length > 0) {
      const error = new Error('OSV client is unavailable');
      error.code = 'OSV_UNAVAILABLE';
      throw error;
    }

    const advisories = packages.length === 0
      ? []
      : await withAnalysisDeadline(signal, async (analysisSignal) => {
        const matches = await lookupAdvisories(
          packages,
          fetchImpl,
          analysisSignal,
          requestTimeoutMs
        );
        return fetchVulnerabilityDetails(
          matches,
          fetchImpl,
          analysisSignal,
          requestTimeoutMs
        );
      }, analysisTimeoutMs);
    const partiallyUnsupported = unsupportedFormats.length > 0;
    return {
      status: partiallyUnsupported ? 'failed' : 'completed',
      findings: advisories,
      metadata: {
        ...baseMetadata,
        manifest: analyzedLockCount === 1 ? packageLocks[0].name : 'multiple',
        manifestCount: analyzedLockCount,
        status: partiallyUnsupported ? 'partial' : 'completed',
        packageCount: packages.length,
        queriedPackageCount: packages.length,
        advisoryCount: advisories.length,
        ...(partiallyUnsupported ? { reason: 'unsupported_dependency_formats' } : {})
      }
    };
  } catch (error) {
    const reason = error.code === 'OSV_TIMEOUT' || error.code === 'DEPENDENCY_TIMEOUT'
      ? 'advisory_query_timeout'
      : error.code === 'ABORT_ERR'
        ? 'analysis_cancelled'
        : error.code?.startsWith('OSV_')
          ? 'advisory_data_unavailable_or_invalid'
          : error.code === 'DEPENDENCY_FILE_LIMIT'
            ? 'lockfile_exceeds_size_limit'
            : error.code === 'DEPENDENCY_PACKAGE_LIMIT'
              ? 'dependency_count_exceeds_limit'
              : 'npm_lockfile_invalid';
    return failure(reason, {
      ...baseMetadata,
      manifest: packageLocks.length === 1 ? packageLocks[0].name : 'multiple',
      manifestCount: null,
      packageCount: null,
      queriedPackageCount: null,
      advisoryCount: null
    });
  }
}
