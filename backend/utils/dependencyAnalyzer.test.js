import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyzeDependencies } from './dependencyAnalyzer.js';

const makeProject = (files) => {
  const projectPath = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-dependencies-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(projectPath, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return projectPath;
};

const writeLock = (projectPath, lock, name = 'package-lock.json') =>
  fs.writeFileSync(path.join(projectPath, name), JSON.stringify(lock));

const writeNestedFile = (projectPath, relativePath, content) => {
  const filePath = path.join(projectPath, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
};

const response = (value, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' }
  });

const lockV3 = (packages, rootDependencies) => {
  const directDependencies = rootDependencies || Object.fromEntries(
    Object.keys(packages)
      .filter((name) => name.startsWith('node_modules/') && !name.includes('/node_modules/'))
      .map((name) => [name.slice('node_modules/'.length).split('/')[0], '*'])
  );
  return ({
  name: 'fixture',
  lockfileVersion: 3,
  packages: {
    '': { name: 'fixture', version: '1.0.0', dependencies: directDependencies },
    ...packages
  }
  });
};

const advisory = (name = 'transitive') => ({
  id: 'GHSA-test-1234',
  summary: 'A concise package vulnerability description',
  modified: '2025-01-02T03:04:05Z',
  affected: [{
    package: { ecosystem: 'npm', name },
    ranges: [{
      type: 'SEMVER',
      events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }]
    }],
    database_specific: { severity: 'HIGH' }
  }]
});

const osvMock = (onQueries) => async (url, options) => {
  if (url.endsWith('/v1/querybatch')) {
    const payload = JSON.parse(options.body);
    return response({ results: onQueries(payload.queries) });
  }
  const id = decodeURIComponent(url.split('/').at(-1));
  assert.equal(id, 'GHSA-test-1234');
  return response(advisory());
};

test('parses npm lockfile v3 and reports direct and transitive vulnerable packages', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({
    'node_modules/direct': { version: '1.2.0' },
    'node_modules/direct/node_modules/transitive': { version: '1.9.9' }
  }, { direct: '^1.0.0' }));

  const queried = [];
  const result = await analyzeDependencies(project, {
    fetch: osvMock((queries) => {
      queried.push(...queries);
      return queries.map((query) => query.package.name === 'transitive'
        ? { vulns: [{ id: 'GHSA-test-1234', modified: '2025-01-02T03:04:05Z' }] }
        : {});
    })
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.metadata.packageCount, 2);
  assert.equal(queried.length, 2);
  assert.deepEqual(result.findings.map((item) => item.dependency.relationship), ['transitive']);
  assert.equal(result.findings[0].dependency.package, 'transitive');
  assert.equal(result.findings[0].dependency.installedVersion, '1.9.9');
  assert.equal(result.findings[0].severity, 'High');
  assert.equal(result.findings[0].fixedVersion, '2.0.0');
});

test('supports npm lockfile v1 direct and nested dependency records', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, {
    lockfileVersion: 1,
    dependencies: {
      direct: {
        version: '1.2.0',
        dependencies: { transitive: { version: '3.4.0' } }
      }
    }
  });
  const result = await analyzeDependencies(project, {
    fetch: osvMock(() => [{}, {}])
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.metadata.packageCount, 2);
});

test('supports npm shrinkwrap with lockfile version 2 and verifies manifest consistency', async (t) => {
  const project = makeProject({
    'package.json': '{"dependencies":{"direct":"^1.0.0"}}'
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, {
    lockfileVersion: 2,
    packages: {
      '': { dependencies: { direct: '^1.0.0' } },
      'node_modules/direct': { version: '1.2.3' }
    }
  }, 'npm-shrinkwrap.json');
  const result = await analyzeDependencies(project, {
    fetch: async (_url, options) => {
      assert.equal(options.redirect, 'error');
      return response({ results: [{}] });
    }
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.metadata.manifest, 'npm-shrinkwrap.json');
  assert.equal(result.metadata.packageCount, 1);
});

test('fails closed when the npm manifest and lockfile direct dependency sets differ', async (t) => {
  const project = makeProject({
    'package.json': '{"dependencies":{"private-lib":"^1.0.0"}}'
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3(
    { 'node_modules/other-lib': { version: '1.0.0' } },
    { 'other-lib': '^1.0.0' }
  ));
  const result = await analyzeDependencies(project);

  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'npm_lockfile_invalid');
  assert.doesNotMatch(JSON.stringify(result), /private-lib|other-lib/);
});

test('allows an explicit privacy opt-out without treating dependencies as clean', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({
    'node_modules/private-library': { version: '1.2.3' }
  }));
  let fetchCalled = false;
  const result = await analyzeDependencies(project, {
    enabled: false,
    fetch: async () => {
      fetchCalled = true;
      throw new Error('network must be disabled');
    }
  });

  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'advisory_query_disabled');
  assert.equal(result.metadata.queriedPackageCount, 0);
  assert.equal(fetchCalled, false);
});

test('treats unsupported ecosystems and absent manifests as unsupported, not clean', async (t) => {
  const project = makeProject({ 'go.mod': 'module example.invalid/app\n' });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  let fetchCalled = false;
  const result = await analyzeDependencies(project, {
    fetch: async () => {
      fetchCalled = true;
      throw new Error('unexpected network request');
    }
  });

  assert.equal(result.status, 'unsupported');
  assert.equal(result.metadata.status, 'unsupported');
  assert.deepEqual(result.metadata.unsupportedFormats, ['Go']);
  assert.equal(fetchCalled, false);
});

test('marks npm manifest without a lockfile incomplete', async (t) => {
  const project = makeProject({ 'package.json': '{"dependencies":{"private-lib":"^1.0.0"}}' });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  const result = await analyzeDependencies(project, { fetch: async () => assert.fail() });
  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'npm_lockfile_missing');
});

test('marks malformed lockfiles and unknown dependency versions incomplete without path disclosure', async (t) => {
  const project = makeProject({
    'package-lock.json': '{"lockfileVersion":3,"packages":{"":{},"node_modules/private-lib":{}}}'
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  const result = await analyzeDependencies(project);
  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'npm_lockfile_invalid');
  assert.doesNotMatch(JSON.stringify(result), new RegExp(project.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('uses OSV version matching across the fixed-version boundary', async (t) => {
  const vulnerableProject = makeProject({});
  const fixedProject = makeProject({});
  t.after(() => fs.rmSync(vulnerableProject, { recursive: true, force: true }));
  t.after(() => fs.rmSync(fixedProject, { recursive: true, force: true }));
  writeLock(vulnerableProject, lockV3({
    'node_modules/transitive': { version: '1.9.9' }
  }));
  writeLock(fixedProject, lockV3({
    'node_modules/transitive': { version: '2.0.0' }
  }));

  const query = async (_url, options) => {
    const version = JSON.parse(options.body).queries[0].version;
    return response({
      results: [version === '1.9.9'
        ? { vulns: [{ id: 'GHSA-test-1234', modified: '2025-01-02T03:04:05Z' }] }
        : {}]
    });
  };
  const vulnerable = await analyzeDependencies(vulnerableProject, {
    fetch: async (url, options) => url.endsWith('/v1/querybatch')
      ? query(url, options)
      : response(advisory())
  });
  const fixed = await analyzeDependencies(fixedProject, { fetch: query });

  assert.equal(vulnerable.findings.length, 1);
  assert.equal(fixed.findings.length, 0);
});

test('deduplicates duplicate name/version records before querying OSV', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({
    'node_modules/parent': { version: '1.0.0' },
    'node_modules/parent/node_modules/duplicate': { version: '2.0.0' },
    'node_modules/duplicate': { version: '2.0.0' }
  }));
  let queryCount = 0;
  const result = await analyzeDependencies(project, {
    fetch: async (url, options) => {
      if (url.endsWith('/v1/querybatch')) {
        queryCount += JSON.parse(options.body).queries.length;
        return response({ results: [{}, {}] });
      }
      return response(advisory());
    }
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.metadata.packageCount, 2);
  assert.equal(queryCount, 2);
});

test('sends only package identity and exact version to OSV, never project content or paths', async (t) => {
  const project = makeProject({
    'src/private.js': 'const TOKEN = "must-not-leave-this-directory";'
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({
    'node_modules/public-library': { version: '1.2.3' }
  }));
  let requestBody;
  const result = await analyzeDependencies(project, {
    fetch: async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return response({ results: [{}] });
    }
  });

  assert.equal(result.status, 'completed');
  assert.deepEqual(requestBody, {
    queries: [{
      package: { name: 'public-library', ecosystem: 'npm' },
      version: '1.2.3'
    }]
  });
  assert.doesNotMatch(JSON.stringify(requestBody), /must-not-leave|private\.js|luminicent-dependencies-/);
});

test('marks malformed and paginated advisory data incomplete', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({ 'node_modules/transitive': { version: '1.0.0' } }));
  const malformed = await analyzeDependencies(project, {
    fetch: async () => response({ unexpected: [] })
  });
  const paginated = await analyzeDependencies(project, {
    fetch: async () => response({
      results: [{ vulns: [], next_page_token: 'more-results' }]
    })
  });

  assert.equal(malformed.status, 'failed');
  assert.equal(malformed.metadata.reason, 'advisory_data_unavailable_or_invalid');
  assert.equal(paginated.status, 'failed');
  assert.equal(paginated.metadata.reason, 'advisory_data_unavailable_or_invalid');
});

test('reports old advisory modification timestamps without claiming upstream freshness', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({ 'node_modules/transitive': { version: '1.0.0' } }));
  const result = await analyzeDependencies(project, {
    fetch: async (url, options) => {
      if (url.endsWith('/v1/querybatch')) {
        return response({
          results: [{ vulns: [{ id: 'GHSA-test-1234', modified: '2018-01-02T03:04:05Z' }] }]
        });
      }
      return response(advisory());
    }
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.findings[0].advisoryModified, '2018-01-02T03:04:05.000Z');
  assert.match(result.metadata.freshness, /does not expose a database-wide freshness timestamp/);
});

test('network errors and request timeouts fail closed', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({ 'node_modules/transitive': { version: '1.0.0' } }));
  const networkFailure = await analyzeDependencies(project, {
    fetch: async () => {
      throw new Error('service unavailable');
    }
  });
  const timeout = await analyzeDependencies(project, {
    requestTimeoutMs: 5,
    analysisTimeoutMs: 100,
    fetch: (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
    })
  });

  assert.equal(networkFailure.status, 'failed');
  assert.equal(timeout.status, 'failed');
  assert.equal(timeout.metadata.reason, 'advisory_query_timeout');
});

test('unsupported severity is preserved as Unknown rather than guessed', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({ 'node_modules/transitive': { version: '1.0.0' } }));
  const result = await analyzeDependencies(project, {
    fetch: async (url) => url.endsWith('/v1/querybatch')
      ? response({ results: [{ vulns: [{ id: 'GHSA-test-1234', modified: '2025-01-02T03:04:05Z' }] }] })
      : response({ ...advisory(), affected: [{ package: { ecosystem: 'npm', name: 'transitive' } }] })
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.findings[0].severity, 'Unknown');
  assert.equal(result.findings[0].fixedVersion, null);
});

test('omits fixed-version guidance when OSV affected ranges disagree', async (t) => {
  const project = makeProject({});
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, lockV3({
    'node_modules/transitive': { version: '1.0.0' }
  }));
  const result = await analyzeDependencies(project, {
    fetch: async (url) => url.endsWith('/v1/querybatch')
      ? response({ results: [{ vulns: [{ id: 'GHSA-test-1234', modified: '2025-01-02T03:04:05Z' }] }] })
      : response({
        ...advisory(),
        affected: [{
          package: { ecosystem: 'npm', name: 'transitive' },
          ranges: [
            { events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] },
            { events: [{ introduced: '1.0.0' }, { fixed: '3.0.0' }] }
          ],
          database_specific: { severity: 'HIGH' }
        }]
      })
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.findings[0].fixedVersion, null);
});

test('discovers npm workspace dependencies once from the root lockfile', async (t) => {
  const project = makeProject({
    'package.json': JSON.stringify({
      workspaces: ['packages/*'],
      dependencies: { rootDependency: '^1.0.0' }
    }),
    'packages/app/package.json': JSON.stringify({
      name: 'workspace-app',
      dependencies: { workspaceDependency: '^2.0.0' }
    }),
    'packages/app/package-lock.json': '{malformed but covered by the root lock}'
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, {
    name: 'fixture',
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { rootDependency: '^1.0.0' } },
      'node_modules/rootDependency': { version: '1.2.0' },
      'node_modules/workspaceDependency': { version: '2.3.0' },
      'node_modules/workspace-app': {
        resolved: 'packages/app',
        link: true
      },
      'packages/app': {
        name: 'workspace-app',
        version: '1.0.0',
        dependencies: { workspaceDependency: '^2.0.0' }
      }
    }
  });

  const queried = [];
  const result = await analyzeDependencies(project, {
    fetch: async (_url, options) => {
      const queries = JSON.parse(options.body).queries;
      queried.push(...queries);
      return response({ results: queries.map(() => ({})) });
    }
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.metadata.manifestCount, 1);
  assert.equal(result.metadata.packageCount, 2);
  assert.deepEqual(queried.map((query) => query.package.name).sort(), [
    'rootDependency',
    'workspaceDependency'
  ]);
});

test('does not assume unsupported workspace glob patterns are covered', async (t) => {
  const project = makeProject({
    'package.json': JSON.stringify({ workspaces: ['packages/{app,cli}'] }),
    'packages/app/package.json': JSON.stringify({ name: 'workspace-app' })
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  writeLock(project, {
    name: 'fixture',
    lockfileVersion: 3,
    packages: {
      '': { name: 'fixture', version: '1.0.0' },
      'node_modules/workspace-app': { resolved: 'packages/app', link: true },
      'packages/app': { name: 'workspace-app', version: '1.0.0' }
    }
  });

  const result = await analyzeDependencies(project);
  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'npm_lockfile_missing');
});

test('deduplicates identical dependencies across independent nested npm projects', async (t) => {
  const lock = lockV3({
    'node_modules/shared-library': { version: '1.2.3' }
  }, { 'shared-library': '^1.0.0' });
  const project = makeProject({
    'apps/one/package.json': JSON.stringify({ dependencies: { 'shared-library': '^1.0.0' } }),
    'apps/one/package-lock.json': JSON.stringify(lock),
    'apps/two/package.json': JSON.stringify({ dependencies: { 'shared-library': '^1.0.0' } }),
    'apps/two/package-lock.json': JSON.stringify(lock)
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));

  let queriedCount = 0;
  const result = await analyzeDependencies(project, {
    fetch: async (_url, options) => {
      queriedCount += JSON.parse(options.body).queries.length;
      return response({ results: [{}] });
    }
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.metadata.manifestCount, 2);
  assert.equal(result.metadata.packageCount, 1);
  assert.equal(queriedCount, 1);
});

test('detects unsupported ecosystems nested alongside supported npm projects', async (t) => {
  const project = makeProject({
    'package-lock.json': JSON.stringify(lockV3({
      'node_modules/library-a': { version: '1.2.3' }
    })),
    'services/api/go.mod': 'module example.invalid/api\n',
    'tools/worker/pyproject.toml': '[project]\nname = "worker"\n',
    'mobile/Cargo.toml': '[package]\nname = "mobile"\n'
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));

  const result = await analyzeDependencies(project, {
    fetch: async (_url, options) => response({
      results: JSON.parse(options.body).queries.map(() => ({}))
    })
  });

  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.status, 'partial');
  assert.equal(result.metadata.reason, 'unsupported_dependency_formats');
  assert.deepEqual(result.metadata.unsupportedFormats, ['Python', 'Rust', 'Go'].sort());
});

test('marks malformed nested npm manifests incomplete without leaking paths', async (t) => {
  const project = makeProject({
    'services/api/package.json': '{malformed',
    'services/api/package-lock.json': JSON.stringify(lockV3({
      'node_modules/library-a': { version: '1.2.3' }
    }))
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));

  const result = await analyzeDependencies(project, {
    fetch: async () => assert.fail('invalid nested manifests must fail before OSV')
  });
  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'npm_lockfile_invalid');
  assert.doesNotMatch(JSON.stringify(result), new RegExp(project.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('marks nested npm manifests without lockfiles incomplete even when the root has a lockfile', async (t) => {
  const project = makeProject({
    'package-lock.json': JSON.stringify(lockV3({})),
    'apps/service/package.json': JSON.stringify({
      dependencies: { 'nested-library': '^1.0.0' }
    })
  });
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));

  const result = await analyzeDependencies(project, {
    fetch: async () => assert.fail('unlocked nested dependencies must fail before OSV')
  });
  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'npm_lockfile_missing');
});

test('does not follow dependency symlinks and reports incomplete inventory', async (t) => {
  const project = makeProject({
    'package-lock.json': JSON.stringify(lockV3({
      'node_modules/library-a': { version: '1.2.3' }
    }))
  });
  const outside = makeProject({ 'go.mod': 'module example.invalid/outside\n' });
  t.after(() => {
    fs.rmSync(project, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });
  fs.symlinkSync(
    outside,
    path.join(project, 'linked-project'),
    process.platform === 'win32' ? 'junction' : 'dir'
  );

  let fetchCalled = false;
  const result = await analyzeDependencies(project, {
    fetch: async () => { fetchCalled = true; return response({ results: [] }); }
  });

  assert.equal(result.status, 'failed');
  assert.equal(result.metadata.reason, 'dependency_symlink_skipped');
  assert.equal(result.metadata.inventory.skippedSymlinkCount, 1);
  assert.equal(fetchCalled, false);
});

test('fails closed at inventory depth, entry-count, and total-byte limits', async (t) => {
  const deepProject = makeProject({});
  t.after(() => fs.rmSync(deepProject, { recursive: true, force: true }));
  const deepDirectory = Array.from({ length: 33 }, (_value, index) => `d${index}`).join(path.sep);
  writeNestedFile(deepProject, path.join(deepDirectory, 'go.mod'), 'module deep\n');
  const depthResult = await analyzeDependencies(deepProject);
  assert.equal(depthResult.status, 'failed');
  assert.equal(depthResult.metadata.reason, 'dependency_depth_limit_exceeded');

  const entryProject = makeProject({});
  t.after(() => fs.rmSync(entryProject, { recursive: true, force: true }));
  for (let index = 0; index < 10001; index += 1) {
    fs.writeFileSync(path.join(entryProject, `untracked-${index}.txt`), '');
  }
  const entryResult = await analyzeDependencies(entryProject);
  assert.equal(entryResult.status, 'failed');
  assert.equal(entryResult.metadata.reason, 'dependency_entry_limit_exceeded');

  const sizeProject = makeProject({});
  t.after(() => fs.rmSync(sizeProject, { recursive: true, force: true }));
  for (let index = 0; index < 6; index += 1) {
    writeNestedFile(
      sizeProject,
      `modules/${index}/go.mod`,
      Buffer.alloc(9 * 1024 * 1024, 0x61)
    );
  }
  const sizeResult = await analyzeDependencies(sizeProject);
  assert.equal(sizeResult.status, 'failed');
  assert.equal(sizeResult.metadata.reason, 'dependency_total_size_limit_exceeded');
});
