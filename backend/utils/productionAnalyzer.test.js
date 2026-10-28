import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyzeProduction } from './productionAnalyzer.js';

const makeProject = (files) => {
  const projectPath = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-analysis-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(projectPath, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return projectPath;
};

const completeProjectFiles = {
  Dockerfile: 'FROM node:22-alpine AS build\nFROM node:22-alpine\nUSER node\nHEALTHCHECK CMD true\n',
  '.dockerignore': 'node_modules\n',
  'README.md': 'Project documentation',
  'package-lock.json': JSON.stringify({
    name: 'fixture',
    lockfileVersion: 3,
    packages: { '': { name: 'fixture', version: '1.0.0' } }
  }),
  'src/config.js': 'export const value = true;\n'
};

const dockerWithImage = {
  listImages: async () => [{ RepoTags: ['test-image:latest'] }],
  getImage: () => ({
    inspect: async () => ({ Id: 'sha256:test', Size: 1024, Created: '2026-01-01T00:00:00Z' })
  })
};

const quietLogger = { info() {}, warn() {}, error() {} };

test('reports partial coverage for a finding-free heuristic scan with unsupported checks', async (t) => {
  const projectPath = makeProject(completeProjectFiles);
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger,
    now: () => new Date('2026-01-01T00:00:00.000Z')
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, false);
  assert.equal(report.scan.findingCount, 0);
  assert.match(report.scan.assessment, /does not establish that the application is secure/);
  assert.ok(report.scan.checks.some((check) =>
    check.id === 'owasp_top_10' && check.status === 'unsupported'
  ));
  assert.ok(report.scan.checks.some((check) =>
    check.id === 'dynamic_vulnerability_testing' && check.status === 'unsupported'
  ));
  assert.ok(report.scan.checks.every((check) =>
    check.name && check.scope && check.explanation &&
    ['passed', 'findings', 'failed', 'unsupported', 'skipped', 'incomplete'].includes(check.status)
  ));
  assert.equal(report.scan.checks.find((check) => check.id === 'dependency_vulnerability_analysis').status, 'passed');
  assert.equal(report.project.path, '.');
});

test('preserves mixed finding, failed, unsupported, incomplete, and skipped check outcomes', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'go.mod': 'module example.invalid/service\n\ngo 1.22\n',
    'src/config.js': 'const API_KEY = "must-not-appear-in-report";\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'missing-image', null, {
    docker: {
      listImages: async () => {
        const error = new Error('must-not-appear-in-report');
        error.code = 'DOCKER_UNAVAILABLE';
        throw error;
      }
    },
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const statuses = new Set(report.scan.checks.map((check) => check.status));

  for (const status of ['passed', 'failed', 'unsupported', 'skipped', 'incomplete']) {
    assert.ok(statuses.has(status), `expected a ${status} check`);
  }
  const secretCheck = report.scan.checks.find((check) => check.id === 'secret_pattern_search');
  assert.equal(secretCheck.status, 'incomplete');
  assert.equal(secretCheck.findingCount, 1);
  assert.equal(report.issues.some((issue) => issue.checkId === 'secret_pattern_search'), true);
  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, true);
  assert.match(report.scan.assessment, /coverage is incomplete/);
  assert.doesNotMatch(JSON.stringify(report), /must-not-appear-in-report/);
});

test('reports redacted credential indicators with safe relative locations', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/private-config.js': 'const API_KEY = "do-not-disclose";\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, true);
  assert.equal(report.scan.findingCount, report.issues.length);
  const finding = report.issues.find((issue) => issue.title === 'Possible hard-coded credential');
  assert.ok(finding);
  assert.equal(finding.ruleId, 'LUM-SEC-001');
  assert.equal(finding.file, 'src/private-config.js');
  assert.equal(finding.line, 1);
  assert.equal(finding.evidence, 'API_KEY=<redacted>');
  assert.doesNotMatch(JSON.stringify(report), /do-not-disclose|luminicent-analysis-/);
});

test('finds multiple credential indicators, emits stable rule IDs, and suppresses placeholders and test fixtures', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/credentials.js': [
      'const API_KEY = "live-value-that-must-not-leak";',
      'const token = "ghp_abcdefghijklmnopqrstuvwxyz123456";',
      'const password = "correct-horse-battery-train";',
      'const PASSWORD = "your_password_here";',
      'const configured = process.env.API_KEY;',
      ''
    ].join('\n'),
    'src/private.pem': '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n',
    'tests/fixtures/example.js': 'const SECRET = "test-fixture-placeholder-value";\n',
    '.env.example': 'API_KEY=replace_me_with_a_real_key\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  const findings = report.issues.filter((issue) => issue.checkId === 'secret_pattern_search');
  assert.equal(findings.length, 4);
  assert.deepEqual(new Set(findings.map((finding) => finding.ruleId)), new Set(['LUM-SEC-001']));
  assert.ok(findings.every((finding) => finding.file && finding.line > 0 && finding.evidence.includes('<redacted>')));
  assert.doesNotMatch(JSON.stringify(report), /live-value-that-must-not-leak|ghp_abcdefghijklmnopqrstuvwxyz123456|correct-horse-battery-train|MIIEvQIBADANBgkqhkiG9w0BAQEFAASC/);
  assert.equal(report.scan.checks.find((check) => check.id === 'secret_pattern_search').findingCount, 4);
});

test('detects explicit TLS weakening and sensitive remote HTTP but excludes secure and loopback endpoints', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    '.env': 'NODE_TLS_REJECT_UNAUTHORIZED="0"\n',
    'config/security.yml': [
      'tls_verify: false',
      'rejectUnauthorized: true',
      'tls_verify: true',
      'auth_endpoint: http://identity.example.invalid/oauth',
      'api_url: http://localhost:3000/api',
      'service_url: http://127.0.0.1:8080',
      'issuer_url: https://issuer.example.invalid',
      ''
    ].join('\n'),
    'README.md': 'Do not set rejectUnauthorized: false; use https://identity.example.invalid instead.\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  const findings = report.issues.filter((issue) => issue.checkId === 'insecure_transport_configuration');
  assert.deepEqual(findings.map((finding) => finding.ruleId).sort(), ['LUM-TLS-001', 'LUM-TLS-001', 'LUM-TLS-002']);
  assert.ok(findings.some((finding) => finding.line === 1 && finding.file === '.env'));
  assert.ok(findings.some((finding) => finding.evidence.includes('non-loopback')));
  assert.doesNotMatch(JSON.stringify(findings), /localhost|127\.0\.0\.1|issuer\.example\.invalid/);
});

test('reports wildcard CORS and debug only with explicit production context', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'config/cors.json': JSON.stringify({
      cors: { origin: '*' }
    }, null, 2),
    'config/app.yml': [
      'environment: production',
      'debug: true',
      ''
    ].join('\n'),
    'config/production-name-only.json': '{"debug":true}',
    'config/safe.yml': [
      'environment: development',
      'debug: true',
      'cors:',
      '  allowed_origins: ["https://app.example.invalid"]',
      ''
    ].join('\n')
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  const findings = report.issues.filter((issue) => issue.checkId === 'dangerous_application_configuration');
  assert.deepEqual(findings.map((finding) => finding.ruleId).sort(), ['LUM-CFG-001', 'LUM-CFG-002']);
  assert.ok(findings.some((finding) => finding.file === 'config/app.yml' && finding.line === 2));
  assert.ok(findings.some((finding) => finding.file === 'config/cors.json'));
  assert.equal(report.scan.checks.find((check) => check.id === 'dangerous_application_configuration').findingCount, 2);
});

test('malformed JSON, binary source files, unreadable files, and symlinks keep static coverage partial', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'config/malformed.json': '{"debug": true',
    'src/binary.js': Buffer.from([0x63, 0x6f, 0x6e, 0x73, 0x74, 0x00, 0xff])
  });
  const secretPath = path.join(projectPath, 'src', 'unreadable.js');
  fs.writeFileSync(secretPath, 'const API_KEY = "unreadable-secret-value";\n');
  const linkedPath = path.join(projectPath, 'linked.js');
  const outsidePath = path.join(os.tmpdir(), `luminicent-outside-${Date.now()}.js`);
  fs.writeFileSync(linkedPath, '');
  fs.writeFileSync(outsidePath, 'const API_KEY = "outside-secret-value";\n');
  t.after(() => {
    fs.rmSync(projectPath, { recursive: true, force: true });
    fs.rmSync(outsidePath, { force: true });
  });

  const unreadableFs = new Proxy(fs, {
    get(target, property) {
      if (property === 'openSync') {
        return (filePath, ...args) => {
          if (path.resolve(filePath) === path.resolve(secretPath)) {
            const error = new Error('inaccessible path must not be logged');
            error.code = 'EACCES';
            throw error;
          }
          return target.openSync(filePath, ...args);
        };
      }
      if (property === 'lstatSync') {
        return (filePath, ...args) => {
          if (path.resolve(filePath) === path.resolve(linkedPath)) {
            return {
              isSymbolicLink: () => true,
              isDirectory: () => false,
              isFile: () => false,
              size: 0
            };
          }
          return target.lstatSync(filePath, ...args);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    }
  });
  const logged = [];
  const report = await analyzeProduction(projectPath, 'test-image', null, {
    fs: unreadableFs,
    docker: dockerWithImage,
    logger: { info() {}, warn: (...args) => logged.push(args), error() {} }
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.issues.some((issue) => issue.evidence === 'API_KEY=<redacted>' && issue.file === 'src/unreadable.js'), false);
  assert.doesNotMatch(JSON.stringify(report), /outside-secret-value|inaccessible path|unreadable-secret-value/);
  assert.doesNotMatch(JSON.stringify(logged), /outside-secret-value|inaccessible path|unreadable-secret-value/);
  for (const id of ['secret_pattern_search', 'insecure_transport_configuration', 'dangerous_application_configuration']) {
    assert.equal(report.scan.checks.find((check) => check.id === id).status, 'failed');
  }
});

test('malformed supported JSON configuration is incomplete, not clean', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'config/broken.json': '{invalid'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, false);
  const check = report.scan.checks.find((item) => item.id === 'dangerous_application_configuration');
  assert.equal(check.status, 'failed');
  assert.match(check.explanation, /malformed/);
});

test('unsupported non-binary formats are skipped and reported as incomplete coverage', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/service.unknown': 'const API_KEY = "unsupported-format-secret";\n',
    'assets/image.png': Buffer.from('const API_KEY = "binary-format-secret";\n')
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.issues.some((issue) => issue.checkId === 'secret_pattern_search'), false);
  for (const id of ['secret_pattern_search', 'insecure_transport_configuration', 'dangerous_application_configuration']) {
    const check = report.scan.checks.find((item) => item.id === id);
    assert.equal(check.status, 'incomplete');
    assert.match(check.explanation, /binary or unsupported file formats were skipped/);
  }
  assert.doesNotMatch(JSON.stringify(report), /unsupported-format-secret|binary-format-secret/);
});

test('marks inspection errors as partial results rather than vulnerability findings', async (t) => {
  const projectPath = makeProject(completeProjectFiles);
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const loggedErrors = [];

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: {
      listImages: async () => {
        const error = new Error('do-not-log-this-path');
        error.code = 'DOCKER_UNAVAILABLE';
        throw error;
      }
    },
    logger: { info() {}, error: (...args) => loggedErrors.push(args) }
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, false);
  assert.equal(report.scan.findingCount, 0);
  assert.ok(report.scan.checks.some((check) =>
    check.id === 'image_metadata' && check.status === 'failed'
  ));
  assert.equal(report.issues.some((issue) => /inspect failed/i.test(issue.title)), false);
  assert.doesNotMatch(JSON.stringify(loggedErrors), /do-not-log-this-path/);
});

test('marks secret-pattern analysis partial when file resource limits are exceeded', async (t) => {
  const projectPath = makeProject(completeProjectFiles);
  const oversizedPath = path.join(projectPath, 'oversized.js');
  fs.closeSync(fs.openSync(oversizedPath, 'w'));
  fs.truncateSync(oversizedPath, 10 * 1024 * 1024 + 1);
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  assert.equal(report.scan.status, 'partial');
  assert.ok(report.scan.checks.some((check) =>
    check.id === 'secret_pattern_search' && check.status === 'failed' &&
    /resource limit/.test(check.explanation)
  ));
});

test('reports npm dependency advisories as structured findings without source paths', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'package-lock.json': JSON.stringify({
      name: 'fixture',
      lockfileVersion: 3,
      packages: {
        '': { name: 'fixture', version: '1.0.0', dependencies: { 'library-a': '^1.0.0' } },
        'node_modules/library-a': { version: '1.2.3' }
      }
    })
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const fetch = async (url) => {
    if (url.endsWith('/v1/querybatch')) {
      return new Response(JSON.stringify({
        results: [{ vulns: [{ id: 'GHSA-test-1234', modified: '2025-01-02T03:04:05Z' }] }]
      }));
    }
    return new Response(JSON.stringify({
      id: 'GHSA-test-1234',
      summary: 'A library vulnerability',
      affected: [{
        package: { ecosystem: 'npm', name: 'library-a' },
        ranges: [{ events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }],
        database_specific: { severity: 'HIGH' }
      }]
    }));
  };

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger,
    fetch,
    now: () => new Date('2026-01-01T00:00:00.000Z')
  });

  const finding = report.issues.find((issue) => issue.dependency?.advisoryId === 'GHSA-test-1234');
  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, true);
  assert.equal(report.scan.findingCount, report.issues.length);
  assert.equal(report.summary.high, 1);
  assert.equal(finding.dependency.package, 'library-a');
  assert.equal(finding.dependency.installedVersion, '1.2.3');
  assert.equal(finding.dependency.relationship, 'direct');
  assert.equal(finding.dependency.fixedVersion, '2.0.0');
  assert.match(finding.recommendation, /2\.0\.0/);
  assert.doesNotMatch(JSON.stringify(report), /luminicent-analysis-/);
});

test('marks dependency advisory network failures partial rather than clean', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'package-lock.json': JSON.stringify({
      name: 'fixture',
      lockfileVersion: 3,
      packages: {
        '': { name: 'fixture', version: '1.0.0' },
        'node_modules/library-a': { version: '1.2.3' }
      }
    })
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger,
    fetch: async () => {
      throw new Error('network failure must not be copied to the report');
    }
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.scan.findingsDetected, false);
  assert.equal(report.dependencyAnalysis.status, 'failed');
  assert.ok(report.scan.checks.some((check) =>
    check.id === 'dependency_vulnerability_analysis' && check.status === 'failed'
  ));
  assert.doesNotMatch(JSON.stringify(report), /network failure|luminicent-analysis-/);
});

test('marks mixed supported and unsupported dependency ecosystems partial', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'services/api/go.mod': 'module example.invalid/api\n',
    'tools/worker/Cargo.toml': '[package]\nname = "worker"\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.dependencyAnalysis.status, 'partial');
  assert.deepEqual(report.dependencyAnalysis.unsupportedFormats, ['Go', 'Rust']);
  const dependencyCheck = report.scan.checks.find((check) =>
    check.id === 'dependency_vulnerability_analysis'
  );
  assert.equal(dependencyCheck.status, 'incomplete');
  assert.match(dependencyCheck.explanation, /Go, Rust/);
});

test('reports malformed nested npm coverage as partial rather than clean', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'apps/service/package.json': '{malformed',
    'apps/service/package-lock.json': JSON.stringify({
      name: 'service',
      lockfileVersion: 3,
      packages: { '': { name: 'service', version: '1.0.0' } }
    })
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger,
    fetch: async () => assert.fail('invalid nested manifests must fail before OSV')
  });

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.dependencyAnalysis.status, 'failed');
  assert.equal(report.dependencyAnalysis.reason, 'npm_lockfile_invalid');
  assert.equal(report.scan.findingsDetected, report.issues.length > 0);
  assert.ok(report.scan.checks.some((check) =>
    check.id === 'dependency_vulnerability_analysis' && check.status === 'failed'
  ));
});

test('scans dependency coverage from the extracted project root, not only the selected build context', async (t) => {
  const projectFiles = Object.fromEntries(
    Object.entries(completeProjectFiles).map(([name, content]) => [
      path.join('services', 'api', name),
      content
    ])
  );
  const projectPath = makeProject({
    ...projectFiles,
    'tools/worker/go.mod': 'module example.invalid/worker\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(
    path.join(projectPath, 'services', 'api'),
    'test-image',
    null,
    {
      dependencyRoot: projectPath,
      docker: dockerWithImage,
      logger: quietLogger
    }
  );

  assert.equal(report.scan.status, 'partial');
  assert.equal(report.dependencyAnalysis.status, 'partial');
  assert.deepEqual(report.dependencyAnalysis.unsupportedFormats, ['Go']);
});
