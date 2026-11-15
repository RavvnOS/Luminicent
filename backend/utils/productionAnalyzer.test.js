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

const analyzeProjectFiles = async (t, files) => {
  const projectPath = makeProject({ ...completeProjectFiles, ...files });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  return analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
};

const registeredExpressRoute = (source, handlerName = 'handle') =>
  `${source}\nconst express = require('express');\n` +
  `const app = express();\napp.post('/route', ${handlerName});\n`;

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
    check.name && check.category && check.categoryName && check.scope && check.explanation &&
    ['completed', 'partial', 'failed', 'unsupported', 'skipped'].includes(check.status) &&
    (check.status === 'completed'
      ? check.reason === undefined
      : check.reason && check.reason.code && check.reason.message)
  ));
  assert.equal(report.scan.checks.find((check) => check.id === 'dependency_vulnerability_analysis').status, 'completed');
  assert.equal(report.scan.checks.find((check) => check.id === 'dependency_vulnerability_analysis').category, 'dependency_analysis');
  assert.equal(report.scan.coverage.status, 'partial');
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'credential_indicators' && category.status === 'completed'
  ));
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'injection_indicators' && category.status === 'completed'
  ));
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'deserialization_indicators' && category.status === 'completed'
  ));
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'dynamic_execution_indicators' && category.status === 'completed'
  ));
  assert.equal(report.project.path, '.');
  assert.deepEqual(report.scan.coverage.counts, {
    completed: 14,
    partial: 0,
    skipped: 1,
    unsupported: 3,
    failed: 0
  });
});

test('marks an empty project partial with explicit reasons rather than treating zero findings as full coverage', async (t) => {
  const projectPath = makeProject({});
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => assert.fail('an empty project has no dependency lockfile to query')
  });

  assert.equal(report.scan.findingsDetected, true);
  assert.ok(report.issues.some((issue) => issue.title === 'Dockerfile Missing'));
  const staticCheck = report.scan.checks.find((check) => check.id === 'secret_pattern_search');
  assert.equal(staticCheck.status, 'partial');
  assert.equal(staticCheck.reason.code, 'no_supported_text_files');
  for (const id of [
    'sql_injection_pattern_search',
    'os_command_injection_pattern_search',
    'unsafe_deserialization_pattern_search',
    'dynamic_code_execution_pattern_search'
  ]) {
    const injectionCheck = report.scan.checks.find((check) => check.id === id);
    assert.equal(injectionCheck.status, 'partial');
  }
  assert.equal(report.scan.checks.find((c) => c.id === 'sql_injection_pattern_search').reason.code, 'no_supported_injection_source_files');
  assert.equal(report.scan.checks.find((c) => c.id === 'os_command_injection_pattern_search').reason.code, 'no_supported_injection_source_files');
  assert.equal(report.scan.checks.find((c) => c.id === 'unsafe_deserialization_pattern_search').reason.code, 'no_supported_deserialization_source_files');
  assert.equal(report.scan.checks.find((c) => c.id === 'dynamic_code_execution_pattern_search').reason.code, 'no_supported_dynamic_execution_source_files');
  const dependencyCheck = report.scan.checks.find((check) =>
    check.id === 'dependency_vulnerability_analysis'
  );
  assert.equal(dependencyCheck.status, 'unsupported');
  assert.equal(dependencyCheck.reason.code, 'no_supported_dependency_manifest');
  assert.equal(report.scan.status, 'partial');
});

test('fixture-only source files do not count as analyzed injection coverage', async (t) => {
  const projectPath = makeProject({
    '__fixtures__/only.js': 'eval(input);\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => assert.fail('a fixture-only project has no dependency lockfile to query')
  });

  for (const [id, reasonCode] of [
    ['sql_injection_pattern_search', 'no_supported_injection_source_files'],
    ['os_command_injection_pattern_search', 'no_supported_injection_source_files'],
    ['unsafe_deserialization_pattern_search', 'no_supported_deserialization_source_files'],
    ['dynamic_code_execution_pattern_search', 'no_supported_dynamic_execution_source_files']
  ]) {
    const check = report.scan.checks.find((item) => item.id === id);
    assert.equal(check.status, 'partial');
    assert.equal(check.reason.code, reasonCode);
  }
});

test('unsupported text and binary files affect only relevant coverage checks', async (t) => {
  const cases = [
    {
      file: 'src/service.unknown',
      content: 'unsupported text format',
      reason: 'unsupported_file_format',
      expectedPartial: [
        'secret_pattern_search'
      ]
    },
    {
      file: 'assets/image.png',
      content: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      expectedPartial: []
    }
  ];

  for (const testCase of cases) {
    const projectFiles = { ...completeProjectFiles, [testCase.file]: testCase.content };
    const projectPath = makeProject(projectFiles);
    t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
    const report = await analyzeProduction(projectPath, 'unused', null, {
      staticOnly: true,
      logger: quietLogger
    });

    assert.equal(report.scan.status, 'partial');
    for (const id of testCase.expectedPartial) {
      const check = report.scan.checks.find((item) => item.id === id);
      assert.equal(check.status, 'partial');
      if (testCase.reason) assert.equal(check.reason.code, testCase.reason);
    }
    if (testCase.file.endsWith('.unknown')) {
      assert.equal(
        report.scan.checks.find((item) => item.id === 'insecure_transport_configuration').status,
        'completed',
        'unsupported files are not inputs to transport checks'
      );
      assert.equal(
        report.scan.checks.find((item) => item.id === 'dangerous_application_configuration').status,
        'completed',
        'unsupported files are not inputs to configuration checks'
      );
      for (const id of [
        'sql_injection_pattern_search',
        'os_command_injection_pattern_search',
        'unsafe_deserialization_pattern_search',
        'dynamic_code_execution_pattern_search'
      ]) {
        assert.equal(report.scan.checks.find((item) => item.id === id).status, 'completed');
      }
    } else if (testCase.file.endsWith('.png')) {
      assert.equal(
        report.scan.checks.find((item) => item.id === 'secret_pattern_search').status,
        'completed',
        'known binary assets are intentionally excluded from text checks'
      );
      assert.equal(report.scan.coverage.inventory.binaryFiles, 1);
      assert.equal(report.scan.coverage.inventory.filesSkipped, 1);
    }
  }
});

test('reports cancellation as the reason static checks did not complete', async (t) => {
  const projectPath = makeProject(completeProjectFiles);
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const controller = new AbortController();
  controller.abort();

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    signal: controller.signal,
    logger: quietLogger
  });

  for (const id of [
    'secret_pattern_search',
    'sql_injection_pattern_search',
    'os_command_injection_pattern_search',
    'unsafe_deserialization_pattern_search',
    'dynamic_code_execution_pattern_search',
    'insecure_transport_configuration',
    'dangerous_application_configuration'
  ]) {
    const check = report.scan.checks.find((item) => item.id === id);
    assert.equal(check.status, 'partial');
    assert.equal(check.reason.code, 'analysis_cancelled');
  }
});

test('reports zero findings as completed only for checks that actually completed', async (t) => {
  const projectPath = makeProject(completeProjectFiles);
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  assert.equal(report.scan.findingsDetected, false);
  assert.equal(report.scan.findingCount, 0);
  for (const id of [
    'dockerfile_presence',
    'dockerfile_configuration',
    'dockerignore_configuration',
    'environment_configuration',
    'secret_pattern_search',
    'sql_injection_pattern_search',
    'os_command_injection_pattern_search',
    'unsafe_deserialization_pattern_search',
    'dynamic_code_execution_pattern_search',
    'insecure_transport_configuration',
    'dangerous_application_configuration',
    'project_structure',
    'dependency_vulnerability_analysis'
  ]) {
    const check = report.scan.checks.find((item) => item.id === id);
    assert.equal(check.status, 'completed', `${id} should have completed`);
    assert.equal(check.reason, undefined);
  }
  assert.equal(report.scan.status, 'partial');
  assert.match(report.scan.assessment, /incomplete/);
});

test('reports a missing npm lockfile only for Node projects', async (t) => {
  const projectFiles = {
    Dockerfile: 'FROM node:22-alpine AS build\nFROM node:22-alpine\nUSER node\nHEALTHCHECK CMD true\n',
    '.dockerignore': 'node_modules\n',
    'README.md': 'Project documentation'
  };
  const nonNodeProject = makeProject(projectFiles);
  const nodeProject = makeProject({
    ...projectFiles,
    'package.json': JSON.stringify({ name: 'fixture', version: '1.0.0' })
  });
  t.after(() => {
    fs.rmSync(nonNodeProject, { recursive: true, force: true });
    fs.rmSync(nodeProject, { recursive: true, force: true });
  });

  const nonNodeReport = await analyzeProduction(nonNodeProject, 'test-image', null, {
    staticOnly: true,
    logger: quietLogger
  });
  const nodeReport = await analyzeProduction(nodeProject, 'test-image', null, {
    staticOnly: true,
    logger: quietLogger
  });

  assert.equal(nonNodeReport.issues.some((issue) => issue.title === 'Lock File Missing'), false);
  assert.equal(nodeReport.issues.some((issue) => issue.title === 'Lock File Missing'), true);
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

  for (const status of ['completed', 'failed', 'unsupported', 'skipped', 'partial']) {
    assert.ok(statuses.has(status), `expected a ${status} check`);
  }
  const secretCheck = report.scan.checks.find((check) => check.id === 'secret_pattern_search');
  assert.equal(secretCheck.status, 'partial');
  assert.equal(secretCheck.reason.code, 'unsupported_file_format');
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
  const finding = report.issues.find((issue) =>
    issue.checkId === 'secret_pattern_search' && issue.ruleId === 'LUM-SEC-001'
  );
  assert.ok(finding);
  assert.equal(finding.ruleId, 'LUM-SEC-001');
  assert.equal(finding.confidence, 'high');
  assert.deepEqual(finding.cwe, ['CWE-798']);
  assert.match(finding.severityRationale, /Medium:/);
  assert.equal(finding.file, 'src/private-config.js');
  assert.equal(finding.line, 1);
  assert.equal(finding.evidence, 'API key or secret=<redacted>');
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
  assert.deepEqual(
    new Set(findings.map((finding) => finding.ruleId)),
    new Set(['LUM-SEC-001', 'LUM-SEC-003'])
  );
  assert.ok(findings.every((finding) => finding.file && finding.line > 0 && finding.evidence.includes('<redacted>')));
  assert.ok(findings.every((finding) => finding.confidence && finding.severityRationale && finding.cwe.length > 0));
  assert.ok(findings.some((finding) => finding.ruleId === 'LUM-SEC-003' && finding.severity === 'Critical'));
  assert.ok(findings.some((finding) => finding.ruleId === 'LUM-SEC-001' && finding.severity === 'Medium'));
  assert.doesNotMatch(JSON.stringify(report), /live-value-that-must-not-leak|ghp_abcdefghijklmnopqrstuvwxyz123456|correct-horse-battery-train|MIIEvQIBADANBgkqhkiG9w0BAQEFAASC/);
  assert.equal(report.scan.checks.find((check) => check.id === 'secret_pattern_search').findingCount, 4);
});

test('suppresses translated credential labels but detects real tokens and PEM keys in localization JSON', async (t) => {
  const providerToken = `ghp_${'R'.repeat(30)}`;
  const pem = [
    '-----BEGIN PRIVATE KEY-----',
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC',
    '-----END PRIVATE KEY-----'
  ].join('\n');
  const projectPath = makeProject({
    ...completeProjectFiles,
    'locales/pl_PL.json': JSON.stringify({
      privateKey: 'Klucz prywatny',
      accessToken: 'Token dostępu'
    }),
    'locales/pt_PT.json': JSON.stringify({
      privateKey: 'Chave privada',
      accessToken: 'Token de acesso'
    }),
    'locales/ru_RU.json': JSON.stringify({
      privateKey: 'Закрытый ключ',
      accessToken: 'Токен доступа'
    }),
    'locales/sv_SE.json': JSON.stringify({
      privateKey: 'Privat nyckel',
      accessToken: 'Åtkomsttoken'
    }),
    'locales/secrets.json': JSON.stringify({
      apiToken: providerToken,
      privateKey: pem
    })
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const findings = report.issues.filter((issue) => issue.checkId === 'secret_pattern_search');

  assert.equal(findings.length, 2);
  assert.ok(findings.some((finding) =>
    finding.ruleId === 'LUM-SEC-001' &&
    finding.file === 'locales/secrets.json' &&
    finding.evidence === 'access token=<redacted>'
  ));
  assert.ok(findings.some((finding) =>
    finding.ruleId === 'LUM-SEC-003' &&
    finding.file === 'locales/secrets.json' &&
    finding.severity === 'Critical'
  ));
  assert.ok(findings.every((finding) =>
    !['locales/pl_PL.json', 'locales/pt_PT.json', 'locales/ru_RU.json', 'locales/sv_SE.json']
      .includes(finding.file)
  ));
  assert.doesNotMatch(JSON.stringify(report), new RegExp(providerToken));
  assert.doesNotMatch(JSON.stringify(report), /MIIEvQIBADANBgkqhkiG9w0BAQEFAASC/);
});

test('groups repeated credential occurrences without merging different values or issue types', async (t) => {
  const sharedSecret = 'shared-access-token-value-123456';
  const distinctSecret = 'different-access-token-value-654321';
  const projectPath = makeProject({
    ...completeProjectFiles,
    'locales/repeated.json': JSON.stringify({
      apiToken: sharedSecret,
      serviceToken: sharedSecret,
      refreshToken: distinctSecret,
      privateKey: sharedSecret
    }),
    'src/repeated.py': `api_token = "${sharedSecret}"\n`
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const findings = report.issues.filter((issue) => issue.checkId === 'secret_pattern_search');
  const repeated = findings.find((finding) =>
    finding.evidence === 'access token=<redacted>' && finding.occurrences === 2
  );

  assert.equal(findings.length, 3, JSON.stringify(findings.map(({ evidence, locations, occurrences }) => ({
    evidence,
    locations,
    occurrences
  }))));
  assert.ok(repeated, 'same value and issue type is grouped across distinct source locations');
  assert.deepEqual(
    repeated.locations.map(({ file, line }) => `${file}:${line}`).sort(),
    ['locales/repeated.json:1', 'src/repeated.py:1']
  );
  assert.equal(
    findings.filter((finding) => finding.evidence === 'access token=<redacted>').length,
    2,
    'different access-token values remain separate findings'
  );
  assert.ok(findings.some((finding) => finding.evidence === 'private key=<redacted>'));
  assert.doesNotMatch(JSON.stringify(report), new RegExp(sharedSecret));
  assert.doesNotMatch(JSON.stringify(report), new RegExp(distinctSecret));
});

test('detects JavaScript, TypeScript, Python, JSON, YAML, and ENV credentials with safe deduplication', async (t) => {
  const sharedValue = '0123456789abcdef0123456789abcdef';
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/secrets.ts': `export const API_KEY = "${sharedValue}";\n`,
    'service/settings.py': `client_secret = "${sharedValue}"\nAWS_SECRET_ACCESS_KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"\nPYTHON_API_KEY: str = """python-triple-quoted-secret-987654"""\n`,
    'config/app.json': '{"api_key":"JSON-credential-value-0123456789"}',
    'config/app.yml': 'password: "Prod-password-value-938271"\n',
    '.env': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSERVICE_TOKEN=service-token-value-948271\n',
    'src/config.js': [
      'const standalone = "ghp_abcdefghijklmnopqrstuvwxyz123456";',
      'const fromEnv = process.env.API_KEY;',
      'const fromPython = os.environ.get("API_KEY");',
      'const template = `${process.env.ACCESS_TOKEN}`;',
      'const sample = "fake_test_credential_value";',
      'const placeholder = "your_api_key_here";',
      '// API_KEY = "commented-out-secret-value";',
      ''
    ].join('\n'),
    'docs/example.py': 'API_KEY = "documentation-secret-value-123456"\n',
    'tests/test_config.py': 'password = "fake-test-password-value-123456"\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const findings = report.issues.filter((issue) => issue.checkId === 'secret_pattern_search');
  const sharedFinding = findings.find((finding) =>
    finding.evidence === 'API key or secret=<redacted>' && finding.occurrences === 2
  );

  assert.ok(findings.some((finding) => finding.locations.some((location) => location.file === 'src/secrets.ts')));
  assert.ok(findings.some((finding) => finding.file === 'service/settings.py' && finding.evidence === 'cloud credential=<redacted>'));
  assert.ok(findings.some((finding) => finding.file === 'service/settings.py' && finding.line === 3));
  assert.ok(findings.some((finding) => finding.file === 'config/app.json'));
  assert.ok(findings.some((finding) => finding.file === 'config/app.yml' && finding.severity === 'Medium'));
  assert.ok(findings.some((finding) => finding.file === '.env'));
  assert.ok(sharedFinding);
  assert.deepEqual(
    sharedFinding.locations.map((location) => location.file).sort(),
    ['service/settings.py', 'src/secrets.ts']
  );
  assert.equal(sharedFinding.occurrences, 2);
  assert.ok(findings.some((finding) => finding.ruleId === 'LUM-SEC-002'));
  const locations = findings.flatMap((finding) => finding.locations);
  for (const [file, line] of [
    ['.env', 1],
    ['src/config.js', 2],
    ['src/config.js', 3],
    ['src/config.js', 4],
    ['src/config.js', 5],
    ['src/config.js', 6],
    ['src/config.js', 7],
    ['docs/example.py', 1],
    ['tests/test_config.py', 1]
  ]) {
    assert.equal(
      locations.some((location) => location.file === file && location.line === line),
      false,
      `${file}:${line} should be ignored as a sample, placeholder, lookup, comment, or excluded path`
    );
  }
  assert.doesNotMatch(JSON.stringify(report), /0123456789abcdef0123456789abcdef|AbCdEfGhIjKlMnOpQrStUvWxYz012345|python-triple-quoted-secret-987654|JSON-credential-value-0123456789|Prod-password-value-938271|AKIAIOSFODNN7EXAMPLE|service-token-value-948271|ghp_abcdefghijklmnopqrstuvwxyz123456|documentation-secret-value|fake-test-password-value/);
  assert.equal(report.scan.checks.find((check) => check.id === 'secret_pattern_search').status, 'completed');
});

test('audits multiline, nested, provider, PEM, suppression, deduplication, and redaction cases', async (t) => {
  const values = {
    jsTemplate: 'js-template-secret-value-239847',
    tsTemplate: 'ts-template-secret-value-928374',
    pythonTripleQuote: 'python-multiline-password-827364',
    nestedJson: 'nested-json-secret-value-827364',
    nestedYaml: 'nested-yaml-secret-value-738291',
    env: 'environment-secret-value-827364',
    hashEnv: 'ab#hash-containing-environment-secret-827364',
    properties: 'properties-secret-value-827364',
    repeated: 'repeated-secret-value-827364',
    inlineComment: 'inline-comment-secret-value-827364',
    providerComment: `ghp_${'C'.repeat(30)}`,
    sameLineClientSecret: 'same-line-client-secret-827364',
    sameLinePassword: 'same-line-password-value-827364',
    completePem: 'A'.repeat(48),
    encryptedPem: 'B'.repeat(48),
    incompletePem: 'C'.repeat(48)
  };
  const providerValues = [
    'ASIAABCDEFGHIJKLMNOP',
    `ghp_${'A'.repeat(30)}`,
    `xoxb-${'D'.repeat(22)}`,
    `sk_live_${'E'.repeat(24)}`,
    `AIza${'F'.repeat(35)}`
  ];
  const logs = [];
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/multiline.js': [
      'const API_KEY = `first-line-prefix-longer-than-eight',
      `${values.jsTemplate}\`;`,
      `const API_KEY = "${values.repeated}";`,
      `const inline = 1; // API_KEY = "${values.inlineComment}";`,
      `const tokenComment = 1; // ${values.providerComment}`,
      'const envKey = process.env.API_KEY;',
      'const envSecret = process.env.API_KEY || `${process.env.SECRET}`;',
      'const placeholder = "your_api_key_here";',
      'const dummy = "fake_test_credential_value";',
      `const CLIENT_SECRET = "${values.sameLineClientSecret}"; const password = "${values.sameLinePassword}";`,
      ''
    ].join('\n'),
    'src/multiline.ts': `export const accessToken: string = \`first line\n${values.tsTemplate}\`;\n`,
    'src/multiline.py': `password = """first line\n${values.pythonTripleQuote}\n"""\nAPI_KEY = os.environ.get("API_KEY")\n`,
    'config/nested.json': JSON.stringify({
      service: { credentials: { api_key: values.nestedJson } }
    }, null, 2),
    'config/nested.yml': `service:\n  credentials:\n    password: "${values.nestedYaml}"\n`,
    '.env': `SERVICE_TOKEN=${values.env}\nSERVICE_TOKEN=${values.hashEnv}\nAPI_KEY=\${API_KEY}\n`,
    'config/runtime.properties': `database.password=${values.properties}\n`,
    'src/repeated.py': `API_KEY = "${values.repeated}"\n`,
    'src/providers.js': providerValues.map((value) => `const value = "${value}";`).join('\n'),
    'src/keys.pem': [
      '-----BEGIN PRIVATE KEY-----',
      values.completePem,
      '-----END PRIVATE KEY-----',
      '-----BEGIN ENCRYPTED PRIVATE KEY-----',
      values.encryptedPem,
      '-----END ENCRYPTED PRIVATE KEY-----',
      ''
    ].join('\n'),
    'src/incomplete.pem': `-----BEGIN PRIVATE KEY-----\n${values.incompletePem}\n`,
    'src/comments.py': [
      `# API_KEY = "${values.inlineComment}"`,
      `password = os.environ.get("PASSWORD"); # API_KEY = "${values.inlineComment}"`,
      ''
    ].join('\n'),
    'src/comments.js': `const marker = true; // -----BEGIN PRIVATE KEY----- ${'D'.repeat(48)} -----END PRIVATE KEY-----\n`,
    'docs/credential-examples.md': `API_KEY = "${values.inlineComment}"\n${providerValues[1]}\n`,
    'tests/fixtures/fake-credentials.js': `const API_KEY = "${values.inlineComment}";\n`
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: {
      info: (...args) => logs.push(args),
      warn: (...args) => logs.push(args),
      error: (...args) => logs.push(args)
    },
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const findings = report.issues.filter((issue) => issue.checkId === 'secret_pattern_search');
  const serializedReport = JSON.stringify(report);
  const allLogs = JSON.stringify(logs);
  const locationExists = (file, line) => findings.some((finding) =>
    finding.locations.some((location) => location.file === file && location.line === line)
  );

  assert.ok(locationExists('src/multiline.js', 1), 'multiline JavaScript template assignment');
  assert.equal(findings.filter((finding) =>
    finding.locations.some((location) => location.file === 'src/multiline.js' && location.line === 1)
  ).length, 1, 'multiline template is emitted once, not as a partial first-line value');
  assert.ok(locationExists('src/multiline.ts', 1), 'multiline TypeScript template assignment');
  assert.ok(locationExists('src/multiline.py', 1), 'multiline Python triple-quoted assignment');
  assert.ok(locationExists('config/nested.json', 4), 'nested JSON credential');
  assert.ok(locationExists('config/nested.yml', 3), 'nested YAML credential');
  assert.ok(locationExists('.env', 1), 'ENV credential');
  assert.ok(locationExists('.env', 2), 'ENV credential containing an unquoted hash');
  assert.ok(locationExists('config/runtime.properties', 1), 'configuration credential');
  assert.ok(locationExists('src/multiline.js', 10), 'first assignment on a shared line');
  assert.ok(findings.some((finding) =>
    finding.file === 'src/multiline.js' && finding.line === 10 &&
    finding.evidence === 'password=<redacted>'
  ), 'second assignment on a shared line');
  assert.equal(
    findings.filter((finding) => finding.ruleId === 'LUM-SEC-002' && finding.file === 'src/providers.js').length,
    providerValues.length,
    'all supported provider token patterns'
  );
  assert.ok(findings.some((finding) => finding.ruleId === 'LUM-SEC-003' && finding.file === 'src/keys.pem'));
  assert.equal(
    findings.filter((finding) => finding.ruleId === 'LUM-SEC-003' && finding.file === 'src/keys.pem').length,
    2,
    'both generic and encrypted PEM private keys'
  );
  assert.ok(findings.some((finding) =>
    finding.ruleId === 'LUM-SEC-003' && finding.file === 'src/keys.pem' &&
    finding.locations.some((location) => location.line === 1) &&
    finding.confidence === 'high' && finding.severity === 'Critical' &&
    finding.cwe.includes('CWE-321')
  ));
  assert.ok(findings.some((finding) =>
    finding.ruleId === 'LUM-SEC-002' && finding.file === 'src/providers.js' &&
    finding.confidence === 'high' && finding.severity === 'High' &&
    finding.cwe.includes('CWE-798')
  ));
  assert.equal(findings.some((finding) => finding.file === 'src/comments.js'), false);
  assert.equal(locationExists('src/incomplete.pem', 1), false, 'incomplete PEM is not reported as complete');

  const repeatedFinding = findings.find((finding) =>
    finding.evidence === 'API key or secret=<redacted>' &&
    finding.locations.some((location) => location.file === 'src/multiline.js' && location.line === 3)
  );
  assert.ok(repeatedFinding);
  assert.equal(repeatedFinding.occurrences, 2);
  assert.deepEqual(
    repeatedFinding.locations.map(({ file, line }) => `${file}:${line}`).sort(),
    ['src/multiline.js:3', 'src/repeated.py:1']
  );
  assert.equal(repeatedFinding.confidence, 'high');
  assert.deepEqual(repeatedFinding.cwe, ['CWE-798']);
  assert.equal(repeatedFinding.severity, 'High');
  assert.match(repeatedFinding.severityRationale, /^High:/);

  for (const suppressed of [
    ['src/multiline.js', 4],
    ['src/multiline.js', 5],
    ['src/multiline.js', 6],
    ['src/multiline.js', 7],
    ['src/multiline.js', 8],
    ['src/multiline.js', 9],
    ['src/multiline.py', 4],
    ['src/comments.py', 1],
    ['src/comments.py', 2],
    ['src/comments.js', 1],
    ['docs/credential-examples.md', 1],
    ['tests/fixtures/fake-credentials.js', 1]
  ]) {
    assert.equal(locationExists(...suppressed), false, `${suppressed.join(':')} should be suppressed`);
  }
  for (const secret of [
    ...Object.values(values),
    ...providerValues
  ]) {
    assert.equal(serializedReport.includes(secret), false, 'serialized report must redact full values');
    assert.equal(allLogs.includes(secret), false, 'logs must not contain full values');
  }
  assert.equal(report.scan.checks.find((check) => check.id === 'secret_pattern_search').status, 'partial');
  assert.equal(
    report.scan.checks.find((check) => check.id === 'secret_pattern_search').reason.code,
    'private_key_material_incomplete'
  );
});

test('does not disclose sensitive values from analyzer read errors or logs', async (t) => {
  const errorSecret = 'exception-value-must-never-be-reported-827364';
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/unreadable.js': 'const API_KEY = "unreadable";\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const logs = [];
  const protectedFs = new Proxy(fs, {
    get(target, property) {
      if (property === 'openSync') {
        return (filePath, ...args) => {
          if (String(filePath).endsWith(path.join('src', 'unreadable.js'))) {
            throw Object.assign(new Error(errorSecret), { code: 'EIO' });
          }
          return target.openSync(filePath, ...args);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    }
  });

  const report = await analyzeProduction(projectPath, 'unused', null, {
    fs: protectedFs,
    staticOnly: true,
    logger: {
      info: (...args) => logs.push(args),
      warn: (...args) => logs.push(args),
      error: (...args) => logs.push(args)
    },
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  assert.equal(JSON.stringify(report).includes(errorSecret), false);
  assert.equal(JSON.stringify(logs).includes(errorSecret), false);
  assert.equal(report.scan.checks.find((check) => check.id === 'secret_pattern_search').status, 'partial');
});

test('detects bounded SQL and shell-command injection patterns without claiming exploitability', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/sql.js': [
      'const userId = req.query.id;',
      'const sql = `SELECT *',
      '  FROM users',
      '  WHERE id = ${userId}`;',
      'db.query(sql);',
      `db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");`,
      'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
      'db.query("SELECT * FROM users WHERE id = " + userId, [userId]);',
      'const concatenatedSql = "SELECT * FROM users WHERE id = " + userId;',
      'db.query(concatenatedSql);',
      ''
    ].join('\n'),
    'src/sql-safe.ts': [
      'const userId = req.params.id;',
      'pool.execute("SELECT * FROM users WHERE id = $1", [userId]);',
      'pool.query("SELECT * FROM users WHERE name = ?", [userId]);',
      'pool.query("SELECT * FROM users");',
      ''
    ].join('\n'),
    'src/sql.py': [
      'user_id = request.args.get("id")',
      'query = f"""SELECT *',
      'FROM users',
      'WHERE id = {user_id}"""',
      'cursor.execute(query)',
      'cursor.execute("SELECT * FROM users WHERE name = \'" + user_id)',
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      'concatenated_query = "SELECT * FROM users WHERE id = " + user_id',
      'cursor.execute(concatenated_query)',
      ''
    ].join('\n'),
    'src/commands.js': [
      'const { exec, spawn } = require("node:child_process");',
      'const userInput = req.query.command;',
      'exec(`echo ${userInput}`);',
      'const command = `echo ${userInput}`;',
      'exec(command);',
      'spawn("echo", [req.query.value]);',
      'exec("echo fixed");',
      ''
    ].join('\n'),
    'src/commands.ts': [
      'import { execFile } from "node:child_process";',
      'const fileName = req.params.file;',
      'execFile("cat", [fileName]);',
      ''
    ].join('\n'),
    'src/commands.py': [
      'import os',
      'import subprocess',
      'value = request.args.get("value")',
      'os.system("echo " + value)',
      'subprocess.run("grep " + value, shell=True)',
      'subprocess.run(["grep", "--", request.args.get("value")])',
      'subprocess.run(["echo", "fixed"], shell=False)',
      'command = "echo " + value',
      'os.system(command)',
      ''
    ].join('\n'),
    'src/injection-comments.js': [
      '// db.query("SELECT * FROM users WHERE id = " + req.query.id)',
      'const comment = true; // child_process.exec("echo " + req.query.value)',
      ''
    ].join('\n'),
    'docs/injection-examples.md': 'db.query("SELECT * FROM users WHERE id = " + userInput)\n',
    'tests/fixtures/injection-example.py': 'os.system("echo " + request.args.get("value"))\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const sqlFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-INJ-001');
  const commandFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-INJ-002');
  const sqlCheck = report.scan.checks.find((check) => check.id === 'sql_injection_pattern_search');
  const commandCheck = report.scan.checks.find((check) => check.id === 'os_command_injection_pattern_search');
  const locationExists = (findings, file, line) => findings.some((finding) =>
    finding.file === file && finding.line === line
  );

  assert.equal(sqlFindings.length, 7);
  assert.ok(locationExists(sqlFindings, 'src/sql.js', 2), 'multiline JS template construction');
  assert.ok(locationExists(sqlFindings, 'src/sql.js', 6), 'JS concatenation reaches query API');
  assert.ok(locationExists(sqlFindings, 'src/sql.py', 2), 'multiline Python f-string construction');
  assert.ok(locationExists(sqlFindings, 'src/sql.py', 6), 'Python concatenation reaches execute');
  assert.ok(locationExists(sqlFindings, 'src/sql.js', 8), 'dynamic SQL remains unsafe despite extra parameters');
  assert.ok(locationExists(sqlFindings, 'src/sql.js', 9), 'concatenated SQL variable reaches query API');
  assert.ok(locationExists(sqlFindings, 'src/sql.py', 8), 'concatenated Python SQL variable reaches execute');
  assert.equal(sqlCheck.findingCount, 7);
  assert.equal(sqlCheck.status, 'completed');
  assert.ok(sqlFindings.every((finding) =>
    finding.severity === 'High' &&
    finding.confidence === 'medium' &&
    finding.cwe.includes('CWE-89') &&
    finding.severityRationale &&
    finding.recommendation &&
    finding.remediation === finding.recommendation &&
    finding.evidence.includes('<redacted>') &&
    /does not establish attacker control or exploitability/.test(finding.description)
  ));
  assert.equal(report.issues.some((issue) =>
    issue.ruleId === 'LUM-INJ-001' && issue.line === 7 &&
    ['src/sql.js', 'src/sql-safe.ts', 'src/sql.py'].includes(issue.file)
  ), false, 'parameterized and static SQL are not reported');
  assert.equal(sqlFindings.some((finding) => finding.file === 'src/sql-safe.ts'), false);

  assert.equal(commandFindings.length, 8);
  assert.ok(locationExists(commandFindings, 'src/commands.js', 3), 'Node shell exec');
  assert.ok(locationExists(commandFindings, 'src/commands.js', 5), 'Node aliased command reaches exec');
  assert.ok(locationExists(commandFindings, 'src/commands.js', 6), 'Node process argument array');
  assert.ok(locationExists(commandFindings, 'src/commands.ts', 3), 'TypeScript execFile argument array');
  assert.ok(locationExists(commandFindings, 'src/commands.py', 4), 'Python os.system');
  assert.ok(locationExists(commandFindings, 'src/commands.py', 5), 'Python subprocess shell mode');
  assert.ok(locationExists(commandFindings, 'src/commands.py', 6), 'Python argument-array process call');
  assert.ok(locationExists(commandFindings, 'src/commands.py', 9), 'Python aliased command reaches os.system');
  assert.equal(commandCheck.findingCount, 8);
  assert.equal(commandCheck.status, 'completed');
  assert.ok(commandFindings.every((finding) =>
    finding.confidence &&
    finding.cwe.includes('CWE-78') &&
    finding.severityRationale &&
    finding.recommendation &&
    finding.remediation === finding.recommendation &&
    finding.evidence.includes('<redacted>') &&
    /does not establish attacker control or exploitability/.test(finding.description)
  ));
  assert.ok(commandFindings.some((finding) =>
    finding.severity === 'High' && /shell-based/.test(finding.severityRationale)
  ));
  assert.ok(commandFindings.some((finding) =>
    finding.severity === 'Medium' && /argument array/.test(finding.severityRationale)
  ));
  assert.equal(commandFindings.some((finding) =>
    finding.file === 'src/commands.js' && finding.line === 7
  ), false, 'fixed shell command is not reported');
  assert.equal(commandFindings.some((finding) =>
    finding.file === 'src/commands.py' && finding.line === 7
  ), false, 'fixed argument array without user input is not reported');
  assert.equal(report.issues.some((finding) =>
    ['src/injection-comments.js', 'docs/injection-examples.md', 'tests/fixtures/injection-example.py'].includes(finding.file) &&
    ['LUM-INJ-001', 'LUM-INJ-002'].includes(finding.ruleId)
  ), false, 'comments, documentation, and test fixtures are excluded');
  assert.equal(report.scan.findingsDetected, true);
  assert.equal(report.scan.findingCount, report.issues.length);
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'injection_indicators' && category.findingCount === 15
  ));
  assert.doesNotMatch(JSON.stringify(sqlFindings.concat(commandFindings)), /SELECT|req\.query|request\.args|userInput|fileName/);
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

test('malformed JSON, binary source files, unreadable files, and symlinks keep relevant coverage partial', async (t) => {
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
  assert.equal(report.scan.checks.find((item) => item.id === 'secret_pattern_search').status, 'partial');
  assert.equal(report.scan.checks.find((item) => item.id === 'insecure_transport_configuration').status, 'partial');
  assert.equal(report.scan.checks.find((item) => item.id === 'dangerous_application_configuration').status, 'partial');
});

test('invalid UTF-8 reports the relative file and does not degrade unrelated categories', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/invalid.js': Buffer.from([0x66, 0x80])
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const checks = new Map(report.scan.checks.map((check) => [check.id, check]));

  assert.equal(checks.get('secret_pattern_search').status, 'partial');
  assert.equal(checks.get('secret_pattern_search').reason.code, 'unsupported_text_encoding');
  assert.deepEqual(checks.get('secret_pattern_search').evidence.readErrors, [
    { file: 'src/invalid.js', code: 'invalid_utf8' }
  ]);
  assert.equal(checks.get('secret_pattern_search').evidence.failedReads, 1);
  assert.equal(checks.get('secret_pattern_search').evidence.unsupportedEncodings, 1);
  assert.equal(report.scan.coverage.inventory.unsupportedEncodings, 1);
  assert.equal(report.scan.coverage.inventory.unreadableFiles, 0);
  for (const id of [
    'sql_injection_pattern_search',
    'os_command_injection_pattern_search',
    'unsafe_deserialization_pattern_search',
    'dynamic_code_execution_pattern_search'
  ]) {
    assert.equal(checks.get(id).status, 'partial', `${id} needs the unreadable JS source`);
  }
  assert.equal(checks.get('dangerous_application_configuration').status, 'completed');
  assert.equal(checks.get('insecure_transport_configuration').status, 'partial');
});

test('unreadable Python source affects Python checks but not JavaScript-only checks', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'python/unreadable.py': Buffer.from([0x66, 0x80])
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const checks = new Map(report.scan.checks.map((check) => [check.id, check]));

  assert.equal(checks.get('secret_pattern_search').status, 'partial');
  assert.ok(checks.get('secret_pattern_search').evidence.readErrors.some((entry) =>
    entry.file === 'python/unreadable.py' && entry.code === 'invalid_utf8'
  ));
  for (const id of [
    'sql_injection_pattern_search',
    'os_command_injection_pattern_search',
    'unsafe_deserialization_pattern_search',
    'insecure_transport_configuration'
  ]) {
    assert.equal(checks.get(id).status, 'partial', `${id} analyzes Python source`);
  }
  assert.equal(checks.get('dynamic_code_execution_pattern_search').status, 'completed');
  assert.equal(checks.get('dangerous_application_configuration').status, 'completed');
});

test('scans mixed JavaScript, TypeScript, and Python source in nested folders with BOM and Unicode', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/api.js': Buffer.concat([
      Buffer.from([0xEF, 0xBB, 0xBF]),
      Buffer.from('export const API_KEY = "js-secret-value-123";\n', 'utf8')
    ]),
    'src/nested/handler.ts': 'export const API_TOKEN = "ts-secret-value-123";\n',
    'python/app.py': 'API_KEY = "py-secret-value-123"\n',
    'python/nested/helper.py': '# unicode: café 東京\nvalue = "safe"\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  const secretLocations = report.issues
    .filter((issue) => issue.checkId === 'secret_pattern_search')
    .map((issue) => issue.file)
    .sort();

  assert.ok(secretLocations.includes('src/api.js'));
  assert.ok(secretLocations.includes('src/nested/handler.ts'));
  assert.ok(secretLocations.includes('python/app.py'));
  assert.equal(report.scan.checks.find((item) => item.id === 'secret_pattern_search').status, 'completed');
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
  assert.equal(check.status, 'partial');
  assert.equal(check.reason.code, 'malformed_json_configuration');
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
  const secretCheck = report.scan.checks.find((item) => item.id === 'secret_pattern_search');
  assert.equal(secretCheck.status, 'partial');
  assert.ok(secretCheck.reason);
  assert.match(secretCheck.reason.message, /unsupported file formats/);
  assert.equal(secretCheck.evidence.filesSkipped, 1);
  assert.equal(secretCheck.evidence.unsupportedFiles, 1);
  assert.equal(secretCheck.evidence.binaryFiles, 0);
  assert.equal(secretCheck.evidence.projectFilesSkipped, 2);
  assert.equal(secretCheck.evidence.projectBinaryFiles, 1);
  for (const id of ['insecure_transport_configuration', 'dangerous_application_configuration']) {
    assert.equal(
      report.scan.checks.find((item) => item.id === id).status,
      'completed',
      `${id} must not be degraded by an unsupported extension or binary asset`
    );
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

test('marks incomplete Docker metadata responses as failed coverage', async (t) => {
  const projectPath = makeProject(completeProjectFiles);
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', {
    inspect: async () => ({ State: { Running: false } })
  }, {
    docker: {
      listImages: async () => [{ RepoTags: ['test-image:latest'] }],
      getImage: () => ({ inspect: async () => ({ Id: 'sha256:test' }) })
    },
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const imageCheck = report.scan.checks.find((check) => check.id === 'image_metadata');
  const runtimeCheck = report.scan.checks.find((check) => check.id === 'runtime_inspection');
  assert.equal(imageCheck.status, 'failed');
  assert.equal(imageCheck.reason.code, 'image_metadata_unavailable');
  assert.equal(runtimeCheck.status, 'failed');
  assert.equal(runtimeCheck.reason.code, 'runtime_inspection_failed');
  assert.equal(report.scan.status, 'partial');

  const completedReport = await analyzeProduction(projectPath, 'test-image', {
    inspect: async () => ({
      State: { Running: true, Status: 'running', StartedAt: '2026-01-01T00:00:00Z', ExitCode: 0 }
    })
  }, {
    docker: dockerWithImage,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });
  assert.equal(completedReport.scan.checks.find((check) => check.id === 'image_metadata').status, 'completed');
  assert.equal(completedReport.scan.checks.find((check) => check.id === 'runtime_inspection').status, 'completed');
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
  const secretCheck = report.scan.checks.find((check) => check.id === 'secret_pattern_search');
  assert.equal(secretCheck.status, 'partial');
  assert.equal(secretCheck.reason.code, 'project_file_too_large');
  assert.equal(secretCheck.evidence.filesSkipped, 1);
  assert.equal(secretCheck.evidence.failedReads, 0);
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
    'package.json': JSON.stringify({
      name: 'fixture',
      version: '1.0.0',
      dependencies: { 'library-a': '^1.0.0' }
    }),
    'package-lock.json': JSON.stringify({
      name: 'fixture',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'fixture',
          version: '1.0.0',
          dependencies: { 'library-a': '^1.0.0' }
        },
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
  const dependencyCheck = report.scan.checks.find((check) =>
    check.id === 'dependency_vulnerability_analysis'
  );
  assert.equal(dependencyCheck.status, 'failed');
  assert.equal(dependencyCheck.reason.code, 'advisory_data_unavailable_or_invalid');
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
  assert.equal(dependencyCheck.status, 'partial');
  assert.equal(dependencyCheck.reason.code, 'unsupported_dependency_formats');
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

test('reports Python dependency advisories with CVE, CVSS, and remediation', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'poetry.lock': `
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP library"
`,
    'pyproject.toml': `
[tool.poetry]
name = "service"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"
`
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger,
    fetch: async (url, options) => {
      if (url.endsWith('/v1/querybatch')) {
        return new Response(JSON.stringify({
          results: [{
            vulns: [{
              id: 'GHSA-test-requests',
              modified: '2025-01-02T03:04:05Z'
            }]
          }]
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({
        id: 'GHSA-test-requests',
        summary: 'Sensitive header leakage across domains in redirects',
        aliases: ['CVE-2023-32681'],
        modified: '2025-01-02T03:04:05Z',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N' }],
        affected: [{
          package: { ecosystem: 'PyPI', name: 'requests' },
          ranges: [{
            type: 'ECOSYSTEM',
            events: [{ introduced: '2.0.0' }, { fixed: '2.31.1' }]
          }],
          database_specific: { severity: 'HIGH' }
        }]
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });

  const depIssue = report.issues.find((issue) => issue.checkId === 'dependency_vulnerability_analysis');
  assert.ok(depIssue);
  assert.equal(depIssue.dependency.ecosystem, 'PyPI');
  assert.equal(depIssue.dependency.package, 'requests');
  assert.equal(depIssue.dependency.installedVersion, '2.31.0');
  assert.equal(depIssue.dependency.advisoryId, 'GHSA-test-requests');
  assert.deepEqual(depIssue.dependency.cveIds, ['CVE-2023-32681']);
  assert.equal(depIssue.dependency.fixedVersion, '2.31.1');
  assert.equal(depIssue.remediation, 'Upgrade requests to 2.31.1 or later.');
  assert.equal(report.dependencyAnalysis.status, 'completed');
  assert.equal(report.dependencyAnalysis.advisoryCount, 1);
});

test('reports missing Python lockfile as python_lockfile_missing', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'pyproject.toml': `
[tool.poetry]
name = "service"
version = "0.1.0"

[tool.poetry.dependencies]
requests = "^2.28.0"
`
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'test-image', null, {
    docker: dockerWithImage,
    logger: quietLogger,
    fetch: async () => assert.fail('should not query OSV')
  });

  assert.equal(report.scan.status, 'partial');
  const depCheck = report.scan.checks.find((check) => check.id === 'dependency_vulnerability_analysis');
  assert.equal(depCheck.status, 'partial');
  assert.equal(depCheck.reason.code, 'python_lockfile_missing');
  assert.match(depCheck.reason.message, /Python manifest was found without a supported lockfile/);
});

test('detects unsafe deserialization patterns in Python and JavaScript without claiming exploitability', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/deserialization.py': [
      'import pickle',
      'import _pickle',
      'import cPickle',
      'import yaml',
      'import marshal',
      'import shelve',
      '',
      '# LUM-DES-001 pickle tests',
      'pickle.loads(payload)',
      'pickle.load(stream)',
      '_pickle.loads(payload)',
      'cPickle.load(stream)',
      'pickle.loads(',
      '    multiline_payload',
      ')',
      '',
      '# LUM-DES-002 YAML tests',
      'yaml.load(raw_yaml)',
      'yaml.load(raw_yaml, Loader=yaml.Loader)',
      'yaml.load(raw_yaml, Loader=yaml.UnsafeLoader)',
      'yaml.load(raw_yaml, Loader=yaml.FullLoader)',
      'yaml.load(raw_yaml, Loader=Loader)',
      'yaml.unsafe_load(raw_yaml)',
      'yaml.unsafe_load_all(raw_yaml)',
      'yaml.load(',
      '    multiline_yaml,',
      '    Loader=yaml.Loader',
      ')',
      '',
      '# LUM-DES-003 marshal tests',
      'marshal.loads(bytecode)',
      'marshal.load(file_obj)',
      '',
      '# LUM-DES-004 shelve tests',
      'db = shelve.open("cache.db")',
      ''
    ].join('\n'),
    'src/deserialization_safe.py': [
      'import pickle',
      'import yaml',
      'import marshal',
      'import json',
      '',
      '# Safe serialization calls (dumps / dump)',
      'pickle.dumps(data)',
      'pickle.dump(data, f)',
      'marshal.dumps(data)',
      'marshal.dump(data, f)',
      '',
      '# Safe standard JSON',
      'json.loads(json_data)',
      'json.load(json_file)',
      '',
      '# Safe YAML loading',
      'yaml.safe_load(data)',
      'yaml.safe_load_all(data)',
      'yaml.load(data, Loader=yaml.SafeLoader)',
      'yaml.load(data, Loader=SafeLoader)',
      'yaml.load(data, Loader=yaml.CSafeLoader)',
      'yaml.load(data, Loader=CSafeLoader)',
      'yaml.load(data, Loader=yaml.BaseLoader)',
      'yaml.load(data, Loader=BaseLoader)',
      'yaml.load(data, Loader=yaml.CBaseLoader)',
      'yaml.load(data, Loader=CBaseLoader)',
      'yaml.dump(data)',
      'yaml.safe_dump(data)',
      'yaml.load(',
      '    multiline_data,',
      '    Loader=yaml.SafeLoader',
      ')',
      ''
    ].join('\n'),
    'src/deserialization.js': [
      'const serialize = require("node-serialize");',
      'serialize.unserialize(payload);',
      'const nodeSerialize = require("node-serialize");',
      'nodeSerialize.unserialize(payload);',
      'const safe = JSON.parse(jsonPayload);',
      ''
    ].join('\n'),
    'src/deserialization-comments.py': [
      '# pickle.loads(untrusted)',
      '# yaml.load(untrusted)',
      '"""',
      'Example of pickle.loads(data) in docstring',
      'yaml.load(data)',
      'marshal.loads(data)',
      '"""',
      'text = "pickle.loads(should_not_flag)"',
      ''
    ].join('\n'),
    'docs/deserialization-guide.md': 'pickle.loads(userInput)\nyaml.load(data)\n',
    'tests/fixtures/deserialization-fixture.py': 'pickle.loads(test_data)\nyaml.unsafe_load(test_data)\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const desFindings = report.issues.filter((issue) => issue.checkId === 'unsafe_deserialization_pattern_search');
  const pickleFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DES-001');
  const yamlFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DES-002');
  const marshalFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DES-003');
  const shelveFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DES-004');
  const jsSerializeFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DES-005');

  const locationExists = (findings, file, line) => findings.some((finding) =>
    finding.file === file && finding.line === line
  );

  // Assert counts
  assert.equal(pickleFindings.length, 5, 'pickle calls detected');
  assert.ok(locationExists(pickleFindings, 'src/deserialization.py', 9));
  assert.ok(locationExists(pickleFindings, 'src/deserialization.py', 10));
  assert.ok(locationExists(pickleFindings, 'src/deserialization.py', 11));
  assert.ok(locationExists(pickleFindings, 'src/deserialization.py', 12));
  assert.ok(locationExists(pickleFindings, 'src/deserialization.py', 13), 'multiline pickle.loads');

  assert.equal(yamlFindings.length, 8, 'unsafe yaml calls detected');
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 18));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 19));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 20));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 21));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 22));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 23));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 24));
  assert.ok(locationExists(yamlFindings, 'src/deserialization.py', 25), 'multiline yaml.load');

  assert.equal(marshalFindings.length, 2, 'marshal calls detected');
  assert.ok(locationExists(marshalFindings, 'src/deserialization.py', 31));
  assert.ok(locationExists(marshalFindings, 'src/deserialization.py', 32));

  assert.equal(shelveFindings.length, 1, 'shelve open detected');
  assert.ok(locationExists(shelveFindings, 'src/deserialization.py', 35));

  assert.equal(jsSerializeFindings.length, 2, 'node-serialize unserialize detected');
  assert.ok(locationExists(jsSerializeFindings, 'src/deserialization.js', 2));
  assert.ok(locationExists(jsSerializeFindings, 'src/deserialization.js', 4));

  // Assert negative cases: safe file must have 0 findings
  assert.equal(desFindings.some((f) => f.file === 'src/deserialization_safe.py'), false, 'safe file has zero findings');

  // Assert exclusions
  assert.equal(report.issues.some((f) =>
    ['src/deserialization-comments.py', 'docs/deserialization-guide.md', 'tests/fixtures/deserialization-fixture.py'].includes(f.file) &&
    ['LUM-DES-001', 'LUM-DES-002', 'LUM-DES-003', 'LUM-DES-004', 'LUM-DES-005'].includes(f.ruleId)
  ), false, 'comments, docstrings, docs, and test fixtures are excluded');

  // Assert finding metadata
  assert.ok(desFindings.every((finding) =>
    finding.cwe.includes('CWE-502') &&
    finding.severityRationale &&
    finding.recommendation &&
    finding.remediation === finding.recommendation &&
    finding.evidence.includes('<redacted>') &&
    /does not establish attacker control or exploitability/.test(finding.description)
  ));

  const desCheck = report.scan.checks.find((check) => check.id === 'unsafe_deserialization_pattern_search');
  assert.equal(desCheck.status, 'completed');
  assert.equal(desCheck.findingCount, 18);
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'deserialization_indicators' && category.findingCount === 18
  ));
});

test('detects JavaScript and TypeScript dynamic code execution patterns without claiming exploitability', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/dynamic.js': [
      '// LUM-DYN-001 eval tests',
      'eval(userInput);',
      'window.eval(code);',
      'global.eval(code);',
      'globalThis.eval(code);',
      'eval(',
      '    multilineCode',
      ');',
      '',
      '// LUM-DYN-002 Function constructor tests',
      'const add = new Function("a", "b", "return a + b");',
      'const compute = Function("return " + expr);',
      'const multilineFn = new Function(',
      '    "x",',
      '    "return x * 2"',
      ');',
      '',
      '// LUM-DYN-003 vm tests',
      'const vm = require("vm");',
      'vm.runInContext(code, context);',
      'vm.runInNewContext(code);',
      'vm.runInThisContext(code);',
      'vm.compileFunction(code);',
      '',
      '// LUM-DYN-004 timer string tests',
      'setTimeout("alert(1)", 1000);',
      'setInterval("refresh()", 5000);',
      'setImmediate("doWork()");',
      'setTimeout(`do(${id})`, 100);',
      'setTimeout("run(" + expr + ")", 200);',
      'setTimeout(',
      '    "delayedAction()",',
      '    500',
      ');',
      ''
    ].join('\n'),
    'src/dynamic_safe.ts': [
      '// Safe alternatives',
      'const fn = (a: number, b: number) => a + b;',
      'function regularFunction() { return 42; }',
      'const lookup = { action: () => true };',
      'JSON.parse(data);',
      '',
      '// Safe timer usages',
      'setTimeout(() => { console.log("ok"); }, 1000);',
      'setTimeout(regularFunction, 500);',
      'setInterval(() => {}, 2000);',
      'setImmediate(() => {});',
      '',
      '// Math or parser eval method on object',
      'const math = { eval: (expr: string) => 0 };',
      'math.eval("1 + 2");',
      ''
    ].join('\n'),
    'src/dynamic-comments.js': [
      '// eval(untrusted)',
      '// new Function("code")',
      '/* setTimeout("alert(1)", 1000) */',
      'const str = "eval(code) is dangerous";',
      'const str2 = `template with eval(code) inside`;',
      ''
    ].join('\n'),
    'docs/dynamic-guide.md': 'eval(userInput)\nnew Function("x", "return x")\n',
    'tests/fixtures/dynamic-fixture.js': 'eval(testExpr);\n'
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const dynFindings = report.issues.filter((issue) => issue.checkId === 'dynamic_code_execution_pattern_search');
  const evalFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DYN-001');
  const fnConstructorFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DYN-002');
  const vmFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DYN-003');
  const timerFindings = report.issues.filter((issue) => issue.ruleId === 'LUM-DYN-004');

  const locationExists = (findings, file, line) => findings.some((finding) =>
    finding.file === file && finding.line === line
  );

  // Assert counts
  assert.equal(evalFindings.length, 5, 'eval calls detected');
  assert.ok(locationExists(evalFindings, 'src/dynamic.js', 2));
  assert.ok(locationExists(evalFindings, 'src/dynamic.js', 3));
  assert.ok(locationExists(evalFindings, 'src/dynamic.js', 4));
  assert.ok(locationExists(evalFindings, 'src/dynamic.js', 5));
  assert.ok(locationExists(evalFindings, 'src/dynamic.js', 6), 'multiline eval');

  assert.equal(fnConstructorFindings.length, 3, 'Function constructor calls detected');
  assert.ok(locationExists(fnConstructorFindings, 'src/dynamic.js', 11));
  assert.ok(locationExists(fnConstructorFindings, 'src/dynamic.js', 12));
  assert.ok(locationExists(fnConstructorFindings, 'src/dynamic.js', 13), 'multiline Function constructor');

  assert.equal(vmFindings.length, 4, 'vm execution calls detected');
  assert.ok(locationExists(vmFindings, 'src/dynamic.js', 20));
  assert.ok(locationExists(vmFindings, 'src/dynamic.js', 21));
  assert.ok(locationExists(vmFindings, 'src/dynamic.js', 22));
  assert.ok(locationExists(vmFindings, 'src/dynamic.js', 23));

  assert.equal(timerFindings.length, 6, 'timer string calls detected');
  assert.ok(locationExists(timerFindings, 'src/dynamic.js', 26));
  assert.ok(locationExists(timerFindings, 'src/dynamic.js', 27));
  assert.ok(locationExists(timerFindings, 'src/dynamic.js', 28));
  assert.ok(locationExists(timerFindings, 'src/dynamic.js', 29));
  assert.ok(locationExists(timerFindings, 'src/dynamic.js', 30));
  assert.ok(locationExists(timerFindings, 'src/dynamic.js', 31), 'multiline timer call');

  // Assert negative cases: safe file must have 0 findings
  assert.equal(dynFindings.some((f) => f.file === 'src/dynamic_safe.ts'), false, 'safe file has zero findings');

  // Assert exclusions
  assert.equal(report.issues.some((f) =>
    ['src/dynamic-comments.js', 'docs/dynamic-guide.md', 'tests/fixtures/dynamic-fixture.js'].includes(f.file) &&
    ['LUM-DYN-001', 'LUM-DYN-002', 'LUM-DYN-003', 'LUM-DYN-004'].includes(f.ruleId)
  ), false, 'comments, strings, docs, and test fixtures are excluded');

  // Assert finding metadata
  assert.ok(evalFindings.every((finding) => finding.cwe.includes('CWE-95')));
  assert.ok(fnConstructorFindings.every((finding) => finding.cwe.includes('CWE-95')));
  assert.ok(vmFindings.every((finding) => finding.cwe.includes('CWE-94')));
  assert.ok(timerFindings.every((finding) => finding.cwe.includes('CWE-95')));

  assert.ok(dynFindings.every((finding) =>
    finding.severityRationale &&
    finding.recommendation &&
    finding.remediation === finding.recommendation &&
    finding.evidence.includes('<redacted>') &&
    /does not establish attacker control or exploitability/.test(finding.description)
  ));

  const dynCheck = report.scan.checks.find((check) => check.id === 'dynamic_code_execution_pattern_search');
  assert.equal(dynCheck.status, 'completed');
  assert.equal(dynCheck.findingCount, 18);
  assert.ok(report.scan.coverage.categories.some((category) =>
    category.id === 'dynamic_execution_indicators' && category.findingCount === 18
  ));
});

test('marks missing eligible files incomplete rather than clean for deserialization and dynamic execution', async (t) => {
  // Python-only project: has deserialization source files, but NO JS/TS source files
  const pythonOnlyPath = makeProject({
    'src/app.py': 'value = True\n'
  });
  t.after(() => fs.rmSync(pythonOnlyPath, { recursive: true, force: true }));

  const pythonReport = await analyzeProduction(pythonOnlyPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const desCheck = pythonReport.scan.checks.find((c) => c.id === 'unsafe_deserialization_pattern_search');
  const dynCheck = pythonReport.scan.checks.find((c) => c.id === 'dynamic_code_execution_pattern_search');
  assert.equal(desCheck.status, 'completed');
  assert.equal(dynCheck.status, 'partial');
  assert.equal(dynCheck.reason.code, 'no_supported_dynamic_execution_source_files');

  // Non-JS and non-Python project (e.g. only Markdown documentation)
  const docOnlyPath = makeProject({
    'README.md': 'Only docs\n'
  });
  t.after(() => fs.rmSync(docOnlyPath, { recursive: true, force: true }));

  const docReport = await analyzeProduction(docOnlyPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const docDesCheck = docReport.scan.checks.find((c) => c.id === 'unsafe_deserialization_pattern_search');
  const docDynCheck = docReport.scan.checks.find((c) => c.id === 'dynamic_code_execution_pattern_search');
  assert.equal(docDesCheck.status, 'partial');
  assert.equal(docDesCheck.reason.code, 'no_supported_deserialization_source_files');
  assert.equal(docDynCheck.status, 'partial');
  assert.equal(docDynCheck.reason.code, 'no_supported_dynamic_execution_source_files');
});

test('audits cross-rule regression: coexisting findings, same-line findings, and safe/unsafe mixture', async (t) => {
  const syntheticSlackToken = ['xox', 'b-', 'synthetic-test-token-for-regression'].join('');
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/cross_cred_sql.js': [
      'const db = require("db");',
      'const userId = req.query.id;',
      'const dbPassword = "SuperSecretDbPassword123!";',
      'db.query("SELECT * FROM users WHERE id = " + userId);',
      'db.query("SELECT * FROM users WHERE id = $1", [userId]);',
      ''
    ].join('\n'),
    'src/cross_cmd_dyn.js': [
      'const child_process = require("child_process");',
      'const userInput = req.query.input;',
      'child_process.exec("cat " + userInput);',
      'eval(userInput);',
      'child_process.execFile("/bin/ls", ["-la"]);',
      'function normalCallback() { return "safe" + "result"; }',
      'setTimeout(() => { const x = "concat" + "string"; }, 1000);',
      'setTimeout("eval(" + userInput + ")", 1000);',
      ''
    ].join('\n'),
    'src/cross_yaml_cred.py': [
      'import yaml',
      'payload = request.args.get("data")',
      'raw_slack = "' + syntheticSlackToken + '"',
      'yaml.load(payload, Loader=yaml.Loader)',
      'yaml.safe_load(payload)',
      'yaml.load(payload, Loader=yaml.SafeLoader)',
      ''
    ].join('\n'),
    'src/same_line.js': [
      'const child_process = require("child_process");',
      'const cmd = req.query.cmd;',
      'const raw_aws = "AKIA1234567890ABCDEF"; eval(cmd);',
      'child_process.exec("ls " + cmd); new Function("return 1")();',
      ''
    ].join('\n'),
    'src/safe_unsafe_mix.py': [
      'import pickle',
      'import yaml',
      'import subprocess',
      'raw = request.args.get("payload")',
      'pickle.dumps({"status": "ok"})',
      'pickle.loads(raw)',
      'yaml.safe_load(raw)',
      'yaml.load(raw, Loader=yaml.UnsafeLoader)',
      'cursor.execute("SELECT * FROM items WHERE id = %s", (raw,))',
      'cursor.execute(f"SELECT * FROM items WHERE name = \'{raw}\'")',
      'subprocess.run(["/usr/bin/git", "status"])',
      'subprocess.run(f"git checkout {raw}", shell=True)',
      ''
    ].join('\n')
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const hasFinding = (ruleId, file, line) =>
    report.issues.some((i) => i.ruleId === ruleId && i.file === file && i.line === line);

  // 1. Credentials + SQL injection in same file
  assert.ok(hasFinding('LUM-SEC-001', 'src/cross_cred_sql.js', 3), 'LUM-SEC-001 at line 3');
  assert.ok(hasFinding('LUM-INJ-001', 'src/cross_cred_sql.js', 4), 'LUM-INJ-001 at line 4');
  assert.ok(!hasFinding('LUM-INJ-001', 'src/cross_cred_sql.js', 5), 'parameterized SQL is not flagged');

  // 2. Command injection + Dynamic execution in same file
  assert.ok(hasFinding('LUM-INJ-002', 'src/cross_cmd_dyn.js', 3), 'LUM-INJ-002 at line 3');
  assert.ok(hasFinding('LUM-DYN-001', 'src/cross_cmd_dyn.js', 4), 'LUM-DYN-001 at line 4');
  assert.ok(!hasFinding('LUM-INJ-002', 'src/cross_cmd_dyn.js', 5), 'safe execFile array is not flagged');
  assert.ok(!hasFinding('LUM-DYN-002', 'src/cross_cmd_dyn.js', 6), 'normal function declaration is not flagged');
  assert.ok(!hasFinding('LUM-DYN-004', 'src/cross_cmd_dyn.js', 7), 'safe timer arrow function callback is not flagged');
  assert.ok(hasFinding('LUM-DYN-004', 'src/cross_cmd_dyn.js', 8), 'LUM-DYN-004 timer string at line 8');

  // 3. Unsafe YAML + Credentials in same file
  assert.ok(hasFinding('LUM-SEC-002', 'src/cross_yaml_cred.py', 3), 'LUM-SEC-002 at line 3');
  assert.ok(hasFinding('LUM-DES-002', 'src/cross_yaml_cred.py', 4), 'LUM-DES-002 at line 4');
  assert.ok(!hasFinding('LUM-DES-002', 'src/cross_yaml_cred.py', 5), 'yaml.safe_load is not flagged');
  assert.ok(!hasFinding('LUM-DES-002', 'src/cross_yaml_cred.py', 6), 'yaml.load with SafeLoader is not flagged');

  // 4. Multiple distinct findings on the same line
  assert.ok(hasFinding('LUM-SEC-002', 'src/same_line.js', 3), 'LUM-SEC-002 on same line 3');
  assert.ok(hasFinding('LUM-DYN-001', 'src/same_line.js', 3), 'LUM-DYN-001 on same line 3');
  assert.ok(hasFinding('LUM-INJ-002', 'src/same_line.js', 4), 'LUM-INJ-002 on same line 4');
  assert.ok(hasFinding('LUM-DYN-002', 'src/same_line.js', 4), 'LUM-DYN-002 on same line 4');

  // 5. Safe and unsafe mix in Python
  assert.ok(!hasFinding('LUM-DES-001', 'src/safe_unsafe_mix.py', 5), 'pickle.dumps is not flagged');
  assert.ok(hasFinding('LUM-DES-001', 'src/safe_unsafe_mix.py', 6), 'LUM-DES-001 pickle.loads at line 6');
  assert.ok(!hasFinding('LUM-DES-002', 'src/safe_unsafe_mix.py', 7), 'yaml.safe_load is not flagged');
  assert.ok(hasFinding('LUM-DES-002', 'src/safe_unsafe_mix.py', 8), 'LUM-DES-002 UnsafeLoader at line 8');
  assert.ok(!hasFinding('LUM-INJ-001', 'src/safe_unsafe_mix.py', 9), 'parameterized cursor.execute is not flagged');
  assert.ok(hasFinding('LUM-INJ-001', 'src/safe_unsafe_mix.py', 10), 'LUM-INJ-001 f-string SQL at line 10');
  assert.ok(!hasFinding('LUM-INJ-002', 'src/safe_unsafe_mix.py', 11), 'safe subprocess argument array is not flagged');
  assert.ok(hasFinding('LUM-INJ-002', 'src/safe_unsafe_mix.py', 12), 'LUM-INJ-002 shell=True at line 12');

  // 6. Comprehensive finding integrity
  for (const issue of report.issues) {
    if (issue.checkId && issue.ruleId) {
      assert.match(issue.ruleId, /^LUM-(?:SEC|INJ|DES|DYN|CFG|TLS)-\d{3}$/);
      assert.ok(['Critical', 'High', 'Medium', 'Low', 'Unknown'].includes(issue.severity));
      assert.ok(['high', 'medium', 'low'].includes(issue.confidence));
      assert.ok(Array.isArray(issue.cwe) && issue.cwe.length > 0, 'non-empty CWE array');
      assert.ok(typeof issue.severityRationale === 'string' && issue.severityRationale.length > 0);
      assert.ok(typeof issue.remediation === 'string' && issue.remediation.length > 0);
      assert.ok(typeof issue.file === 'string' && !path.isAbsolute(issue.file));
      assert.ok(!issue.file.includes('..'), 'no path traversal in finding location');
      assert.ok(Number.isInteger(issue.line) && issue.line > 0);

      // Verify no disclosure of secret tokens/passwords in evidence
      if (issue.ruleId.startsWith('LUM-SEC-')) {
        assert.ok(issue.evidence.includes('<redacted>'), 'credential evidence must be redacted');
        assert.ok(!issue.evidence.includes('SuperSecretDbPassword123!'), 'password must not leak in evidence');
        assert.ok(!issue.evidence.includes('xoxb-123456789012'), 'slack token must not leak in evidence');
      }
    }
  }

  // Distinct sink spans may legitimately produce same-rule findings on one line.
  const locationKeys = report.issues.map((i) =>
    `${i.ruleId}:${i.file}:${i.sinkIdentity || i.line}`
  );
  const uniqueKeys = new Set(locationKeys);
  assert.equal(locationKeys.length, uniqueKeys.size, 'no duplicate findings for the same sink identity');
});

test('production static analysis propagates taint across project modules without executing source', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/route.js': registeredExpressRoute([
      "import { query } from './helper.js';",
      "throw new Error('scanned source must not execute');",
      'export function handle(req) { query(req.query.id); }'
    ].join('\n')),
    'src/helper.js': [
      "import { execute } from './database.js';",
      'export function query(value) { execute(value); }'
    ].join('\n'),
    'src/database.js': [
      'export function execute(value) {',
      "  const sql = 'SELECT * FROM records WHERE id=' + value;",
      '  db.query(sql);',
      '}'
    ].join('\n')
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));

  const report = await analyzeProduction(projectPath, 'unused', null, {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  });

  const finding = report.issues.find((issue) =>
    issue.ruleId === 'LUM-INJ-001' && issue.file === 'src/database.js' && issue.line === 3
  );
  assert.ok(finding, 'cross-file taint finding is merged into the production report');
  assert.equal(finding.isTaintConfirmed, true);
  assert.equal(finding.taintTrace.source.file, 'src/route.js');
  assert.ok(finding.taintTrace.steps.some((step) =>
    step.fromModule === 'src/route.js' && step.toModule === 'src/helper.js'
  ));
  assert.ok(finding.taintTrace.steps.some((step) =>
    step.fromModule === 'src/helper.js' && step.toModule === 'src/database.js'
  ));
});

test('production analyzer resolves supported cross-file import and export forms', async (t) => {
  const sinkFunction = [
    'export function run(value) {',
    "  const sql = 'SELECT * FROM records WHERE id=' + value;",
    '  db.query(sql);',
    '}'
  ].join('\n');
  const cases = [
    {
      name: 'named import',
      route: registeredExpressRoute("import { run } from './database.js';\nexport function handle(req) { run(req.query.id); }"),
      files: { 'src/database.js': sinkFunction }
    },
    {
      name: 'default import',
      route: registeredExpressRoute("import run from './database.js';\nexport function handle(req) { run(req.query.id); }"),
      files: { 'src/database.js': sinkFunction.replace('export function run', 'export default function run') }
    },
    {
      name: 'namespace import',
      route: registeredExpressRoute("import * as database from './database.js';\nexport function handle(req) { database.run(req.query.id); }"),
      files: { 'src/database.js': sinkFunction }
    },
    {
      name: 'aliased import',
      route: registeredExpressRoute("import { run as execute } from './database.js';\nexport function handle(req) { execute(req.query.id); }"),
      files: { 'src/database.js': sinkFunction }
    },
    {
      name: 'named re-export through barrel',
      route: registeredExpressRoute("import { run } from './barrel.js';\nexport function handle(req) { run(req.query.id); }"),
      files: {
        'src/barrel.js': "export { run } from './middle.js';",
        'src/middle.js': "export { run } from './database.js';",
        'src/database.js': sinkFunction
      }
    },
    {
      name: 'star re-export through barrel',
      route: registeredExpressRoute("import { run } from './barrel.js';\nexport function handle(req) { run(req.query.id); }"),
      files: {
        'src/barrel.js': "export * from './middle.js';",
        'src/middle.js': "export * from './database.js';",
        'src/database.js': sinkFunction
      }
    },
    {
      name: 'CommonJS import and export',
      route: registeredExpressRoute("const { run: execute } = require('./database.cjs');\nfunction handle(req) { execute(req.query.id); }"),
      files: {
        'src/database.cjs': [
          'function run(value) {',
          "  const sql = 'SELECT * FROM records WHERE id=' + value;",
          '  db.query(sql);',
          '}',
          'module.exports = { run };'
        ].join('\n')
      }
    }
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (subtest) => {
      const report = await analyzeProjectFiles(subtest, {
        'src/route.js': scenario.route,
        ...scenario.files
      });
      assert.equal(report.schemaVersion, '2.0.0');
      const sinkFile = scenario.files['src/database.cjs'] ? 'src/database.cjs' : 'src/database.js';
      const finding = report.issues.find((issue) =>
        issue.ruleId === 'LUM-INJ-001' && issue.file === sinkFile && issue.isTaintConfirmed
      );
      assert.ok(finding, 'production report contains the cross-module SQL finding');
      assert.deepEqual(finding.cwe, ['CWE-89']);
      assert.equal(finding.taintTrace.source.file, 'src/route.js');
      assert.equal(finding.taintTrace.source.line, 2);
      assert.equal(finding.taintTrace.sink.file, sinkFile);
      assert.equal(finding.taintTrace.sink.line, 3);
      assert.equal(finding.taintTrace.sink.api, 'db.query(sql)');
      assert.equal(finding.taintTrace.sink.argumentRole, 'sql_query');
      assert.ok(finding.taintTrace.steps.some((step) => step.fromModule === 'src/route.js'));
      if (scenario.name.includes('re-export')) {
        assert.ok(finding.taintTrace.steps.some((step) =>
          step.importExport?.reExportChain?.length > 0
        ));
      }
    });
  }
});

test('production analyzer preserves command sink classifications across modules', async (t) => {
  const scenarios = [
    {
      name: 'shell command injection',
      sink: "import { exec } from 'node:child_process';\nexport function run(value) { exec('echo ' + value); }",
      cwe: ['CWE-78'],
      argumentRole: 'shell_command'
    },
    {
      name: 'non-shell argument injection',
      sink: "import { spawn } from 'node:child_process';\nexport function run(value) { spawn('tool', [value], { shell: false }); }",
      cwe: ['CWE-88'],
      argumentRole: 'command_argument'
    },
    {
      name: 'untrusted executable path',
      sink: "import { execFile } from 'node:child_process';\nexport function run(value) { execFile(value, ['fixed']); }",
      cwe: ['CWE-114'],
      argumentRole: 'command_executable'
    }
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async (subtest) => {
      const report = await analyzeProjectFiles(subtest, {
        'src/route.js': registeredExpressRoute([
          "import { forward } from './helper.js';",
          'export function handle(req) { forward(req.query.command); }'
        ].join('\n')),
        'src/helper.js': [
          "import { run } from './process.js';",
          'export function forward(value) { run(value); }'
        ].join('\n'),
        'src/process.js': scenario.sink
      });
      const finding = report.issues.find((issue) =>
        issue.ruleId === 'LUM-INJ-002' && issue.file === 'src/process.js' && issue.isTaintConfirmed
      );
      assert.ok(finding, 'production report contains the cross-module command finding');
      assert.deepEqual(finding.cwe, scenario.cwe);
      assert.ok(!finding.cwe.includes('CWE-426'));
      assert.equal(finding.taintTrace.source.file, 'src/route.js');
      assert.equal(finding.taintTrace.sink.file, 'src/process.js');
      assert.equal(finding.taintTrace.sink.argumentRole, scenario.argumentRole);
      assert.equal(finding.taintTrace.sink.line, 2);
      assert.ok(finding.taintTrace.steps.some((step) =>
        step.fromModule === 'src/route.js' && step.toModule === 'src/helper.js'
      ));
      assert.ok(finding.taintTrace.steps.some((step) =>
        step.fromModule === 'src/helper.js' && step.toModule === 'src/process.js'
      ));
    });
  }
});

test('production analyzer keeps numeric transformations sink-context-specific across modules', async (t) => {
  const cases = [
    {
      name: 'numeric conversion remains tainted in non-shell process arguments',
      sink: "import { spawn } from 'node:child_process';\nexport function run(value) { spawn('tool', [value], { shell: false }); }",
      argumentRole: 'command_argument',
      cwe: ['CWE-88']
    },
    {
      name: 'numeric conversion remains tainted for executable selection',
      sink: "import { execFile } from 'node:child_process';\nexport function run(value) { execFile(value, ['fixed']); }",
      argumentRole: 'command_executable',
      cwe: ['CWE-114']
    }
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (subtest) => {
      const report = await analyzeProjectFiles(subtest, {
        'src/route.js': registeredExpressRoute([
          "import { forward } from './helper.js';",
          'export function handle(req) { forward(req.query.command); }'
        ].join('\n')),
        'src/helper.js': [
          "import { run } from './process.js';",
          'export function forward(value) { run(parseInt(value, 10)); }'
        ].join('\n'),
        'src/process.js': scenario.sink
      });
      const finding = report.issues.find((issue) =>
        issue.ruleId === 'LUM-INJ-002' && issue.file === 'src/process.js' && issue.isTaintConfirmed
      );
      assert.ok(finding);
      assert.deepEqual(finding.cwe, scenario.cwe);
      assert.equal(finding.taintTrace.sink.argumentRole, scenario.argumentRole);
    });
  }
});

test('production analyzer reports circular module imports as partial taint coverage', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/a.js': registeredExpressRoute([
      "import { forward } from './b.js';",
      'export function handle(req) { forward(req.query.id); }'
    ].join('\n')),
    'src/b.js': [
      "import { handle } from './a.js';",
      'export function forward(value) {',
      "  db.query('SELECT ' + value);",
      '}'
    ].join('\n')
  });
  const sqlCheck = report.scan.checks.find((check) => check.id === 'sql_injection_pattern_search');
  assert.equal(sqlCheck.status, 'partial');
  assert.equal(sqlCheck.reason.code, 'cross_file_taint_analysis_incomplete');
  assert.ok(report.issues.some((issue) => issue.ruleId === 'LUM-INJ-001'));
});

test('production analyzer preserves sanitizer semantics across module boundaries', async (t) => {
  const cases = [
    {
      name: 'mysql.escape does not suppress SQL sink findings without verified context',
      middle: [
        "import * as mysql from 'mysql';",
        'export function clean(value) { return mysql.escape(value); }'
      ].join('\n'),
      sink: [
        "import { clean } from './helper.js';",
        'export function run(value) {',
        '  const escaped = clean(value);',
        '  db.query("SELECT * FROM records WHERE id=\'" + escaped + "\'");',
        '}'
      ].join('\n'),
      expectedFindings: 1
    },
    {
      name: 'unverified cross-file SQL escape import preserves taint',
      middle: [
        "import * as mysql from 'unknown-package';",
        'export function clean(value) { return mysql.escape(value); }'
      ].join('\n'),
      sink: [
        "import { clean } from './helper.js';",
        'export function run(value) {',
        '  const escaped = clean(value);',
        `  db.query("SELECT * FROM records WHERE id='" + escaped + "'");`,
        '}'
      ].join('\n'),
      expectedFindings: 1
    },
    {
      name: 'HTML escaping does not suppress SQL sink findings',
      middle: 'export function clean(value) { return escapeHtml(value); }',
      sink: [
        "import { clean } from './helper.js';",
        'export function run(value) {',
        '  const escaped = clean(value);',
        '  db.query("SELECT * FROM records WHERE id=\'" + escaped + "\'");',
        '}'
      ].join('\n'),
      expectedFindings: 1
    },
    {
      name: 'cross-file identity function named escape does not suppress SQL sink findings',
      middle: 'export function escape(value) { return value; }',
      sink: [
        "import { escape as clean } from './helper.js';",
        'export function run(value) {',
        '  const escaped = clean(value);',
        `  db.query("SELECT * FROM records WHERE id='" + escaped + "'");`,
        '}'
      ].join('\n'),
      expectedFindings: 1
    },
    {
      name: 'boolean validation retains taint',
      middle: 'export function clean(value) { validator.isInt(value); return value; }',
      sink: [
        "import { clean } from './helper.js';",
        'export function run(value) {',
        '  const checked = clean(value);',
        '  db.query("SELECT * FROM records WHERE id=" + checked);',
        '}'
      ].join('\n'),
      expectedFindings: 1
    }
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (subtest) => {
      const report = await analyzeProjectFiles(subtest, {
        'src/route.js': registeredExpressRoute([
          "import { run } from './sink.js';",
          'export function handle(req) { run(req.query.id); }'
        ].join('\n')),
        'src/helper.js': scenario.middle,
        'src/sink.js': scenario.sink
      });
      const findings = report.issues.filter((issue) =>
        issue.ruleId === 'LUM-INJ-001' && issue.file === 'src/sink.js' && issue.isTaintConfirmed
      );
      assert.equal(findings.length, scenario.expectedFindings);
      if (scenario.expectedFindings) {
        assert.deepEqual(findings[0].cwe, ['CWE-89']);
        if (scenario.name.includes('mysql.escape')) {
          assert.equal(findings[0].line, 4);
          assert.equal(findings[0].taintTrace.sink.line, 4);
          assert.equal(findings[0].taintTrace.source.expression, 'req.query');
          assert.match(findings[0].evidence, /req\.query/);
          assert.ok(findings[0].taintTrace.steps.some((step) =>
            step.fromModule === 'src/sink.js' && step.toModule === 'src/helper.js'
          ));
        }
        if (scenario.name.includes('identity function named escape')) {
          assert.equal(findings[0].taintTrace.source.file, 'src/route.js');
          assert.equal(findings[0].taintTrace.sink.file, 'src/sink.js');
          assert.ok(findings[0].taintTrace.steps.some((step) =>
            step.fromModule === 'src/route.js' && step.toModule === 'src/sink.js'
          ));
          assert.ok(findings[0].taintTrace.steps.some((step) =>
            step.fromModule === 'src/sink.js' && step.toModule === 'src/helper.js'
          ));
        }
      }
    });
  }
});

test('production analyzer keeps clean call sites separate and cross-file finding IDs stable', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/route.js': [
      "import { run } from './sink.js';",
      'export function first(req) { run(req.query.id); }',
      'export function second(req) { run(req.params.name); }',
      "export function clean() { run('fixed'); }",
      "const express = require('express');",
      'const app = express();',
      "app.get('/first', first);",
      "app.get('/second', second);"
    ].join('\n'),
    'src/sink.js': [
      'export function run(value) {',
      "  const sql = 'SELECT * FROM records WHERE id=' + value;",
      '  db.query(sql);',
      '}'
    ].join('\n')
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const options = {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  };
  const firstReport = await analyzeProduction(projectPath, 'unused', null, options);
  const secondReport = await analyzeProduction(projectPath, 'unused', null, options);
  const select = (report) => report.issues.filter((issue) =>
    issue.ruleId === 'LUM-INJ-001' && issue.file === 'src/sink.js' &&
    issue.line === 3 && issue.isTaintConfirmed
  );
  const firstFindings = select(firstReport);
  const secondFindings = select(secondReport);

  assert.equal(firstFindings.length, 1);
  assert.equal(secondFindings.length, 1);
  assert.equal(firstFindings[0].id, secondFindings[0].id);
  assert.equal(firstFindings[0].taintTrace.source.file, 'src/route.js');
  assert.ok(firstFindings[0].taintTrace.alternatePaths?.length >= 1);
});

test('production analyzer discovers Express entry points and traces imported controllers', async (t) => {
  const projectPath = makeProject({
    ...completeProjectFiles,
    'src/routes.js': [
      "import express from 'express';",
      "import { run as controller } from './controller.js';",
      'const router = express.Router();',
      "router.post('/query', controller);"
    ].join('\n'),
    'src/controller.js': [
      "import { persist } from './database.js';",
      'export function run(input) { persist(input.body.query); }'
    ].join('\n'),
    'src/database.js': [
      'export function persist(value) {',
      "  db.query('SELECT * FROM records WHERE id=' + value);",
      '}'
    ].join('\n')
  });
  t.after(() => fs.rmSync(projectPath, { recursive: true, force: true }));
  const options = {
    staticOnly: true,
    logger: quietLogger,
    fetch: async () => new Response(JSON.stringify({ results: [] }))
  };
  const report = await analyzeProduction(projectPath, 'unused', null, options);
  const repeatedReport = await analyzeProduction(projectPath, 'unused', null, options);

  const findings = report.issues.filter((issue) =>
    issue.ruleId === 'LUM-INJ-001' && issue.file === 'src/database.js' && issue.isTaintConfirmed
  );
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].cwe, ['CWE-89']);
  assert.equal(findings[0].taintTrace.source.file, 'src/controller.js');
  assert.equal(findings[0].taintTrace.sink.file, 'src/database.js');
  assert.equal(findings[0].taintTrace.sink.line, 2);
  assert.equal(findings[0].evidence.includes('<redacted>'), true);
  assert.ok(findings[0].taintTrace.steps.some((step) =>
    step.fromModule === 'src/routes.js' &&
    step.toModule === 'src/controller.js' &&
    step.frameworkEntryPoint === true
  ));
  const repeatedFindings = repeatedReport.issues.filter((issue) =>
    issue.ruleId === 'LUM-INJ-001' && issue.file === 'src/database.js' && issue.isTaintConfirmed
  );
  assert.equal(repeatedFindings.length, 1);
  assert.equal(findings[0].id, repeatedFindings[0].id);
  assert.deepEqual(findings[0].taintTrace, repeatedFindings[0].taintTrace);
});

test('production analyzer does not confirm request taint without a verified router', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/routes.js': [
      'function handler(req) { db.query("SELECT " + req.query.id); }',
      'function controller(request) { db.query("SELECT " + request.body.id); }',
      'const app = {};',
      "app.post('/unverified', handler);"
    ].join('\n')
  });

  assert.equal(report.issues.some((issue) =>
    issue.file === 'src/routes.js' && issue.isTaintConfirmed
  ), false);
  const sqlCheck = report.scan.checks.find((check) =>
    check.id === 'sql_injection_pattern_search'
  );
  assert.equal(sqlCheck.status, 'partial');
  assert.equal(sqlCheck.reason.code, 'framework_router_identity_ambiguous');
});

test('production analyzer merges same-file route-seeded findings and reports framework limitations', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/routes.js': [
      "import express from 'express';",
      'const app = express();',
      "app.post(getPath(), (input) => child_process.exec('tool ' + input.body.command));"
    ].join('\n')
  });

  const findings = report.issues.filter((issue) =>
    issue.ruleId === 'LUM-INJ-002' && issue.file === 'src/routes.js' && issue.isTaintConfirmed
  );
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].cwe, ['CWE-78']);
  const commandCheck = report.scan.checks.find((check) =>
    check.id === 'os_command_injection_pattern_search'
  );
  assert.equal(commandCheck.status, 'partial');
  assert.equal(commandCheck.reason.code, 'dynamic_route_registration_detected');
});

test('production analyzer preserves distinct same-line SQL sink identities and taint evidence', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/routes.js': registeredExpressRoute([
      'export function handle(req) {',
      "  db.query('SELECT ' + req.query.first); db.query('SELECT ' + req.query.second);",
      '}'
    ].join('\n'))
  });
  const findings = report.issues.filter((issue) =>
    issue.ruleId === 'LUM-INJ-001' &&
    issue.file === 'src/routes.js' &&
    issue.isTaintConfirmed
  );

  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map((finding) => finding.taintTrace.sink.line), [2, 2]);
  assert.equal(new Set(findings.map((finding) => finding.sinkIdentity)).size, 2);
  assert.equal(new Set(findings.map((finding) => finding.findingFingerprint)).size, 2);
  assert.ok(findings.some((finding) =>
    finding.taintTrace.sink.expression.includes('first')
  ));
  assert.ok(findings.some((finding) =>
    finding.taintTrace.sink.expression.includes('second')
  ));
  assert.ok(findings.every((finding) =>
    finding.producerOrigins.includes('pattern') &&
    finding.producerOrigins.includes('ast_pattern') &&
    finding.producerOrigins.includes('project_taint') &&
    finding.sourceSpan?.start < finding.sourceSpan?.end
  ));
});

test('production analyzer retains identical same-line SQL calls as independent taint findings', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/repeated-routes.js': registeredExpressRoute([
      'export function handle(req) {',
      "  db.query('SELECT ' + req.query.x); db.query('SELECT ' + req.query.x);",
      '}'
    ].join('\n'))
  });
  const findings = report.issues.filter((issue) =>
    issue.ruleId === 'LUM-INJ-001' &&
    issue.file === 'src/repeated-routes.js' &&
    issue.isTaintConfirmed
  );

  assert.equal(findings.length, 2);
  assert.equal(new Set(findings.map((finding) => finding.sinkIdentity)).size, 2);
  assert.equal(new Set(findings.map((finding) =>
    `${finding.sourceSpan.start}:${finding.sourceSpan.end}`
  )).size, 2);
  assert.equal(new Set(findings.map((finding) =>
    `${finding.taintTrace.source.file}:${finding.taintTrace.source.expression}:${finding.taintTrace.sink.expression}:${finding.taintTrace.sink.column}`
  )).size, 2);
});

test('production analyzer follows aliases of eval and imported child_process.exec', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/aliased-sinks.js': [
      "import { exec } from 'node:child_process';",
      'const runEval = eval;',
      'const runCommand = exec;',
      'function handle(req) {',
      '  runEval(req.query.code);',
      "  runCommand('echo ' + req.query.command);",
      '}',
      "const express = require('express');",
      'const app = express();',
      "app.get('/aliased', handle);"
    ].join('\n')
  });
  const findings = report.issues.filter((issue) =>
    issue.file === 'src/aliased-sinks.js' && issue.isTaintConfirmed
  );

  assert.ok(findings.some((finding) => finding.ruleId === 'LUM-DYN-001'));
  assert.ok(findings.some((finding) => finding.ruleId === 'LUM-INJ-002'));
});

test('production analyzer does not treat local query, exec, or eval methods as security sinks', async (t) => {
  const report = await analyzeProjectFiles(t, {
    'src/custom-methods.js': [
      "const child_process = require('node:child_process');",
      "const metrics = { query(value) { return value; } };",
      "const worker = { exec(value) { return value; } };",
      "const evaluator = { eval(value) { return value; } };",
      'function handle(req) {',
      "  metrics.query('SELECT ' + req.query.label);",
      "  worker.exec('echo ' + req.query.command);",
      '  evaluator.eval(req.query.expression);',
      '}',
      "const express = require('express');",
      'const app = express();',
      "app.get('/custom', handle);"
    ].join('\n')
  });

  assert.equal(report.issues.some((issue) =>
    ['LUM-INJ-001', 'LUM-INJ-002', 'LUM-DYN-001'].includes(issue.ruleId) &&
    issue.file === 'src/custom-methods.js'
  ), false);
});
