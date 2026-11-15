import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { parseSource, PARSER_LIMITS } from './parser.js';
import { walkAST } from './traversal.js';
import { analyzeAstSource } from './analyzer.js';
import { createRequire } from 'node:module';
import { analyzeProduction } from '../productionAnalyzer.js';

const quietLogger = { info() {}, warn() {}, error() {} };

const makeProject = (files) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ast-test-project-'));
  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }
  return dir;
};

const baseProjectFiles = {
  Dockerfile: 'FROM node:20-alpine\nUSER node\nHEALTHCHECK CMD true\n',
  '.dockerignore': 'node_modules\n',
  'README.md': 'Project documentation',
  'package.json': JSON.stringify({ name: 'fixture', version: '1.0.0' }),
  'package-lock.json': JSON.stringify({
    name: 'fixture',
    lockfileVersion: 3,
    packages: { '': { name: 'fixture', version: '1.0.0' } }
  })
};

test('AST Parser & Traversal: Syntax Support and Safety Limits', async (t) => {
  await t.test('resolves @babel/parser strictly from backend dependencies without frontend coupling', () => {
    const backendRequire = createRequire(import.meta.url);
    const resolvedPath = backendRequire.resolve('@babel/parser');
    assert.match(resolvedPath.replace(/\\/g, '/'), /\/backend\/node_modules\/@babel\/parser\//);
    assert.doesNotMatch(resolvedPath.replace(/\\/g, '/'), /\/frontend\/node_modules\//);
  });
  await t.test('parses valid JavaScript with modern ECMAScript features', () => {
    const code = `
      import path from 'node:path';
      const greeting = 'hello';
      const obj = { a: 1, b: 2, ...{ c: 3 } };
      const val = obj?.a ?? 42;
      async function run() {
        return await Promise.resolve(val);
      }
      export default run;
    `;
    const result = parseSource(code, { filePath: 'src/app.js' });
    assert.equal(result.parseStatus, 'success');
    assert.equal(result.isPartial, false);
    assert.ok(result.ast);
    assert.equal(result.ast.type, 'File');
    assert.equal(result.ast.program.type, 'Program');
    assert.equal(result.errors.length, 0);
  });

  await t.test('parses valid TypeScript with types, interfaces, and generics', () => {
    const code = `
      interface User<T> {
        id: string;
        data: T;
      }
      type Role = 'admin' | 'user';
      function getUser<T>(id: string, role: Role): User<T> | null {
        return null;
      }
      export { getUser };
    `;
    const result = parseSource(code, { filePath: 'src/types.ts' });
    assert.equal(result.parseStatus, 'success');
    assert.equal(result.isPartial, false);
    assert.ok(result.ast);
  });

  await t.test('parses JSX and TSX with embedded expressions', () => {
    const jsxCode = `
      export function Button({ label, onClick }) {
        return <button onClick={onClick} className="btn">{label}</button>;
      }
    `;
    const jsxResult = parseSource(jsxCode, { filePath: 'src/Button.jsx' });
    assert.equal(jsxResult.parseStatus, 'success');
    assert.ok(jsxResult.ast);

    const tsxCode = `
      interface Props { name: string; }
      export const Card: React.FC<Props> = ({ name }) => (
        <div className="card"><span>{name}</span></div>
      );
    `;
    const tsxResult = parseSource(tsxCode, { filePath: 'src/Card.tsx' });
    assert.equal(tsxResult.parseStatus, 'success');
    assert.ok(tsxResult.ast);
  });

  await t.test('parses empty source gracefully with valid Program node', () => {
    const result = parseSource('', { filePath: 'src/empty.js' });
    assert.equal(result.parseStatus, 'success');
    assert.equal(result.isPartial, false);
    assert.equal(result.ast.type, 'Program');
    assert.equal(result.ast.body.length, 0);
  });

  await t.test('recovers from incomplete or partially written source code', () => {
    const code = `
      let duplicateVar = 1;
      let duplicateVar = 2;
      eval(payload);
    `;
    const result = parseSource(code, { filePath: 'src/partial.js', errorRecovery: true });
    assert.ok(result.ast, 'AST is produced via error recovery');
    assert.equal(result.isPartial, true);
    assert.ok(result.errors.length > 0, 'syntax error is recorded');
  });

  await t.test('handles non-recoverable fatal syntax errors safely without throwing', () => {
    const code = `
      /* unclosed comment with totally invalid syntax
      const = {;
    `;
    const result = parseSource(code, { filePath: 'src/fatal.js' });
    assert.equal(result.ast, null);
    assert.equal(result.parseStatus, 'failed');
    assert.equal(result.isPartial, true);
    assert.ok(result.errors.length > 0);
  });

  await t.test('enforces maxSourceBytes limit and skips oversized files', () => {
    const oversizedCode = 'const a = 1;\n'.repeat(200_000); // > 2MB
    const result = parseSource(oversizedCode, { filePath: 'src/huge.js', maxSourceBytes: 1024 * 1024 });
    assert.equal(result.ast, null);
    assert.equal(result.parseStatus, 'skipped');
    assert.equal(result.isPartial, true);
    assert.equal(result.errors[0].code, 'SOURCE_SIZE_EXCEEDED');
  });

  await t.test('enforces maxDepth traversal limits to guard against deeply nested ASTs', () => {
    // Generate deeply nested AST with object properties: { a: { a: ... } }
    let nestedCode = '1';
    for (let i = 0; i < 50; i++) {
      nestedCode = `{ prop: ${nestedCode} }`;
    }
    const parseRes = parseSource(`const deep = ${nestedCode};`, { filePath: 'src/nested.js' });
    assert.ok(parseRes.ast);

    const traversalRes = walkAST(parseRes.ast, {}, { maxDepth: 25 });
    assert.equal(traversalRes.depthLimitExceeded, true);
    assert.ok(traversalRes.maxDepthReached >= 25);
  });
});

test('AST Detection: JavaScript/TypeScript Security Recognizers', async (t) => {
  await t.test('detects direct eval() calls (LUM-DYN-001)', () => {
    const code = `
      const input = "alert(1)";
      eval(input);
    `;
    const result = analyzeAstSource(code, { filePath: 'src/eval.js' });
    assert.equal(result.findings.length, 1);
    const f = result.findings[0];
    assert.equal(f.ruleId, 'LUM-DYN-001');
    assert.equal(f.line, 3);
    assert.equal(f.severity, 'High');
    assert.equal(f.confidence, 'high');
    assert.ok(f.cwe.includes('CWE-95'));
    assert.equal(f.origin, 'ast_analysis');
  });

  await t.test('detects indirect eval calls via SequenceExpression and global objects (LUM-DYN-001)', () => {
    const code = `
      (0, eval)("var x = 1;");
      window.eval("var y = 2;");
      globalThis.eval("var z = 3;");
    `;
    const result = analyzeAstSource(code, { filePath: 'src/indirectEval.js' });
    assert.equal(result.findings.length, 3);
    assert.ok(result.findings.every((f) => f.ruleId === 'LUM-DYN-001'));
    assert.ok(result.findings.some((f) => f.line === 2));
    assert.ok(result.findings.some((f) => f.line === 3));
    assert.ok(result.findings.some((f) => f.line === 4));
  });

  await t.test('detects Function constructor invocations (LUM-DYN-002)', () => {
    const code = `
      const add = new Function('a', 'b', 'return a + b');
      const sub = Function('a', 'b', 'return a - b');
    `;
    const result = analyzeAstSource(code, { filePath: 'src/func.js' });
    assert.equal(result.findings.length, 2);
    assert.ok(result.findings.every((f) => f.ruleId === 'LUM-DYN-002'));
    assert.equal(result.findings[0].line, 2);
    assert.equal(result.findings[1].line, 3);
  });

  await t.test('detects Node.js vm dynamic execution calls (LUM-DYN-003)', () => {
    const code = `
      import vm from 'node:vm';
      vm.runInContext(code, context);
      vm.runInNewContext(code);
      vm.runInThisContext(code);
      vm.compileFunction(code);
      new vm.Script(code);
    `;
    const result = analyzeAstSource(code, { filePath: 'src/vmTest.js' });
    assert.equal(result.findings.length, 5);
    assert.ok(result.findings.every((f) => f.ruleId === 'LUM-DYN-003'));
    assert.ok(result.findings.every((f) => f.cwe.includes('CWE-94')));
  });

  await t.test('detects timer APIs called with string arguments (LUM-DYN-004)', () => {
    const code = `
      setTimeout("doSomething()", 500);
      setInterval("refresh()", 1000);
      setImmediate("cleanup()");
    `;
    const result = analyzeAstSource(code, { filePath: 'src/timers.js' });
    assert.equal(result.findings.length, 3);
    assert.ok(result.findings.every((f) => f.ruleId === 'LUM-DYN-004'));
    assert.ok(result.findings.every((f) => f.severity === 'Medium'));
  });

  await t.test('detects command execution with dynamic arguments and shell mode (LUM-INJ-002)', () => {
    const code = `
      import { exec, spawn } from 'node:child_process';
      exec("cat " + userFile);
      spawn("sh", ["-c", userCmd], { shell: true });
    `;
    const result = analyzeAstSource(code, { filePath: 'src/exec.js' });
    assert.equal(result.findings.length, 2);
    assert.ok(result.findings.every((f) => f.ruleId === 'LUM-INJ-002'));
    assert.ok(result.findings.every((f) => f.cwe.includes('CWE-78')));
  });

  await t.test('detects dynamic SQL via concatenation, template literals, and variable tracking (LUM-INJ-001)', () => {
    const code = `
      const query1 = "SELECT * FROM users WHERE id = " + userId;
      db.query(query1);
      db.query(\`SELECT * FROM users WHERE email = '\${userEmail}'\`);
      db.execute("INSERT INTO logs VALUES ('" + message + "')");
    `;
    const result = analyzeAstSource(code, { filePath: 'src/sqlTest.js' });
    assert.equal(result.findings.length, 3);
    assert.ok(result.findings.every((f) => f.ruleId === 'LUM-INJ-001'));
    assert.ok(result.findings.every((f) => f.cwe.includes('CWE-89')));
  });

  await t.test('detects node-serialize unsafe deserialization (LUM-DES-005)', () => {
    const code = `
      import serialize from 'node-serialize';
      const obj = serialize.unserialize(payload);
    `;
    const result = analyzeAstSource(code, { filePath: 'src/deserialize.js' });
    assert.equal(result.findings.length, 1);
    const f = result.findings[0];
    assert.equal(f.ruleId, 'LUM-DES-005');
    assert.equal(f.line, 3);
    assert.ok(f.cwe.includes('CWE-502'));
  });
});

test('AST Recognizers: Safe Patterns and Exclusions', async (t) => {
  await t.test('parameterized SQL queries are not flagged', () => {
    const code = `
      db.query("SELECT * FROM users WHERE id = ?", [userId]);
      db.execute("SELECT * FROM users WHERE email = $1", [email]);
      db.raw("SELECT * FROM items");
    `;
    const result = analyzeAstSource(code, { filePath: 'src/safeSql.js' });
    assert.equal(result.findings.length, 0);
  });

  await t.test('safe static argument-array process execution is not flagged', () => {
    const code = `
      import { execFile, spawn } from 'node:child_process';
      execFile("git", ["status"]);
      spawn("node", ["server.js"]);
    `;
    const result = analyzeAstSource(code, { filePath: 'src/safeExec.js' });
    assert.equal(result.findings.length, 0);
  });

  await t.test('timer callbacks using functions/arrows are not flagged', () => {
    const code = `
      setTimeout(() => console.log('done'), 1000);
      setInterval(function handler() { check(); }, 500);
      setImmediate(callbackFn);
    `;
    const result = analyzeAstSource(code, { filePath: 'src/safeTimer.js' });
    assert.equal(result.findings.length, 0);
  });

  await t.test('harmless identifiers, declarations, comments, and strings are not flagged', () => {
    const code = `
      // eval("alert(1)") in comment
      /* db.query("SELECT * FROM " + table) */
      function evalResults(x) { return x; }
      const doc = "child_process.exec('rm -rf /')";
      const config = { evalMode: false, execPath: '/bin/ls' };
    `;
    const result = analyzeAstSource(code, { filePath: 'src/safeSample.js' });
    assert.equal(result.findings.length, 0);
  });
});

test('AST Integration into Production Analyzer', async (t) => {
  await t.test('AST findings enter normalized report without duplication with pattern findings', async () => {
    const projectPath = makeProject({
      ...baseProjectFiles,
      'src/vulnerable.js': [
        'const userInput = req.query.code;',
        'eval(userInput);',
        'const query = `SELECT * FROM items WHERE name = ${req.query.name}`;',
        'db.query(query);',
        ''
      ].join('\n')
    });

    const report = await analyzeProduction(projectPath, 'test-image', null, {
      staticOnly: true,
      logger: quietLogger,
      fetch: async () => new Response(JSON.stringify({ results: [] }))
    });

    const evalFindings = report.issues.filter((i) => i.ruleId === 'LUM-DYN-001');
    const sqlFindings = report.issues.filter((i) => i.ruleId === 'LUM-INJ-001');

    assert.equal(evalFindings.length, 1, 'eval finding is not duplicated');
    assert.equal(sqlFindings.length, 1, 'SQL finding is not duplicated');
    assert.equal(evalFindings[0].line, 2);
    assert.ok(evalFindings[0].evidence.includes('<redacted>'));

    fs.rmSync(projectPath, { recursive: true, force: true });
  });

  await t.test('malformed source file causes coverage to reflect partial status without crashing scan', async () => {
    const projectPath = makeProject({
      ...baseProjectFiles,
      'src/valid.js': 'eval(code);\n',
      'src/malformed.js': '/* unclosed comment with fatal syntax\nconst = {;\n'
    });

    const report = await analyzeProduction(projectPath, 'test-image', null, {
      staticOnly: true,
      logger: quietLogger,
      fetch: async () => new Response(JSON.stringify({ results: [] }))
    });

    assert.ok(report, 'scan completes and returns report');
    // Valid file finding is still detected
    const evalFinding = report.issues.find((i) => i.ruleId === 'LUM-DYN-001');
    assert.ok(evalFinding, 'eval in valid.js is successfully detected');

    // Coverage is recorded as partial with ast_parse_syntax_error reason
    const dynCheck = report.scan.checks.find((c) => c.id === 'dynamic_code_execution_pattern_search');
    assert.equal(dynCheck.status, 'partial');
    assert.equal(dynCheck.reason.code, 'ast_parse_syntax_error');
    assert.match(dynCheck.explanation, /syntax errors that prevented full AST analysis/);

    fs.rmSync(projectPath, { recursive: true, force: true });
  });
});
