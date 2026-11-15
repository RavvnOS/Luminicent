import { test, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseSource } from '../parser.js';
import { analyzeAstTaint } from './taintAnalyzer.js';
import { analyzeAstSource } from '../analyzer.js';
import { createSinkProvenanceResolver } from '../sinkProvenance.js';

describe('AST Intra-Function Taint Analysis (Phase 5.2)', () => {
  it('resolves global eval and imported exec aliases without trusting local implementations', () => {
    const evalAlias = 'const run = eval;\nfunction handle(req) {\n  run(req.query.code);\n}';
    const execAlias = [
      "import { exec } from 'node:child_process';",
      'const run = exec;',
      'function handle(req) {',
      "  run('echo ' + req.query.command);",
      '}'
    ].join('\n');
    const localEval = [
      'function eval(value) {',
      '  return value;',
      '}',
      'function handle(req) {',
      '  eval(req.query.code);',
      '}'
    ].join('\n');
    const localExec = [
      'const tools = {',
      '  exec(value) {',
      '    return value;',
      '  }',
      '};',
      'function handle(req) {',
      '  tools.exec(req.query.command);',
      '}'
    ].join('\n');
    const getCallProvenance = (code) => {
      const parsed = parseSource(code);
      return createSinkProvenanceResolver(parsed.ast)
        .getCallDescriptors()
        .find((call) => call.callee?.endsWith('eval') || call.callee?.endsWith('run') ||
          call.callee?.endsWith('exec'))?.provenance;
    };

    assert.equal(getCallProvenance(evalAlias).status, 'global_builtin');
    assert.equal(getCallProvenance(execAlias).status, 'supported_external_api');
    assert.equal(getCallProvenance(localEval).status, 'locally_defined');
    assert.equal(getCallProvenance(localExec).status, 'locally_defined');

    const evalFindings = analyzeAstSource(evalAlias, { filePath: 'src/eval-alias.js' }).findings;
    const execFindings = analyzeAstSource(execAlias, { filePath: 'src/exec-alias.js' }).findings;
    assert.ok(evalFindings.some((finding) =>
      finding.ruleId === 'LUM-DYN-001' && finding.isTaintConfirmed
    ));
    assert.ok(execFindings.some((finding) =>
      finding.ruleId === 'LUM-INJ-002' && finding.isTaintConfirmed
    ));
    assert.equal(analyzeAstSource(localEval, { filePath: 'src/local-eval.js' }).findings.length, 0);
    assert.equal(analyzeAstSource(localExec, { filePath: 'src/local-exec.js' }).findings.length, 0);
  });

  it('resolves assignment aliases without retaining provenance across ambiguous reassignment', () => {
    const evalAssignment = [
      'let run;',
      'run = eval;',
      'function handle(req) {',
      '  run(req.query.code);',
      '}'
    ].join('\n');
    const execAssignment = [
      "import { exec } from 'node:child_process';",
      'let run;',
      'run = exec;',
      'function handle(req) {',
      "  run('echo ' + req.query.command);",
      '}'
    ].join('\n');
    const unresolvedExecAssignment = [
      "import { exec } from 'unverified-package';",
      'let run;',
      'run = exec;',
      'function handle(req) {',
      "  run('echo ' + req.query.command);",
      '}'
    ].join('\n');
    const repeatedAssignment = [
      'let run = eval;',
      'run = eval;',
      'function handle(req) { run(req.query.code); }'
    ].join('\n');
    const chainedAssignment = [
      'let first;',
      'first = eval;',
      'let run;',
      'run = first;',
      'function handle(req) { run(req.query.code); }'
    ].join('\n');
    const safeReassignment = [
      'function safe(value) { return value; }',
      'let run = eval;',
      'run = safe;',
      'function handle(req) { run(req.query.code); }'
    ].join('\n');
    const unknownReassignment = [
      'let run = eval;',
      'run = getHandler();',
      'function handle(req) { run(req.query.code); }'
    ].join('\n');
    const sameNameDifferentScopes = [
      'const run = eval;',
      'function handle(req) {',
      '  { let run = getHandler(); run(req.query.code); }',
      '}'
    ].join('\n');
    const provenance = (code) => {
      const parsed = parseSource(code);
      return createSinkProvenanceResolver(parsed.ast).getCallDescriptors()
        .find((call) => call.callee === 'run')?.provenance;
    };
    const taintFindings = (code, filePath) =>
      analyzeAstSource(code, { filePath }).findings.filter((finding) => finding.isTaintConfirmed);

    assert.equal(provenance(evalAssignment).status, 'global_builtin');
    assert.equal(provenance(evalAssignment).resolution, 'resolved_alias');
    assert.ok(taintFindings(evalAssignment, 'src/eval-assignment.js')
      .some((finding) => finding.ruleId === 'LUM-DYN-001'));

    assert.equal(provenance(execAssignment).status, 'supported_external_api');
    assert.equal(provenance(execAssignment).resolution, 'resolved_alias');
    assert.ok(taintFindings(execAssignment, 'src/exec-assignment.js')
      .some((finding) => finding.ruleId === 'LUM-INJ-002'));

    assert.equal(provenance(unresolvedExecAssignment).status, 'external_unresolved');
    assert.ok(taintFindings(unresolvedExecAssignment, 'src/unresolved-exec-assignment.js')
      .some((finding) => finding.ruleId === 'LUM-INJ-002'));

    assert.equal(provenance(repeatedAssignment).status, 'global_builtin');
    assert.ok(taintFindings(repeatedAssignment, 'src/eval-repeated-assignment.js')
      .some((finding) => finding.ruleId === 'LUM-DYN-001'));
    assert.equal(provenance(chainedAssignment).status, 'global_builtin');
    assert.ok(taintFindings(chainedAssignment, 'src/eval-chained-assignment.js')
      .some((finding) => finding.ruleId === 'LUM-DYN-001'));

    assert.equal(provenance(safeReassignment).status, 'ambiguous');
    assert.equal(provenance(unknownReassignment).status, 'ambiguous');
    assert.equal(provenance(sameNameDifferentScopes).resolution, 'local_variable');
    assert.equal(taintFindings(safeReassignment, 'src/eval-safe-reassignment.js')
      .some((finding) => finding.ruleId === 'LUM-DYN-001'), false);
    assert.equal(taintFindings(unknownReassignment, 'src/eval-unknown-reassignment.js')
      .some((finding) => finding.ruleId === 'LUM-DYN-001'), false);
  });

  it('keeps unresolved imported sink aliases conservative and distinguishes shadowed eval', () => {
    const unresolvedExec = [
      "import { exec } from 'unverified-package';",
      'const run = exec;',
      'function handle(req) {',
      "  run('echo ' + req.query.command);",
      '}'
    ].join('\n');
    const shadowedEval = [
      'function handle(eval, req) {',
      '  eval(req.query.code);',
      '}'
    ].join('\n');
    const unresolvedResolver = createSinkProvenanceResolver(
      parseSource(unresolvedExec).ast
    );
    const shadowedResolver = createSinkProvenanceResolver(
      parseSource(shadowedEval).ast
    );

    assert.equal(
      unresolvedResolver.getCallDescriptors()[0].provenance.status,
      'external_unresolved'
    );
    assert.equal(
      shadowedResolver.getCallDescriptors()[0].provenance.resolution,
      'parameter_binding'
    );
    assert.ok(analyzeAstSource(unresolvedExec, {
      filePath: 'src/unresolved-exec.js'
    }).findings.some((finding) =>
      finding.ruleId === 'LUM-INJ-002' && finding.isTaintConfirmed
    ));
    assert.equal(analyzeAstSource(shadowedEval, {
      filePath: 'src/shadowed-eval.js'
    }).findings.some((finding) => finding.ruleId === 'LUM-DYN-001'), false);
  });

  it('preserves independent taint findings for identical SQL calls on the same line', () => {
    const code = [
      'function handle(req) {',
      "  db.query('SELECT ' + req.query.x); db.query('SELECT ' + req.query.x);",
      '}'
    ].join('\n');
    const result = analyzeAstSource(code, { filePath: 'src/repeated-sinks.js' });
    const findings = result.findings.filter((finding) =>
      finding.ruleId === 'LUM-INJ-001' && finding.isTaintConfirmed
    );

    assert.equal(findings.length, 2);
    assert.equal(new Set(findings.map((finding) => finding.sinkIdentity)).size, 2);
    assert.equal(new Set(findings.map((finding) =>
      `${finding.sourceSpan.start}:${finding.sourceSpan.end}`
    )).size, 2);
    assert.equal(new Set(findings.map((finding) =>
      `${finding.taintTrace.source.expression}:${finding.taintTrace.sink.expression}:${finding.taintTrace.sink.column}`
    )).size, 2);
  });

  describe('Positive Cases: Source to Sink Data Flow', () => {
    it('detects direct request input to SQL sink via concatenation', () => {
      const code = `
        app.get('/user', (req, res) => {
          const userInput = req.query.name;
          const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
          db.query(query);
        });
      `;
      const parseResult = parseSource(code, { filePath: 'src/routes.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/routes.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.category, 'injection');
      assert.equal(finding.severity, 'High');
      assert.equal(finding.confidence, 'medium');
      assert.equal(finding.isTaintConfirmed, true);
      assert.ok(finding.taintTrace);
      assert.equal(finding.taintTrace.source.expression, 'req.query.name');
      assert.equal(finding.taintTrace.sink.type, 'sql');
      assert.match(finding.evidence, /req\.query\.name/);
      assert.match(finding.evidence, /db\.query/);
    });

    it('detects request input copied through multiple variable assignments', () => {
      const code = `
        function handle(req) {
          const step1 = req.params.userId;
          const step2 = step1;
          const step3 = step2;
          const sql = "SELECT * FROM accounts WHERE id = " + step3;
          client.execute(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/service.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/service.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.isTaintConfirmed, true);
      assert.ok(finding.taintTrace.steps.length >= 3);
      assert.equal(finding.taintTrace.source.expression, 'req.params.userId');
    });

    it('detects request input flowing into a template literal SQL query', () => {
      const code = `
        async function getUser(req) {
          const email = req.body.email;
          const query = \`SELECT * FROM users WHERE email = '\${email}'\`;
          await pool.query(query);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/user.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/user.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.isTaintConfirmed, true);
      assert.equal(finding.taintTrace.source.expression, 'req.body.email');
    });

    it('detects tainted variable reassignment and compound assignment', () => {
      const code = `
        function executeQuery(req) {
          let query = "SELECT * FROM logs WHERE ";
          query += req.query.filter;
          db.query(query);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/logs.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/logs.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.isTaintConfirmed, true);
    });

    it('detects tainted object property container propagation', () => {
      const code = `
        function search(req) {
          const payload = {
            searchTerm: req.query.term,
            timestamp: Date.now()
          };
          const sql = "SELECT * FROM items WHERE name LIKE '%" + payload.searchTerm + "%'";
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/search.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/search.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.isTaintConfirmed, true);
    });

    it('detects tainted array element container propagation', () => {
      const code = `
        function queryItems(req) {
          const values = [req.query.id, 'fixed'];
          const sql = "SELECT * FROM items WHERE id = " + values[0];
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/items.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/items.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.isTaintConfirmed, true);
    });

    it('detects request input flowing into command execution (exec)', () => {
      const code = `
        function backup(req) {
          const folder = req.query.folder;
          const cmd = 'tar -czf backup.tar.gz ' + folder;
          child_process.exec(cmd);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/admin.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/admin.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-002');
      assert.equal(finding.category, 'injection');
      assert.equal(finding.severity, 'High');
      assert.equal(finding.isTaintConfirmed, true);
      assert.equal(finding.taintTrace.sink.type, 'command');
    });

    it('detects request input flowing into eval() dynamic code execution', () => {
      const code = `
        function runScript(req) {
          const expression = req.body.code;
          eval(expression);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/eval.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/eval.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-DYN-001');
      assert.equal(finding.category, 'dynamic_execution');
      assert.equal(finding.isTaintConfirmed, true);
    });

    it('detects destructured sources flowing to sinks', () => {
      const code = `
        function handle(req) {
          const { id, type } = req.query;
          const sql = "SELECT * FROM entries WHERE id=" + id;
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/destructure.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/destructure.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].isTaintConfirmed, true);
    });
  });

  describe('Negative Cases: Safe Patterns and Exclusions', () => {
    it('does NOT flag safe parameterized queries with bound parameters', () => {
      const code = `
        function handle(req) {
          const userId = req.query.id;
          // Parameterized query: static SQL with separate parameter array
          db.query("SELECT * FROM users WHERE id = ?", [userId]);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/safe.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/safe.js' });

      // The tainted parameter is passed as a bound parameter, not dynamic SQL syntax
      assert.equal(result.findings.length, 0);
    });

    it('does NOT flag static SQL queries without taint flow', () => {
      const code = `
        function handle(req) {
          const user = req.query.user; // unused in query
          db.query("SELECT count(*) FROM users");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/staticSql.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/staticSql.js' });

      assert.equal(result.findings.length, 0);
    });

    it('does NOT flag static command execution with argument array', () => {
      const code = `
        function run(req) {
          const input = req.query.x; // unused
          spawn('git', ['status'], { shell: false });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/staticCmd.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/staticCmd.js' });

      assert.equal(result.findings.length, 0);
    });

    it('distinguishes source and sink in the same function when no data flow exists', () => {
      const code = `
        function handle(req) {
          const userInput = req.query.name;
          logger.info("Received request for " + userInput);
          // Unrelated query using a purely static string
          db.query("SELECT * FROM system_health");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/unrelated.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/unrelated.js' });

      assert.equal(result.findings.length, 0);
    });

    it('isolates taint state between unrelated functions', () => {
      const code = `
        function routeOne(req) {
          const taintedVar = req.query.name;
        }

        function routeTwo() {
          const taintedVar = "constant_value";
          db.query("SELECT * FROM users WHERE name = " + taintedVar);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/multiFunc.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/multiFunc.js' });

      // routeTwo has its own scope and taintedVar is a clean constant
      assert.equal(result.findings.length, 0);
    });

    it('suppresses finding when appropriate numeric sanitizer is applied for SQL', () => {
      const code = `
        function handle(req) {
          const rawId = req.query.id;
          const safeId = parseInt(rawId, 10);
          const sql = "SELECT * FROM users WHERE id = " + safeId;
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/sanitized.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/sanitized.js' });

      // parseInt sanitizes numeric inputs for SQL injection
      assert.equal(result.findings.length, 0);
    });

    it('preserves SQL taint through mysql.escape when execution context is unverified', () => {
      const code = `
        import * as mysql from 'mysql';
        function handle(req) {
          const safeName = mysql.escape(req.query.name);
          const sql = "SELECT * FROM users WHERE name = " + safeName;
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/escaped.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/escaped.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.taintTrace.sink.line, 6);
      assert.equal(finding.taintTrace.sink.api, 'db.query(sql)');
      assert.equal(finding.taintTrace.source.expression, 'req.query.name');
      assert.match(finding.evidence, /req\.query\.name/);
    });

    it('does not trust an escape method from an unknown namespace import', () => {
      const code = [
        "import * as mysql from 'unknown-package';",
        'function handle(req) {',
        '  const value = mysql.escape(req.query.name);',
        `  const sql = "SELECT * FROM users WHERE name = '" + value + "'";`,
        '  db.query(sql);',
        '}'
      ].join('\n');
      const parseResult = parseSource(code, { filePath: 'src/unknownMysql.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/unknownMysql.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.sink.line, 5);
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.api, 'db.query(sql)');
      assert.ok(result.findings[0].taintTrace.steps.some((step) => /mysql\.escape/.test(step.to)));
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('does not trust an aliased namespace import from an unverified package', () => {
      const code = [
        "import * as dbLibrary from 'unverified-package';",
        'function handle(req) {',
        '  const value = dbLibrary.escape(req.query.name);',
        `  const sql = "SELECT * FROM users WHERE name = '" + value + "'";`,
        '  db.query(sql);',
        '}'
      ].join('\n');
      const parseResult = parseSource(code, { filePath: 'src/unverifiedDbLibrary.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/unverifiedDbLibrary.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.sink.line, 5);
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.api, 'db.query(sql)');
      assert.ok(result.findings[0].taintTrace.steps.some((step) => /dbLibrary\.escape/.test(step.to)));
    });

    it('does not trust an escape method on a dynamically obtained object', () => {
      const code = [
        'function handle(req) {',
        '  const mysql = getCustomLibrary();',
        '  const value = mysql.escape(req.query.name);',
        `  const sql = "SELECT * FROM users WHERE name = '" + value + "'";`,
        '  db.query(sql);',
        '}'
      ].join('\n');
      const parseResult = parseSource(code, { filePath: 'src/dynamicMysql.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/dynamicMysql.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.sink.line, 5);
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.api, 'db.query(sql)');
      assert.ok(result.findings[0].taintTrace.steps.some((step) => /mysql\.escape/.test(step.to)));
    });

    it('preserves taint through an aliased MySQL escape import', () => {
      const code = [
        "import { escape as escapeSql } from 'mysql';",
        'function handle(req) {',
        '  const value = escapeSql(req.query.name);',
        `  const sql = "SELECT * FROM users WHERE name = '" + value + "'";`,
        '  db.query(sql);',
        '}'
      ].join('\n');
      const parseResult = parseSource(code, { filePath: 'src/aliasedMysqlEscape.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/aliasedMysqlEscape.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.taintTrace.sink.line, 5);
      assert.equal(finding.taintTrace.sink.api, 'db.query(sql)');
      assert.equal(finding.taintTrace.source.expression, 'req.query.name');
      assert.match(finding.evidence, /req\.query\.name/);
    });

    it('does not use identifier escaping as SQL value escaping', () => {
      const code = [
        "import * as mysql from 'mysql';",
        'function handle(req) {',
        '  const value = mysql.escapeId(req.query.name);',
        `  const sql = "SELECT * FROM users WHERE name = '" + value + "'";`,
        '  db.query(sql);',
        '}'
      ].join('\n');
      const parseResult = parseSource(code, { filePath: 'src/mysqlEscapeId.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/mysqlEscapeId.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.sink.line, 5);
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.api, 'db.query(sql)');
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('does not trust an imported namespace shadowed by a local parameter', () => {
      const code = [
        "import * as mysql from 'mysql';",
        'function handle(req, mysql) {',
        '  const value = mysql.escape(req.query.name);',
        `  const sql = "SELECT * FROM users WHERE name = '" + value + "'";`,
        '  db.query(sql);',
        '}'
      ].join('\n');
      const parseResult = parseSource(code, { filePath: 'src/shadowedMysql.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/shadowedMysql.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.sink.line, 5);
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.api, 'db.query(sql)');
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('does not trust an unqualified escape call without a verified SQL sanitizer', () => {
      const code = `
        function handle(req) {
          const safeName = escape(req.query.name);
          db.query("SELECT * FROM users WHERE name = '" + safeName + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/unqualifiedEscape.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/unqualifiedEscape.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.line, 4);
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('preserves taint through a user-defined identity function named escape', () => {
      const code = `
        function escape(value) {
          return value;
        }
        function handle(req) {
          const userInput = req.query.name;
          const safeName = escape(userInput);
          db.query("SELECT * FROM users WHERE name = '" + safeName + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/identityEscape.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/identityEscape.js' });

      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.taintTrace.source.expression, 'req.query.name');
      assert.equal(finding.taintTrace.sink.line, 8);
      assert.match(finding.taintTrace.sink.api, /^db\.query/);
      assert.ok(finding.taintTrace.steps.some((step) => /escape/.test(step.to)));
      assert.match(finding.evidence, /req\.query\.name/);
      assert.match(finding.evidence, /db\.query/);
    });

    it('does not trust a locally defined method that resembles a database escape API', () => {
      const code = `
        const mysql = {
          escape(value) {
            return value;
          }
        };
        function handle(req) {
          const safeName = mysql.escape(req.query.name);
          db.query("SELECT * FROM users WHERE name = '" + safeName + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/localMysqlEscape.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/localMysqlEscape.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.line, 9);
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('preserves taint through an unrelated customEscape function', () => {
      const code = `
        function customEscape(value) {
          return value;
        }
        function handle(req) {
          const safeName = customEscape(req.query.name);
          db.query("SELECT * FROM users WHERE name = '" + safeName + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/customEscape.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/customEscape.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.line, 7);
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('preserves taint through URL encoding before a SQL sink', () => {
      const code = `
        function handle(req) {
          const encodedName = encodeURIComponent(req.query.name);
          db.query("SELECT * FROM users WHERE name = '" + encodedName + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/urlEncodedSql.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/urlEncodedSql.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.line, 4);
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('does NOT suppress finding when inappropriate HTML sanitizer is applied for SQL', () => {
      const code = `
        function handle(req) {
          // HTML sanitizer does NOT protect against SQL injection!
          const htmlClean = DOMPurify.sanitize(req.query.name);
          const sql = "SELECT * FROM users WHERE name = '" + htmlClean + "'";
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/htmlSanitize.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/htmlSanitize.js' });

      // HTML sanitizer must be rejected as an inappropriate sanitizer for SQL
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.query.name');
      assert.equal(result.findings[0].taintTrace.sink.line, 6);
      assert.match(result.findings[0].evidence, /req\.query\.name/);
    });

    it('correctly handles lexical variable shadowing inside nested blocks', () => {
      const code = `
        function handle(req) {
          const user = req.query.user;
          if (true) {
            const user = "safe_user"; // shadows outer tainted variable
            db.query("SELECT * FROM users WHERE name = '" + user + "'");
          }
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/shadow.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/shadow.js' });

      // Shadowed variable in inner block is clean
      assert.equal(result.findings.length, 0);
    });
  });

  describe('Edge Cases and Complex Data Flows', () => {
    it('tracks taint through conditional ternary expressions', () => {
      const code = `
        function handle(req) {
          const search = req.query.q ? req.query.q : 'default';
          const sql = "SELECT * FROM items WHERE q=" + search;
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/ternary.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/ternary.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].isTaintConfirmed, true);
    });

    it('tracks taint through logical OR fallback expressions', () => {
      const code = `
        function handle(req) {
          const queryTerm = req.query.search || 'all';
          const sql = "SELECT * FROM records WHERE name=" + queryTerm;
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/logical.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/logical.js' });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].isTaintConfirmed, true);
    });

    it('tracks multiple sources to multiple sinks independently', () => {
      const code = `
        function processRequest(req) {
          const sqlQuery = "SELECT * FROM users WHERE id = " + req.query.id;
          db.query(sqlQuery);

          const cmd = "cat " + req.body.filename;
          child_process.exec(cmd);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/multi.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/multi.js' });

      assert.equal(result.findings.length, 2);
      const ruleIds = result.findings.map((f) => f.ruleId).sort();
      assert.deepEqual(ruleIds, ['LUM-INJ-001', 'LUM-INJ-002']);
    });
  });

  describe('Full Coordinator Integration (analyzeAstSource)', () => {
    it('enriches AST recognizer findings with taintTrace and isTaintConfirmed', () => {
      const code = `
        app.get('/search', (req, res) => {
          const input = req.query.term;
          const sql = "SELECT * FROM catalog WHERE name = '" + input + "'";
          db.query(sql);
        });
      `;
      const result = analyzeAstSource(code, { filePath: 'src/app.js' });
      assert.equal(result.findings.length, 1);
      const finding = result.findings[0];
      assert.equal(finding.ruleId, 'LUM-INJ-001');
      assert.equal(finding.isTaintConfirmed, true);
      assert.equal(finding.confidence, 'medium');
      assert.ok(finding.taintTrace);
      assert.equal(finding.taintTrace.source.expression, 'req.query.term');
      assert.equal(result.metrics.taint.findingsCount, 1);
    });

    it('produces identical deterministic finding IDs across repeated runs', () => {
      const code = `
        function handle(req) {
          const userInput = req.query.name;
          const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
          db.query(query);
        }
      `;
      const run1 = analyzeAstSource(code, { filePath: 'src/test.js' });
      const run2 = analyzeAstSource(code, { filePath: 'src/test.js' });

      assert.equal(run1.findings.length, 1);
      assert.equal(run2.findings.length, 1);
      assert.equal(run1.findings[0].evidence, run2.findings[0].evidence);
      assert.equal(run1.findings[0].line, run2.findings[0].line);
    });
  });

  describe('Phase 5.2.1 Audit and Targeted Hardening', () => {
    it('retains taint when boolean validator (validator.isInt) is called but result is ignored', () => {
      const code = `
        function handle(req) {
          const id = req.query.id;
          validator.isInt(id); // boolean validation result ignored!
          const sql = "SELECT * FROM users WHERE id = " + id;
          db.query(sql);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/boolIgnored.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/boolIgnored.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('retains taint conservatively when boolean validator succeeds inside a conditional', () => {
      const code = `
        function handle(req) {
          const id = req.query.id;
          if (validator.isInt(id)) {
            const sql = "SELECT * FROM users WHERE id = " + id;
            db.query(sql);
          }
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/boolCond.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/boolCond.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('retains taint when validator.isUUID is called', () => {
      const code = `
        function handle(req) {
          const uuid = req.query.uuid;
          validator.isUUID(uuid);
          db.query("SELECT * FROM items WHERE id = '" + uuid + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/uuid.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/uuid.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('flags raw input when original unvalidated value is used even after numeric transformation', () => {
      const code = `
        function handle(req) {
          const rawId = req.query.id;
          const safeId = parseInt(rawId, 10);
          db.query("SELECT * FROM users WHERE id = " + rawId);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/rawUsed.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/rawUsed.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('retains taint when generic unknown sanitizer clean() is called', () => {
      const code = `
        function handle(req) {
          const cleaned = clean(req.query.input);
          db.query("SELECT * FROM users WHERE name = '" + cleaned + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/unknownSanitizer.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/unknownSanitizer.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('does NOT suppress command injection when HTML sanitizer is applied', () => {
      const code = `
        function handle(req) {
          const safeHtml = DOMPurify.sanitize(req.body.cmd);
          child_process.exec("cat " + safeHtml);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/htmlCmd.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/htmlCmd.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.body.cmd');
      assert.equal(result.findings[0].taintTrace.sink.argumentRole, 'shell_command');
      assert.match(result.findings[0].evidence, /req\.body\.cmd/);
    });

    it('detects tainted query object in SQL sink', () => {
      const code = `
        function handle(req) {
          const queryObj = { text: "SELECT * FROM users WHERE name = '" + req.query.name + "'" };
          db.query(queryObj);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/queryObj.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/queryObj.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('detects inline tainted query object in db.query', () => {
      const code = `
        function handle(req) {
          db.query({ text: "SELECT * FROM users WHERE id = " + req.query.id });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/inlineQueryObj.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/inlineQueryObj.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('flags dynamic SQL even when a parameter array is passed as second argument', () => {
      const code = `
        function handle(req) {
          const sql = "SELECT * FROM users WHERE name = '" + req.query.name + "' AND status = ?";
          db.query(sql, ['active']);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/fakeParam.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/fakeParam.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-001');
    });

    it('flags shell injection when spawn is invoked with shell: true and tainted arguments', () => {
      const code = `
        function run(req) {
          spawn('sh', ['-c', req.query.cmd], { shell: true });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/spawnShell.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/spawnShell.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.ok(result.findings[0].cwe.includes('CWE-78'));
    });

    it('flags tainted executable path in spawn without shell', () => {
      const code = `
        function run(req) {
          spawn(req.query.bin, ['--version']);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/taintedBin.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/taintedBin.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.match(result.findings[0].title, /executable path/i);
    });

    it('flags tainted argument in spawn without shell as argument injection risk', () => {
      const code = `
        function run(req) {
          spawn('git', [req.query.arg]);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/taintedArg.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/taintedArg.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.ok(result.findings[0].cwe.includes('CWE-88'));
      assert.match(result.findings[0].title, /argument/i);
    });

    it('clears taint when variable is reassigned to clean value', () => {
      const code = `
        function handle(req) {
          let x = req.query.name;
          x = 'clean_static_string';
          db.query("SELECT * FROM users WHERE name = '" + x + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/reassignedClean.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/reassignedClean.js' });
      assert.equal(result.findings.length, 0);
    });

    it('clears container property taint when container is reassigned to clean scalar', () => {
      const code = `
        function handle(req) {
          let data = { name: req.query.name };
          data = 'clean_constant';
          db.query("SELECT * FROM users WHERE name = '" + data + "'");
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/containerCleared.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/containerCleared.js' });
      assert.equal(result.findings.length, 0);
    });
  });

  describe('Phase 5.2.2 Command Injection Classification and Final Engine Audit', () => {
    it('classifies child_process.exec as shell injection (CWE-78)', () => {
      const code = `
        function handle(req) {
          child_process.exec("ping -c 1 " + req.query.host);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/execTest.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/execTest.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      assert.match(result.findings[0].title, /shell execution/i);
    });

    it('classifies child_process.execSync as shell injection (CWE-78)', () => {
      const code = `
        function handle(req) {
          child_process.execSync("echo " + req.query.msg);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/execSyncTest.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/execSyncTest.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('classifies child_process.spawn with shell: true as shell-enabled execution (CWE-78)', () => {
      const code = `
        function handle(req) {
          child_process.spawn('sh', ['-c', req.query.cmd], { shell: true });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/spawnShellTrue.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/spawnShellTrue.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      assert.match(result.findings[0].title, /shell-enabled/i);
    });

    it('classifies child_process.spawnSync with shell: false as argument injection (strictly CWE-88, not CWE-78)', () => {
      const code = `
        function handle(req) {
          child_process.spawnSync('git', [req.query.arg], { shell: false });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/spawnSyncArg.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/spawnSyncArg.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'), 'Non-shell argument injection must NOT include CWE-78');
      assert.match(result.findings[0].title, /argument injection/i);
    });

    it('classifies child_process.execFile with tainted executable as executable path control (CWE-114)', () => {
      const code = `
        function handle(req) {
          child_process.execFile(req.query.bin, ['--status']);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/execFileBin.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/execFileBin.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.deepEqual(result.findings[0].cwe, ['CWE-114']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'), 'Untrusted executable path must NOT be assigned CWE-78');
      assert.ok(!result.findings[0].cwe.includes('CWE-426'), 'Untrusted executable path must NOT be assigned CWE-426 without search path evidence');
      assert.match(result.findings[0].title, /executable path/i);
    });

    it('excludes child_process.execFileSync with safe static binary and static arguments', () => {
      const code = `
        function handle(req) {
          const user = req.query.user; // unused
          child_process.execFileSync('/usr/bin/id', ['-u']);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/execFileSyncSafe.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/execFileSyncSafe.js' });
      assert.equal(result.findings.length, 0);
    });

    it('recognizes aliased child_process requires (const { spawn: mySpawn } = require("child_process"))', () => {
      const code = `
        function handle(req) {
          const { spawn: mySpawn } = require('child_process');
          mySpawn('git', [req.query.target]);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/aliasedRequire.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/aliasedRequire.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
    });

    it('confirms SQL escaping is ineffective for command sinks and retains taint', () => {
      const code = `
        import * as mysql from 'mysql';
        function handle(req) {
          const escaped = mysql.escape(req.body.cmd);
          child_process.exec("cat " + escaped);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/sqlEscapeCmd.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/sqlEscapeCmd.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].ruleId, 'LUM-INJ-002');
      assert.equal(result.findings[0].taintTrace.source.expression, 'req.body.cmd');
      assert.equal(result.findings[0].taintTrace.sink.argumentRole, 'shell_command');
      assert.match(result.findings[0].evidence, /req\.body\.cmd/);
    });

    it('confirms numeric transformation affects only transformed copy while raw variable remains tainted', () => {
      const code = `
        function handle(req) {
          const rawInput = req.query.id;
          const numId = Number(rawInput);
          // safe query using numeric transformation
          db.query("SELECT * FROM users WHERE id = " + numId);
          // unsafe query using original raw variable
          db.query("SELECT * FROM orders WHERE id = " + rawInput);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/rawStillTainted.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/rawStillTainted.js' });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].line, 8);
    });
  });

  describe('Phase 5.2.3 Command Sink Semantics and Sanitizer Precision Audit', () => {
    it('classifies tainted executable in spawn without shell as CWE-114 (not CWE-78, not CWE-88, not CWE-426)', () => {
      const code = `
        function run(req) {
          spawn(req.query.bin, ['--status'], { shell: false });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/spawnTaintedBin.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/spawnTaintedBin.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-114']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
      assert.ok(!result.findings[0].cwe.includes('CWE-88'));
      assert.ok(!result.findings[0].cwe.includes('CWE-426'));
      assert.match(result.findings[0].title, /executable path/i);
    });

    it('classifies fixed executable with tainted arguments in spawn without shell as CWE-88 (strictly not CWE-78)', () => {
      const code = `
        function run(req) {
          spawn('/bin/ls', [req.query.dir], { shell: false });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/spawnTaintedArg.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/spawnTaintedArg.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
    });

    it('excludes fixed executable with static arguments across spawn and execFile', () => {
      const code = `
        function run(req) {
          const user = req.query.user;
          spawn('git', ['log', '-n', '5'], { shell: false });
          execFile('/usr/bin/env', ['node', '-v']);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/fixedStatic.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/fixedStatic.js' });
      assert.equal(result.findings.length, 0);
    });

    it('verifies shell option handling across all supported child_process APIs', () => {
      // Test spawnSync with shell: true -> CWE-78
      const code1 = `
        function run1(req) {
          spawnSync('tool', [req.query.cmd], { shell: true });
        }
      `;
      const res1 = analyzeAstTaint(parseSource(code1).ast, { code: code1 });
      assert.equal(res1.findings.length, 1);
      assert.deepEqual(res1.findings[0].cwe, ['CWE-78']);

      // Test spawnSync with shell: false -> CWE-88
      const code2 = `
        function run2(req) {
          spawnSync('tool', [req.query.cmd], { shell: false });
        }
      `;
      const res2 = analyzeAstTaint(parseSource(code2).ast, { code: code2 });
      assert.equal(res2.findings.length, 1);
      assert.deepEqual(res2.findings[0].cwe, ['CWE-88']);

      // Test execFile with shell: true -> CWE-78
      const code3 = `
        function run3(req) {
          execFile('tool', [req.query.cmd], { shell: true });
        }
      `;
      const res3 = analyzeAstTaint(parseSource(code3).ast, { code: code3 });
      assert.equal(res3.findings.length, 1);
      assert.deepEqual(res3.findings[0].cwe, ['CWE-78']);

      // Test execFile with shell: false -> CWE-88
      const code4 = `
        function run4(req) {
          execFile('tool', [req.query.cmd], { shell: false });
        }
      `;
      const res4 = analyzeAstTaint(parseSource(code4).ast, { code: code4 });
      assert.equal(res4.findings.length, 1);
      assert.deepEqual(res4.findings[0].cwe, ['CWE-88']);

      // Test execFileSync with shell: true -> CWE-78
      const code5 = `
        function run5(req) {
          execFileSync('tool', [req.query.cmd], { shell: true });
        }
      `;
      const res5 = analyzeAstTaint(parseSource(code5).ast, { code: code5 });
      assert.equal(res5.findings.length, 1);
      assert.deepEqual(res5.findings[0].cwe, ['CWE-78']);

      // Test execFileSync with shell: false -> CWE-88
      const code6 = `
        function run6(req) {
          execFileSync('tool', [req.query.cmd], { shell: false });
        }
      `;
      const res6 = analyzeAstTaint(parseSource(code6).ast, { code: code6 });
      assert.equal(res6.findings.length, 1);
      assert.deepEqual(res6.findings[0].cwe, ['CWE-88']);
    });

    it('tracks options object stored in a variable with shell: true (CWE-78)', () => {
      const code = `
        function run(req) {
          const options = { shell: true };
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/optionsVarTrue.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/optionsVarTrue.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      assert.match(result.findings[0].title, /shell-enabled/i);
    });

    it('tracks options object stored in a variable with shell: false (CWE-88)', () => {
      const code = `
        function run(req) {
          const options = { shell: false };
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/optionsVarFalse.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/optionsVarFalse.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
    });

    it('tracks options variable reassigned from shell: false to shell: true (CWE-78)', () => {
      const code = `
        function run(req) {
          let options = { shell: false };
          options = { shell: true };
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/optionsReassignedTrue.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/optionsReassignedTrue.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('tracks options variable reassigned from shell: true to shell: false (CWE-88)', () => {
      const code = `
        function run(req) {
          let options = { shell: true };
          options = { shell: false };
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/optionsReassignedFalse.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/optionsReassignedFalse.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
    });

    it('does not infer shell mode when options object has unrelated properties', () => {
      const code = `
        function run(req) {
          const options = { cwd: '/var/log', timeout: 5000, env: process.env };
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/optionsUnrelated.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/optionsUnrelated.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'), 'Unrelated options must not default to shell: true in spawn');
    });

    it('suppresses shell injection finding when numeric transformation is used in shell command', () => {
      const code = `
        function run(req) {
          const safePort = parseInt(req.query.port, 10);
          child_process.exec("nc -l -p " + safePort);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/shellNumericSafe.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/shellNumericSafe.js' });
      assert.equal(result.findings.length, 0, 'Numeric scalar cannot inject shell metacharacters into shell command string');
    });

    it('retains argument injection finding (CWE-88) even after numeric transformation in non-shell execution', () => {
      const code = `
        function run(req) {
          const numFlag = parseInt(req.query.val, 10);
          child_process.spawn("tool", [numFlag], { shell: false });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/nonShellNumericArg.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/nonShellNumericArg.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88'], 'Numeric transformation does not neutralize CLI flag injection or target executable argument manipulation');
    });

    it('suppresses shell injection finding when Math transformations produce numeric scalar', () => {
      const code = `
        function run(req) {
          const rounded = Math.round(Number(req.query.val));
          child_process.exec("cat file_" + rounded);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/mathShellSafe.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/mathShellSafe.js' });
      assert.equal(result.findings.length, 0);
    });

    it('recognizes aliased ES module imports for child_process', () => {
      const code = `
        import { spawn as mySpawn } from 'node:child_process';
        function run(req) {
          mySpawn('git', [req.query.branch], { shell: false });
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/esmImportAliased.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/esmImportAliased.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
    });
  });

  describe('Phase 5.2.4 Final CWE Classification and Options Mutation Audit', () => {
    it('tracks options.shell mutation from false to true -> CWE-78', () => {
      const code = `
        function run(req) {
          const options = { shell: false };
          options.shell = true;
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/mutatedShellTrue.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/mutatedShellTrue.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      assert.match(result.findings[0].title, /shell-enabled/i);
    });

    it('tracks options.shell mutation from true to false -> CWE-88', () => {
      const code = `
        function run(req) {
          const options = { shell: true };
          options.shell = false;
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/mutatedShellFalse.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/mutatedShellFalse.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
    });

    it('tracks options mutation inside nested block scope', () => {
      const code = `
        function run(req) {
          const options = { shell: false };
          if (req.query.enableShell) {
            options.shell = true;
            spawn("tool", [req.query.input], options);
          }
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/nestedBlockMutation.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/nestedBlockMutation.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('handles variable shadowing of options in nested block scope without leaking', () => {
      const code = `
        function run(req) {
          const options = { shell: false };
          if (true) {
            const options = { shell: true };
            spawn("tool1", [req.query.input1], options);
          }
          spawn("tool2", [req.query.input2], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/shadowedOptions.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/shadowedOptions.js' });
      assert.equal(result.findings.length, 2);
      // First finding inside the block uses shadowed options -> shell: true (CWE-78)
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      // Second finding outside uses outer options -> shell: false (CWE-88)
      assert.deepEqual(result.findings[1].cwe, ['CWE-88']);
    });

    it('handles reassignment after property mutation', () => {
      const code = `
        function run(req) {
          let options = { shell: false };
          options.shell = true;
          options = { shell: false };
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/reassignAfterMutation.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/reassignAfterMutation.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
    });

    it('tracks options copied into another variable when original is mutated', () => {
      const code = `
        function run(req) {
          const options = { shell: false };
          const optsCopy = options;
          options.shell = true;
          spawn("tool", [req.query.input], optsCopy);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/optionsCopiedMutation.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/optionsCopiedMutation.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('handles unknown dynamic mutation falling back to API default (spawn defaults to false -> CWE-88)', () => {
      const code = `
        function run(req) {
          const options = { shell: false };
          options.shell = getDynamicShell();
          spawn("tool", [req.query.input], options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/dynamicMutationSpawn.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/dynamicMutationSpawn.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
      assert.ok(!result.findings[0].cwe.includes('CWE-78'));
    });

    it('handles unknown dynamic mutation falling back to API default (exec defaults to true -> CWE-78)', () => {
      const code = `
        function run(req) {
          const options = { shell: true };
          options.shell = getDynamicShell();
          exec(req.query.cmd, options);
        }
      `;
      const parseResult = parseSource(code, { filePath: 'src/dynamicMutationExec.js' });
      const result = analyzeAstTaint(parseResult.ast, { code, filePath: 'src/dynamicMutationExec.js' });
      assert.equal(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('verifies API-specific defaults for omitted options and unresolved options expressions', () => {
      // exec with omitted options -> CWE-78
      const codeExecOmitted = `function f(req) { exec(req.query.cmd); }`;
      const res1 = analyzeAstTaint(parseSource(codeExecOmitted).ast, { code: codeExecOmitted });
      assert.deepEqual(res1.findings[0].cwe, ['CWE-78']);

      // execSync with unresolved options -> CWE-78
      const codeExecSyncUnresolved = `function f(req) { execSync(req.query.cmd, getDynamicOpts()); }`;
      const res2 = analyzeAstTaint(parseSource(codeExecSyncUnresolved).ast, { code: codeExecSyncUnresolved });
      assert.deepEqual(res2.findings[0].cwe, ['CWE-78']);

      // spawn with omitted options -> CWE-88
      const codeSpawnOmitted = `function f(req) { spawn('tool', [req.query.arg]); }`;
      const res3 = analyzeAstTaint(parseSource(codeSpawnOmitted).ast, { code: codeSpawnOmitted });
      assert.deepEqual(res3.findings[0].cwe, ['CWE-88']);

      // spawnSync with unresolved options -> CWE-88
      const codeSpawnSyncUnresolved = `function f(req) { spawnSync('tool', [req.query.arg], getDynamicOpts()); }`;
      const res4 = analyzeAstTaint(parseSource(codeSpawnSyncUnresolved).ast, { code: codeSpawnSyncUnresolved });
      assert.deepEqual(res4.findings[0].cwe, ['CWE-88']);

      // execFile with omitted options -> CWE-88
      const codeExecFileOmitted = `function f(req) { execFile('tool', [req.query.arg]); }`;
      const res5 = analyzeAstTaint(parseSource(codeExecFileOmitted).ast, { code: codeExecFileOmitted });
      assert.deepEqual(res5.findings[0].cwe, ['CWE-88']);

      // execFileSync with unresolved options -> CWE-88
      const codeExecFileSyncUnresolved = `function f(req) { execFileSync('tool', [req.query.arg], getDynamicOpts()); }`;
      const res6 = analyzeAstTaint(parseSource(codeExecFileSyncUnresolved).ast, { code: codeExecFileSyncUnresolved });
      assert.deepEqual(res6.findings[0].cwe, ['CWE-88']);
    });

    it('distinguishes argument semantics in CWE-88 descriptions (option-like vs subcommand vs operand vs unknown)', () => {
      // 1. Option-like argument
      const codeOption = `
        function f1(req) {
          const cliOption = "--user=" + req.query.val;
          spawn('tool', [cliOption], { shell: false });
        }
      `;
      const res1 = analyzeAstTaint(parseSource(codeOption).ast, { code: codeOption });
      assert.deepEqual(res1.findings[0].cwe, ['CWE-88']);
      assert.match(res1.findings[0].description, /option-like argument/i);

      // 2. Subcommand selection
      const codeSubcmd = `
        function f2(req) {
          const subcommand = req.query.cmd;
          spawn('git', [subcommand], { shell: false });
        }
      `;
      const res2 = analyzeAstTaint(parseSource(codeSubcmd).ast, { code: codeSubcmd });
      assert.deepEqual(res2.findings[0].cwe, ['CWE-88']);
      assert.match(res2.findings[0].description, /subcommand selection/i);

      // 3. Ordinary operand
      const codeOperand = `
        function f3(req) {
          const filePath = req.query.file;
          spawn('tool', [filePath], { shell: false });
        }
      `;
      const res3 = analyzeAstTaint(parseSource(codeOperand).ast, { code: codeOperand });
      assert.deepEqual(res3.findings[0].cwe, ['CWE-88']);
      assert.match(res3.findings[0].description, /ordinary operand/i);

      // 4. Unknown argument semantics
      const codeUnknown = `
        function f4(req) {
          const x = req.query.raw;
          spawn('tool', [x], { shell: false });
        }
      `;
      const res4 = analyzeAstTaint(parseSource(codeUnknown).ast, { code: codeUnknown });
      assert.deepEqual(res4.findings[0].cwe, ['CWE-88']);
      assert.match(res4.findings[0].description, /unknown argument semantics/i);
    });
  });

  describe('AST Inter-Procedural Taint Analysis (Phase 5.3)', () => {
    it('detects direct source-to-sink flow through a single helper function', () => {
      const code = `
        function handler(req) {
          runTask(req.query.cmd);
        }
        function runTask(command) {
          exec(command);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      const finding = result.findings[0];
      assert.deepEqual(finding.cwe, ['CWE-78']);
      assert.strictEqual(finding.isTaintConfirmed, true);
      assert.strictEqual(finding.taintTrace.source.expression, 'req.query.cmd');
      assert.strictEqual(finding.taintTrace.sink.expression, 'exec(command)');
      assert.ok(finding.taintTrace.steps.some((s) => s.to.includes('runTask')));
    });

    it('detects multiple helper-function chains (motivating 3-function chain)', () => {
      const code = `
        app.get("/run", (req, res) => {
          executeTask(req.query.command);
        });

        function executeTask(command) {
          runCommand(command);
        }

        function runCommand(input) {
          exec(input);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      const finding = result.findings[0];
      assert.deepEqual(finding.cwe, ['CWE-78']);
      assert.strictEqual(finding.isTaintConfirmed, true);
      assert.strictEqual(finding.taintTrace.source.expression, 'req.query.command');
      assert.strictEqual(finding.taintTrace.sink.expression, 'exec(input)');
      assert.ok(finding.taintTrace.steps.some((s) => s.to.includes('executeTask')));
      assert.ok(finding.taintTrace.steps.some((s) => s.to.includes('runCommand')));
    });

    it('detects tainted return values from helper functions', () => {
      const code = `
        function prepareCommand(input) {
          return "tool --param=" + input;
        }
        function handler(req) {
          const cmd = prepareCommand(req.query.val);
          exec(cmd);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      const finding = result.findings[0];
      assert.deepEqual(finding.cwe, ['CWE-78']);
      assert.strictEqual(finding.taintTrace.source.expression, 'req.query.val');
    });

    it('does NOT flag clean return values from helper functions', () => {
      const code = `
        function getSafeCommand(unusedParam) {
          return "echo safe_constant";
        }
        function handler(req) {
          const cmd = getSafeCommand(req.query.val);
          exec(cmd);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 0);
    });

    it('distinguishes multiple independent call sites (context sensitivity)', () => {
      const code = `
        function executeWorker(command) {
          exec(command);
        }
        function safeService() {
          executeWorker("echo safe");
        }
        function vulnerableService(req) {
          executeWorker(req.query.cmd);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      assert.strictEqual(result.findings[0].taintTrace.source.expression, 'req.query.cmd');
    });

    it('handles recursive calls safely with cycle detection without infinite loop', () => {
      const code = `
        function recursiveRun(n, command) {
          if (n <= 0) {
            exec(command);
            return;
          }
          recursiveRun(n - 1, command);
        }
        function test(req) {
          recursiveRun(3, req.query.cmd);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      assert.ok(result.limitations.includes('recursive_call_cycle_detected'));
    });

    it('tracks taint through function expressions and arrow functions', () => {
      const code = `
        const format = (cmd) => "prefix " + cmd;
        const runner = function(c) {
          exec(c);
        };
        function test(req) {
          const formatted = format(req.query.input);
          runner(formatted);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('tracks taint into concise arrow function sinks', () => {
      const code = `
        const run = (c) => exec(c);
        function test(req) {
          run(req.query.cmd);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('tracks taint across statically resolvable CommonJS module exports and imports', () => {
      const modules = {
        './taskRunner': `
          function executeTask(cmd) {
            exec(cmd);
          }
          module.exports = { executeTask };
        `
      };
      const code = `
        const { executeTask } = require('./taskRunner');
        function handleRequest(req) {
          executeTask(req.query.command);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code, modules });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
    });

    it('tracks taint across statically resolvable ES module exports and imports', () => {
      const modules = {
        './dbHelper.js': `
          export function runQuery(sql) {
            db.query(sql);
          }
        `
      };
      const code = `
        import { runQuery } from './dbHelper.js';
        function handleRequest(req) {
          runQuery("SELECT * FROM users WHERE name = " + req.query.name);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code, modules });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-89']);
    });

    it('suppresses finding when sanitizer is applied inside helper function', () => {
      const code = `
        function sanitizeId(raw) {
          return parseInt(raw, 10);
        }
        function handler(req) {
          const id = sanitizeId(req.query.id);
          db.query("SELECT * FROM items WHERE id = " + id);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 0);
    });

    it('ensures sanitization in helper does not propagate to unrelated variables or calls', () => {
      const code = `
        function sanitizeId(raw) {
          return parseInt(raw, 10);
        }
        function handler(req) {
          const safeId = sanitizeId(req.query.id);
          const rawCommand = req.query.cmd;
          db.query("SELECT * FROM items WHERE id = " + safeId);
          exec(rawCommand);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      assert.strictEqual(result.findings[0].taintTrace.source.expression, 'req.query.cmd');
    });

    it('correctly classifies cross-function non-shell argument injection (CWE-88)', () => {
      const code = `
        function invokeTool(arg) {
          spawn("tool", [arg], { shell: false });
        }
        function handler(req) {
          invokeTool(req.query.flag);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.findings.length, 1);
      assert.deepEqual(result.findings[0].cwe, ['CWE-88']);
    });

    it('enforces maximum call-graph depth limit safely and reflects partial coverage', () => {
      const code = `
        function f1(x) { f2(x); }
        function f2(x) { f3(x); }
        function f3(x) { f4(x); }
        function f4(x) { f5(x); }
        function f5(x) { f6(x); }
        function f6(x) { exec(x); }
        function test(req) {
          f1(req.query.cmd);
        }
      `;
      const ast = parseSource(code).ast;
      const result = analyzeAstTaint(ast, { code });
      assert.strictEqual(result.coverageStatus, 'partial');
      assert.ok(result.limitations.includes('call_graph_depth_limit_exceeded'));
    });
  });

  describe('Phase 5.3.1 Inter-Procedural Taint Correctness Audit', () => {
    describe('1. Return-Path Correctness', () => {
      it('does NOT conclude function is clean when one return path is clean and another is tainted', () => {
        const code = `
          function prepare(input, condition) {
            if (condition) return "safe";
            return input;
          }
          function handler(req) {
            const cmd = prepare(req.query.cmd, req.query.isSafe);
            exec(cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      });

      it('prunes statically unreachable returns after an unconditional return in the same block', () => {
        const code = `
          function prepare(input) {
            return "safe";
            return input; // Statically unreachable
          }
          function handler(req) {
            const cmd = prepare(req.query.cmd);
            exec(cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 0);
      });

      it('prunes statically dead branches (if false)', () => {
        const code = `
          function prepare(input) {
            if (false) {
              return input; // Statically unreachable
            }
            return "safe";
          }
          function handler(req) {
            const cmd = prepare(req.query.cmd);
            exec(cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 0);
      });

      it('tracks return value across nested conditionals with local assignment', () => {
        const code = `
          function format(input, mode) {
            let res = "default";
            if (mode) {
              if (mode === 1) {
                res = input;
              }
            }
            return res;
          }
          function handler(req) {
            const val = format(req.query.c, req.query.m);
            exec(val);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('handles early return with clean expression and downstream tainted return', () => {
        const code = `
          function parse(input, flag) {
            if (!flag) return "clean";
            const processed = input;
            return processed;
          }
          function handler(req) {
            exec(parse(req.query.input, true));
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });
    });

    describe('2. Parameter and Object Aliasing', () => {
      it('tracks object aliasing: const copy = data', () => {
        const code = `
          function handler(req) {
            const data = { cmd: req.query.c };
            const copy = data;
            exec(copy.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      });

      it('tracks multiple aliases pointing to the same object', () => {
        const code = `
          function handler(req) {
            const data = { cmd: req.query.c };
            const copy1 = data;
            const copy2 = copy1;
            exec(copy2.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('clears taint when property is reassigned to clean value on object or alias', () => {
        const code = `
          function handler(req) {
            const data = { cmd: req.query.c };
            const copy = data;
            data.cmd = "safe_fixed_command";
            exec(copy.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 0);
      });

      it('tracks array element indexing and element reassignment to clean', () => {
        const codeTainted = `
          function handler(req) {
            const arr = [req.query.c];
            exec(arr[0]);
          }
        `;
        const astTainted = parseSource(codeTainted).ast;
        assert.strictEqual(analyzeAstTaint(astTainted, { code: codeTainted }).findings.length, 1);

        const codeClean = `
          function handler(req) {
            const arr = [req.query.c];
            arr[0] = "safe_echo";
            exec(arr[0]);
          }
        `;
        const astClean = parseSource(codeClean).ast;
        assert.strictEqual(analyzeAstTaint(astClean, { code: codeClean }).findings.length, 0);
      });

      it('isolates destructured parameters so clean properties do not inherit taint', () => {
        const code = `
          function executeTask({ command, timeout }) {
            exec(timeout);
          }
          function handler(req) {
            executeTask({ command: req.query.c, timeout: 5000 });
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 0);
      });

      it('propagates destructured tainted property into helper function', () => {
        const code = `
          function executeTask({ command, timeout }) {
            exec(command);
          }
          function handler(req) {
            executeTask({ command: req.query.c, timeout: 5000 });
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('tracks object mutation inside helper functions reflecting back to caller', () => {
        const code = `
          function mutate(obj, val) {
            obj.cmd = val;
          }
          function handler(req) {
            const data = {};
            mutate(data, req.query.c);
            exec(data.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('tracks nested properties: data.user.cmd', () => {
        const code = `
          function handler(req) {
            const data = { user: {} };
            data.user.cmd = req.query.c;
            exec(data.user.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('ensures clean reassignment after tainted assignment clears taint', () => {
        const code = `
          function handler(req) {
            let x = req.query.cmd;
            x = "safe_echo";
            exec(x);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 0);
      });
    });

    describe('3. Promise and Async/Await Propagation', () => {
      it('tracks await helper(input) return value into command sink', () => {
        const code = `
          async function fetchCommand(cmd) {
            return cmd;
          }
          async function handler(req) {
            const cmd = await fetchCommand(req.query.cmd);
            exec(cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      });

      it('tracks return await helper(input) through helper chains', () => {
        const code = `
          function step1(c) { return c; }
          async function step2(c) { return await step1(c); }
          async function handler(req) {
            exec(await step2(req.query.cmd));
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('tracks Promise .then() callback parameter propagation', () => {
        const code = `
          function getCmd(c) { return c; }
          function handler(req) {
            const p = getCmd(req.query.cmd);
            p.then((resolvedCmd) => {
              exec(resolvedCmd);
            });
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('tracks tainted values through chained Promise .then() calls', () => {
        const code = `
          function getCmd(c) { return c; }
          function handler(req) {
            getCmd(req.query.cmd)
              .then((x) => x)
              .then((y) => {
                exec(y);
              });
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });
    });

    describe('4. Cross-Module Resolution', () => {
      it('resolves relative imports without explicit extension', () => {
        const modules = {
          './helper.js': `
            export function run(cmd) { exec(cmd); }
          `
        };
        const code = `
          import { run } from './helper';
          function handler(req) {
            run(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code, modules });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      });

      it('resolves CommonJS named function export assignment: exports.run = function(cmd) { ... }', () => {
        const modules = {
          './runner.js': `
            exports.run = function(c) { exec(c); };
          `
        };
        const code = `
          const { run } = require('./runner');
          function handler(req) {
            run(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code, modules });
        assert.strictEqual(result.findings.length, 1);
      });

      it('resolves ES module export { run } specifier lists', () => {
        const modules = {
          './utils.js': `
            function execute(c) { exec(c); }
            export { execute as run };
          `
        };
        const code = `
          import { run } from './utils.js';
          function handler(req) {
            run(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code, modules });
        assert.strictEqual(result.findings.length, 1);
      });

      it('resolves namespace imports: import * as helpers from "./helpers"', () => {
        const modules = {
          './helpers.js': `
            export function run(c) { exec(c); }
          `
        };
        const code = `
          import * as helpers from './helpers.js';
          function handler(req) {
            helpers.run(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code, modules });
        assert.strictEqual(result.findings.length, 1);
      });

      it('detects missing imported module, adds limitation and marks partial coverage', () => {
        const code = `
          import { unknownHelper } from './missingModule.js';
          function handler(req) {
            unknownHelper(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.coverageStatus, 'partial');
        assert.ok(result.limitations.includes('unresolved_imported_module'));
      });

      it('detects circular module imports safely without infinite loop and reports partial coverage', () => {
        const modules = {
          './modA.js': `
            import { funcB } from './modB.js';
            export function funcA(x) { return funcB(x); }
          `,
          './modB.js': `
            import { funcA } from './modA.js';
            export function funcB(x) { return funcA(x); }
          `
        };
        const code = `
          import { funcA } from './modA.js';
          function handler(req) {
            funcA(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code, modules });
        assert.strictEqual(result.coverageStatus, 'partial');
        assert.ok(result.limitations.includes('circular_module_import_detected'));
      });

      it('guards against module paths outside scan root and flags limitation', () => {
        const code = `
          import { run } from '../../outside/secret.js';
          function handler(req) {
            run(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code, scanRoot: 'c:/project/src', filePath: 'c:/project/src/index.js' });
        assert.strictEqual(result.coverageStatus, 'partial');
        assert.ok(result.limitations.includes('module_path_outside_scan_root'));
      });
    });

    describe('5. Context Sensitivity and Sanitizers', () => {
      it('differentiates clean call site from tainted call site for the same helper function', () => {
        const code = `
          function runner(c) {
            exec(c);
          }
          function handler(req) {
            runner("echo safe");
            runner(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.strictEqual(result.findings[0].taintTrace.source.expression, 'req.query.cmd');
      });

      it('flags finding when sanitization is applied in only one branch of a helper', () => {
        const code = `
          function parse(input, flag) {
            if (flag) {
              return parseInt(input, 10);
            }
            return input;
          }
          function handler(req) {
            db.query("SELECT * FROM items WHERE id = " + parse(req.query.id, false));
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-89']);
      });

      it('confirms HTML sanitizer is ineffective at SQL sinks across helper calls', () => {
        const code = `
          function escapeHtml(str) {
            return str.replace(/</g, "&lt;");
          }
          function handler(req) {
            const val = escapeHtml(req.query.name);
            db.query("SELECT * FROM users WHERE name = " + val);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-89']);
      });

      it('confirms SQL sanitizer is ineffective at command sinks across helper calls', () => {
        const code = `
          import * as mysql from 'mysql';
          function sanitizeForSql(str) {
            return mysql.escape(str);
          }
          function handler(req) {
            const val = sanitizeForSql(req.query.cmd);
            exec(val);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
        assert.deepEqual(result.findings[0].cwe, ['CWE-78']);
      });

      it('retains taint when boolean validator (validator.isInt) is called inside helper without control flow', () => {
        const code = `
          function check(val) {
            validator.isInt(val);
            return val;
          }
          function handler(req) {
            db.query("SELECT * FROM items WHERE id = " + check(req.query.id));
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 1);
      });

      it('suppresses finding when numeric transformation is returned from helper', () => {
        const code = `
          function toNum(val) {
            return parseInt(val, 10);
          }
          function handler(req) {
            db.query("SELECT * FROM items WHERE id = " + toNum(req.query.id));
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 0);
      });
    });

    describe('6. Call-Graph Limits and Cycle Detection', () => {
      it('detects mutual recursion between two functions safely without infinite loop', () => {
        const code = `
          function ping(x) { pong(x); }
          function pong(x) { ping(x); }
          function handler(req) {
            ping(req.query.cmd);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.coverageStatus, 'partial');
        assert.ok(result.limitations.includes('recursive_call_cycle_detected'));
      });

      it('does NOT count the same call site repeatedly to prematurely exhaust invocation budget', () => {
        const code = `
          function helper(x) { return x; }
          function handler(req) {
            const a = helper(req.query.c1);
            const b = helper(req.query.c2);
            exec(a);
            exec(b);
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.findings.length, 2);
        assert.strictEqual(result.coverageStatus, 'completed');
      });

      it('enforces maxCallSitesPerFunction limit and records limitation', () => {
        let calls = '';
        for (let i = 0; i < 55; i++) {
          calls += `dummyCall(${i});\n`;
        }
        const code = `
          function dummyCall(x) { return x; }
          function heavyCaller() {
            ${calls}
          }
        `;
        const ast = parseSource(code).ast;
        const result = analyzeAstTaint(ast, { code });
        assert.strictEqual(result.coverageStatus, 'partial');
        assert.ok(result.limitations.includes('max_call_sites_per_function_exceeded'));
      });
    });
  });
});
