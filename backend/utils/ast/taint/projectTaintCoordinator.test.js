import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ProjectBudgetManager } from './projectBudgetManager.js';
import { ProjectTaintCoordinator } from './projectTaintCoordinator.js';
import { locationKey } from './projectTaintCoordinator.js';
import { ProjectModuleRegistry } from './projectRegistry.js';
import { ProjectSymbolRegistry } from './projectSymbolRegistry.js';

const querySink = `
  export function run(value) {
    const sql = 'SELECT * FROM records WHERE id=' + value;
    db.query(sql);
  }
`;

function analyze(modules, options = {}) {
  const coordinator = new ProjectTaintCoordinator('/project', { modules, ...options });
  return { coordinator, result: coordinator.analyze() };
}

function sourceRoute(importCode, callCode = 'helper(req.query.id);') {
  return `import express from 'express';
    ${importCode}
    export function handle(req) {
      ${callCode}
    }
    const app = express();
    app.get('/source', handle);
  `;
}

describe('ProjectTaintCoordinator (Phase 5.4.3)', () => {
  it('does not derive a merge key from fallback coordinates without a sink span', () => {
    const first = {
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'route.js',
      line: 4,
      column: 8
    };
    const second = { ...first, evidence: 'different sink' };

    assert.equal(locationKey(first), null);
    assert.equal(locationKey(second), null);
  });

  it('propagates a request source through a helper and sink across three files', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { helper } from './b.js';"),
      'b.js': "import { run } from './c.js'; export function helper(value) { run(value); }",
      'c.js': querySink
    });

    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'c.js');
    assert.equal(result.findings[0].taintTrace.source.file, 'a.js');
    assert.ok(result.findings[0].taintTrace.steps.some((step) => step.fromModule === 'a.js' && step.toModule === 'b.js'));
    assert.ok(result.findings[0].taintTrace.steps.some((step) => step.fromModule === 'b.js' && step.toModule === 'c.js'));
  });

  it('keeps distinct same-line sink spans and traces separate', () => {
    const { result } = analyze({
      'route.js': sourceRoute('', [
        "db.query('SELECT ' + req.query.first);",
        "db.query('SELECT ' + req.query.second);"
      ].join(' '))
    });
    const findings = result.findings.filter((finding) => finding.ruleId === 'LUM-INJ-001');

    assert.equal(findings.length, 2);
    assert.equal(new Set(findings.map((finding) =>
      `${finding.sourceSpan.start}:${finding.sourceSpan.end}`
    )).size, 2);
    assert.ok(findings.some((finding) =>
      finding.taintTrace.sink.expression.includes('first')
    ));
    assert.ok(findings.some((finding) =>
      finding.taintTrace.sink.expression.includes('second')
    ));
  });

  it('resolves named imports and exports to the original function symbol', () => {
    const { coordinator, result } = analyze({
      'a.js': sourceRoute("import { run } from './b.js';", 'run(req.query.id);'),
      'b.js': querySink
    });
    const imported = coordinator.symbolRegistry.getImport('a.js', 'run');
    assert.equal(imported.resolutionStatus, 'resolved');
    assert.equal(imported.symbolId, coordinator.symbolRegistry.resolveExport('b.js', 'run').symbol.id);
    assert.equal(result.findings.length, 1);
  });

  it('resolves default imports and exports', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import run from './b.js';", 'run(req.query.id);'),
      'b.js': querySink.replace('export function run(value)', 'export default function run(value)')
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'b.js');
  });

  it('preserves local import aliases while resolving the target symbol', () => {
    const { coordinator, result } = analyze({
      'a.js': sourceRoute("import { run as execute } from './b.js';", 'execute(req.query.id);'),
      'b.js': querySink
    });
    assert.equal(coordinator.symbolRegistry.getImport('a.js', 'execute').resolutionStatus, 'resolved');
    assert.equal(result.findings.length, 1);
  });

  it('resolves statically identifiable namespace members', () => {
    const { coordinator, result } = analyze({
      'a.js': sourceRoute("import * as sink from './b.js';", 'sink.run(req.query.id);'),
      'b.js': querySink
    });
    assert.equal(coordinator.symbolRegistry.getImport('a.js', 'sink').isNamespace, true);
    assert.equal(result.findings.length, 1);
  });

  it('resolves CommonJS namespace and destructured imports', () => {
    const { result } = analyze({
      'a.js': `
        const { run: execute } = require('./b.js');
        function handle(req) { execute(req.query.id); }
        const express = require('express');
        const app = express();
        app.get('/source', handle);
      `,
      'b.js': `
        function run(value) {
          const sql = 'SELECT * FROM records WHERE id=' + value;
          db.query(sql);
        }
        module.exports = { run };
      `
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'b.js');
  });

  it('follows renamed re-exports and retains their relationship trace', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { execute } from './barrel.js';", 'execute(req.query.id);'),
      'barrel.js': "export { run as execute } from './middle.js';",
      'middle.js': "export { run } from './sink.js';",
      'sink.js': querySink
    });
    const finding = result.findings[0];
    assert.ok(finding);
    assert.deepEqual(
      finding.taintTrace.steps.flatMap((step) => step.importExport?.reExportChain || [])
        .map((item) => item.fromModule),
      ['barrel.js', 'middle.js']
    );
  });

  it('follows barrel-file chains', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { run } from './barrel/index.js';", 'run(req.query.id);'),
      'barrel/index.js': "export * from '../services/sink.js';",
      'services/sink.js': querySink
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'services/sink.js');
  });

  it('reports circular import coverage without looping', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { b } from './b.js';", 'b(req.query.id);'),
      'b.js': "import { handle } from './a.js'; export function b(value) { return value; }"
    });
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('circular_module_import_detected') ||
      result.limitations.includes('circular_reexport_detected') ||
      result.limitations.includes('recursive_call_cycle_detected') ||
      result.limitations.includes('unresolved_imported_export'));
  });

  it('stops recursive function cycles with an explicit limitation', () => {
    const { result } = analyze({
      'a.js': `
        export function first(req, depth) {
          if (depth) return second(req, depth - 1);
          db.query('SELECT ' + req.query.id);
        }
        function second(req, depth) { return first(req, depth); }
      `
    });
    assert.ok(result.limitations.includes('recursive_call_cycle_detected') ||
      result.coverageStatus === 'completed');
  });

  it('preserves context-specific sanitizer behavior across modules', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { run } from './b.js';", 'run(parseInt(req.query.id, 10));'),
      'b.js': `
        export function run(value) {
          child_process.exec('tool ' + value);
        }
      `
    });
    assert.equal(result.findings.length, 0);
  });

  it('propagates returned taint through a helper module into a third-module sink', () => {
    const { result } = analyze({
      'a.js': sourceRoute(
        "import normalize from './b.js'; import { persist } from './c.js';",
        'persist(normalize(req.query.id));'
      ),
      'b.js': 'export default function normalize(value) { return value; }',
      'c.js': querySink.replace('export function run(value)', 'export function persist(value)')
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'c.js');
    assert.ok(result.findings[0].taintTrace.steps.some((step) => step.fromModule === 'a.js' && step.toModule === 'b.js'));
  });

  it('keeps clean and tainted call sites separate', () => {
    const { result } = analyze({
      'a.js': sourceRoute(
        "import { run } from './b.js';",
        "run('fixed'); run(req.query.id);"
      ),
      'b.js': querySink
    });
    assert.equal(result.findings.length, 1);
  });

  it('reports independent source-to-sink paths', () => {
    const { result } = analyze({
      'a.js': sourceRoute(
        "import { first, second } from './b.js';",
        'first(req.query.id); second(req.params.name);'
      ),
      'b.js': `
        import { run } from './c.js';
        export function first(value) { run(value); }
        export function second(value) { run(value); }
      `,
      'c.js': `
        export function run(value) {
          db.query('SELECT ' + value);
          child_process.exec('tool ' + value);
        }
      `
    });
    assert.deepEqual(new Set(result.findings.map((finding) => finding.ruleId)), new Set(['LUM-INJ-001', 'LUM-INJ-002']));
  });

  it('suppresses duplicate sink findings and retains distinct paths deterministically', () => {
    const modules = {
      'a.js': sourceRoute("import { run } from './sink.js';", 'run(req.query.id);'),
      'b.js': sourceRoute("import { run } from './sink.js';", 'run(req.params.id);'),
      'sink.js': querySink
    };
    const { result } = analyze(modules);
    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].taintTrace.alternatePaths?.length >= 1);
  });

  it('redacts string literals and credentials from cross-file traces', () => {
    const secret = 'sk_live_12345678901234567890';
    const { result } = analyze({
      'a.js': sourceRoute(
        "import { run } from './sink.js';",
        `run(req.query.id, '${secret}');`
      ),
      'sink.js': querySink
    });
    assert.equal(result.findings.length, 1);
    assert.doesNotMatch(JSON.stringify(result.findings[0].taintTrace), new RegExp(secret));
    assert.match(JSON.stringify(result.findings[0].taintTrace), /<literal>/);
  });

  it('produces deterministic trace order independent of module insertion order', () => {
    const modules = {
      'a.js': sourceRoute("import { run } from './b.js';"),
      'b.js': "import { run } from './c.js'; export function helper(value) { run(value); }",
      'c.js': querySink
    };
    const forward = analyze(modules).result.findings;
    const reverse = analyze(Object.fromEntries(Object.entries(modules).reverse())).result.findings;
    assert.deepEqual(forward, reverse);
  });

  it('reports unresolved local modules and degrades coverage', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { helper } from './missing.js';")
    });
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('unresolved_imported_module'));
  });

  it('does not guess when a re-export is ambiguous', () => {
    const { coordinator, result } = analyze({
      'a.js': sourceRoute("import { run } from './barrel.js';", 'run(req.query.id);'),
      'left.js': 'export function run(value) { db.query("SELECT " + value); }',
      'right.js': 'export function run(value) { db.query("SELECT " + value); }',
      'barrel.js': "export * from './left.js'; export * from './right.js';"
    });
    assert.equal(coordinator.symbolRegistry.getImport('a.js', 'run').resolutionStatus, 'ambiguous');
    assert.ok(result.limitations.includes('ambiguous_export_detected'));
    assert.equal(result.findings.length, 0);
  });

  it('classifies external package boundaries without traversing them', () => {
    const { coordinator } = analyze({
      'a.js': "import { helper } from 'external-package'; export function handle(req) { helper(req.query.id); }"
    });
    assert.equal(coordinator.symbolRegistry.getImport('a.js', 'helper').resolutionStatus, 'external');
    assert.equal(coordinator.projectRegistry.modules.size, 1);
  });

  it('reports dynamic imports and unresolved namespace dispatch', () => {
    const { result } = analyze({
      'a.js': `
        import * as handlers from './b.js';
        export async function handle(req) {
          await import('./' + req.query.module);
          handlers[req.query.name](req.query.id);
        }
      `,
      'b.js': 'export function run(value) { return value; }'
    });
    assert.ok(result.limitations.includes('unsupported_dynamic_import'));
    assert.ok(result.limitations.includes('unsupported_computed_dispatch'));
    assert.equal(result.coverageStatus, 'partial');
  });

  it('rejects import traversal outside the scan root', () => {
    const { coordinator, result } = analyze({
      'a.js': "import { helper } from '../../outside.js'; export function handle(req) { helper(req.query.id); }"
    });
    assert.equal(coordinator.projectRegistry.resolveModule('../../outside.js', 'a.js'), null);
    assert.ok(result.limitations.includes('module_path_outside_scan_root'));
  });

  it('shares exactly one budget manager across project components and child registries', () => {
    const manager = new ProjectBudgetManager();
    const observedManagerReceivers = new Set();
    for (const method of ['check', 'consume', 'consumeOnce', 'acquire']) {
      const original = manager[method].bind(manager);
      manager[method] = function (...args) {
        observedManagerReceivers.add(this);
        return original(...args);
      };
    }
    const projectRegistry = new ProjectModuleRegistry('/project', {
      modules: {
        'a.js': sourceRoute("import { run } from './b.js';", 'run(req.query.id);'),
        'b.js': querySink
      },
      budgetManager: manager
    });
    const symbolRegistry = new ProjectSymbolRegistry(projectRegistry, { budgetManager: manager });
    const coordinator = new ProjectTaintCoordinator('/project', {
      projectRegistry,
      symbolRegistry,
      budgetManager: manager
    }).build();
    const result = coordinator.analyze();

    assert.equal(coordinator.budgetManager, manager);
    assert.equal(coordinator.projectRegistry.budgetManager, manager);
    assert.equal(coordinator.symbolRegistry.budgetManager, manager);
    assert.equal(coordinator.projectRegistry.astCache.budgetManager, manager);
    for (const registry of coordinator.functionRegistries.values()) {
      assert.equal(registry.budgetManager, manager);
      assert.equal(registry.options.budgetManager, manager);
      for (const descriptor of registry.functions.values()) {
        assert.equal(descriptor.moduleRegistry, registry);
        assert.equal(descriptor.moduleRegistry.budgetManager, manager);
      }
    }
    assert.equal(result.findings.length, 1);
    assert.ok(observedManagerReceivers.size > 0);
    assert.ok([...observedManagerReceivers].every((receiver) => receiver === manager));
    assert.ok(manager.getStats().counters.maxTaintOperations > 0);
    assert.equal(manager.getStats().counters.maxTotalInvocations, 1);
  });

  it('enforces the project-file limit across modules and marks partial coverage', () => {
    const { result } = analyze({
      'a.js': 'export function a() {}',
      'b.js': 'export function b() {}'
    }, { budgetLimits: { maxProjectFiles: 1 } });
    assert.equal(result.moduleStats.modulesCount, 1);
    assert.ok(result.limitations.includes('project_file_limit_exceeded'));
  });

  it('shares AST cache capacity accounting across modules', () => {
    const { result } = analyze({
      'a.js': 'export function a() {}',
      'b.js': 'export function b() {}'
    }, { budgetLimits: { maxAstCacheEntries: 1, maxAstReparses: 0 } });
    assert.ok(result.budgetStats.counters.maxAstCacheEntries <= 1);
    assert.ok(result.moduleStats.astCacheStats.evictions >= 1);
    assert.ok(result.limitations.includes('ast_cache_eviction_budget_exceeded'));
  });

  it('enforces module graph edge and import-resolution budgets with partial coverage', () => {
    const graphLimited = analyze({
      'a.js': sourceRoute("import { run } from './b.js';", 'run(req.query.id);'),
      'b.js': querySink
    }, { budgetLimits: { maxModuleGraphEdges: 0 } }).result;
    assert.ok(graphLimited.limitations.includes('module_graph_edge_limit_exceeded'));
    assert.equal(graphLimited.coverageStatus, 'partial');

    const importLimited = analyze({
      'a.js': sourceRoute("import { run } from './b.js';", 'run(req.query.id);'),
      'b.js': querySink
    }, { budgetLimits: { maxImportResolutions: 0 } }).result;
    assert.ok(importLimited.limitations.includes('import_resolution_limit_exceeded'));
    assert.equal(importLimited.coverageStatus, 'partial');
  });

  it('does not allow cache eviction reparses to bypass the shared project budget', () => {
    const manager = new ProjectBudgetManager({
      limits: { maxAstCacheEntries: 1, maxAstReparses: 0 }
    });
    const registry = new ProjectModuleRegistry('/project', {
      modules: {
        'a.js': 'export function a() {}',
        'b.js': 'export function b() {}'
      },
      budgetManager: manager
    });
    registry.getAst('a.js');
    registry.getAst('b.js');
    const reparsed = registry.getAst('a.js');

    assert.equal(reparsed.parseStatus, 'skipped');
    assert.ok(registry.limitations.includes('ast_cache_eviction_budget_exceeded'));
    assert.equal(manager.getStats().counters.maxAstReparses, 0);
    assert.equal(registry.astCache.budgetManager, manager);
  });

  it('applies call depth and invocation limits project-wide', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { run } from './b.js';", 'run(req.query.id);'),
      'b.js': "export function run(value) { db.query('SELECT ' + value); }"
    }, { budgetLimits: { maxCallDepth: 0, maxTotalInvocations: 0 } });
    assert.ok(result.coverageStatus === 'partial');
    assert.ok(result.limitations.includes('call_graph_depth_limit_exceeded') ||
      result.limitations.includes('call_graph_invocation_limit_exceeded'));
  });

  it('enforces total invocation limits across the project', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { run } from './b.js';", 'run(req.query.id);'),
      'b.js': "export function run(value) { db.query('SELECT ' + value); }"
    }, { budgetLimits: { maxTotalInvocations: 0 } });
    assert.ok(result.limitations.includes('call_graph_invocation_limit_exceeded'));
    assert.equal(result.coverageStatus, 'partial');
  });

  it('enforces call-site limits across module analysis', () => {
    const { result } = analyze({
      'a.js': `
        import { run } from './b.js';
        export function handle(req) {
          run(req.query.first);
          run(req.query.second);
        }
        import express from 'express';
        const app = express();
        app.get('/source', handle);
      `,
      'b.js': "export function run(value) { db.query('SELECT ' + value); }"
    }, { budgetLimits: { maxCallSitesPerFunction: 1 } });
    assert.ok(result.limitations.includes('call_graph_call_site_limit_exceeded'));
    assert.equal(result.coverageStatus, 'partial');
  });

  it('stops on the shared taint-operation limit and reports partial coverage', () => {
    const { result } = analyze({
      'a.js': sourceRoute("import { run } from './b.js';"),
      'b.js': "export function run(value) { db.query('SELECT ' + value); }"
    }, { budgetLimits: { maxTaintOperations: 0 } });
    assert.ok(result.limitations.includes('taint_operation_limit_exceeded'));
    assert.equal(result.coverageStatus, 'partial');
  });

  it('enforces the project analysis duration limit', () => {
    let time = 0;
    const { result } = analyze({
      'a.js': 'export function handle(req) { db.query("SELECT " + req.query.id); }'
    }, {
      now: () => {
        time += 16_000;
        return time;
      }
    });
    assert.ok(result.limitations.includes('analysis_duration_limit_exceeded'));
    assert.equal(result.coverageStatus, 'partial');
  });

  it('does not execute scanned project code', () => {
    delete globalThis.__luminicentProjectCodeExecuted;
    analyze({
      'a.js': 'globalThis.__luminicentProjectCodeExecuted = true; export function handle(req) { return req.query.id; }'
    });
    assert.equal(globalThis.__luminicentProjectCodeExecuted, undefined);
  });

  it('seeds directly registered Express callbacks without relying on parameter names', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        const app = express();
        app.post('/query', (input) => {
          globalThis.__frameworkProjectCodeExecuted = true;
          db.query('SELECT * FROM records WHERE id=' + input.body.id);
        });
      `
    });

    assert.equal(globalThis.__frameworkProjectCodeExecuted, undefined);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].file, 'routes.js');
    assert.equal(result.findings[0].taintTrace.source.file, 'routes.js');
    assert.equal(result.findings[0].taintTrace.source.expression, 'input.body');
    assert.ok(result.findings[0].taintTrace.steps.some((step) =>
      step.frameworkEntryPoint === true && step.registrationMethod === 'post'
    ));
  });

  it('resolves an aliased imported controller and traces its route registration', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        import { run as execute } from './controller.js';
        const router = express.Router();
        router.post('/query', execute);
      `,
      'controller.js': `
        export function run(input) {
          db.query('SELECT * FROM records WHERE id=' + input.body.id);
        }
      `
    });

    assert.equal(result.findings.length, 1);
    const [finding] = result.findings;
    assert.equal(finding.file, 'controller.js');
    assert.equal(finding.taintTrace.source.file, 'controller.js');
    assert.ok(finding.taintTrace.steps.some((step) =>
      step.fromModule === 'routes.js' &&
      step.toModule === 'controller.js' &&
      step.importExport?.localName === 'execute'
    ));
  });

  it('seeds supported destructured request properties and every statically resolved handler', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        import { first, second } from './controller.js';
        const router = express.Router();
        router.get('/query', ({ query: { id } }) => db.query('SELECT ' + id), first, second);
      `,
      'controller.js': `
        export function first(input) { db.query('SELECT ' + input.params.name); }
        export function second(input) { db.query('SELECT ' + input.headers.value); }
      `
    });

    assert.equal(result.findings.length, 3);
    assert.ok(result.findings.some((finding) =>
      finding.taintTrace.source.expression === 'request.query.id'
    ));
    assert.ok(result.findings.some((finding) => finding.taintTrace.source.file === 'controller.js'));
  });

  it('retains route-seeded taint through helpers while preserving command CWE distinctions', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        import { shell, argument, executable } from './process.js';
        const app = express();
        app.post('/run', (input) => {
          shell(input.body.command);
          argument(input.body.command);
          executable(input.body.path);
        });
      `,
      'process.js': `
        import { exec, spawn, execFile } from 'node:child_process';
        export function shell(value) { exec('tool ' + value); }
        export function argument(value) { spawn('tool', [value], { shell: false }); }
        export function executable(value) { execFile(value, ['fixed']); }
      `
    });

    assert.deepEqual(
      new Set(result.findings.map((finding) => finding.cwe.join(','))),
      new Set(['CWE-78', 'CWE-88', 'CWE-114'])
    );
    assert.ok(result.findings.every((finding) =>
      !finding.cwe.includes('CWE-426') &&
      finding.taintTrace.steps.some((step) => step.frameworkEntryPoint === true)
    ));
  });

  it('does not treat ordinary functions or unverified routers as framework entry points', () => {
    const { result } = analyze({
      'ordinary.js': `
        function handler(req) {
          db.query('SELECT ' + req.query.id);
        }
        const app = {};
        app.get('/not-express', handler);
      `
    });
    assert.equal(result.findings.length, 0);
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('framework_router_identity_ambiguous'));
  });

  it('does not seed request taint from ordinary request-shaped parameters or function names', () => {
    const { result } = analyze({
      'ordinary.js': `
        function handler(req) { db.query('SELECT ' + req.body.id); }
        function controller(request) { db.query('SELECT ' + request.query.id); }
        function middleware(ctx) { db.query('SELECT ' + ctx.request.body.id); }
        function routeHandler(input) { db.query('SELECT ' + input.body.id); }
      `
    });

    assert.equal(result.findings.length, 0);
    assert.equal(result.coverageStatus, 'completed');
  });

  it('does not independently seed an unregistered helper invoked by a route callback', () => {
    const { coordinator, result } = analyze({
      'routes.js': `
        import express from 'express';
        function helper(req) {
          db.query('SELECT ' + req.query.id);
        }
        const app = express();
        app.post('/route', (input) => helper({}));
      `
    });
    const routeEntries = coordinator.frameworkEntryPoints.get('routes.js');

    assert.equal(routeEntries.size, 1);
    assert.equal(result.findings.length, 0);
    assert.equal(result.coverageStatus, 'completed');
  });

  it('rejects shadowed, reassigned, and mutated Express router identities', () => {
    const { coordinator, result } = analyze({
      'routes.js': `
        import express from 'express';
        function shadowed(express) {
          const app = express();
          app.post('/shadowed', handler);
        }
        let reassigned = express();
        reassigned = {};
        reassigned.post('/reassigned', handler);
        const mutated = express();
        mutated.get = customGet;
        mutated.get('/mutated', handler);
        const reflected = express();
        Object.assign(reflected, { post: customPost });
        reflected.post('/reflected', handler);
        const escaped = express();
        configure(escaped);
        escaped.post('/escaped', handler);
        class Register {
          #fromParameter(express) {
            const app = express();
            app.post('/private-shadow', handler);
          }
        }
        try {
          throw new Error('static only');
        } catch (express) {
          const app = express();
          app.post('/catch-shadow', handler);
        }
        function handler(input) { db.query('SELECT ' + input.body.id); }
      `,
      'routes.ts': `
        import type express from 'express';
        const app = express();
        app.post('/type-only', handler);
      `
    });

    assert.equal(coordinator.frameworkEntryPoints.size, 0);
    assert.equal(result.findings.length, 0);
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('framework_router_identity_ambiguous'));
  });

  it('recognizes statically aliased verified Express routers', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        const original = express.Router();
        const router = original;
        router.post('/query', (req, res, next) => {
          const input = req;
          {
            const req = {};
            db.query('SELECT ' + req.body.id);
          }
          db.query('SELECT ' + input['body'].id);
          db.query('SELECT ' + res.body.id);
          db.query('SELECT ' + next.body.id);
        });
      `
    });

    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].taintTrace.source.expression, 'req.body');
    assert.ok(result.findings[0].taintTrace.steps.some((step) =>
      step.frameworkEntryPoint === true
    ));
  });

  it('does not trust an imported router whose Express identity is not resolved', () => {
    const { result } = analyze({
      'routes.js': `
        import router from './router.js';
        router.post('/query', (input) => db.query('SELECT ' + input.body.id));
      `,
      'router.js': `
        import express from 'express';
        const router = express.Router();
        export default router;
      `
    });

    assert.equal(result.findings.length, 0);
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('framework_router_identity_ambiguous'));
  });

  it('supports bracket request-property access through a verified route', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        const app = express();
        app.post('/query', (req) => {
          db.query('SELECT ' + req['body']['id']);
          db.query('SELECT ' + req.query.id);
          db.query('SELECT ' + req.params.id);
          db.query('SELECT ' + req.headers.authorization);
          db.query('SELECT ' + req.cookies.session);
          db.query('SELECT ' + req.signedCookies.session);
        });
      `
    });

    assert.equal(result.findings.length, 6);
    assert.ok(result.findings[0].taintTrace.steps.some((step) =>
      step.frameworkEntryPoint === true
    ));
  });

  it('records dynamic and unresolved route-handler registrations as partial coverage', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        const app = express();
        const method = 'post';
        app[method]('/dynamic', missingController);
        app.post('/unresolved', unknownController);
      `
    });

    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('dynamic_route_registration_detected'));
    assert.ok(result.limitations.includes('framework_handler_unresolved'));
  });

  it('does not resolve imported controllers that escape the scan root', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        import handler from '../../outside.js';
        const app = express();
        app.get('/query', handler);
      `
    });

    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('module_path_outside_scan_root'));
    assert.ok(!result.findings.some((finding) => finding.taintTrace?.steps?.some((step) =>
      step.toModule?.startsWith('..')
    )));
  });

  it('keeps framework-seeded finding IDs and traces deterministic', () => {
    const modules = {
      'routes.js': `
        import express from 'express';
        import { run as handle } from './controller.js';
        const app = express();
        app.post('/query', handle);
      `,
      'controller.js': "export function run(input) { db.query('SELECT ' + input.body.id); }"
    };
    const first = analyze(modules).result.findings;
    const second = analyze(Object.fromEntries(Object.entries(modules).reverse())).result.findings;

    assert.deepEqual(first, second);
  });

  it('recognizes the supported Express registration methods from verified factories', () => {
    const methods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all', 'use'];
    const registrations = methods.map((method) =>
      method === 'use'
        ? 'app.use(handler);'
        : `app.${method}('/route', handler);`
    ).join('\n');
    const { coordinator, result } = analyze({
      'routes.js': `
        import { default as createExpress } from 'express';
        const app = createExpress();
        function handler(input) { db.query('SELECT ' + input.body.id); }
        ${registrations}
      `
    });

    assert.equal(result.findings.length, 1);
    assert.equal(coordinator.frameworkEntryPoints.get('routes.js').get(
      [...coordinator.frameworkEntryPoints.get('routes.js').keys()][0]
    ).length, methods.length);
  });

  it('recognizes statically chained Express route registrations', () => {
    const { result } = analyze({
      'routes.js': `
        const express = require('express');
        const router = express.Router();
        router.route('/query').post((input) => {
          db.query('SELECT ' + input.body.id);
        });
      `
    });

    assert.equal(result.findings.length, 1);
    assert.ok(result.findings[0].taintTrace.steps.some((step) =>
      step.frameworkEntryPoint === true && step.registrationMethod === 'post'
    ));
  });

  it('resolves default, namespace, and CommonJS controller references', () => {
    const scenarios = [
      {
        routes: "import handler from './controller.js';",
        controller: "export default function handle(input) { db.query('SELECT ' + input.body.id); }",
        call: 'handler'
      },
      {
        routes: "import * as controllers from './controller.js';",
        controller: "export function handle(input) { db.query('SELECT ' + input.body.id); }",
        call: 'controllers.handle'
      },
      {
        routes: "const controllers = require('./controller.js');",
        controller: "function handle(input) { db.query('SELECT ' + input.body.id); }\nmodule.exports = { handle };",
        call: 'controllers.handle'
      }
    ];

    for (const scenario of scenarios) {
      const { result } = analyze({
        'routes.js': `
          import express from 'express';
          ${scenario.routes}
          const router = express.Router();
          router.post('/route', ${scenario.call});
        `,
        'controller.js': scenario.controller
      });
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].file, 'controller.js');
      assert.ok(result.findings[0].taintTrace.steps.some((step) =>
        step.frameworkEntryPoint === true
      ));
    }
  });

  it('preserves sanitizer behavior when route-seeded taint crosses modules', () => {
    const cases = [
      {
        name: 'mysql.escape preserves taint without verified execution context',
        helper: [
          "import * as mysql from 'mysql';",
          'export function clean(value) { return mysql.escape(value); }'
        ].join('\n'),
        expected: 1
      },
      {
        helper: 'export function clean(value) { return escapeHtml(value); }',
        expected: 1
      },
      {
        helper: 'export function clean(value) { validator.isInt(value); return value; }',
        expected: 1
      }
    ];

    for (const scenario of cases) {
      const { result } = analyze({
        'routes.js': `
          import express from 'express';
          import { run } from './controller.js';
          const app = express();
          app.post('/route', run);
        `,
        'controller.js': `
          import { clean } from './helper.js';
          export function run(input) {
            const value = clean(input.body.id);
            db.query('SELECT ' + value);
          }
        `,
        'helper.js': scenario.helper
      });
      assert.equal(result.findings.length, scenario.expected, scenario.sink);
      if (scenario.name?.includes('mysql.escape')) {
        const [finding] = result.findings;
        assert.equal(finding.ruleId, 'LUM-INJ-001');
        assert.equal(finding.taintTrace.sink.line, 5);
        assert.match(finding.taintTrace.sink.api, /^db\.query\(/);
        assert.equal(finding.taintTrace.source.expression, 'input.body');
        assert.match(finding.evidence, /input\.body/);
        assert.ok(finding.taintTrace.steps.some((step) =>
          step.fromModule === 'controller.js' && step.toModule === 'helper.js'
        ));
      }
    }
  });

  it('keeps numeric conversion behavior specific to route-seeded sink contexts', () => {
    const cases = [
      {
        sink: "db.query('SELECT ' + parseInt(input.body.id, 10));",
        expected: 0
      },
      {
        sink: "spawn('tool', [parseInt(input.body.command, 10)], { shell: false });",
        imports: "import { spawn } from 'node:child_process';",
        expected: 1,
        cwe: ['CWE-88']
      },
      {
        sink: "execFile(parseInt(input.body.path, 10), ['fixed']);",
        imports: "import { execFile } from 'node:child_process';",
        expected: 1,
        cwe: ['CWE-114']
      }
    ];

    for (const scenario of cases) {
      const { result } = analyze({
        'routes.js': `
          import express from 'express';
          ${scenario.imports || ''}
          const app = express();
          app.post('/route', (input) => { ${scenario.sink} });
        `
      });
      assert.equal(result.findings.length, scenario.expected, scenario.sink);
      if (scenario.cwe) assert.deepEqual(result.findings[0].cwe, scenario.cwe);
    }
  });

  it('shares discovery accounting with existing budgets and degrades coverage on exhaustion', () => {
    const modules = {
      'routes.js': `
        import express from 'express';
        const app = express();
        app.post('/route', (input) => db.query('SELECT ' + input.body.id));
      `
    };
    const options = { budgetLimits: { maxTaintOperations: 0 } };
    const result = analyze(modules, options).result;
    const repeated = analyze(modules, options).result;

    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('taint_operation_limit_exceeded'));
    assert.deepEqual(result.findings, repeated.findings);
    assert.deepEqual(result.limitations, repeated.limitations);
  });

  it('deduplicates route discovery and ordinary taint paths to the same sink', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        const app = express();
        function execute(input) {
          db.query('SELECT ' + input.body.id);
        }
        function ordinary(req) { execute(req.body.id); }
        app.post('/route', execute);
      `
    });

    assert.equal(result.findings.length, 1);
  });

  it('reports ambiguous imported route controllers without guessing', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        import { run } from './barrel.js';
        const app = express();
        app.post('/route', run);
      `,
      'barrel.js': "export * from './left.js'; export * from './right.js';",
      'left.js': "export function run(input) { db.query('SELECT ' + input.body.id); }",
      'right.js': "export function run(input) { db.query('SELECT ' + input.body.id); }"
    });

    assert.equal(result.findings.length, 0);
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('framework_handler_ambiguous'));
  });

  it('records external handler boundaries without traversing packages', () => {
    const { coordinator, result } = analyze({
      'routes.js': `
        import express from 'express';
        import handler from 'external-controller-package';
        const app = express();
        app.post('/route', handler);
      `
    });

    assert.equal(coordinator.projectRegistry.modules.size, 1);
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('framework_handler_external_boundary'));
  });

  it('keeps circular route imports bounded while retaining resolvable handler analysis', () => {
    const { result } = analyze({
      'routes.js': `
        import express from 'express';
        import { run } from './controller.js';
        const app = express();
        export function routeMarker() {}
        app.post('/route', run);
      `,
      'controller.js': `
        import { routeMarker } from './routes.js';
        export function run(input) { db.query('SELECT ' + input.body.id); }
      `
    });

    assert.equal(result.findings.length, 1);
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('circular_module_import_detected'));
  });
});
