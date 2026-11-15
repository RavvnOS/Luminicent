import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ProjectBudgetManager, PROJECT_BUDGET_LIMITATION_CODES } from './projectBudgetManager.js';
import { BoundedAstCache } from './boundedAstCache.js';
import { ProjectModuleRegistry } from './projectRegistry.js';
import { parseSource } from '../parser.js';
import { analyzeAstTaint } from './taintAnalyzer.js';
import { buildFunctionRegistry } from './callGraph.js';

describe('ProjectBudgetManager', () => {
  it('uses the phase limits and stable exhaustion codes for every resource', () => {
    const manager = new ProjectBudgetManager({
      limits: {
        maxProjectFiles: 0,
        maxModuleGraphEdges: 0,
        maxImportResolutions: 0,
        maxAstCacheEntries: 0,
        maxAstReparses: 0,
        maxCallDepth: 0,
        maxTotalInvocations: 0,
        maxCallSitesPerFunction: 0,
        maxTaintOperations: 0
      }
    });
    const exhausted = [
      manager.consume('maxProjectFiles'),
      manager.consume('maxModuleGraphEdges'),
      manager.consume('maxImportResolutions'),
      manager.acquire('maxAstCacheEntries', 'cache-entry'),
      manager.consume('maxAstReparses'),
      manager.check('maxCallDepth', 1),
      manager.consume('maxTotalInvocations'),
      manager.consume('maxCallSitesPerFunction', 1, { scope: 'function-a' }),
      manager.consume('maxTaintOperations')
    ];
    assert.deepEqual(
      exhausted.map((result) => result.code),
      Object.entries(PROJECT_BUDGET_LIMITATION_CODES)
        .filter(([resource]) => resource !== 'maxAnalysisDurationMs')
        .map(([, code]) => code)
    );
    assert.equal(manager.getLimitations().length, Object.keys(PROJECT_BUDGET_LIMITATION_CODES).length - 1);
    assert.ok(manager.getLimitations().every((item) => item.coverage === 'partial'));

    let time = 0;
    const durationManager = new ProjectBudgetManager({
      limits: { maxAnalysisDurationMs: 1 },
      now: () => time
    });
    time = 1;
    const duration = durationManager.consume('maxAnalysisDurationMs');
    assert.equal(duration.code, 'analysis_duration_limit_exceeded');
    assert.equal(duration.limit, 1);
  });

  it('shares project counters across module registries without resetting child usage', () => {
    const manager = new ProjectBudgetManager({ limits: { maxProjectFiles: 2 } });
    const first = new ProjectModuleRegistry('/project', {
      budgetManager: manager,
      modules: { 'a.js': 'export const a = 1;' }
    });
    const second = new ProjectModuleRegistry('/project', {
      budgetManager: manager,
      modules: {
        'b.js': 'export const b = 1;',
        'c.js': 'export const c = 1;'
      }
    });

    assert.equal(first.modules.size, 1);
    assert.equal(second.modules.size, 1);
    assert.deepEqual([...second.modules.keys()], ['b.js']);
    assert.equal(manager.getStats().counters.maxProjectFiles, 2);
    assert.ok(second.limitations.includes('project_file_limit_exceeded'));
  });

  it('records file-limit metadata when registry indexing is denied', () => {
    const manager = new ProjectBudgetManager({ limits: { maxProjectFiles: 0 } });
    const registry = new ProjectModuleRegistry('/project', {
      budgetManager: manager,
      modules: { 'blocked.js': 'export const value = 1;' }
    });
    assert.equal(registry.modules.size, 0);
    assert.deepEqual(manager.getLimitations()[0], {
      code: 'project_file_limit_exceeded',
      resource: 'maxProjectFiles',
      limit: 0,
      used: 0,
      coverage: 'partial'
    });
    assert.ok(registry.limitations.includes('project_file_limit_exceeded'));
  });

  it('checks call depth, bounds total invocations, and scopes call-site limits per function', () => {
    const manager = new ProjectBudgetManager({
      limits: {
        maxCallDepth: 2,
        maxTotalInvocations: 1,
        maxCallSitesPerFunction: 1
      }
    });
    assert.equal(manager.check('maxCallDepth', 2).allowed, true);
    assert.equal(manager.check('maxCallDepth', 3).code, 'call_graph_depth_limit_exceeded');
    assert.equal(manager.consume('maxTotalInvocations').allowed, true);
    assert.equal(manager.consume('maxTotalInvocations').code, 'call_graph_invocation_limit_exceeded');

    assert.equal(manager.consume('maxCallSitesPerFunction', 1, { scope: 'f', key: 'a' }).allowed, true);
    assert.equal(manager.consume('maxCallSitesPerFunction', 1, { scope: 'f', key: 'b' }).code, 'call_graph_call_site_limit_exceeded');
    assert.equal(manager.consume('maxCallSitesPerFunction', 1, { scope: 'g', key: 'a' }).allowed, true);
  });

  it('counts taint operations project-wide and supports injected duration clocks', () => {
    let time = 10;
    const manager = new ProjectBudgetManager({
      limits: { maxTaintOperations: 1, maxAnalysisDurationMs: 5 },
      now: () => time
    });
    assert.equal(manager.consume('maxTaintOperations').allowed, true);
    assert.equal(manager.consume('maxTaintOperations').code, 'taint_operation_limit_exceeded');
    time += 5;
    assert.equal(manager.check('maxProjectFiles').code, 'analysis_duration_limit_exceeded');
    assert.equal(manager.getLimitations().at(-1).resource, 'maxAnalysisDurationMs');
  });

  it('deduplicates keyed consumption and keeps active cache accounting bounded', () => {
    const manager = new ProjectBudgetManager({ limits: { maxAstCacheEntries: 1 } });
    assert.equal(manager.consumeOnce('maxProjectFiles', 'src/a.js').allowed, true);
    const duplicate = manager.consumeOnce('maxProjectFiles', 'src/a.js');
    assert.equal(duplicate.allowed, true);
    assert.equal(duplicate.duplicate, true);
    assert.equal(manager.getStats().counters.maxProjectFiles, 1);

    assert.equal(manager.acquire('maxAstCacheEntries', 'cache-a').allowed, true);
    assert.equal(manager.acquire('maxAstCacheEntries', 'cache-a').duplicate, true);
    assert.equal(manager.acquire('maxAstCacheEntries', 'cache-b').code, 'ast_cache_entry_limit_exceeded');
    assert.equal(manager.release('maxAstCacheEntries', 'cache-a'), true);
    assert.equal(manager.getStats().counters.maxAstCacheEntries, 0);
    assert.equal(manager.acquire('maxAstCacheEntries', 'cache-b').allowed, true);
  });

  it('preserves standalone cache limits and only consumes shared reparse budget for evicted misses', () => {
    const standalone = new BoundedAstCache({ maxCachedAsts: 1, maxAstReparses: 1 });
    standalone.getOrParse('const a = 1;', 'a.js');
    standalone.getOrParse('const b = 1;', 'b.js');
    assert.equal(standalone.getOrParse('const a = 1;', 'a.js').ast !== null, true);
    assert.equal(standalone.getOrParse('const b = 1;', 'b.js').parseStatus, 'skipped');

    const manager = new ProjectBudgetManager({
      limits: { maxAstCacheEntries: 5, maxAstReparses: 1 }
    });
    const first = new BoundedAstCache({ maxCachedAsts: 1, budgetManager: manager });
    first.getOrParse('const a = 1;', 'a.js');
    first.getOrParse('const b = 1;', 'b.js');
    const beforeHit = manager.getStats().counters.maxAstReparses;
    first.getOrParse('const b = 1;', 'b.js');
    assert.equal(manager.getStats().counters.maxAstReparses, beforeHit);
    assert.equal(first.getOrParse('const a = 1;', 'a.js').ast !== null, true);
    assert.equal(manager.getStats().counters.maxAstReparses, 1);
    first.getOrParse('const c = 1;', 'c.js');
    const exhausted = first.getOrParse('const b = 1;', 'b.js');
    assert.equal(exhausted.parseStatus, 'skipped');
    assert.equal(exhausted.isPartial, true);
    assert.ok(first.limitations.includes('ast_cache_eviction_budget_exceeded'));
  });

  it('does not cache past a shared AST-entry limit and marks returned coverage partial', () => {
    const manager = new ProjectBudgetManager({ limits: { maxAstCacheEntries: 1 } });
    const first = new BoundedAstCache({ budgetManager: manager });
    const second = new BoundedAstCache({ budgetManager: manager });
    assert.ok(first.getOrParse('const a = 1;', 'a.js').ast);
    const secondResult = second.getOrParse('const b = 1;', 'b.js');
    assert.ok(secondResult.ast);
    assert.equal(secondResult.isPartial, true);
    assert.equal(second.has('b.js'), false);
    assert.ok(second.limitations.includes('ast_cache_entry_limit_exceeded'));
  });

  it('releases cache-entry accounting on source invalidation and failed parses', () => {
    const manager = new ProjectBudgetManager({ limits: { maxAstCacheEntries: 1 } });
    const cache = new BoundedAstCache({ budgetManager: manager });
    assert.ok(cache.getOrParse('const value = 1;', 'value.js').ast);
    const broken = cache.getOrParse('function (((; // broken', 'value.js');
    assert.equal(broken.ast, null);
    assert.equal(cache.has('value.js'), false);
    assert.equal(manager.getStats().counters.maxAstCacheEntries, 0);
    assert.ok(cache.getOrParse('const value = 2;', 'value.js').ast);
    assert.equal(manager.getStats().counters.maxAstCacheEntries, 1);
  });

  it('marks a cache miss skipped when the shared analysis-duration limit is reached', () => {
    let time = 0;
    const manager = new ProjectBudgetManager({
      limits: { maxAnalysisDurationMs: 10 },
      now: () => time
    });
    const cache = new BoundedAstCache({ budgetManager: manager });
    time = 10;
    const result = cache.getOrParse('const a = 1;', 'a.js');
    assert.equal(result.parseStatus, 'skipped');
    assert.equal(result.errors[0].code, 'ANALYSIS_DURATION_LIMIT_EXCEEDED');
    assert.ok(cache.limitations.includes('analysis_duration_limit_exceeded'));
  });

  it('passes the shared manager through function registries and degrades taint coverage on exhaustion', () => {
    const manager = new ProjectBudgetManager({ limits: { maxTaintOperations: 0 } });
    const source = 'function handler(req) { const value = req.query.value; child_process.exec(value); }';
    const ast = parseSource(source, { filePath: 'src/handler.js' }).ast;
    const functionRegistry = buildFunctionRegistry(ast, {
      code: source,
      filePath: 'src/handler.js',
      budgetManager: manager
    });
    assert.equal(functionRegistry.budgetManager, manager);

    const result = analyzeAstTaint(ast, {
      code: source,
      filePath: 'src/handler.js',
      budgetManager: manager,
      functionRegistry
    });
    assert.equal(result.coverageStatus, 'partial');
    assert.ok(result.limitations.includes('taint_operation_limit_exceeded'));
  });
});
