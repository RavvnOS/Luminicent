/**
 * Phase 5.4.1.1 — Bounded AST Cache Integration and Correctness Tests
 *
 * Coverage targets (all 10 items from Phase 5.4.1.1 Section 5):
 *  1. Cache integration through the ProjectModuleRegistry.getAst() path
 *  2. Repeated unchanged-file parse produces a cache hit (no reparse)
 *  3. Changed source content invalidates the cached AST
 *  4. LRU eviction followed by a permitted reparse
 *  5. Reparse budget exhaustion produces partial coverage
 *  6. Cache capacity and project-file limits are independently enforced
 *  7. Nested module resolution preserves the original scan root
 *  8. Parse failures do not create or leave reusable invalid cache entries
 *  9. Static module resolution does not execute project code
 * 10. Resource counters remain consistent across nested module registries
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { BoundedAstCache, AST_CACHE_LIMITS, normalizeCacheKey } from './boundedAstCache.js';
import { ProjectModuleRegistry, PROJECT_REGISTRY_LIMITS } from './projectRegistry.js';
import { buildFunctionRegistry } from './callGraph.js';
import { parseSource } from '../parser.js';

describe('BoundedAstCache — Phase 5.4.1.1 Integration & Correctness', () => {
  // ─── 1. Cache integration through ProjectModuleRegistry.getAst() ────────────
  describe('1. Cache integration via ProjectModuleRegistry.getAst()', () => {
    it('getAst() routes through astCache.getOrParse and updates cache stats', () => {
      const code = 'export const greeting = "hello";';
      const reg = new ProjectModuleRegistry('/fake/root', {
        modules: { 'greet.js': code }
      });

      // First call: cache miss → parse → store
      const r1 = reg.getAst('greet.js');
      assert.ok(r1.ast, 'AST must be present after first getAst call');
      const stats1 = reg.astCache.getStats();
      assert.strictEqual(stats1.misses, 1, 'first call must be a cache miss');
      assert.strictEqual(stats1.hits, 0, 'no hits yet');
      assert.strictEqual(stats1.size, 1, 'one AST cached');

      // Second call: cache hit
      const r2 = reg.getAst('greet.js');
      assert.ok(r2.ast, 'AST must be present on second getAst call');
      const stats2 = reg.astCache.getStats();
      assert.strictEqual(stats2.hits, 1, 'second call must be a cache hit');
      assert.strictEqual(stats2.misses, 1, 'miss count must not change');
      assert.strictEqual(r1.ast, r2.ast, 'both calls must return the same AST object reference');
    });

    it('getStats() exposes astCacheStats alongside registry counters', () => {
      const reg = new ProjectModuleRegistry('/fake/root', {
        modules: { 'util.js': 'export const x = 1;' }
      });
      reg.getAst('util.js');
      const stats = reg.getStats();
      assert.ok(stats.astCacheStats, 'getStats() must include astCacheStats');
      assert.strictEqual(typeof stats.astCacheStats.hits, 'number');
      assert.strictEqual(typeof stats.astCacheStats.misses, 'number');
      assert.strictEqual(typeof stats.astCacheStats.evictions, 'number');
      assert.strictEqual(typeof stats.astCacheStats.size, 'number');
      assert.strictEqual(stats.astCacheStats.capacity, 250);
    });

    it('shared cache instance is used when injected via options.astCache', () => {
      const sharedCache = new BoundedAstCache();
      const code = 'export const z = 42;';

      const reg1 = new ProjectModuleRegistry('/fake/root', {
        astCache: sharedCache,
        modules: { 'shared.js': code }
      });
      const reg2 = new ProjectModuleRegistry('/fake/root', {
        astCache: sharedCache,
        modules: { 'shared.js': code }
      });

      reg1.getAst('shared.js');  // miss → parse
      assert.strictEqual(sharedCache.getStats().misses, 1);
      assert.strictEqual(sharedCache.getStats().hits, 0);

      reg2.getAst('shared.js');  // hit (same shared cache)
      assert.strictEqual(sharedCache.getStats().hits, 1);
      assert.strictEqual(sharedCache.getStats().misses, 1);
    });
  });

  // ─── 2. Repeated unchanged-file parse produces a cache hit ──────────────────
  describe('2. Repeated unchanged-file parsing produces cache hit', () => {
    it('multiple getOrParse calls with identical source and key produce a single parse', () => {
      const cache = new BoundedAstCache();
      const code = 'function square(n) { return n * n; }';
      const key = 'math/square.js';

      cache.getOrParse(code, key, { relativePath: key });  // parse
      cache.getOrParse(code, key, { relativePath: key });  // hit
      cache.getOrParse(code, key, { relativePath: key });  // hit

      const stats = cache.getStats();
      assert.strictEqual(stats.misses, 1, 'only one real parse (miss) expected');
      assert.strictEqual(stats.hits, 2, 'two subsequent requests must be cache hits');
    });

    it('normalizeCacheKey treats Windows backslash path same as POSIX forward-slash path', () => {
      const cache = new BoundedAstCache();
      const code = 'export const win = true;';

      // Simulate Windows absolute path as relative cache key
      cache.getOrParse(code, 'src\\utils\\helper.js', { relativePath: 'src\\utils\\helper.js' });

      // Now request with POSIX path — must be a cache hit, not a miss
      const result = cache.getOrParse(code, 'src/utils/helper.js', { relativePath: 'src/utils/helper.js' });
      const stats = cache.getStats();
      assert.strictEqual(stats.hits, 1, 'Windows and POSIX paths for same file must share the cache entry');
      assert.ok(result.ast, 'cached AST must be returned on normalized-key hit');
    });

    it('./prefix and bare key resolve to the same cache slot', () => {
      const cache = new BoundedAstCache();
      const code = 'export const a = 1;';

      cache.getOrParse(code, 'lib/a.js', { relativePath: './lib/a.js' });
      cache.getOrParse(code, 'lib/a.js', { relativePath: 'lib/a.js' });  // should be a hit

      const stats = cache.getStats();
      assert.strictEqual(stats.misses, 1);
      assert.strictEqual(stats.hits, 1);
    });
  });

  // ─── 3. Changed source content invalidates cached AST ───────────────────────
  describe('3. Changed source invalidates cached AST', () => {
    it('fingerprint mismatch causes cache invalidation and re-parse', () => {
      const cache = new BoundedAstCache();
      const key = 'config.js';

      const v1 = 'const PORT = 3000;';
      const r1 = cache.getOrParse(v1, key, { relativePath: key });
      assert.ok(r1.ast);

      const v2 = 'const PORT = 8080; // changed';
      const r2 = cache.getOrParse(v2, key, { relativePath: key });
      assert.ok(r2.ast);

      // Must be a distinct object (re-parsed) and two misses
      assert.notStrictEqual(r1.ast, r2.ast, 'changed content must produce a fresh AST object');
      assert.strictEqual(cache.getStats().misses, 2, 'both versions count as misses');
      assert.strictEqual(cache.getStats().hits, 0);
    });

    it('after content change, subsequent identical request is a hit again', () => {
      const cache = new BoundedAstCache();
      const key = 'route.js';
      const v1 = 'module.exports = function() {};';
      const v2 = 'module.exports = function handler() {};';

      cache.getOrParse(v1, key, { relativePath: key });   // miss #1
      cache.getOrParse(v2, key, { relativePath: key });   // miss #2 (changed)
      cache.getOrParse(v2, key, { relativePath: key });   // hit

      const stats = cache.getStats();
      assert.strictEqual(stats.misses, 2);
      assert.strictEqual(stats.hits, 1);
    });
  });

  // ─── 4. LRU eviction followed by a permitted reparse ────────────────────────
  describe('4. LRU eviction followed by permitted reparse', () => {
    it('evicted entry is reparsed once the cache has capacity', () => {
      const cache = new BoundedAstCache({ maxCachedAsts: 2, maxAstReparses: 5 });

      cache.getOrParse('const a = 1;', 'a.js', { relativePath: 'a.js' });
      cache.getOrParse('const b = 2;', 'b.js', { relativePath: 'b.js' });
      // a.js is LRU at this point

      // c.js insertion evicts a.js
      cache.getOrParse('const c = 3;', 'c.js', { relativePath: 'c.js' });
      assert.strictEqual(cache.getStats().evictions, 1);
      assert.ok(!cache.has('a.js'), 'a.js must be evicted');

      // Reparse a.js — within budget
      const reparsed = cache.getOrParse('const a = 1;', 'a.js', { relativePath: 'a.js' });
      assert.ok(reparsed.ast, 'reparse must produce a valid AST');
      assert.strictEqual(cache.getStats().reparses, 1, 'reparse counter incremented');
      assert.strictEqual(cache.getStats().isReparseBudgetExceeded, false);
    });
  });

  // ─── 5. Reparse budget exhaustion ───────────────────────────────────────────
  describe('5. Reparse budget exhaustion produces partial coverage', () => {
    it('exceeding reparse budget returns skipped status and pushes limitation', () => {
      const limitations = [];
      // maxCachedAsts: 1 makes evictions deterministic — every new unique entry evicts the current one
      const cache = new BoundedAstCache({
        maxCachedAsts: 1,
        maxAstReparses: 1,
        limitations
      });

      // Parse a.js — fills the only slot
      cache.getOrParse('const a = 1;', 'a.js', { relativePath: 'a.js' });
      assert.strictEqual(cache.getStats().size, 1);

      // b.js evicts a.js — a.js enters eviction history
      cache.getOrParse('const b = 2;', 'b.js', { relativePath: 'b.js' });
      assert.strictEqual(cache.getStats().evictions, 1);
      assert.ok(cache.evictionHistory.has('a.js'), 'a.js must be in eviction history');

      // Reparse 1: re-request a.js — within budget (reparses -> 1); a.js evicts b.js
      cache.getOrParse('const a = 1;', 'a.js', { relativePath: 'a.js' });
      assert.strictEqual(cache.getStats().reparses, 1, 'first reparse must succeed');

      // c.js evicts a.js again — a.js is back in eviction history
      cache.getOrParse('const c = 3;', 'c.js', { relativePath: 'c.js' });

      // Reparse attempt 2: reparses (1) >= maxAstReparses (1) → MUST be blocked
      const failed = cache.getOrParse('const a = 1;', 'a.js', { relativePath: 'a.js' });
      assert.strictEqual(failed.parseStatus, 'skipped', 'must degrade to skipped when budget exceeded');
      assert.strictEqual(failed.isPartial, true);
      assert.ok(failed.errors.some(e => e.code === 'CACHE_REPARSE_LIMIT_EXCEEDED'));
      assert.ok(limitations.includes('ast_cache_eviction_budget_exceeded'));
      assert.strictEqual(cache.getStats().isReparseBudgetExceeded, true);
    });

    it('budget exhaustion also propagates to call-site options.limitations array', () => {
      const cacheLimitations = [];
      const cache = new BoundedAstCache({
        maxCachedAsts: 1,
        maxAstReparses: 0,  // zero reparses allowed
        limitations: cacheLimitations
      });

      // Fill cache
      cache.getOrParse('const x = 1;', 'x.js', { relativePath: 'x.js' });
      // Evict x.js
      cache.getOrParse('const y = 2;', 'y.js', { relativePath: 'y.js' });

      const callSiteLimitations = [];
      cache.getOrParse('const x = 1;', 'x.js', {
        relativePath: 'x.js',
        limitations: callSiteLimitations
      });

      assert.ok(cacheLimitations.includes('ast_cache_eviction_budget_exceeded'));
      assert.ok(callSiteLimitations.includes('ast_cache_eviction_budget_exceeded'),
        'budget exhaustion must propagate to call-site limitations array');
    });
  });

  // ─── 6. Cache capacity and project-file limits are independently enforced ────
  describe('6. Cache capacity and project-file limits are independently enforced', () => {
    it('AST cache capacity (maxCachedAsts) is separate from project file limit (maxProjectFiles)', () => {
      const manyFiles = {};
      for (let i = 0; i < 8; i++) {
        manyFiles[`mod_${i}.js`] = `export const v${i} = ${i};`;
      }

      // Project file limit = 5, AST cache capacity = 3
      const reg = new ProjectModuleRegistry('/fake/root', {
        maxProjectFiles: 5,
        modules: manyFiles,
        astCache: new BoundedAstCache({ maxCachedAsts: 3 })
      });

      // Registry indexed 5 files, not 8
      assert.strictEqual(reg.modules.size, 5, 'project file limit must cap indexed files at 5');
      assert.ok(reg.isPartial);
      assert.ok(reg.limitations.includes('project_file_limit_exceeded'));

      // AST cache holds 3 max — parse 3 of the 5 indexed files
      const keys = Array.from(reg.modules.keys()).slice(0, 3);
      for (const k of keys) {
        reg.getAst(k);
      }

      const cacheStats = reg.astCache.getStats();
      assert.strictEqual(cacheStats.size, 3, 'AST cache must cap at 3 entries');
      assert.strictEqual(cacheStats.misses, 3, '3 misses for 3 files parsed');

      // 4th parse triggers LRU eviction, not project file rejection
      reg.getAst(Array.from(reg.modules.keys())[3]);
      assert.strictEqual(reg.astCache.getStats().evictions, 1, 'AST cache eviction must fire independently of project file limit');
    });
  });

  // ─── 7. Nested module resolution preserves the original scan root ────────────
  describe('7. Nested module resolution preserves the original scan root', () => {
    it('child FunctionRegistry inherits scanRoot and resolves sibling imports correctly', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-411-scanroot-'));
      try {
        fs.mkdirSync(path.join(tmpDir, 'src', 'routes'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'src', 'services'), { recursive: true });

        const serviceCode = `
          function fetchUser(id) { return { id }; }
          module.exports = { fetchUser };
        `;
        const routeCode = `
          const svc = require('../services/user');
          function handler(req) {
            return svc.fetchUser(req.params.id);
          }
        `;
        fs.writeFileSync(path.join(tmpDir, 'src', 'services', 'user.js'), serviceCode);
        fs.writeFileSync(path.join(tmpDir, 'src', 'routes', 'api.js'), routeCode);

        const routeAst = parseSource(routeCode, { filePath: path.join(tmpDir, 'src', 'routes', 'api.js') }).ast;
        const reg = buildFunctionRegistry(routeAst, {
          filePath: path.join(tmpDir, 'src', 'routes', 'api.js'),
          scanRoot: tmpDir,
          code: routeCode
        });

        // scanRoot must survive registration
        assert.strictEqual(reg.scanRoot, tmpDir, 'FunctionRegistry.scanRoot must equal original scan root');

        // Resolve callee from nested route — must not falsely reject as traversal
        const handlerFn = reg.getFunction('handler');
        assert.ok(handlerFn, 'handler function must be indexed');

        // The module resolver should resolve '../services/user' without a traversal rejection
        const limitations = [];
        const resolvedMod = reg.resolveModule('../services/user', { limitations });
        assert.ok(resolvedMod, '../services/user must resolve without traversal rejection');
        assert.ok(
          !limitations.includes('module_path_outside_scan_root'),
          'sibling import must not be flagged as traversal'
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('ProjectModuleRegistry child resolution does not reset the per-registry import counter', () => {
      const reg = new ProjectModuleRegistry('/fake/root', {
        maxImportResolutions: 4,
        modules: {
          'a.js': 'import "./b";',
          'b.js': 'import "./c";',
          'c.js': 'import "./d";',
          'd.js': 'export const d = 1;'
        }
      });

      assert.strictEqual(reg.importResolutionsCount, 0);
      reg.resolveModule('./b', 'a.js');   // count: 1
      reg.resolveModule('./c', 'b.js');   // count: 2
      reg.resolveModule('./d', 'c.js');   // count: 3

      // 4th is the last permitted resolution (limit is 4, not strictly >4)
      reg.resolveModule('./b', 'a.js');   // count: 4

      // 5th must fail
      const overflow = reg.resolveModule('./c', 'b.js');
      assert.strictEqual(overflow, null, '5th resolution must be rejected when limit is 4');
      assert.ok(reg.limitations.includes('import_resolution_limit_exceeded'));
    });
  });

  // ─── 8. Parse failures do not create reusable invalid cache entries ──────────
  describe('8. Parse failures do not create reusable invalid cache entries', () => {
    it('fatally invalid syntax is not stored in cache', () => {
      const cache = new BoundedAstCache();
      // Syntax that Babel cannot recover and produces null ast
      const broken = 'function (((; // catastrophically broken';
      const r1 = cache.getOrParse(broken, 'broken.js', { relativePath: 'broken.js' });

      // Even if Babel returns partial recovery, a null ast must not be cached as a hit
      if (!r1.ast) {
        // If truly failed, cache size must still be 0 (no entry stored)
        assert.strictEqual(cache.cache.size, 0, 'failed parse must not occupy a cache slot');
        assert.strictEqual(cache.getStats().parseErrors, 1, 'parse error counter must be incremented');

        // Trying again must not produce a false hit
        cache.getOrParse(broken, 'broken.js', { relativePath: 'broken.js' });
        assert.strictEqual(cache.getStats().hits, 0, 'failed entry must not produce a cache hit on retry');
      } else {
        // Babel recovered (partial) — acceptable: it's an isPartial entry, not a hard failure
        assert.ok(r1.isPartial || r1.recoveredErrors.length > 0,
          'if babel recovered, the result must be marked partial');
      }
    });

    it('a successful parse following a failed parse for a different key is cached normally', () => {
      const cache = new BoundedAstCache();
      cache.getOrParse('function (;', 'bad.js', { relativePath: 'bad.js' }); // may fail

      const good = 'export const good = true;';
      const r = cache.getOrParse(good, 'good.js', { relativePath: 'good.js' });
      assert.ok(r.ast, 'valid file must be cached and returned normally');

      cache.getOrParse(good, 'good.js', { relativePath: 'good.js' });  // hit
      assert.strictEqual(cache.getStats().hits, 1, 'second request for valid file must be a cache hit');
    });
  });

  // ─── 9. Static module resolution does not execute project code ───────────────
  describe('9. Static module resolution does not execute project code', () => {
    it('registry resolves and caches modules containing side-effect code without executing them', () => {
      let executed = false;
      globalThis.__phase5411_test_flag = () => { executed = true; };

      const maliciousCode = `
        globalThis.__phase5411_test_flag();
        process.exit(1);
      `;

      const reg = new ProjectModuleRegistry('/fake/root', {
        modules: {
          'malicious.js': maliciousCode,
          'app.js': 'const m = require("./malicious");'
        },
        astCache: new BoundedAstCache({ maxCachedAsts: 10 })
      });

      // Resolve
      const resolved = reg.resolveModule('./malicious', 'app.js');
      assert.ok(resolved, 'malicious module must be resolvable without execution');
      assert.strictEqual(executed, false, 'resolveModule must not execute scanned code');

      // Parse / cache
      const astResult = reg.getAst('malicious.js');
      assert.ok(astResult.ast, 'getAst must return parsed AST');
      assert.strictEqual(executed, false, 'getAst must not execute scanned code');

      const stats = reg.astCache.getStats();
      assert.strictEqual(stats.size, 1, 'cached exactly one AST');
      assert.strictEqual(executed, false, 'no scanned code executed at any point');

      delete globalThis.__phase5411_test_flag;
    });
  });

  // ─── 10. Resource counters remain consistent across nested registries ─────────
  describe('10. Resource counters are consistent across nested registries', () => {
    it('separate ProjectModuleRegistry instances have independent counters', () => {
      const shared = new BoundedAstCache({ maxCachedAsts: 50 });
      const modules = { 'a.js': 'export const a = 1;', 'b.js': 'export const b = 2;' };

      const reg1 = new ProjectModuleRegistry('/root1', { modules, astCache: shared });
      const reg2 = new ProjectModuleRegistry('/root2', { modules, astCache: shared });

      reg1.resolveModule('./b', 'a.js');
      reg1.resolveModule('./b', 'a.js'); // second time, same edge counts once

      reg2.resolveModule('./b', 'a.js');

      // Independent edge and resolution counts per registry
      assert.strictEqual(reg1.importResolutionsCount, 2, 'reg1 must count 2 resolutions');
      assert.strictEqual(reg2.importResolutionsCount, 1, 'reg2 must count 1 resolution independently');
      assert.strictEqual(reg1.graphEdges.size, 1, 'reg1 must record 1 unique edge');
      assert.strictEqual(reg2.graphEdges.size, 1, 'reg2 must record 1 unique edge independently');
    });

    it('CALL_GRAPH_LIMITS (Phase 5.3) limits are not overridden by Phase 5.4.1 additions', async () => {
      const { CALL_GRAPH_LIMITS } = await import('./callGraph.js');
      assert.strictEqual(CALL_GRAPH_LIMITS.maxCallDepth, 5, 'maxCallDepth must remain 5');
      assert.strictEqual(CALL_GRAPH_LIMITS.maxTotalInvocations, 200, 'maxTotalInvocations must remain 200');
      assert.strictEqual(CALL_GRAPH_LIMITS.maxCallSitesPerFunction, 50, 'maxCallSitesPerFunction must remain 50');
    });

    it('PROJECT_REGISTRY_LIMITS and AST_CACHE_LIMITS are frozen and match specification', () => {
      assert.strictEqual(PROJECT_REGISTRY_LIMITS.maxProjectFiles, 250);
      assert.strictEqual(PROJECT_REGISTRY_LIMITS.maxModuleGraphEdges, 1000);
      assert.strictEqual(PROJECT_REGISTRY_LIMITS.maxImportResolutions, 500);
      assert.strictEqual(AST_CACHE_LIMITS.maxCachedAsts, 250);
      assert.strictEqual(AST_CACHE_LIMITS.maxAstReparses, 50);

      assert.throws(() => { PROJECT_REGISTRY_LIMITS.maxProjectFiles = 999; }, TypeError,
        'PROJECT_REGISTRY_LIMITS must be frozen');
      assert.throws(() => { AST_CACHE_LIMITS.maxCachedAsts = 999; }, TypeError,
        'AST_CACHE_LIMITS must be frozen');
    });
  });

  // ─── normalizeCacheKey unit tests ────────────────────────────────────────────
  describe('normalizeCacheKey', () => {
    it('converts Windows backslash paths to forward slash', () => {
      assert.strictEqual(normalizeCacheKey('src\\utils\\helper.js'), 'src/utils/helper.js');
    });

    it('strips leading ./ prefix', () => {
      assert.strictEqual(normalizeCacheKey('./lib/mod.js'), 'lib/mod.js');
    });

    it('handles mixed separators', () => {
      assert.strictEqual(normalizeCacheKey('.\\src\\index.js'), 'src/index.js');
    });

    it('returns source.js for null or undefined input', () => {
      assert.strictEqual(normalizeCacheKey(null), 'source.js');
      assert.strictEqual(normalizeCacheKey(undefined), 'source.js');
      assert.strictEqual(normalizeCacheKey(''), 'source.js');
    });

    it('leaves plain POSIX paths unchanged', () => {
      assert.strictEqual(normalizeCacheKey('controllers/api.js'), 'controllers/api.js');
    });
  });
});
