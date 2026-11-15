import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  ProjectModuleRegistry,
  PROJECT_REGISTRY_LIMITS,
  normalizePosixPath
} from './projectRegistry.js';
import {
  BoundedAstCache,
  AST_CACHE_LIMITS
} from './boundedAstCache.js';
import { buildFunctionRegistry } from './callGraph.js';
import { parseSource } from '../parser.js';

describe('ProjectModuleRegistry and BoundedAstCache (Phase 5.4.1)', () => {
  describe('1. Path Normalization and Boundaries', () => {
    it('normalizes scan-root-relative POSIX paths', () => {
      assert.strictEqual(normalizePosixPath('.\\src\\routes\\api.js'), 'src/routes/api.js');
      assert.strictEqual(normalizePosixPath('./controllers/user.ts'), 'controllers/user.ts');
      assert.strictEqual(normalizePosixPath('services\\db\\index.js'), 'services/db/index.js');
      assert.strictEqual(normalizePosixPath('app.js'), 'app.js');
    });

    it('rejects path traversal attempting to escape the scan root', () => {
      const reg = new ProjectModuleRegistry('/fake/root', {
        modules: {
          'app.js': 'console.log(1);'
        }
      });
      const resolved = reg.resolveModule('../../etc/passwd', 'app.js');
      assert.strictEqual(resolved, null);
      assert.ok(reg.limitations.includes('module_path_outside_scan_root'));
    });

    it('resolves nested directory imports within scan root without false traversal alarms', () => {
      const reg = new ProjectModuleRegistry('/fake/root', {
        modules: {
          'src/routes/api.js': "const db = require('../helpers/db');",
          'src/helpers/db.js': 'module.exports = { query() {} };'
        }
      });
      const resolved = reg.resolveModule('../helpers/db', 'src/routes/api.js');
      assert.ok(resolved);
      assert.strictEqual(resolved.relativePath, 'src/helpers/db.js');
      assert.strictEqual(resolved.resolved, true);
      assert.ok(!reg.limitations.includes('module_path_outside_scan_root'));
    });
  });
  describe('2. Deterministic Module Indexing', () => {
    it('indexes files deterministically regardless of input order', () => {
      const mockFiles1 = {
        'z_last.js': 'export const z = 1;',
        'a_first.js': 'export const a = 2;',
        'm_middle.ts': 'export const m = 3;'
      };
      const mockFiles2 = {
        'a_first.js': 'export const a = 2;',
        'm_middle.ts': 'export const m = 3;',
        'z_last.js': 'export const z = 1;'
      };

      const reg1 = new ProjectModuleRegistry('/test/root', { modules: mockFiles1 });
      const reg2 = new ProjectModuleRegistry('/test/root', { modules: mockFiles2 });

      const keys1 = Array.from(reg1.modules.keys());
      const keys2 = Array.from(reg2.modules.keys());

      assert.deepEqual(keys1, ['a_first.js', 'm_middle.ts', 'z_last.js']);
      assert.deepEqual(keys1, keys2);
    });

    it('indexes live filesystem directory recursively and sorts files', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-registry-test-'));
      try {
        fs.mkdirSync(path.join(tmpDir, 'routes'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'services'), { recursive: true });
        fs.writeFileSync(path.join(tmpDir, 'routes', 'api.js'), 'export const r = 1;');
        fs.writeFileSync(path.join(tmpDir, 'services', 'user.ts'), 'export const u = 2;');
        fs.writeFileSync(path.join(tmpDir, 'main.js'), 'export const m = 3;');
        // Unsupported or ignored files
        fs.writeFileSync(path.join(tmpDir, 'README.md'), 'docs');

        const reg = new ProjectModuleRegistry(tmpDir);
        reg.indexProject();

        const keys = Array.from(reg.modules.keys());
        assert.deepEqual(keys, ['main.js', 'routes/api.js', 'services/user.ts']);
        assert.strictEqual(reg.modules.get('services/user.ts').isTypeScript, true);
        assert.strictEqual(reg.modules.get('routes/api.js').isTypeScript, false);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('3. Static Module Resolution (CJS, ESM, Extensions & Barrel Files)', () => {
    const modules = {
      'src/routes/api.js': `
        const userModel = require('../models/user');
        const db = require('../db');
        import { logger } from '../utils/logger';
      `,
      'src/models/user.ts': 'export const User = {};',
      'src/db/index.js': 'module.exports = { query() {} };',
      'src/utils/logger.mjs': 'export const logger = {};',
      'src/handlers/index.tsx': 'export const Handler = () => null;'
    };

    it('resolves CommonJS relative extensionless imports', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule('../models/user', 'src/routes/api.js');
      assert.ok(res);
      assert.strictEqual(res.resolved, true);
      assert.strictEqual(res.relativePath, 'src/models/user.ts');
      assert.strictEqual(res.isBarrel, false);
    });

    it('resolves directory index files (barrel files)', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule('../db', 'src/routes/api.js');
      assert.ok(res);
      assert.strictEqual(res.resolved, true);
      assert.strictEqual(res.relativePath, 'src/db/index.js');
      assert.strictEqual(res.isBarrel, true);
    });

    it('resolves TSX directory index barrel file', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule('../handlers', 'src/routes/api.js');
      assert.ok(res);
      assert.strictEqual(res.resolved, true);
      assert.strictEqual(res.relativePath, 'src/handlers/index.tsx');
      assert.strictEqual(res.isBarrel, true);
    });

    it('resolves ESM relative imports across different extensions (.mjs, .ts)', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule('../utils/logger', 'src/routes/api.js');
      assert.ok(res);
      assert.strictEqual(res.resolved, true);
      assert.strictEqual(res.relativePath, 'src/utils/logger.mjs');
    });

    it('classifies Node.js built-ins without disk lookup', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res1 = reg.resolveModule('node:fs', 'src/routes/api.js');
      assert.ok(res1);
      assert.strictEqual(res1.isBuiltin, true);
      assert.strictEqual(res1.isExternal, true);
      assert.strictEqual(res1.resolved, false);

      const res2 = reg.resolveModule('crypto', 'src/routes/api.js');
      assert.ok(res2);
      assert.strictEqual(res2.isBuiltin, true);
      assert.strictEqual(res2.isExternal, true);
    });

    it('classifies third-party packages without traversing node_modules', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule('express', 'src/routes/api.js');
      assert.ok(res);
      assert.strictEqual(res.isThirdParty, true);
      assert.strictEqual(res.isExternal, true);
      assert.strictEqual(res.resolved, false);
    });

    it('reports unresolvable local imports explicitly with limitations', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule('./missing-module', 'src/routes/api.js');
      assert.strictEqual(res, null);
      assert.ok(reg.limitations.includes('unresolved_imported_module'));
    });

    it('handles dynamic imports gracefully with limitation', () => {
      const reg = new ProjectModuleRegistry('/fake/root', { modules });
      const res = reg.resolveModule(null, 'src/routes/api.js');
      assert.strictEqual(res, null);
      assert.ok(reg.limitations.includes('unresolved_dynamic_import'));
    });
  });

  describe('4. BoundedAstCache Mechanics and Resource Limits', () => {
    it('verifies default cache limits match specification (250 ASTs, 50 reparses)', () => {
      assert.strictEqual(AST_CACHE_LIMITS.maxCachedAsts, 250);
      assert.strictEqual(AST_CACHE_LIMITS.maxAstReparses, 50);
      const cache = new BoundedAstCache();
      const stats = cache.getStats();
      assert.strictEqual(stats.capacity, 250);
      assert.strictEqual(stats.maxReparses, 50);
    });

    it('caches parsed ASTs and serves repeated requests as cache hits', () => {
      const cache = new BoundedAstCache();
      const code = 'function add(a, b) { return a + b; }';
      const r1 = cache.getOrParse(code, 'math.js');
      assert.ok(r1.ast);
      assert.strictEqual(cache.getStats().hits, 0);
      assert.strictEqual(cache.getStats().misses, 1);

      const r2 = cache.getOrParse(code, 'math.js');
      assert.strictEqual(r1.ast, r2.ast);
      assert.strictEqual(cache.getStats().hits, 1);
      assert.strictEqual(cache.getStats().misses, 1);
    });

    it('invalidates cache entry when source code fingerprint changes', () => {
      const cache = new BoundedAstCache();
      const codeV1 = 'const x = 1;';
      const codeV2 = 'const x = 2;';

      const r1 = cache.getOrParse(codeV1, 'config.js');
      assert.ok(r1.ast);

      const r2 = cache.getOrParse(codeV2, 'config.js');
      assert.ok(r2.ast);
      assert.notStrictEqual(r1.ast, r2.ast);
      assert.strictEqual(cache.getStats().misses, 2);
    });

    it('enforces LRU capacity eviction when maxCachedAsts is reached', () => {
      const cache = new BoundedAstCache({ maxCachedAsts: 3 });
      cache.getOrParse('const a = 1;', 'a.js');
      cache.getOrParse('const b = 2;', 'b.js');
      cache.getOrParse('const c = 3;', 'c.js');
      assert.strictEqual(cache.cache.size, 3);
      assert.strictEqual(cache.getStats().evictions, 0);

      // Access 'a.js' to make it MRU; 'b.js' becomes the oldest
      cache.getOrParse('const a = 1;', 'a.js');

      // Adding 4th file must evict 'b.js'
      cache.getOrParse('const d = 4;', 'd.js');
      assert.strictEqual(cache.cache.size, 3);
      assert.strictEqual(cache.getStats().evictions, 1);
      assert.ok(cache.has('a.js'));
      assert.ok(!cache.has('b.js'));
      assert.ok(cache.has('c.js'));
      assert.ok(cache.has('d.js'));
    });

    it('tracks reparses of evicted files and enforces reparse budget limit', () => {
      const limitations = [];
      const cache = new BoundedAstCache({
        maxCachedAsts: 2,
        maxAstReparses: 2,
        limitations
      });

      // Fill cache: a.js, b.js
      cache.getOrParse('const a = 1;', 'a.js');
      cache.getOrParse('const b = 2;', 'b.js');

      // Add c.js -> evicts a.js
      cache.getOrParse('const c = 3;', 'c.js');
      assert.strictEqual(cache.getStats().evictions, 1);

      // Reparse 1: re-request a.js (evicts b.js)
      cache.getOrParse('const a = 1;', 'a.js');
      assert.strictEqual(cache.getStats().reparses, 1);

      // Reparse 2: re-request b.js (evicts c.js)
      cache.getOrParse('const b = 2;', 'b.js');
      assert.strictEqual(cache.getStats().reparses, 2);

      // Add e.js -> evicts a.js again
      cache.getOrParse('const e = 5;', 'e.js');

      // Reparse 3: re-request a.js -> exceeds reparse budget of 2!
      const failed = cache.getOrParse('const a = 1;', 'a.js');
      assert.strictEqual(failed.parseStatus, 'skipped');
      assert.strictEqual(failed.isPartial, true);
      assert.ok(limitations.includes('ast_cache_eviction_budget_exceeded'));
    });

    it('safely handles syntax errors without throwing; failed parses are not cached', () => {
      const cache = new BoundedAstCache();
      const invalidCode = 'const = ;'; // Syntax error

      // First call: parse fails
      const r1 = cache.getOrParse(invalidCode, 'bad.js');
      assert.ok(r1.parseStatus === 'failed' || r1.isPartial);
      assert.strictEqual(cache.getStats().parseErrors, 1);

      // Failed parses must not occupy a cache slot (security: no stale invalid ASTs)
      assert.strictEqual(cache.cache.size, 0, 'parse failure must not leave a cache entry');

      // Re-requesting the same broken code is another miss, not a cached hit
      const r2 = cache.getOrParse(invalidCode, 'bad.js');
      assert.strictEqual(cache.getStats().hits, 0, 'no cache hit for failed parse entry');
      assert.strictEqual(cache.getStats().misses, 2, 'both requests are misses');
      assert.strictEqual(r1.parseStatus, r2.parseStatus, 'both calls return identical failure status');
    });
  });

  describe('5. Project Registry Resource Limits', () => {
    it('enforces maxProjectFiles limit and flags partial coverage', () => {
      const manyFiles = {};
      for (let i = 0; i < 10; i++) {
        manyFiles[`file_${i}.js`] = `export const v${i} = ${i};`;
      }

      const reg = new ProjectModuleRegistry('/fake/root', {
        maxProjectFiles: 5,
        modules: manyFiles
      });

      assert.strictEqual(reg.modules.size, 5);
      assert.strictEqual(reg.isPartial, true);
      assert.ok(reg.limitations.includes('project_file_limit_exceeded'));
    });

    it('enforces maxImportResolutions limit and flags partial coverage', () => {
      const reg = new ProjectModuleRegistry('/fake/root', {
        maxImportResolutions: 3,
        modules: {
          'a.js': 'import "./b";',
          'b.js': 'import "./c";',
          'c.js': 'import "./d";',
          'd.js': 'export const d = 1;'
        }
      });

      assert.ok(reg.resolveModule('./b', 'a.js'));
      assert.ok(reg.resolveModule('./c', 'b.js'));
      assert.ok(reg.resolveModule('./d', 'c.js'));

      // 4th resolution exceeds limit of 3
      const excess = reg.resolveModule('./b', 'a.js');
      assert.strictEqual(excess, null);
      assert.strictEqual(reg.isPartial, true);
      assert.ok(reg.limitations.includes('import_resolution_limit_exceeded'));
    });

    it('enforces maxModuleGraphEdges limit and flags partial coverage', () => {
      const reg = new ProjectModuleRegistry('/fake/root', {
        maxModuleGraphEdges: 2,
        modules: {
          'a.js': 'export const a = 1;',
          'b.js': 'export const b = 2;',
          'c.js': 'export const c = 3;'
        }
      });

      reg.resolveModule('./b', 'a.js'); // edge 1: a -> b
      reg.resolveModule('./c', 'a.js'); // edge 2: a -> c
      assert.strictEqual(reg.graphEdges.size, 2);

      reg.resolveModule('./c', 'b.js'); // edge 3: exceeds limit of 2!
      assert.strictEqual(reg.isPartial, true);
      assert.ok(reg.limitations.includes('module_graph_edge_limit_exceeded'));
    });
  });

  describe('6. Regression: callGraph.js scanRoot Inheritance & Directory Resolution', () => {
    it('resolves sibling relative imports across nested directories when scanRoot is configured', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-callgraph-root-test-'));
      try {
        fs.mkdirSync(path.join(tmpDir, 'routes'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'helpers'), { recursive: true });

        const helperCode = `
          function compute(x) { return x * 2; }
          module.exports = { compute };
        `;
        const routeCode = `
          const helpers = require('../helpers/math');
          function handler(val) {
            return helpers.compute(val);
          }
        `;

        fs.writeFileSync(path.join(tmpDir, 'helpers', 'math.js'), helperCode);
        fs.writeFileSync(path.join(tmpDir, 'routes', 'api.js'), routeCode);

        const routeAst = parseSource(routeCode).ast;
        const reg = buildFunctionRegistry(routeAst, {
          filePath: path.join(tmpDir, 'routes', 'api.js'),
          scanRoot: tmpDir,
          code: routeCode
        });

        // The route calls helpers.compute
        const handlerFunc = reg.getFunction('handler');
        assert.ok(handlerFunc);
        const callExpr = handlerFunc.body.body[0].argument;

        const resolved = reg.resolveCallee(callExpr.callee);
        assert.ok(resolved, 'helpers.compute should resolve across sibling directories');
        assert.strictEqual(resolved.name, 'compute');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('resolves directory index barrel files in callGraph.js', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-callgraph-barrel-test-'));
      try {
        fs.mkdirSync(path.join(tmpDir, 'models'), { recursive: true });

        const modelIndexCode = `
          function findUser(id) { return { id }; }
          module.exports = { findUser };
        `;
        const appCode = `
          const models = require('./models');
          function test() {
            models.findUser(42);
          }
        `;

        fs.writeFileSync(path.join(tmpDir, 'models', 'index.js'), modelIndexCode);
        fs.writeFileSync(path.join(tmpDir, 'app.js'), appCode);

        const appAst = parseSource(appCode).ast;
        const reg = buildFunctionRegistry(appAst, {
          filePath: path.join(tmpDir, 'app.js'),
          scanRoot: tmpDir,
          code: appCode
        });

        const testFunc = reg.getFunction('test');
        assert.ok(testFunc);
        const callExpr = testFunc.body.body[0].expression;

        const resolved = reg.resolveCallee(callExpr.callee);
        assert.ok(resolved, 'models.findUser in models/index.js should resolve via barrel file');
        assert.strictEqual(resolved.name, 'findUser');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('7. Security Invariant: Zero Scanned Code Execution', () => {
    it('indexes, caches, and resolves modules containing hazardous side effects without executing them', () => {
      let sideEffectExecuted = false;
      globalThis.__luminicentSideEffectFlag = () => {
        sideEffectExecuted = true;
      };

      const hazardousCode = `
        globalThis.__luminicentSideEffectFlag();
        throw new Error("Scanned code execution must NEVER happen!");
      `;

      const reg = new ProjectModuleRegistry('/fake/root', {
        modules: {
          'evil.js': hazardousCode,
          'app.js': 'const evil = require("./evil");'
        }
      });

      // 1. Indexing
      reg.indexProject();
      assert.strictEqual(sideEffectExecuted, false, 'indexing must not execute code');

      // 2. Resolution
      const res = reg.resolveModule('./evil', 'app.js');
      assert.ok(res);
      assert.strictEqual(sideEffectExecuted, false, 'resolution must not execute code');

      // 3. AST Caching & Parsing
      const astRes = reg.getAst('evil.js');
      assert.ok(astRes.ast);
      assert.strictEqual(sideEffectExecuted, false, 'AST parsing must not execute code');

      delete globalThis.__luminicentSideEffectFlag;
    });
  });
});
