import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseSource } from '../parser.js';
import {
  CALL_GRAPH_LIMITS,
  FunctionDescriptor,
  FunctionRegistry,
  buildFunctionRegistry,
  extractParamNames,
  findReturnStatements
} from './callGraph.js';

describe('AST Call Graph and Inter-Procedural Registry (Phase 5.3)', () => {
  describe('CALL_GRAPH_LIMITS Constants', () => {
    it('verifies calibrated resource limits for call-graph exploration', () => {
      assert.strictEqual(CALL_GRAPH_LIMITS.maxCallDepth, 5);
      assert.strictEqual(CALL_GRAPH_LIMITS.maxFunctionsPerFile, 100);
      assert.strictEqual(CALL_GRAPH_LIMITS.maxCallSitesPerFunction, 50);
      assert.strictEqual(CALL_GRAPH_LIMITS.maxTotalInvocations, 200);
      assert.ok(Object.isFrozen(CALL_GRAPH_LIMITS));
    });
  });

  describe('extractParamNames', () => {
    it('extracts identifiers, default values, rest elements, and object patterns', () => {
      const code = 'function test(a, b = 10, ...rest) {}';
      const ast = parseSource(code).ast;
      const fnNode = ast.program.body[0];
      const params = extractParamNames(fnNode.params);
      assert.deepEqual(params, ['a', 'b', 'rest']);

      const codeObj = 'function testDestruct({ id, name: userName }) {}';
      const astObj = parseSource(codeObj).ast;
      const fnNodeObj = astObj.program.body[0];
      const paramsObj = extractParamNames(fnNodeObj.params);
      assert.strictEqual(paramsObj[0].type, 'ObjectPattern');
      assert.deepEqual(paramsObj[0].properties, ['id', 'userName']);
    });
  });

  describe('findReturnStatements', () => {
    it('finds top-level function returns without descending into nested child functions', () => {
      const code = `
        function outer(x) {
          if (x > 0) return x * 2;
          const inner = () => { return 42; };
          function nested() { return "nested"; }
          return -1;
        }
      `;
      const ast = parseSource(code).ast;
      const fnNode = ast.program.body[0];
      const returns = findReturnStatements(fnNode.body);
      assert.strictEqual(returns.length, 2);
    });
  });

  describe('buildFunctionRegistry', () => {
    it('indexes function declarations, arrow functions, and method properties', () => {
      const code = `
        function directDecl(a) { return a; }
        const arrowFunc = (b) => b + 1;
        const helpers = {
          format(str) { return str.trim(); },
          exec: (cmd) => cmd
        };
      `;
      const ast = parseSource(code).ast;
      const reg = buildFunctionRegistry(ast, { code, filePath: 'service.js' });

      assert.ok(reg.hasFunction('directDecl'));
      assert.ok(reg.hasFunction('arrowFunc'));
      assert.ok(reg.hasFunction('helpers.format'));
      assert.ok(reg.hasFunction('helpers.exec'));
      assert.ok(reg.hasFunction('format'));
      assert.ok(reg.hasFunction('exec'));
    });

    it('indexes CommonJS and ES module exports and imports', () => {
      const code = `
        import { utility } from './utils';
        import defaultHelper from './defaultHelper';
        const { runner } = require('./runner');
        export function publicApi(x) { return x; }
        export const asyncTask = async (y) => y;
        module.exports = { publicApi };
      `;
      const ast = parseSource(code).ast;
      const reg = buildFunctionRegistry(ast, { code, filePath: 'api.js' });

      assert.ok(reg.imports.has('utility'));
      assert.strictEqual(reg.imports.get('utility').sourceModule, './utils');
      assert.ok(reg.imports.has('defaultHelper'));
      assert.ok(reg.imports.has('runner'));
      assert.strictEqual(reg.imports.get('runner').sourceModule, './runner');

      assert.ok(reg.exports.has('publicApi'));
      assert.ok(reg.exports.has('asyncTask'));
    });
  });

  describe('FunctionRegistry resolution', () => {
    it('resolves MemberExpression callees and namespace imports', () => {
      const modules = {
        './tools': `
          function run(x) { return x; }
          module.exports = { run };
        `
      };
      const code = `
        const tools = require('./tools');
        function main() {
          tools.run("test");
        }
      `;
      const ast = parseSource(code).ast;
      const reg = buildFunctionRegistry(ast, { code, filePath: 'main.js' });
      const mainFunc = ast.program.body[1];
      const callExpr = mainFunc.body.body[0].expression;

      const resolved = reg.resolveCallee(callExpr.callee, { modules });
      assert.ok(resolved);
      assert.strictEqual(resolved.name, 'run');
    });

    it('supports custom fileResolver hook', () => {
      const code = `
        import { compute } from 'virtual:math';
        function run() { compute(10); }
      `;
      const fileResolver = (specifier) => {
        if (specifier === 'virtual:math') {
          return 'export function compute(n) { return n * n; }';
        }
        return null;
      };
      const ast = parseSource(code).ast;
      const reg = buildFunctionRegistry(ast, { code, filePath: 'app.js' });
      const runFunc = ast.program.body[1];
      const callExpr = runFunc.body.body[0].expression;

      const resolved = reg.resolveCallee(callExpr.callee, { fileResolver });
      assert.ok(resolved);
      assert.strictEqual(resolved.name, 'compute');
    });

    it('detects ambiguous or duplicate exports and records limitation', () => {
      const reg = new FunctionRegistry('lib.js');
      const desc1 = new FunctionDescriptor({ id: 'lib#fn1:1', name: 'fn1' });
      const desc2 = new FunctionDescriptor({ id: 'lib#fn2:10', name: 'fn2' });
      reg.registerExport('helper', desc1);
      reg.registerExport('helper', desc2);

      const limitations = [];
      const exp = reg.getExport('helper', { limitations });
      assert.ok(exp);
      assert.ok(limitations.includes('ambiguous_export_detected'));
    });

    it('enforces maxFunctionsPerFile limit and records limitation', () => {
      const limitations = [];
      const reg = new FunctionRegistry('heavy.js', { limitations });
      for (let i = 0; i < 105; i++) {
        reg.registerFunction(`fn_${i}`, new FunctionDescriptor({ id: `heavy#fn_${i}:1`, name: `fn_${i}` }));
      }
      assert.strictEqual(reg.functions.size, CALL_GRAPH_LIMITS.maxFunctionsPerFile);
      assert.ok(limitations.includes('max_functions_per_file_exceeded'));
    });

    it('prunes statically unreachable returns in if (false) and keeps if (true)', () => {
      const codeFalse = `
        function testF() {
          if (false) return 1;
          return 2;
        }
      `;
      const astF = parseSource(codeFalse).ast;
      const returnsF = findReturnStatements(astF.program.body[0].body);
      assert.strictEqual(returnsF.length, 1);
      assert.strictEqual(returnsF[0].argument.value, 2);

      const codeTrue = `
        function testT() {
          if (true) return 1;
          return 2;
        }
      `;
      const astT = parseSource(codeTrue).ast;
      const returnsT = findReturnStatements(astT.program.body[0].body);
      assert.strictEqual(returnsT.length, 1);
      assert.strictEqual(returnsT[0].argument.value, 1);
    });
  });
});
