import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ProjectModuleRegistry } from './projectRegistry.js';
import { ProjectSymbolRegistry } from './projectSymbolRegistry.js';

function makeSymbolRegistry(modules, options = {}) {
  const projectRegistry = new ProjectModuleRegistry('/project', { modules, ...options });
  return new ProjectSymbolRegistry(projectRegistry).build();
}

describe('ProjectSymbolRegistry', () => {
  it('indexes function declarations, named function expressions, arrows, classes, methods, and object methods', () => {
    const registry = makeSymbolRegistry({
      'src/functions.js': `
        function declared(value, fallback = 1) { return value; }
        const named = function inner(input) { return input; };
        const arrow = (item) => item;
        class Worker {
          run(value) { return value; }
          static create(value) { return value; }
        }
        const helpers = {
          execute(value) { return value; },
          transform: (value) => value
        };
      `
    });
    const symbols = registry.getSymbols('src/functions.js');
    const byName = (name) => symbols.find((symbol) => symbol.localName === name);

    assert.equal(byName('declared').kind, 'function');
    assert.deepEqual(byName('declared').parameterNames, ['value', 'fallback']);
    assert.equal(byName('named').namedFunctionExpression, 'inner');
    assert.equal(byName('arrow').node.type, 'ArrowFunctionExpression');
    assert.equal(byName('Worker').kind, 'class');
    assert.equal(byName('Worker.run').kind, 'class-method');
    assert.equal(byName('Worker.create').kind, 'static-method');
    assert.equal(byName('helpers.execute').kind, 'object-method');
    assert.equal(byName('helpers.transform').kind, 'object-method');
  });

  it('resolves named exports, local aliases, default exports, and imported aliases', () => {
    const registry = makeSymbolRegistry({
      'src/target.js': `
        export function findUser(id) { return id; }
        export const configured = true;
        export default class UserService {}
      `,
      'src/consumer.js': `
        import { findUser as lookup, configured as isConfigured } from './target.js';
        import UserService from './target.js';
        import * as target from './target.js';
      `
    });
    const named = registry.resolveExport('src/target.js', 'findUser');
    const defaultExport = registry.resolveExport('src/target.js', 'default');

    assert.equal(named.status, 'resolved');
    assert.equal(named.symbol.localName, 'findUser');
    assert.equal(defaultExport.status, 'resolved');
    assert.equal(defaultExport.symbol.kind, 'default-class');
    assert.equal(registry.getImport('src/consumer.js', 'lookup').symbolId, named.symbol.id);
    assert.equal(registry.getImport('src/consumer.js', 'isConfigured').resolutionStatus, 'resolved');
    assert.equal(registry.getImport('src/consumer.js', 'UserService').symbolId, defaultExport.symbol.id);
    assert.equal(registry.getImport('src/consumer.js', 'target').isNamespace, true);
    assert.equal(registry.getImport('src/consumer.js', 'target').resolutionStatus, 'resolved');
    const importedAlias = registry.getSymbols('src/consumer.js').find((symbol) => symbol.localName === 'lookup');
    const namespace = registry.getSymbols('src/consumer.js').find((symbol) => symbol.localName === 'target');
    assert.equal(importedAlias.kind, 'import');
    assert.equal(importedAlias.targetSymbolId, named.symbol.id);
    assert.equal(namespace.kind, 'namespace-import');
  });

  it('supports named, renamed, and default re-exports with source identity and trace chains', () => {
    const registry = makeSymbolRegistry({
      'src/original.js': 'export function helper() { return 1; } export default function main() {}',
      'src/rename.js': "export { helper as renamed } from './original.js';",
      'src/default.js': "export { default } from './original.js';",
      'src/default-alias.js': "export { default as helper } from './original.js';",
      'src/barrel.js': "export { renamed as publicHelper } from './rename.js';"
    });
    const original = registry.resolveExport('src/original.js', 'helper');
    const renamed = registry.resolveExport('src/rename.js', 'renamed');
    const chained = registry.resolveExport('src/barrel.js', 'publicHelper');

    assert.equal(renamed.symbol.id, original.symbol.id);
    assert.equal(registry.resolveExport('src/default.js', 'default').symbol.localName, 'main');
    assert.equal(registry.resolveExport('src/default-alias.js', 'helper').symbol.localName, 'main');
    assert.equal(chained.symbol.id, original.symbol.id);
    assert.deepEqual(chained.reExportChain.map((entry) => entry.fromModule), ['src/barrel.js', 'src/rename.js']);
  });

  it('resolves star exports through chained barrel files while excluding default exports', () => {
    const registry = makeSymbolRegistry({
      'src/leaf.js': 'export const value = 42; export default function privateDefault() {}',
      'src/first.js': "export * from './leaf.js';",
      'src/second.js': "export * from './first.js';"
    });
    const result = registry.resolveExport('src/second.js', 'value');

    assert.equal(result.status, 'resolved');
    assert.equal(result.symbol.localName, 'value');
    assert.equal(result.reExportChain.length, 2);
    assert.equal(registry.resolveExport('src/second.js', 'default').status, 'not_found');
  });

  it('detects circular re-export chains and reports partial coverage', () => {
    const registry = makeSymbolRegistry({
      'a.js': "export * from './b.js';",
      'b.js': "export * from './a.js';"
    });
    assert.ok(registry.limitations.includes('circular_reexport_detected'));
    assert.equal(registry.getStats().coverageStatus, 'partial');
    assert.equal(registry.resolveExport('a.js', 'missing').status, 'circular');
  });

  it('marks conflicting star exports ambiguous instead of choosing one', () => {
    const registry = makeSymbolRegistry({
      'left.js': 'export const collision = 1;',
      'right.js': 'export const collision = 2;',
      'index.js': "export * from './left.js'; export * from './right.js';"
    });
    const result = registry.resolveExport('index.js', 'collision');
    assert.equal(result.status, 'ambiguous');
    assert.equal(result.symbol, null);
    assert.ok(registry.limitations.includes('ambiguous_export_detected'));
  });

  it('resolves statically identifiable CommonJS exports and re-exports', () => {
    const registry = makeSymbolRegistry({
      'src/original.js': 'function run() {} module.exports = { run };',
      'src/reexport.js': `
        const original = require('./original.js');
        exports.run = original.run;
        module.exports.extra = require('./original.js').run;
      `,
      'src/barrel.js': "module.exports = { ...require('./original.js') };"
    });
    const original = registry.resolveExport('src/original.js', 'run');
    assert.equal(registry.resolveExport('src/reexport.js', 'run').symbol.id, original.symbol.id);
    assert.equal(registry.resolveExport('src/reexport.js', 'extra').symbol.id, original.symbol.id);
    assert.equal(registry.resolveExport('src/barrel.js', 'run').symbol.id, original.symbol.id);
  });

  it('records missing local modules and unresolved relevant imports without traversing packages', () => {
    const registry = makeSymbolRegistry({
      'src/app.js': `
        import { missing } from './does-not-exist.js';
        import external from 'external-package';
      `
    });
    assert.equal(registry.getImport('src/app.js', 'missing').resolutionStatus, 'unresolved');
    assert.equal(registry.getImport('src/app.js', 'external').resolutionStatus, 'external');
    assert.ok(registry.limitations.includes('unresolved_imported_module'));
    assert.equal(registry.getStats().coverageStatus, 'partial');
    assert.equal(registry.projectRegistry.modules.size, 1);
  });

  it('keeps deterministic IDs and prevents duplicate registration across repeated builds', () => {
    const modulesA = {
      'z.js': 'export const z = () => 1;',
      'a.js': 'export function a() {}'
    };
    const modulesB = {
      'a.js': 'export function a() {}',
      'z.js': 'export const z = () => 1;'
    };
    const first = makeSymbolRegistry(modulesA);
    const second = makeSymbolRegistry(modulesB);
    const initialIds = first.getSymbols().map((symbol) => symbol.id).sort();
    first.build();
    assert.deepEqual(first.getSymbols().map((symbol) => symbol.id).sort(), initialIds);
    assert.deepEqual(second.getSymbols().map((symbol) => symbol.id).sort(), initialIds);
  });

  it('enforces normalized module paths and scan-root boundaries', () => {
    const registry = makeSymbolRegistry({
      'src\\inside.js': 'export function inside() {}',
      '../outside.js': 'export function outside() {}'
    });
    assert.equal(registry.resolveExport('src/inside.js', 'inside').status, 'resolved');
    assert.equal(registry.getSymbols().some((symbol) => symbol.modulePath.includes('outside')), false);
    assert.ok(registry.limitations.includes('module_path_outside_scan_root'));
    assert.equal(registry.getStats().coverageStatus, 'partial');
  });

  it('records unsupported dynamic exports as partial rather than guessing', () => {
    const registry = makeSymbolRegistry({
      'dynamic.js': 'exports[getName()] = function value() {};'
    });
    assert.ok(registry.limitations.includes('unsupported_dynamic_export'));
    assert.equal(registry.getStats().coverageStatus, 'partial');
    assert.equal(registry.getExports('dynamic.js').length, 0);
  });
});
