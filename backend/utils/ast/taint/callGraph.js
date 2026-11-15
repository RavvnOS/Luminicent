import fs from 'node:fs';
import path from 'node:path';
import {
  getNodeLocation,
  getMemberExpressionPath,
  getStringValue
} from '../traversal.js';
import { parseSource } from '../parser.js';
import { readProjectFile } from '../../projectFileReader.js';

export const CALL_GRAPH_LIMITS = Object.freeze({
  maxCallDepth: 5,
  maxFunctionsPerFile: 100,
  maxCallSitesPerFunction: 50,
  maxTotalInvocations: 200
});

export const NODE_BUILTIN_MODULES = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'fs/promises', 'http', 'http2', 'https', 'inspector',
  'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode',
  'querystring', 'readline', 'repl', 'stream', 'stream/promises', 'stream/web',
  'string_decoder', 'test', 'timers', 'timers/promises', 'tls', 'trace_events',
  'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib'
]);

export function isProjectModuleSpecifier(specifier, options = {}) {
  if (!specifier || typeof specifier !== 'string') return false;
  if (specifier.startsWith('node:')) return false;
  if (NODE_BUILTIN_MODULES.has(specifier)) return false;
  if (specifier.startsWith('./') || specifier.startsWith('../')) return true;
  if (path.isAbsolute(specifier)) return true;
  if (options.modules && (
    specifier in options.modules ||
    ('./' + specifier) in options.modules ||
    specifier.replace(/^\.\//, '') in options.modules
  )) {
    return true;
  }
  return false;
}

/**
 * Metadata descriptor representing a user-defined function in AST.
 */
export class FunctionDescriptor {
  constructor({
    id,
    name,
    file,
    node,
    params = [],
    paramNames = [],
    body,
    isArrowExpression = false,
    returnStatements = [],
    sourceCode = ''
  }) {
    this.id = id;
    this.name = name;
    this.file = file;
    this.filePath = file;
    this.relativePath = file;
    this.node = node;
    this.params = params;
    this.paramNames = paramNames;
    this.body = body;
    this.isArrowExpression = isArrowExpression;
    this.returnStatements = returnStatements;
    this.sourceCode = sourceCode;
  }
}

/**
 * Extracts parameter names and patterns from a function parameter list.
 */
export function extractParamNames(params = []) {
  return params.map((p, idx) => {
    if (!p) return `arg_${idx}`;
    if (p.type === 'Identifier') return p.name;
    if (p.type === 'AssignmentPattern' && p.left?.type === 'Identifier') return p.left.name;
    if (p.type === 'RestElement' && p.argument?.type === 'Identifier') return p.argument.name;
    if (p.type === 'ObjectPattern') {
      const propNames = (p.properties || []).map((prop) => {
        if (prop.value?.type === 'Identifier') return prop.value.name;
        if (prop.key?.type === 'Identifier') return prop.key.name;
        return null;
      }).filter(Boolean);
      return {
        type: 'ObjectPattern',
        properties: propNames
      };
    }
    return `arg_${idx}`;
  });
}

/**
 * Checks if an AST node is a statically identifiable truthy literal.
 */
export function isStaticallyTruthy(node) {
  if (!node) return false;
  if (node.type === 'BooleanLiteral' && node.value === true) return true;
  if (node.type === 'NumericLiteral' && node.value !== 0) return true;
  if (node.type === 'StringLiteral' && node.value.length > 0) return true;
  if (node.type === 'Literal') return Boolean(node.value);
  return false;
}

/**
 * Checks if an AST node is a statically identifiable falsy literal.
 */
export function isStaticallyFalsy(node) {
  if (!node) return false;
  if (node.type === 'BooleanLiteral' && node.value === false) return true;
  if (node.type === 'NumericLiteral' && node.value === 0) return true;
  if (node.type === 'StringLiteral' && node.value === '') return true;
  if (node.type === 'NullLiteral') return true;
  if (node.type === 'Identifier' && node.name === 'undefined') return true;
  if (node.type === 'Literal') return !node.value;
  return false;
}

/**
 * Gathers return statements belonging to this specific function,
 * without descending into nested child functions, pruning statically unreachable paths.
 */
export function findReturnStatements(bodyNode) {
  const returns = [];
  if (!bodyNode) return returns;

  function walkStatements(statements) {
    if (!Array.isArray(statements)) return;

    for (const stmt of statements) {
      if (!stmt) continue;

      // Do not descend into nested function boundaries
      if (
        stmt.type === 'FunctionDeclaration' ||
        stmt.type === 'FunctionExpression' ||
        stmt.type === 'ArrowFunctionExpression'
      ) {
        continue;
      }

      if (stmt.type === 'ReturnStatement') {
        returns.push(stmt);
        // Statements following an unconditional return in the same block are statically unreachable
        break;
      }

      if (stmt.type === 'ThrowStatement') {
        // Statements following an unconditional throw in the same block are statically unreachable
        break;
      }

      if (stmt.type === 'BlockStatement') {
        walkStatements(stmt.body);
        continue;
      }

      if (stmt.type === 'IfStatement') {
        if (isStaticallyFalsy(stmt.test)) {
          // Statically false: consequent is unreachable, walk alternate only
          if (stmt.alternate) {
            walkStatements(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate]);
          }
        } else if (isStaticallyTruthy(stmt.test)) {
          // Statically true: alternate is unreachable, walk consequent only
          let unconditionallyExits = false;
          if (stmt.consequent) {
            if (stmt.consequent.type === 'ReturnStatement' || stmt.consequent.type === 'ThrowStatement') {
              if (stmt.consequent.type === 'ReturnStatement') returns.push(stmt.consequent);
              unconditionallyExits = true;
            } else if (stmt.consequent.type === 'BlockStatement') {
              walkStatements(stmt.consequent.body);
              if (stmt.consequent.body.some((s) => s && (s.type === 'ReturnStatement' || s.type === 'ThrowStatement'))) {
                unconditionallyExits = true;
              }
            } else {
              walkStatements([stmt.consequent]);
            }
          }
          if (unconditionallyExits) {
            break;
          }
        } else {
          // Dynamic condition: both branches are potentially reachable
          if (stmt.consequent) {
            walkStatements(stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent]);
          }
          if (stmt.alternate) {
            walkStatements(stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate]);
          }
        }
        continue;
      }

      if (stmt.type === 'TryStatement') {
        if (stmt.block) walkStatements(stmt.block.body);
        if (stmt.handler?.body) walkStatements(stmt.handler.body.body);
        if (stmt.finalizer) walkStatements(stmt.finalizer.body);
        continue;
      }

      if (stmt.type === 'SwitchStatement') {
        for (const switchCase of stmt.cases || []) {
          walkStatements(switchCase.consequent);
        }
        continue;
      }

      if (stmt.type === 'ForStatement' || stmt.type === 'ForOfStatement' || stmt.type === 'ForInStatement' || stmt.type === 'WhileStatement' || stmt.type === 'DoWhileStatement') {
        const loopBody = stmt.body?.type === 'BlockStatement' ? stmt.body.body : [stmt.body];
        walkStatements(loopBody);
        continue;
      }
    }
  }

  const initialStmts = bodyNode.type === 'BlockStatement'
    ? bodyNode.body
    : Array.isArray(bodyNode)
      ? bodyNode
      : [bodyNode];

  walkStatements(initialStmts);
  return returns;
}

/**
 * Registry holding function definitions, imports, and exports for a module or file.
 */
export class FunctionRegistry {
  constructor(filePath = 'source.js', options = {}) {
    this.filePath = filePath;
    this.options = options;
    this.budgetManager = options.budgetManager || null;
    this.scanRoot = options.scanRoot || options.projectRoot || null;
    this.functions = new Map(); // function name or path -> FunctionDescriptor
    this.imports = new Map(); // local identifier -> { sourceModule, importedName, isNamespace }
    this.exports = new Map(); // exported name -> FunctionDescriptor
    this.moduleCache = new Map(); // specifier -> FunctionRegistry
  }

  registerFunction(name, descriptor) {
    if (!name || !descriptor) return;
    descriptor.moduleRegistry = this;
    if (this.functions.size >= CALL_GRAPH_LIMITS.maxFunctionsPerFile) {
      if (this.options?.limitations && !this.options.limitations.includes('max_functions_per_file_exceeded')) {
        this.options.limitations.push('max_functions_per_file_exceeded');
      }
      return;
    }
    this.functions.set(name, descriptor);
  }

  registerImport(localName, { sourceModule, importedName, isNamespace = false }) {
    if (!localName || !sourceModule) return;
    this.imports.set(localName, { sourceModule, importedName, isNamespace });
  }

  registerExport(exportedName, descriptor) {
    if (!exportedName || !descriptor) return;
    descriptor.moduleRegistry = this;
    if (this.exports.has(exportedName)) {
      const existing = this.exports.get(exportedName);
      if (existing.id !== descriptor.id) {
        if (!this.ambiguousExports) this.ambiguousExports = new Set();
        this.ambiguousExports.add(exportedName);
      }
    }
    this.exports.set(exportedName, descriptor);
  }

  getFunction(name) {
    if (!name) return null;
    return this.functions.get(name) || null;
  }

  hasFunction(name) {
    if (!name) return false;
    return this.functions.has(name);
  }

  getExport(exportedName, options = {}) {
    if (!exportedName) return null;
    if (this.ambiguousExports?.has(exportedName)) {
      if (options.limitations && !options.limitations.includes('ambiguous_export_detected')) {
        options.limitations.push('ambiguous_export_detected');
      }
    }
    return this.exports.get(exportedName) || this.functions.get(exportedName) || null;
  }

  /**
   * Resolves a CallExpression callee node to a FunctionDescriptor.
   */
  resolveCallee(calleeNode, options = {}) {
    if (!calleeNode) return null;

    // 1. Direct identifier callee, e.g. executeTask(...)
    if (calleeNode.type === 'Identifier') {
      const name = calleeNode.name;
      const local = this.functions.get(name);
      if (local) return local;

      // Check if imported from another module
      const imp = this.imports.get(name);
      if (imp) {
        const isProjectMod = isProjectModuleSpecifier(imp.sourceModule, options);
        const targetModule = this.resolveModule(imp.sourceModule, options);
        if (targetModule) {
          const exp = targetModule.getExport(imp.importedName, options);
          if (!exp && options.limitations && !options.limitations.includes('unresolved_imported_export')) {
            options.limitations.push('unresolved_imported_export');
          }
          return exp;
        } else if (isProjectMod) {
          if (options.limitations && !options.limitations.includes('unresolved_imported_module')) {
            options.limitations.push('unresolved_imported_module');
          }
        }
      }
      return null;
    }

    // 2. MemberExpression callee, e.g. helpers.runCommand(...)
    if (calleeNode.type === 'MemberExpression') {
      const fullPath = getMemberExpressionPath(calleeNode);
      if (fullPath && this.functions.has(fullPath)) {
        return this.functions.get(fullPath);
      }

      if (calleeNode.object.type === 'Identifier' && calleeNode.property) {
        const objName = calleeNode.object.name;
        const propName = calleeNode.property.type === 'Identifier'
          ? calleeNode.property.name
          : getStringValue(calleeNode.property);

        // Check if object is an imported namespace
        const imp = this.imports.get(objName);
        if (imp) {
          const isProjectMod = isProjectModuleSpecifier(imp.sourceModule, options);
          const targetModule = this.resolveModule(imp.sourceModule, options);
          if (targetModule) {
            const exp = targetModule.getExport(propName, options);
            if (!exp && options.limitations && !options.limitations.includes('unresolved_imported_export')) {
              options.limitations.push('unresolved_imported_export');
            }
            return exp;
          } else if (isProjectMod) {
            if (options.limitations && !options.limitations.includes('unresolved_imported_module')) {
              options.limitations.push('unresolved_imported_module');
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Resolves a relative or in-memory module specifier to its FunctionRegistry.
   */
  resolveModule(specifier, options = {}) {
    if (!specifier) return null;

    // Project-wide coordinators preload only scan-root-resolved registries here.
    if (this.moduleCache.has(specifier)) {
      return this.moduleCache.get(specifier);
    }
    if (options.moduleCache && options.moduleCache.has(specifier)) {
      return options.moduleCache.get(specifier);
    }

    // Guard against module paths outside scan root if scanRoot or projectRoot is specified
    const scanRoot = options.projectRoot || options.scanRoot || this.options?.projectRoot || this.options?.scanRoot || this.scanRoot || null;
    if (scanRoot && (specifier.startsWith('./') || specifier.startsWith('../') || path.isAbsolute(specifier))) {
      const baseDir = this.filePath && this.filePath !== 'source.js' ? path.dirname(path.resolve(this.filePath)) : path.resolve(scanRoot);
      const testPath = path.resolve(baseDir, specifier);
      const relFromRoot = path.relative(path.resolve(scanRoot), testPath);
      if (relFromRoot.startsWith('..') || path.isAbsolute(relFromRoot)) {
        if (options.limitations && !options.limitations.includes('module_path_outside_scan_root')) {
          options.limitations.push('module_path_outside_scan_root');
        }
        return null;
      }
    }

    // Guard against circular module imports
    const currentMod = this.filePath || 'source.js';
    const moduleChain = options.moduleChain || [currentMod];
    const isCircular = moduleChain.some((mod) => {
      if (mod === specifier) return true;
      const cleanMod = mod.replace(/^\.\//, '').replace(/\.[a-z]+$/, '');
      const cleanSpec = specifier.replace(/^\.\//, '').replace(/\.[a-z]+$/, '');
      return cleanMod && cleanSpec && cleanMod === cleanSpec;
    });

    if (isCircular) {
      const lim = options.limitations || this.options?.limitations;
      if (lim && !lim.includes('circular_module_import_detected')) {
        lim.push('circular_module_import_detected');
      }
      return null;
    }

    const activeResolutions = options.activeResolutions || new Set();
    if (activeResolutions.has(specifier)) {
      const lim = options.limitations || this.options?.limitations;
      if (lim && !lim.includes('circular_module_import_detected')) {
        lim.push('circular_module_import_detected');
      }
      return null;
    }

    activeResolutions.add(specifier);
    const childOpts = {
      ...options,
      activeResolutions,
      moduleChain: [...moduleChain, specifier]
    };

    try {
      // 1. In-memory module map (useful for unit testing and fast evaluation)
      if (options.modules) {
        let codeOrAst = null;
        let matchedKey = null;
        const baseKey = specifier.replace(/^\.\//, '');
        const candidateKeys = [
          specifier,
          baseKey,
          `./${baseKey}`
        ];

        for (const k of candidateKeys) {
          for (const ext of ['', '.js', '.ts', '.mjs', '.cjs']) {
            if (options.modules[k + ext]) {
              codeOrAst = options.modules[k + ext];
              matchedKey = k + ext;
              break;
            }
          }
          if (codeOrAst) break;
        }

        if (codeOrAst) {
          const modPath = matchedKey || `${specifier}.js`;
          const ast = typeof codeOrAst === 'string'
            ? parseSource(codeOrAst, { filePath: modPath }).ast
            : codeOrAst;
          if (ast) {
            const reg = buildFunctionRegistry(ast, {
              ...childOpts,
              filePath: modPath,
              code: typeof codeOrAst === 'string' ? codeOrAst : ''
            });
            this.moduleCache.set(specifier, reg);
            if (options.moduleCache) options.moduleCache.set(specifier, reg);
            return reg;
          }
        }
      }

      // 2. Custom file resolver hook
      if (typeof options.fileResolver === 'function') {
        const codeOrAst = options.fileResolver(specifier, this.filePath);
        if (codeOrAst) {
          const ast = typeof codeOrAst === 'string'
            ? parseSource(codeOrAst, { filePath: specifier }).ast
            : codeOrAst;
          if (ast) {
            const reg = buildFunctionRegistry(ast, {
              ...childOpts,
              filePath: specifier,
              code: typeof codeOrAst === 'string' ? codeOrAst : ''
            });
            this.moduleCache.set(specifier, reg);
            if (options.moduleCache) options.moduleCache.set(specifier, reg);
            return reg;
          }
        }
      }

      if (this.options.disableFilesystemResolution || options.disableFilesystemResolution) {
        return null;
      }

      // 3. Statically resolve relative paths on disk
      if (this.filePath && (specifier.startsWith('./') || specifier.startsWith('../'))) {
        try {
          const baseDir = path.dirname(this.filePath);
          const effectiveScanRoot = scanRoot || null;
          const candidateExtensions = ['', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.mts', '.cts'];
          const indexFiles = ['index.js', 'index.ts', 'index.jsx', 'index.tsx', 'index.mjs', 'index.cjs', 'index.mts', 'index.cts'];
          let resolvedPath = null;

          // Probe extensions directly
          for (const ext of candidateExtensions) {
            const testPath = path.resolve(baseDir, specifier + ext);
            // Guard against path traversal outside scan root if scanRoot is configured
            if (effectiveScanRoot) {
              const relFromRoot = path.relative(path.resolve(effectiveScanRoot), testPath);
              if (relFromRoot.startsWith('..') || path.isAbsolute(relFromRoot)) {
                if (options.limitations && !options.limitations.includes('module_path_outside_scan_root')) {
                  options.limitations.push('module_path_outside_scan_root');
                }
                return null;
              }
            }
            if (fs.existsSync(testPath) && fs.statSync(testPath).isFile()) {
              resolvedPath = testPath;
              break;
            }
          }

          // Probe directory index (barrel) files
          if (!resolvedPath) {
            for (const idx of indexFiles) {
              const testPath = path.resolve(baseDir, specifier, idx);
              if (effectiveScanRoot) {
                const relFromRoot = path.relative(path.resolve(effectiveScanRoot), testPath);
                if (relFromRoot.startsWith('..') || path.isAbsolute(relFromRoot)) {
                  if (options.limitations && !options.limitations.includes('module_path_outside_scan_root')) {
                    options.limitations.push('module_path_outside_scan_root');
                  }
                  return null;
                }
              }
              if (fs.existsSync(testPath) && fs.statSync(testPath).isFile()) {
                resolvedPath = testPath;
                break;
              }
            }
          }

          if (resolvedPath) {
            const content = readProjectFile(fs, resolvedPath, {
              maxBytes: 10 * 1024 * 1024,
              rootPath: effectiveScanRoot
            }).content;
            const parseResult = parseSource(content, { filePath: resolvedPath });
            if (parseResult.ast) {
              const relPath = effectiveScanRoot
                ? path.relative(effectiveScanRoot, resolvedPath).replace(/\\/g, '/')
                : resolvedPath;
              const reg = buildFunctionRegistry(parseResult.ast, {
                ...childOpts,
                scanRoot: effectiveScanRoot,
                projectRoot: effectiveScanRoot,
                filePath: resolvedPath,
                relativePath: relPath,
                code: content
              });
              this.moduleCache.set(specifier, reg);
              if (options.moduleCache) options.moduleCache.set(specifier, reg);
              return reg;
            }
          }
        } catch {
          // Fall back gracefully if disk lookup fails
        }
      }

      return null;
    } finally {
      activeResolutions.delete(specifier);
    }
  }
}

/**
 * Traverses an AST to index all function definitions, variable-assigned functions,
 * ES module imports/exports, and CommonJS requires/exports into a FunctionRegistry.
 */
export function buildFunctionRegistry(programNode, options = {}) {
  const filePath = options.filePath || options.relativePath || 'source.js';
  const sourceCode = options.code || '';
  const registry = new FunctionRegistry(filePath, options);
  const root = programNode?.type === 'File' ? programNode.program : programNode;
  if (!root || !root.body) return registry;

  const statements = Array.isArray(root.body) ? root.body : [root.body];

  for (const stmt of statements) {
    if (!stmt) continue;

    // 1. FunctionDeclaration
    if (stmt.type === 'FunctionDeclaration' && stmt.id?.name) {
      const name = stmt.id.name;
      const paramNames = extractParamNames(stmt.params);
      const returnStatements = findReturnStatements(stmt.body);
      const desc = new FunctionDescriptor({
        id: `${filePath}#${name}:${stmt.loc?.start?.line || 1}`,
        name,
        file: filePath,
        node: stmt,
        params: stmt.params || [],
        paramNames,
        body: stmt.body,
        isArrowExpression: false,
        returnStatements,
        sourceCode
      });
      registry.registerFunction(name, desc);
      continue;
    }

    // 2. VariableDeclaration holding function expressions or arrows
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations || []) {
        if (!decl || !decl.id) continue;

        // CommonJS require import: const { run } = require('./helpers') or const helpers = require('./helpers')
        if (decl.init?.type === 'CallExpression' && decl.init.callee?.name === 'require') {
          const srcArg = decl.init.arguments?.[0];
          if (srcArg && typeof srcArg.value === 'string') {
            const sourceModule = srcArg.value;
            if (decl.id.type === 'ObjectPattern') {
              for (const prop of decl.id.properties || []) {
                const importedName = prop.key?.name || prop.key?.value;
                const localName = prop.value?.name || importedName;
                if (localName && importedName) {
                  registry.registerImport(localName, { sourceModule, importedName });
                }
              }
            } else if (decl.id.type === 'Identifier') {
              registry.registerImport(decl.id.name, { sourceModule, importedName: 'default', isNamespace: true });
            }
          }
          continue;
        }

        // Variable function: const f = (x) => ... or const f = function(x) ...
        if (decl.id.type === 'Identifier' && decl.init) {
          const name = decl.id.name;
          const isFunc = decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression';
          if (isFunc) {
            const isArrowExpression = decl.init.type === 'ArrowFunctionExpression' && decl.init.body.type !== 'BlockStatement';
            const paramNames = extractParamNames(decl.init.params);
            const returnStatements = isArrowExpression ? [] : findReturnStatements(decl.init.body);
            const desc = new FunctionDescriptor({
              id: `${filePath}#${name}:${decl.loc?.start?.line || 1}`,
              name,
              file: filePath,
              node: decl.init,
              params: decl.init.params || [],
              paramNames,
              body: decl.init.body,
              isArrowExpression,
              returnStatements,
              sourceCode
            });
            registry.registerFunction(name, desc);
          }

          // Object literal holding methods: const helpers = { run(x) { ... }, exec: (x) => ... }
          if (decl.init.type === 'ObjectExpression') {
            for (const prop of decl.init.properties || []) {
              if (prop.type === 'Property' || prop.type === 'ObjectProperty' || prop.type === 'ObjectMethod') {
                const propKey = prop.key?.name || getStringValue(prop.key);
                const propVal = prop.value || prop;
                const isMethod = prop.type === 'ObjectMethod' ||
                  (propVal && (propVal.type === 'FunctionExpression' || propVal.type === 'ArrowFunctionExpression'));
                if (propKey && isMethod) {
                  const isArrowExpr = propVal.type === 'ArrowFunctionExpression' && propVal.body.type !== 'BlockStatement';
                  const paramNames = extractParamNames(propVal.params);
                  const returnStatements = isArrowExpr ? [] : findReturnStatements(propVal.body);
                  const fullName = `${name}.${propKey}`;
                  const desc = new FunctionDescriptor({
                    id: `${filePath}#${fullName}:${prop.loc?.start?.line || 1}`,
                    name: fullName,
                    file: filePath,
                    node: propVal,
                    params: propVal.params || [],
                    paramNames,
                    body: propVal.body,
                    isArrowExpression: isArrowExpr,
                    returnStatements,
                    sourceCode
                  });
                  registry.registerFunction(fullName, desc);
                  registry.registerFunction(propKey, desc);
                }
              }
            }
          }
        }
      }
      continue;
    }

    // 3. CommonJS exports: module.exports = ... or exports.run = ...
    if (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'AssignmentExpression') {
      const assign = stmt.expression;
      const leftPath = getMemberExpressionPath(assign.left);
      if (leftPath === 'module.exports' || leftPath?.startsWith('exports.')) {
        if (assign.right.type === 'Identifier') {
          const funcName = assign.right.name;
          const localDesc = registry.getFunction(funcName);
          if (localDesc) {
            const expName = leftPath.startsWith('exports.') ? leftPath.replace(/^exports\./, '') : funcName;
            registry.registerExport(expName, localDesc);
            registry.registerExport('default', localDesc);
          }
        } else if (assign.right.type === 'FunctionExpression' || assign.right.type === 'ArrowFunctionExpression') {
          const isArrowExpr = assign.right.type === 'ArrowFunctionExpression' && assign.right.body.type !== 'BlockStatement';
          const paramNames = extractParamNames(assign.right.params);
          const returnStatements = isArrowExpr ? [] : findReturnStatements(assign.right.body);
          const funcName = assign.right.id?.name || (leftPath.startsWith('exports.') ? leftPath.replace(/^exports\./, '') : 'default');
          const desc = new FunctionDescriptor({
            id: `${filePath}#${funcName}:${stmt.loc?.start?.line || 1}`,
            name: funcName,
            file: filePath,
            node: assign.right,
            params: assign.right.params || [],
            paramNames,
            body: assign.right.body,
            isArrowExpression: isArrowExpr,
            returnStatements,
            sourceCode
          });
          const expName = leftPath.startsWith('exports.') ? leftPath.replace(/^exports\./, '') : 'default';
          registry.registerExport(expName, desc);
          registry.registerExport('default', desc);
          registry.registerFunction(funcName, desc);
        } else if (assign.right.type === 'ObjectExpression') {
          for (const prop of assign.right.properties || []) {
            const keyName = prop.key?.name || getStringValue(prop.key);
            if (prop.value?.type === 'Identifier') {
              const localDesc = registry.getFunction(prop.value.name);
              if (localDesc) registry.registerExport(keyName, localDesc);
            }
          }
        }
      }
      continue;
    }

    // 4. ES Module imports: import { run } from './helpers'
    if (stmt.type === 'ImportDeclaration' && stmt.source?.value) {
      const sourceModule = stmt.source.value;
      for (const spec of stmt.specifiers || []) {
        if (spec.type === 'ImportSpecifier') {
          const importedName = spec.imported?.name || spec.imported?.value;
          const localName = spec.local?.name || importedName;
          registry.registerImport(localName, { sourceModule, importedName });
        } else if (spec.type === 'ImportDefaultSpecifier') {
          registry.registerImport(spec.local?.name, { sourceModule, importedName: 'default' });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          registry.registerImport(spec.local?.name, { sourceModule, importedName: 'default', isNamespace: true });
        }
      }
      continue;
    }

    // 5. ES Module exports: export function run(...) or export const run = ... or export { run }
    if (stmt.type === 'ExportNamedDeclaration') {
      if (stmt.specifiers && stmt.specifiers.length > 0) {
        for (const spec of stmt.specifiers) {
          if (spec.type === 'ExportSpecifier') {
            const localName = spec.local?.name;
            const exportedName = spec.exported?.name || spec.exported?.value || localName;
            const localDesc = registry.getFunction(localName);
            if (localDesc) {
              registry.registerExport(exportedName, localDesc);
            }
          }
        }
      }
      if (stmt.declaration?.type === 'FunctionDeclaration' && stmt.declaration.id?.name) {
        const name = stmt.declaration.id.name;
        const paramNames = extractParamNames(stmt.declaration.params);
        const returnStatements = findReturnStatements(stmt.declaration.body);
        const desc = new FunctionDescriptor({
          id: `${filePath}#${name}:${stmt.loc?.start?.line || 1}`,
          name,
          file: filePath,
          node: stmt.declaration,
          params: stmt.declaration.params || [],
          paramNames,
          body: stmt.declaration.body,
          isArrowExpression: false,
          returnStatements,
          sourceCode
        });
        registry.registerFunction(name, desc);
        registry.registerExport(name, desc);
      } else if (stmt.declaration?.type === 'VariableDeclaration') {
        for (const decl of stmt.declaration.declarations || []) {
          if (decl?.id?.type === 'Identifier' && decl.init) {
            const name = decl.id.name;
            const isFunc = decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression';
            if (isFunc) {
              const isArrowExpr = decl.init.type === 'ArrowFunctionExpression' && decl.init.body.type !== 'BlockStatement';
              const paramNames = extractParamNames(decl.init.params);
              const returnStatements = isArrowExpr ? [] : findReturnStatements(decl.init.body);
              const desc = new FunctionDescriptor({
                id: `${filePath}#${name}:${decl.loc?.start?.line || 1}`,
                name,
                file: filePath,
                node: decl.init,
                params: decl.init.params || [],
                paramNames,
                body: decl.init.body,
                isArrowExpression: isArrowExpr,
                returnStatements,
                sourceCode
              });
              registry.registerFunction(name, desc);
              registry.registerExport(name, desc);
            }
          }
        }
      }
      continue;
    }

    // 6. ES Module default export: export default function run(...)
    if (stmt.type === 'ExportDefaultDeclaration') {
      if (stmt.declaration?.type === 'FunctionDeclaration') {
        const name = stmt.declaration.id?.name || 'default';
        const paramNames = extractParamNames(stmt.declaration.params);
        const returnStatements = findReturnStatements(stmt.declaration.body);
        const desc = new FunctionDescriptor({
          id: `${filePath}#default:${stmt.loc?.start?.line || 1}`,
          name,
          file: filePath,
          node: stmt.declaration,
          params: stmt.declaration.params || [],
          paramNames,
          body: stmt.declaration.body,
          isArrowExpression: false,
          returnStatements,
          sourceCode
        });
        registry.registerFunction(name, desc);
        registry.registerExport('default', desc);
      } else if (stmt.declaration?.type === 'Identifier') {
        const localDesc = registry.getFunction(stmt.declaration.name);
        if (localDesc) {
          registry.registerExport('default', localDesc);
        }
      }
      continue;
    }
  }

  return registry;
}
