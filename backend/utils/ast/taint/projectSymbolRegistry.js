import { getStringValue } from '../traversal.js';
import { extractParamNames } from './callGraph.js';
import { normalizePosixPath } from './projectRegistry.js';

function nodeName(node) {
  if (!node) return null;
  if (node.type === 'Identifier' || node.type === 'PrivateName') {
    return node.name || node.id?.name || null;
  }
  return getStringValue(node);
}

function locationOf(node) {
  if (!node?.loc) return null;
  return {
    start: { line: node.loc.start?.line ?? null, column: node.loc.start?.column ?? null },
    end: { line: node.loc.end?.line ?? null, column: node.loc.end?.column ?? null }
  };
}

function stableSymbolId(modulePath, kind, localName, node) {
  const start = node?.loc?.start;
  const suffix = start ? `@${start.line}:${start.column}` : '';
  return `${modulePath}#${kind}:${localName || '<anonymous>'}${suffix}`;
}

function parameterMetadata(params = []) {
  return params.map((node, index) => ({
    index,
    name: extractParamNames([node])[0],
    type: node?.type || 'Unknown',
    optional: Boolean(node?.optional || node?.type === 'AssignmentPattern'),
    rest: node?.type === 'RestElement',
    location: locationOf(node)
  }));
}

function functionNode(node) {
  return node && (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'ObjectMethod' ||
    node.type === 'ClassMethod' ||
    node.type === 'ClassPrivateMethod'
  );
}

function addUnique(list, value) {
  if (!list.includes(value)) list.push(value);
}

export class ProjectSymbolRegistry {
  constructor(projectModuleRegistry, options = {}) {
    if (!projectModuleRegistry || !(projectModuleRegistry.modules instanceof Map)) {
      throw new TypeError('ProjectSymbolRegistry requires a ProjectModuleRegistry');
    }
    if (options.budgetManager && options.budgetManager !== projectModuleRegistry.budgetManager) {
      throw new TypeError('ProjectSymbolRegistry must share the ProjectModuleRegistry budget manager');
    }
    this.projectRegistry = projectModuleRegistry;
    this.budgetManager = projectModuleRegistry.budgetManager;
    this.limitations = options.limitations || projectModuleRegistry.limitations || [];
    this.symbols = new Map();
    this.symbolsByModule = new Map();
    this.exportsByModule = new Map();
    this.importsByModule = new Map();
    this.moduleResolutions = new Map();
    this.resolvedExports = new Map();
    this.indexedModules = new Set();
    this.isPartial = false;
  }

  build() {
    this.symbols.clear();
    this.symbolsByModule.clear();
    this.exportsByModule.clear();
    this.importsByModule.clear();
    this.moduleResolutions.clear();
    this.resolvedExports.clear();
    this.indexedModules.clear();
    this.isPartial = false;

    const modulePaths = [...this.projectRegistry.modules.keys()].sort((a, b) => a.localeCompare(b));
    for (const modulePath of modulePaths) {
      const normalizedPath = normalizePosixPath(modulePath);
      if (!this._isWithinScanRoot(normalizedPath)) {
        this._limit('module_path_outside_scan_root', 'maxProjectFiles');
        continue;
      }
      const parsed = this.projectRegistry.getAst(normalizedPath);
      if (!parsed?.ast) {
        this._limit('unresolved_project_module_ast', null);
        continue;
      }
      this._indexModule(normalizedPath, parsed.ast);
    }

    this._resolveRelationships();
    return this;
  }

  indexProject() {
    return this.build();
  }

  _isWithinScanRoot(modulePath) {
    return Boolean(
      modulePath &&
      modulePath !== '..' &&
      !modulePath.startsWith('../') &&
      !modulePath.startsWith('/') &&
      !/^[a-zA-Z]:/.test(modulePath)
    );
  }

  _moduleExportMap(modulePath) {
    if (!this.exportsByModule.has(modulePath)) {
      this.exportsByModule.set(modulePath, new Map());
    }
    return this.exportsByModule.get(modulePath);
  }

  _moduleImportMap(modulePath) {
    if (!this.importsByModule.has(modulePath)) {
      this.importsByModule.set(modulePath, new Map());
    }
    return this.importsByModule.get(modulePath);
  }

  _registerSymbol(modulePath, kind, localName, node, extra = {}) {
    const id = stableSymbolId(modulePath, kind, localName, node);
    if (this.symbols.has(id)) return this.symbols.get(id);
    const params = functionNode(node) ? (node.params || []) : [];
    const symbol = {
      id,
      modulePath,
      exportedName: null,
      localDeclarationName: localName || null,
      localName: localName || null,
      kind,
      node,
      params: parameterMetadata(params),
      parameterNames: extractParamNames(params),
      relationship: { exports: [], imports: [], reExportChain: [], reExportChains: [] },
      resolutionStatus: 'resolved',
      location: locationOf(node),
      ...extra
    };
    this.symbols.set(id, symbol);
    let names = this.symbolsByModule.get(modulePath);
    if (!names) {
      names = new Map();
      this.symbolsByModule.set(modulePath, names);
    }
    if (!names.has(localName)) names.set(localName, []);
    names.get(localName).push(id);
    return symbol;
  }

  _addExport(modulePath, exportedName, entry) {
    if (!exportedName) {
      this._limit('unsupported_dynamic_export', null);
      return;
    }
    const exports = this._moduleExportMap(modulePath);
    if (!exports.has(exportedName)) exports.set(exportedName, []);
    const entries = exports.get(exportedName);
    const signature = JSON.stringify({
      kind: entry.kind,
      symbolId: entry.symbolId,
      localName: entry.localName,
      sourceSpecifier: entry.sourceSpecifier,
      importedName: entry.importedName
    });
    if (!entries.some((existing) => existing.signature === signature)) {
      entries.push({ ...entry, exportedName, modulePath, signature });
    }
  }

  _addLocalExport(modulePath, exportedName, localName, node) {
    this._addExport(modulePath, exportedName, {
      kind: 'local',
      localName,
      location: locationOf(node)
    });
  }

  _indexModule(modulePath, rootAst) {
    const program = rootAst.type === 'File' ? rootAst.program : rootAst;
    if (!program?.body || this.indexedModules.has(modulePath)) return;
    this.indexedModules.add(modulePath);
    const statements = Array.isArray(program.body) ? program.body : [program.body];

    for (const statement of statements) {
      if (!statement) continue;

      if (statement.type === 'ImportDeclaration') {
        this._indexImport(modulePath, statement);
        continue;
      }

      if (statement.type === 'ExportAllDeclaration') {
        if (statement.exported) {
          this._addExport(modulePath, nodeName(statement.exported), {
            kind: 'reExport',
            sourceSpecifier: statement.source?.value,
            importedName: '*',
            location: locationOf(statement)
          });
        } else {
          this._addExport(modulePath, '*', {
            kind: 'star',
            sourceSpecifier: statement.source?.value,
            location: locationOf(statement)
          });
        }
        continue;
      }

      if (statement.type === 'ExportNamedDeclaration') {
        this._indexNamedExport(modulePath, statement);
        continue;
      }

      if (statement.type === 'ExportDefaultDeclaration') {
        this._indexDefaultExport(modulePath, statement);
        continue;
      }

      if (statement.type === 'FunctionDeclaration' && statement.id?.name) {
        this._registerSymbol(modulePath, 'function', statement.id.name, statement);
        continue;
      }

      if (statement.type === 'ClassDeclaration' && statement.id?.name) {
        this._registerSymbol(modulePath, 'class', statement.id.name, statement);
        this._indexClassMembers(modulePath, statement.id.name, statement);
        continue;
      }

      if (statement.type === 'VariableDeclaration') {
        this._indexVariables(modulePath, statement);
        continue;
      }

      if (statement.type === 'ExpressionStatement' &&
          statement.expression?.type === 'AssignmentExpression') {
        this._indexCommonJsAssignment(modulePath, statement.expression);
      }
    }
  }

  _indexImport(modulePath, statement) {
    const sourceSpecifier = statement.source?.value;
    for (const specifier of statement.specifiers || []) {
      const localName = specifier.local?.name;
      if (!localName) {
        this._limit('unsupported_dynamic_import', null);
        continue;
      }
      let importedName = 'default';
      let isNamespace = false;
      if (specifier.type === 'ImportSpecifier') {
        importedName = nodeName(specifier.imported) || 'default';
      } else if (specifier.type === 'ImportNamespaceSpecifier') {
        importedName = '*';
        isNamespace = true;
      }
      this._registerImport(modulePath, {
        modulePath,
        localName,
        sourceSpecifier,
        importedName,
        isNamespace,
        location: locationOf(specifier),
        resolutionStatus: 'pending',
        targetModulePath: null,
        symbolId: null,
        reExportChain: []
      }, specifier);
    }
  }

  _registerImport(modulePath, entry, node) {
    const symbol = this._registerSymbol(
      modulePath,
      entry.isNamespace ? 'namespace-import' : 'import',
      entry.localName,
      node,
      {
        importedName: entry.importedName,
        sourceSpecifier: entry.sourceSpecifier,
        isNamespace: entry.isNamespace,
        targetModulePath: null,
        targetSymbolId: null
      }
    );
    this._moduleImportMap(modulePath).set(entry.localName, {
      ...entry,
      localSymbolId: symbol.id
    });
  }

  _indexNamedExport(modulePath, statement) {
    if (statement.declaration) {
      const declaration = statement.declaration;
      if (declaration.type === 'FunctionDeclaration' && declaration.id?.name) {
        const symbol = this._registerSymbol(modulePath, 'function', declaration.id.name, declaration);
        this._addExport(modulePath, declaration.id.name, { kind: 'symbol', symbolId: symbol.id });
      } else if (declaration.type === 'ClassDeclaration' && declaration.id?.name) {
        const symbol = this._registerSymbol(modulePath, 'class', declaration.id.name, declaration);
        this._indexClassMembers(modulePath, declaration.id.name, declaration);
        this._addExport(modulePath, declaration.id.name, { kind: 'symbol', symbolId: symbol.id });
      } else if (declaration.type === 'VariableDeclaration') {
        this._indexVariables(modulePath, declaration);
        for (const declarator of declaration.declarations || []) {
          if (declarator.id?.type === 'Identifier') {
            this._addLocalExport(modulePath, declarator.id.name, declarator.id.name, declarator);
          } else {
            this._limit('unsupported_dynamic_export', null);
          }
        }
      } else {
        this._limit('unsupported_dynamic_export', null);
      }
    }

    for (const specifier of statement.specifiers || []) {
      const exportedName = nodeName(specifier.exported);
      if (statement.source?.value) {
        const importedName = specifier.type === 'ExportNamespaceSpecifier'
          ? '*'
          : nodeName(specifier.local);
        this._addExport(modulePath, exportedName, {
          kind: 'reExport',
          sourceSpecifier: statement.source.value,
          importedName,
          location: locationOf(specifier)
        });
      } else {
        const localName = nodeName(specifier.local);
        this._addLocalExport(modulePath, exportedName, localName, specifier);
      }
    }
  }

  _indexDefaultExport(modulePath, statement) {
    const declaration = statement.declaration;
    if (declaration?.type === 'FunctionDeclaration' ||
        declaration?.type === 'FunctionExpression' ||
        declaration?.type === 'ArrowFunctionExpression') {
      const localName = declaration.id?.name || 'default';
      const symbol = this._registerSymbol(modulePath, 'default-function', localName, declaration);
      this._addExport(modulePath, 'default', { kind: 'symbol', symbolId: symbol.id });
    } else if (declaration?.type === 'ClassDeclaration' || declaration?.type === 'ClassExpression') {
      const localName = declaration.id?.name || 'default';
      const symbol = this._registerSymbol(modulePath, 'default-class', localName, declaration);
      if (declaration.body) this._indexClassMembers(modulePath, localName, declaration);
      this._addExport(modulePath, 'default', { kind: 'symbol', symbolId: symbol.id });
    } else if (declaration?.type === 'Identifier') {
      this._addLocalExport(modulePath, 'default', declaration.name, statement);
    } else if (declaration) {
      const symbol = this._registerSymbol(modulePath, 'default-expression', 'default', declaration);
      this._addExport(modulePath, 'default', { kind: 'symbol', symbolId: symbol.id });
    } else {
      this._limit('unsupported_dynamic_export', null);
    }
  }

  _indexVariables(modulePath, declaration) {
    for (const declarator of declaration.declarations || []) {
      if (declarator.id?.type !== 'Identifier') {
        if (declarator.init?.type === 'CallExpression' && declarator.init.callee?.name === 'require') {
          this._indexCommonJsRequireBinding(modulePath, declarator);
        }
        continue;
      }
      const name = declarator.id.name;
      const init = declarator.init;
      if (!init) continue;
      if (init.type === 'CallExpression' && init.callee?.name === 'require') {
        const source = init.arguments?.[0];
        if (source?.type !== 'StringLiteral') {
          this._limit('unsupported_dynamic_import', null);
          continue;
        }
        this._registerImport(modulePath, {
          modulePath,
          localName: name,
          sourceSpecifier: source.value,
          importedName: '*',
          isNamespace: true,
          location: locationOf(declarator),
          resolutionStatus: 'pending',
          targetModulePath: null,
          symbolId: null,
          reExportChain: []
        }, declarator);
        continue;
      }
      if (functionNode(init)) {
        this._registerSymbol(modulePath, 'function', name, init, { namedFunctionExpression: init.id?.name || null });
      } else if (init.type === 'ClassExpression') {
        this._registerSymbol(modulePath, 'class', name, init);
        this._indexClassMembers(modulePath, name, init);
      } else if (init.type === 'ObjectExpression') {
        this._registerSymbol(modulePath, 'object', name, init);
        this._indexObjectMethods(modulePath, name, init);
      } else {
        this._registerSymbol(modulePath, 'variable', name, declarator);
      }
    }
  }

  _indexCommonJsRequireBinding(modulePath, declarator) {
    for (const property of declarator.id.properties || []) {
      const importedName = nodeName(property.key);
      const localName = property.value?.name || importedName;
      const source = declarator.init.arguments?.[0];
      if (!localName || source?.type !== 'StringLiteral') {
        this._limit('unsupported_dynamic_import', null);
        continue;
      }
      this._registerImport(modulePath, {
        modulePath,
        localName,
        sourceSpecifier: source.value,
        importedName,
        isNamespace: false,
        location: locationOf(property),
        resolutionStatus: 'pending',
        targetModulePath: null,
        symbolId: null,
        reExportChain: []
      }, property);
    }
  }

  _indexClassMembers(modulePath, className, classNode) {
    for (const member of classNode.body?.body || []) {
      if (!functionNode(member)) continue;
      const methodName = nodeName(member.key);
      if (!methodName) {
        this._limit('unsupported_dynamic_symbol', null);
        continue;
      }
      const kind = member.static ? 'static-method' : 'class-method';
      this._registerSymbol(modulePath, kind, `${className}.${methodName}`, member, {
        className,
        methodName,
        isStatic: Boolean(member.static)
      });
    }
  }

  _indexObjectMethods(modulePath, objectName, objectNode) {
    for (const property of objectNode.properties || []) {
      const value = property.value || property;
      const isMethod = property.type === 'ObjectMethod' || functionNode(value);
      if (!isMethod) continue;
      const methodName = nodeName(property.key);
      if (!methodName) {
        this._limit('unsupported_dynamic_symbol', null);
        continue;
      }
      this._registerSymbol(modulePath, 'object-method', `${objectName}.${methodName}`, value, {
        objectName,
        methodName
      });
    }
  }

  _indexCommonJsAssignment(modulePath, assignment) {
    const left = assignment.left;
    const leftName = this._memberPath(left);
    if (!leftName) {
      if (this._isCommonJsExportTarget(left)) this._limit('unsupported_dynamic_export', null);
      return;
    }

    if (leftName === 'module.exports') {
      const right = assignment.right;
      if (right.type === 'Identifier') {
        const required = this._referenceToRequire(modulePath, right);
        if (required) {
          this._addExport(modulePath, 'default', {
            kind: 'reExport',
            sourceSpecifier: required.sourceSpecifier,
            importedName: required.importedName,
            location: locationOf(assignment)
          });
          if (required.isNamespace) {
            this._addExport(modulePath, '*', {
              kind: 'star',
              sourceSpecifier: required.sourceSpecifier,
              commonJsStar: true,
              location: locationOf(assignment)
            });
          }
          return;
        }
        this._addLocalExport(modulePath, 'default', right.name, assignment);
        return;
      }
      if (functionNode(right)) {
        const symbol = this._registerSymbol(modulePath, 'commonjs-default', right.id?.name || 'default', right);
        this._addExport(modulePath, 'default', { kind: 'symbol', symbolId: symbol.id });
        return;
      }
      if (right.type === 'ClassExpression') {
        const symbol = this._registerSymbol(modulePath, 'commonjs-default-class', right.id?.name || 'default', right);
        this._indexClassMembers(modulePath, symbol.localName, right);
        this._addExport(modulePath, 'default', { kind: 'symbol', symbolId: symbol.id });
        return;
      }
      if (right.type === 'ObjectExpression') {
        const objectSymbol = this._registerSymbol(modulePath, 'commonjs-default-object', 'default', right);
        this._addExport(modulePath, 'default', { kind: 'symbol', symbolId: objectSymbol.id });
        this._indexCommonJsObject(modulePath, right);
        return;
      }
      if (right.type === 'CallExpression' && right.callee?.name === 'require') {
        const specifier = right.arguments?.[0];
        if (specifier?.type === 'StringLiteral') {
          this._addExport(modulePath, 'default', {
            kind: 'reExport',
            sourceSpecifier: specifier.value,
            importedName: 'default',
            commonJsStar: true,
            location: locationOf(assignment)
          });
          this._addExport(modulePath, '*', {
            kind: 'star',
            sourceSpecifier: specifier.value,
            commonJsStar: true,
            location: locationOf(assignment)
          });
        } else {
          this._limit('unsupported_dynamic_export', null);
        }
        return;
      }
      this._limit('unsupported_dynamic_export', null);
      return;
    }

    const namedExportPrefix = leftName.startsWith('exports.')
      ? 'exports.'
      : leftName.startsWith('module.exports.')
        ? 'module.exports.'
        : null;
    if (!namedExportPrefix) return;
    const exportedName = leftName.slice(namedExportPrefix.length);
    if (!exportedName || exportedName.includes('[')) {
      this._limit('unsupported_dynamic_export', null);
      return;
    }
    const right = assignment.right;
    if (right.type === 'Identifier') {
      this._addLocalExport(modulePath, exportedName, right.name, assignment);
    } else if (functionNode(right)) {
      const symbol = this._registerSymbol(modulePath, 'commonjs-export', exportedName, right);
      this._addExport(modulePath, exportedName, { kind: 'symbol', symbolId: symbol.id });
    } else if (right.type === 'ClassExpression') {
      const symbol = this._registerSymbol(modulePath, 'commonjs-export-class', exportedName, right);
      this._indexClassMembers(modulePath, exportedName, right);
      this._addExport(modulePath, exportedName, { kind: 'symbol', symbolId: symbol.id });
    } else if (this._referenceToRequire(modulePath, right)) {
      const required = this._referenceToRequire(modulePath, right);
      if (required) {
        this._addExport(modulePath, exportedName, {
          kind: 'reExport',
          sourceSpecifier: required.sourceSpecifier,
          importedName: required.importedName,
          location: locationOf(assignment)
        });
      } else {
        this._limit('unsupported_dynamic_export', null);
      }
    } else if (right.type === 'CallExpression' && right.callee?.name === 'require') {
      this._limit('unsupported_dynamic_export', null);
    } else {
      const symbol = this._registerSymbol(modulePath, 'commonjs-export-value', exportedName, right);
      this._addExport(modulePath, exportedName, { kind: 'symbol', symbolId: symbol.id });
    }
  }

  _indexCommonJsObject(modulePath, objectNode) {
    for (const property of objectNode.properties || []) {
      if (property.type === 'SpreadElement') {
        const argument = property.argument;
        if (argument?.type === 'CallExpression' && argument.callee?.name === 'require' &&
            argument.arguments?.[0]?.type === 'StringLiteral') {
          this._addExport(modulePath, '*', {
            kind: 'star',
            sourceSpecifier: argument.arguments[0].value,
            commonJsStar: true,
            location: locationOf(property)
          });
        } else {
          this._limit('unsupported_dynamic_export', null);
        }
        continue;
      }
      const exportedName = nodeName(property.key);
      if (!exportedName) {
        this._limit('unsupported_dynamic_export', null);
        continue;
      }
      const value = property.value || property;
      if (value.type === 'Identifier') {
        this._addLocalExport(modulePath, exportedName, value.name, property);
      } else if (functionNode(value)) {
        const symbol = this._registerSymbol(modulePath, 'commonjs-object-method', exportedName, value);
        this._addExport(modulePath, exportedName, { kind: 'symbol', symbolId: symbol.id });
      } else if (this._referenceToRequire(modulePath, value)) {
        const required = this._referenceToRequire(modulePath, value);
        this._addExport(modulePath, exportedName, {
          kind: 'reExport',
          sourceSpecifier: required.sourceSpecifier,
          importedName: required.importedName,
            location: locationOf(property)
          });
      } else {
        const symbol = this._registerSymbol(modulePath, 'commonjs-export-value', exportedName, value);
        this._addExport(modulePath, exportedName, { kind: 'symbol', symbolId: symbol.id });
      }
    }
  }

  _memberPath(node) {
    if (node?.type === 'Identifier') return node.name;
    if (node?.type !== 'MemberExpression') return null;
    const object = this._memberPath(node.object);
    const property = node.computed ? getStringValue(node.property) : nodeName(node.property);
    if (!object || !property) return null;
    return `${object}.${property}`;
  }

  _isCommonJsExportTarget(node) {
    if (node?.type !== 'MemberExpression') return false;
    if (node.object?.type === 'Identifier' && node.object.name === 'exports') return true;
    const objectPath = this._memberPath(node.object);
    return objectPath === 'module.exports';
  }

  _referenceToRequire(modulePath, node) {
    if (node?.type === 'CallExpression' && node.callee?.name === 'require') {
      const source = node.arguments?.[0];
      return source?.type === 'StringLiteral'
        ? { sourceSpecifier: source.value, importedName: 'default', isNamespace: true }
        : null;
    }
    if (node?.type === 'MemberExpression') {
      const importedName = node.computed ? getStringValue(node.property) : nodeName(node.property);
      if (!importedName) return null;
      if (node.object?.type === 'CallExpression' && node.object.callee?.name === 'require') {
        const source = node.object.arguments?.[0];
        return source?.type === 'StringLiteral'
          ? { sourceSpecifier: source.value, importedName, isNamespace: false }
          : null;
      }
      if (node.object?.type === 'Identifier') {
        const imported = this.importsByModule.get(modulePath)?.get(node.object.name);
        if (imported?.isNamespace) {
          return {
            sourceSpecifier: imported.sourceSpecifier,
            importedName,
            isNamespace: false
          };
        }
      }
    }
    if (node?.type === 'Identifier') {
      const imported = this.importsByModule.get(modulePath)?.get(node.name);
      if (imported?.isNamespace) {
        return {
          sourceSpecifier: imported.sourceSpecifier,
          importedName: 'default',
          isNamespace: true
        };
      }
    }
    return null;
  }

  _resolveModule(fromModule, sourceSpecifier) {
    const key = `${fromModule}\u0000${sourceSpecifier || ''}`;
    if (this.moduleResolutions.has(key)) return this.moduleResolutions.get(key);
    if (typeof sourceSpecifier !== 'string') {
      const resolution = { status: 'unsupported', modulePath: null };
      this.moduleResolutions.set(key, resolution);
      return resolution;
    }
    const resolved = this.projectRegistry.resolveModule(sourceSpecifier, fromModule, {
      limitations: this.limitations
    });
    let resolution;
    if (resolved?.isExternal) {
      resolution = { status: 'external', modulePath: null };
    } else if (resolved?.resolved && this._isWithinScanRoot(normalizePosixPath(resolved.relativePath))) {
      resolution = { status: 'resolved', modulePath: normalizePosixPath(resolved.relativePath) };
    } else {
      resolution = { status: 'unresolved', modulePath: null };
    }
    this.moduleResolutions.set(key, resolution);
    return resolution;
  }

  _resolveRelationships() {
    this._detectExportCycles();
    for (const [modulePath, imports] of [...this.importsByModule].sort(([a], [b]) => a.localeCompare(b))) {
      for (const [localName, imported] of [...imports].sort(([a], [b]) => a.localeCompare(b))) {
        const moduleResolution = this._resolveModule(modulePath, imported.sourceSpecifier);
        imported.targetModulePath = moduleResolution.modulePath;
        const importSymbol = this.symbols.get(imported.localSymbolId);
        if (importSymbol) importSymbol.targetModulePath = moduleResolution.modulePath;
        if (moduleResolution.status !== 'resolved') {
          imported.resolutionStatus = moduleResolution.status;
          if (importSymbol) importSymbol.resolutionStatus = moduleResolution.status;
          if (moduleResolution.status === 'unresolved' || moduleResolution.status === 'unsupported') {
            this._limit('unresolved_imported_module', null);
          }
          continue;
        }
        if (imported.isNamespace) {
          imported.resolutionStatus = 'resolved';
          if (importSymbol) importSymbol.resolutionStatus = 'resolved';
          continue;
        }
        const target = this.resolveExport(moduleResolution.modulePath, imported.importedName, {
          report: false
        });
        imported.resolutionStatus = target.status;
        imported.symbolId = target.symbol?.id || null;
        imported.reExportChain = target.reExportChain || [];
        if (importSymbol) {
          importSymbol.resolutionStatus = target.status;
          importSymbol.targetSymbolId = target.symbol?.id || null;
          if (target.symbol) {
            importSymbol.params = target.symbol.params.map((param) => ({ ...param }));
            importSymbol.parameterNames = [...target.symbol.parameterNames];
            importSymbol.relationship.imports.push(target.symbol.id);
          }
        }
        if (target.status === 'resolved' && target.symbol) {
          addUnique(target.symbol.relationship.imports, `${modulePath}:${localName}`);
        } else if (target.status !== 'external') {
          this._limit(target.status === 'ambiguous' ? 'ambiguous_export_detected' : 'unresolved_imported_export', null);
        }
      }
    }

    const paths = [...this.exportsByModule.keys()].sort((a, b) => a.localeCompare(b));
    for (const modulePath of paths) {
      const names = this._getExportNames(modulePath);
      for (const name of names) {
        const resolved = this.resolveExport(modulePath, name, { report: true });
        const entries = this._moduleExportMap(modulePath).get(name) || [];
        for (const entry of entries) {
          entry.resolutionStatus = resolved.status;
          entry.symbolId = resolved.symbol?.id || null;
          entry.reExportChain = resolved.reExportChain || [];
          if (resolved.symbol) {
            resolved.symbol.exportedName = resolved.symbol.exportedName || name;
            addUnique(resolved.symbol.relationship.exports, `${modulePath}:${name}`);
            const chain = resolved.reExportChain || [];
            const chainKey = JSON.stringify(chain);
            if (!resolved.symbol.relationship.reExportChains.some((item) => JSON.stringify(item) === chainKey)) {
              resolved.symbol.relationship.reExportChains.push(chain);
            }
            if (resolved.symbol.relationship.reExportChain.length === 0 && chain.length > 0) {
              resolved.symbol.relationship.reExportChain = chain;
            }
          }
        }
      }
    }
  }

  _detectExportCycles() {
    const active = new Set();
    const complete = new Set();
    const visit = (modulePath) => {
      if (active.has(modulePath)) {
        this._limit('circular_reexport_detected', null);
        return;
      }
      if (complete.has(modulePath)) return;
      active.add(modulePath);
      for (const star of this.exportsByModule.get(modulePath)?.get('*') || []) {
        const target = this._resolveModule(modulePath, star.sourceSpecifier);
        if (target.status === 'resolved') visit(target.modulePath);
      }
      active.delete(modulePath);
      complete.add(modulePath);
    };
    for (const modulePath of [...this.exportsByModule.keys()].sort((a, b) => a.localeCompare(b))) {
      visit(modulePath);
    }
  }

  _getExportNames(modulePath, visited = new Set()) {
    if (visited.has(modulePath)) return [];
    visited.add(modulePath);
    const names = new Set();
    const entries = this.exportsByModule.get(modulePath);
    if (entries) {
      for (const name of entries.keys()) {
        if (name !== '*') names.add(name);
      }
      for (const star of entries.get('*') || []) {
        const target = this._resolveModule(modulePath, star.sourceSpecifier);
        if (target.status === 'resolved') {
          for (const name of this._getExportNames(target.modulePath, visited)) {
            if (name !== 'default') names.add(name);
          }
        }
      }
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }

  resolveExport(modulePath, exportedName, options = {}) {
    const normalizedPath = normalizePosixPath(modulePath);
    const cacheKey = `${normalizedPath}\u0000${exportedName}`;
    if (!options.stack && this.resolvedExports.has(cacheKey)) {
      return this._copyResolution(this.resolvedExports.get(cacheKey));
    }
    const stack = options.stack || [];
    if (stack.includes(cacheKey)) {
      this._limit('circular_reexport_detected', null);
      return { status: 'circular', symbol: null, reExportChain: [] };
    }
    const nextStack = [...stack, cacheKey];
    const explicit = this.exportsByModule.get(normalizedPath)?.get(exportedName) || [];
    let candidateEntries = explicit;
    if (explicit.length === 0 && exportedName !== 'default') {
      candidateEntries = this.exportsByModule.get(normalizedPath)?.get('*') || [];
    }

    const candidates = [];
    let unresolvedStatus = null;
    for (const entry of candidateEntries) {
      let result;
      if (entry.kind === 'symbol') {
        result = { status: 'resolved', symbol: this.symbols.get(entry.symbolId) || null, reExportChain: [] };
      } else if (entry.kind === 'local') {
        result = this._resolveLocal(normalizedPath, entry.localName);
      } else if (entry.kind === 'reExport' || entry.kind === 'star') {
        const target = this._resolveModule(normalizedPath, entry.sourceSpecifier);
        if (target.status !== 'resolved') {
          result = { status: target.status, symbol: null, reExportChain: [] };
          if (target.status === 'unresolved' || target.status === 'unsupported') {
            this._limit('unresolved_reexport_module', null);
          }
        } else if (entry.kind === 'star' && exportedName === 'default') {
          continue;
        } else if (entry.importedName === '*') {
          result = {
            status: 'resolved',
            symbol: null,
            namespaceModulePath: target.modulePath,
            reExportChain: []
          };
        } else {
          const targetName = entry.kind === 'star' ? exportedName : entry.importedName;
          result = this.resolveExport(target.modulePath, targetName, { stack: nextStack });
        }
        if (result.status === 'resolved') {
          result.reExportChain = [
            {
              fromModule: normalizedPath,
              toModule: target.modulePath,
              importedName: entry.kind === 'star' ? exportedName : entry.importedName,
              exportedName
            },
            ...(result.reExportChain || [])
          ];
        }
      } else {
        result = { status: 'unsupported', symbol: null, reExportChain: [] };
      }
      if (result.status === 'resolved' && (result.symbol || result.namespaceModulePath)) {
        const candidateKey = result.symbol?.id || `namespace:${result.namespaceModulePath}`;
        if (!candidates.some((candidate) => candidate.key === candidateKey)) {
          candidates.push({ key: candidateKey, result });
        }
      } else if (result.status !== 'not_found') {
        unresolvedStatus = unresolvedStatus || result.status;
      }
    }

    let result;
    if (candidates.length > 1) {
      result = { status: 'ambiguous', symbol: null, reExportChain: [] };
      this._limit('ambiguous_export_detected', null);
    } else if (candidates.length === 1) {
      result = candidates[0].result;
    } else if (unresolvedStatus) {
      result = { status: unresolvedStatus, symbol: null, reExportChain: [] };
    } else {
      result = { status: 'not_found', symbol: null, reExportChain: [] };
    }
    if (options.report && result.status !== 'resolved' && result.status !== 'external') {
      this._limit(result.status === 'ambiguous' ? 'ambiguous_export_detected' : 'unresolved_export', null);
    }
    if (!options.stack) this.resolvedExports.set(cacheKey, result);
    return this._copyResolution(result);
  }

  _resolveLocal(modulePath, localName) {
    const imported = this.importsByModule.get(modulePath)?.get(localName);
    if (imported?.isNamespace && imported.resolutionStatus === 'resolved' && imported.targetModulePath) {
      return {
        status: 'resolved',
        symbol: null,
        namespaceModulePath: imported.targetModulePath,
        reExportChain: []
      };
    }
    if (imported?.resolutionStatus === 'resolved' && imported.symbolId) {
      return {
        status: 'resolved',
        symbol: this.symbols.get(imported.symbolId) || null,
        reExportChain: imported.reExportChain || []
      };
    }
    if (imported?.resolutionStatus === 'external') {
      return { status: 'external', symbol: null, reExportChain: [] };
    }
    if (imported) {
      return { status: imported.resolutionStatus || 'not_found', symbol: null, reExportChain: [] };
    }
    const symbolIds = this.symbolsByModule.get(modulePath)?.get(localName) || [];
    const uniqueIds = [...new Set(symbolIds)];
    if (uniqueIds.length > 1) {
      return { status: 'ambiguous', symbol: null, reExportChain: [] };
    }
    if (uniqueIds.length === 1) {
      return { status: 'resolved', symbol: this.symbols.get(uniqueIds[0]), reExportChain: [] };
    }
    return { status: imported?.resolutionStatus || 'not_found', symbol: null, reExportChain: [] };
  }

  _copyResolution(result) {
    return {
      ...result,
      reExportChain: (result.reExportChain || []).map((item) => ({ ...item })),
      symbol: result.symbol || null
    };
  }

  getImport(modulePath, localName) {
    const entry = this.importsByModule.get(normalizePosixPath(modulePath))?.get(localName);
    return entry ? { ...entry, reExportChain: [...entry.reExportChain] } : null;
  }

  getExports(modulePath) {
    const normalizedPath = normalizePosixPath(modulePath);
    return this._getExportNames(normalizedPath).map((exportedName) => ({
      exportedName,
      ...this.resolveExport(normalizedPath, exportedName)
    }));
  }

  getSymbols(modulePath = null) {
    if (!modulePath) return [...this.symbols.values()];
    const normalizedPath = normalizePosixPath(modulePath);
    return [...this.symbols.values()].filter((symbol) => symbol.modulePath === normalizedPath);
  }

  _limit(code, resource) {
    this.isPartial = true;
    if (code && !this.limitations.includes(code)) this.limitations.push(code);
    if (resource && this.budgetManager) {
      const details = this.budgetManager.getLimitations().find((item) => item.resource === resource);
      if (details && code && !this.limitations.includes(details.code)) this.limitations.push(details.code);
    }
  }

  getStats() {
    return {
      modulesIndexed: this.indexedModules.size,
      symbolsIndexed: this.symbols.size,
      exportCount: [...this.exportsByModule.values()].reduce(
        (total, exports) => total + [...exports.keys()].filter((name) => name !== '*').length,
        0
      ),
      importCount: [...this.importsByModule.values()].reduce((total, imports) => total + imports.size, 0),
      coverageStatus: this.isPartial || this.limitations.length > 0 ? 'partial' : 'completed',
      limitations: [...this.limitations]
    };
  }
}
