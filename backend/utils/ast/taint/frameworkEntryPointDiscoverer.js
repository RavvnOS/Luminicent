import { getNodeLocation, getStringValue, walkAST } from '../traversal.js';
import { normalizePosixPath } from './projectRegistry.js';

export const FRAMEWORK_ROUTE_METHODS = Object.freeze(new Set([
  'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all', 'use'
]));

const EXPRESS_MODULE = 'express';

function addUnique(values, value) {
  if (value && !values.includes(value)) values.push(value);
}

function staticMemberName(node) {
  if (node?.type !== 'MemberExpression') return null;
  if (!node.computed && node.property?.type === 'Identifier') return node.property.name;
  return getStringValue(node.property);
}

function requireModule(node, specifier) {
  return node?.type === 'CallExpression' &&
    node.callee?.type === 'Identifier' &&
    node.callee.name === 'require' &&
    getStringValue(node.arguments?.[0]) === specifier;
}

function isStaticPath(node) {
  if (!node) return false;
  if (node.type === 'StringLiteral' || node.type === 'RegExpLiteral') return true;
  if (node.type === 'TemplateLiteral') return node.expressions?.length === 0;
  if (node.type === 'ArrayExpression') {
    return node.elements?.every((item) => item && isStaticPath(item)) || false;
  }
  return false;
}

function declarationNames(node, names = []) {
  if (!node) return names;
  if (node.type === 'Identifier') {
    names.push(node.name);
  } else if (node.type === 'ObjectPattern') {
    for (const property of node.properties || []) {
      if (property.type === 'RestElement') declarationNames(property.argument, names);
      else declarationNames(property.value, names);
    }
  } else if (node.type === 'ArrayPattern') {
    for (const element of node.elements || []) declarationNames(element, names);
  } else if (node.type === 'AssignmentPattern') {
    declarationNames(node.left, names);
  } else if (node.type === 'RestElement') {
    declarationNames(node.argument, names);
  } else if (node.type === 'TSParameterProperty') {
    declarationNames(node.parameter, names);
  }
  return names;
}

function rootIdentifier(node) {
  let current = node;
  while (current?.type === 'MemberExpression') current = current.object;
  return current?.type === 'Identifier' ? current.name : null;
}

function collectFrameworkBindings(ast, budgetManager, limitations) {
  const expressBindings = new Set();
  const routerFactoryBindings = new Set();
  const routerBindings = new Set();
  const routerCandidates = new Set();
  const declarations = new Map();
  const variableDeclarators = [];
  const calls = [];
  const reassignedBindings = new Set();
  const mutatedObjects = new Set();
  const aliasSources = new Map();
  const aliasesBySource = new Map();

  const recordDeclaration = (name) => {
    declarations.set(name, (declarations.get(name) || 0) + 1);
  };
  const registerRouterFactory = (name) => {
    if (name) routerFactoryBindings.add(name);
  };

  let visits = 0;
  let stoppedForDuration = false;
  const traversal = walkAST(ast, {
    enter(_node, _parent, context) {
      visits++;
      if (visits % 128 !== 0) return;
      const duration = budgetManager?.check('maxAnalysisDurationMs');
      if (duration && !duration.allowed) {
        addUnique(limitations, duration.code);
        stoppedForDuration = true;
        context.stop();
      }
    },
    ImportDeclaration(node) {
      if (node.source?.value !== EXPRESS_MODULE) return;
      for (const specifier of node.specifiers || []) {
        if (node.importKind === 'type' || specifier.importKind === 'type') continue;
        const localName = specifier.local?.name;
        if (!localName) continue;
        recordDeclaration(localName);
        if (specifier.type === 'ImportSpecifier') {
          const importedName = specifier.imported?.name || specifier.imported?.value;
          if (importedName === 'Router') {
            registerRouterFactory(localName);
          } else if (importedName === 'default') {
            expressBindings.add(localName);
          }
        } else {
          expressBindings.add(localName);
        }
      }
    },
    VariableDeclarator(node) {
      variableDeclarators.push(node);
      for (const name of declarationNames(node.id)) recordDeclaration(name);
      if (node.id?.type === 'Identifier' && node.init?.type === 'Identifier') {
        aliasSources.set(node.id.name, node.init.name);
        if (!aliasesBySource.has(node.init.name)) aliasesBySource.set(node.init.name, new Set());
        aliasesBySource.get(node.init.name).add(node.id.name);
      }
    },
    AssignmentExpression(node) {
      if (node.left?.type === 'Identifier') reassignedBindings.add(node.left.name);
      else if (node.left?.type === 'MemberExpression') {
        const name = rootIdentifier(node.left.object);
        if (name) mutatedObjects.add(name);
      } else {
        for (const name of declarationNames(node.left)) reassignedBindings.add(name);
      }
    },
    ForInStatement(node) {
      if (node.left?.type !== 'VariableDeclaration') {
        for (const name of declarationNames(node.left)) reassignedBindings.add(name);
      }
    },
    ForOfStatement(node) {
      if (node.left?.type !== 'VariableDeclaration') {
        for (const name of declarationNames(node.left)) reassignedBindings.add(name);
      }
    },
    UpdateExpression(node) {
      if (node.argument?.type === 'Identifier') reassignedBindings.add(node.argument.name);
    },
    UnaryExpression(node) {
      if (node.operator === 'delete' && node.argument?.type === 'MemberExpression') {
        const name = rootIdentifier(node.argument.object);
        if (name) mutatedObjects.add(name);
      }
    },
    CallExpression(node) {
      calls.push(node);
      const owner = node.callee?.type === 'MemberExpression' &&
        node.callee.object?.type === 'Identifier'
        ? node.callee.object.name
        : null;
      const method = staticMemberName(node.callee);
      const reflectiveMutation =
        (owner === 'Object' && ['assign', 'defineProperty'].includes(method)) ||
        (owner === 'Reflect' && method === 'set');
      const target = reflectiveMutation ? node.arguments?.[0] : null;
      const name = target?.type === 'Identifier' ? target.name : rootIdentifier(target);
      if (name) mutatedObjects.add(name);
    },
    FunctionDeclaration(node) {
      if (node.id?.name) recordDeclaration(node.id.name);
      for (const param of node.params || []) {
        for (const name of declarationNames(param)) recordDeclaration(name);
      }
    },
    FunctionExpression(node) {
      if (node.id?.name) recordDeclaration(node.id.name);
      for (const param of node.params || []) {
        for (const name of declarationNames(param)) recordDeclaration(name);
      }
    },
    ArrowFunctionExpression(node) {
      for (const param of node.params || []) {
        for (const name of declarationNames(param)) recordDeclaration(name);
      }
    },
    ObjectMethod(node) {
      for (const param of node.params || []) {
        for (const name of declarationNames(param)) recordDeclaration(name);
      }
    },
    ClassMethod(node) {
      for (const param of node.params || []) {
        for (const name of declarationNames(param)) recordDeclaration(name);
      }
    },
    ClassPrivateMethod(node) {
      for (const param of node.params || []) {
        for (const name of declarationNames(param)) recordDeclaration(name);
      }
    },
    CatchClause(node) {
      for (const name of declarationNames(node.param)) recordDeclaration(name);
    }
  });
  if (traversal.nodeLimitExceeded || traversal.depthLimitExceeded) {
    addUnique(limitations, 'framework_discovery_traversal_limit_exceeded');
  }
  if (stoppedForDuration) {
    return {
      routerBindings,
      isExpressFactory: () => false,
      isRouterFactoryCall: () => false,
      declarations,
      stoppedForDuration
    };
  }

  for (const declarator of variableDeclarators) {
    const init = declarator.init;
    if (declarator.id?.type === 'Identifier') {
      if (requireModule(init, EXPRESS_MODULE)) expressBindings.add(declarator.id.name);
    } else if (declarator.id?.type === 'ObjectPattern' && requireModule(init, EXPRESS_MODULE)) {
      for (const property of declarator.id.properties || []) {
        const importedName = property.key?.name || getStringValue(property.key);
        const local = property.value?.type === 'Identifier' ? property.value.name : null;
        if (importedName === 'Router') registerRouterFactory(local);
      }
    }
  }

  const usable = (name) =>
    declarations.get(name) === 1 && !reassignedBindings.has(name);
  const isExpressFactory = (node) => {
    if (node?.type === 'Identifier') return expressBindings.has(node.name) && usable(node.name);
    if (node?.type === 'CallExpression' && requireModule(node, EXPRESS_MODULE)) return true;
    return false;
  };
  const isRouterFactory = (node) => {
    if (node?.type === 'Identifier') {
      return routerFactoryBindings.has(node.name) && usable(node.name);
    }
    if (node?.type === 'MemberExpression') {
      return staticMemberName(node) === 'Router' &&
        (isExpressFactory(node.object) || requireModule(node.object, EXPRESS_MODULE));
    }
    return false;
  };
  const isRouterFactoryCall = (node) =>
    node?.type === 'CallExpression' && isRouterFactory(node.callee);

  const isExpressAppCall = (node) =>
    node?.type === 'CallExpression' && isExpressFactory(node.callee);

  for (let pass = 0; pass < 2; pass++) {
    const addBinding = (set, name) => {
      if (name && usable(name)) {
        set.add(name);
      }
    };
    for (const declarator of variableDeclarators) {
      if (declarator.id?.type !== 'Identifier') continue;
      const name = declarator.id.name;
      const init = declarator.init;
      if (init?.type === 'Identifier') {
        if (isExpressFactory(init)) addBinding(expressBindings, name);
        if (isRouterFactory(init)) addBinding(routerFactoryBindings, name);
        if (routerCandidates.has(init.name)) addBinding(routerCandidates, name);
      }
      if (isExpressAppCall(init) || isRouterFactoryCall(init)) {
        addBinding(routerCandidates, name);
      }
    }
  }

  const reachesMutatedObject = (name, visited = new Set()) => {
    if (visited.has(name)) return false;
    visited.add(name);
    if (mutatedObjects.has(name)) return true;
    const source = aliasSources.get(name);
    if (source && reachesMutatedObject(source, visited)) return true;
    for (const alias of aliasesBySource.get(name) || []) {
      if (reachesMutatedObject(alias, visited)) return true;
    }
    return false;
  };
  const preliminaryRouterBindings = new Set(
    [...routerCandidates].filter((name) =>
      usable(name) && !reachesMutatedObject(name)
    )
  );
  const isPreliminaryRouterReceiver = (node) =>
    (node?.type === 'Identifier' && preliminaryRouterBindings.has(node.name)) ||
    isRouterFactoryCall(node);
  for (const call of calls) {
    const callee = call.callee;
    const method = callee?.type === 'MemberExpression'
      ? staticMemberName(callee)
      : null;
    const receiverVerified = callee?.type === 'MemberExpression' &&
      isPreliminaryRouterReceiver(callee.object);
    if (receiverVerified &&
        (FRAMEWORK_ROUTE_METHODS.has(method) || method === 'route')) {
      continue;
    }
    for (const argument of call.arguments || []) {
      if (argument?.type === 'Identifier' && routerCandidates.has(argument.name)) {
        mutatedObjects.add(argument.name);
      }
    }
  }
  for (const name of routerCandidates) {
    if (usable(name) && !reachesMutatedObject(name)) routerBindings.add(name);
  }

  return {
    routerBindings: new Set([...routerBindings].filter(usable)),
    routerCandidates,
    isExpressFactory,
    isRouterFactoryCall,
    declarations,
    reassignedBindings,
    mutatedObjects,
    reachesMutatedObject,
    stoppedForDuration
  };
}

function resolveFunctionReference(node, modulePath, options) {
  const registry = options.functionRegistries.get(modulePath);
  const descriptorsBySymbolId = options.functionDescriptorsBySymbolId;
  if (!node) return { status: 'unresolved' };
  if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression' || node.type === 'ObjectMethod' ||
      node.type === 'ClassMethod' || node.type === 'ClassPrivateMethod') {
    return { status: 'resolved', node, modulePath, importExport: null };
  }

  if (node.type === 'Identifier') {
    const localDescriptor = registry?.getFunction(node.name);
    if (localDescriptor?.node) {
      return {
        status: 'resolved',
        node: localDescriptor.node,
        modulePath,
        importExport: null
      };
    }
    return resolveImportedReference(node.name, null, modulePath, options);
  }

  if (node.type === 'MemberExpression') {
    const memberName = staticMemberName(node);
    if (!memberName || node.object?.type !== 'Identifier') return { status: 'unresolved' };
    const localName = node.object.name;
    const localDescriptor = registry?.getFunction(`${localName}.${memberName}`);
    if (localDescriptor?.node) {
      return {
        status: 'resolved',
        node: localDescriptor.node,
        modulePath,
        importExport: null
      };
    }
    return resolveImportedReference(localName, memberName, modulePath, options);
  }

  return { status: 'unresolved' };
}

function resolveImportedReference(localName, memberName, modulePath, options) {
  const relation = options.symbolRegistry.getImport(modulePath, localName);
  if (!relation) return { status: 'unresolved' };
  if (relation.resolutionStatus === 'external') return { status: 'external' };
  if (relation.resolutionStatus === 'ambiguous') return { status: 'ambiguous' };
  if (relation.resolutionStatus !== 'resolved' || !relation.targetModulePath) {
    return { status: 'unresolved' };
  }

  let symbol = null;
  let reExportChain = relation.reExportChain || [];
  if (relation.isNamespace) {
    if (!memberName) {
      const localImport = options.symbolRegistry.getSymbols(modulePath)
        .find((candidate) => candidate.id === relation.localSymbolId);
      if (localImport?.node?.type === 'ImportNamespaceSpecifier') {
        return { status: 'unresolved' };
      }
    }
    const exported = options.symbolRegistry.resolveExport(
      relation.targetModulePath,
      memberName || 'default',
      { report: false }
    );
    if (exported.status !== 'resolved') return { status: exported.status };
    symbol = exported.symbol;
    reExportChain = exported.reExportChain || [];
  } else {
    const resolved = relation.symbolId
      ? options.symbolRegistry.getSymbols(relation.targetModulePath)
        .find((candidate) => candidate.id === relation.symbolId)
      : null;
    symbol = resolved;
  }

  let descriptor = symbol ? options.functionDescriptorsBySymbolId.get(symbol.id) : null;
  if ((!descriptor || !descriptor.node) && memberName && symbol) {
    const targetRegistry = options.functionRegistries.get(relation.targetModulePath);
    descriptor = targetRegistry?.getFunction(`${symbol.localName}.${memberName}`) ||
      targetRegistry?.getFunction(`${symbol.exportedName}.${memberName}`);
  }
  if (!descriptor?.node) return { status: 'unresolved' };

  return {
    status: 'resolved',
    node: descriptor.node,
    modulePath: relation.targetModulePath,
    importExport: {
      sourceSpecifier: relation.sourceSpecifier,
      localName,
      importedName: relation.isNamespace ? (memberName || 'default') : relation.importedName,
      exportedName: memberName || relation.importedName,
      reExportChain: reExportChain.map((item) => ({ ...item }))
    }
  };
}

function flattenHandlerCandidates(node, result = []) {
  if (node?.type === 'ArrayExpression') {
    for (const item of node.elements || []) {
      if (item?.type === 'SpreadElement') result.push({ node: item, spread: true });
      else if (item) flattenHandlerCandidates(item, result);
    }
  } else {
    result.push({ node, spread: node?.type === 'SpreadElement' });
  }
  return result;
}

function routeBuilderReceiver(node, isRouterReceiver) {
  return node?.type === 'CallExpression' &&
    node.callee?.type === 'MemberExpression' &&
    staticMemberName(node.callee) === 'route' &&
    isRouterReceiver(node.callee.object);
}

function isRouterReceiver(node, frameworkBindings) {
  if (node?.type === 'Identifier') {
    return frameworkBindings.routerBindings.has(node.name) &&
      frameworkBindings.declarations.get(node.name) === 1;
  }
  return frameworkBindings.isRouterFactoryCall(node);
}

function registrationMethod(node) {
  const property = staticMemberName(node);
  return property && FRAMEWORK_ROUTE_METHODS.has(property) ? property : null;
}

function hasHandlerCandidate(args, method, chainedRoute) {
  const candidates = chainedRoute || method === 'use' ? args : args.slice(1);
  return candidates.some((argument) =>
    argument?.type === 'FunctionExpression' ||
    argument?.type === 'ArrowFunctionExpression' ||
    argument?.type === 'Identifier' ||
    argument?.type === 'MemberExpression' ||
    argument?.type === 'ArrayExpression'
  );
}

function addEntry(entriesByModule, target, registration) {
  let moduleEntries = entriesByModule.get(target.modulePath);
  if (!moduleEntries) {
    moduleEntries = new Map();
    entriesByModule.set(target.modulePath, moduleEntries);
  }
  let registrations = moduleEntries.get(target.node);
  if (!registrations) {
    registrations = [];
    moduleEntries.set(target.node, registrations);
  }
  const key = `${registration.modulePath}:${registration.line}:${registration.method}:${registration.importExport?.localName || ''}`;
  if (!registrations.some((item) => item.key === key)) {
    registrations.push({
      ...registration,
      handlerModulePath: target.modulePath,
      key
    });
    registrations.sort((left, right) => left.key.localeCompare(right.key));
  }
}

export function discoverFrameworkEntryPoints(options = {}) {
  const entriesByModule = new Map();
  const limitations = options.limitations || [];
  let stoppedForDuration = false;

  const modulePaths = [...(options.projectRegistry?.modules?.keys() || [])]
    .map(normalizePosixPath)
    .sort((left, right) => left.localeCompare(right));
  for (const modulePath of modulePaths) {
    if (stoppedForDuration) break;
    const duration = options.budgetManager?.check('maxAnalysisDurationMs');
    if (duration && !duration.allowed) {
      addUnique(limitations, duration.code);
      stoppedForDuration = true;
      break;
    }
    const parsed = options.projectRegistry.getAst(modulePath, { limitations });
    if (!parsed?.ast) continue;

    const bindings = collectFrameworkBindings(
      parsed.ast,
      options.budgetManager,
      limitations
    );
    if (bindings.stoppedForDuration) {
      stoppedForDuration = true;
      break;
    }
    const moduleWork = { count: 0 };
    const traversal = walkAST(parsed.ast, {
      enter(node, _parent, context) {
        moduleWork.count++;
        if (moduleWork.count % 128 === 0) {
          const currentDuration = options.budgetManager?.check('maxAnalysisDurationMs');
          if (currentDuration && !currentDuration.allowed) {
            addUnique(limitations, currentDuration.code);
            stoppedForDuration = true;
            context.stop();
            return;
          }
        }

        if (node.type !== 'CallExpression' || node.callee?.type !== 'MemberExpression') return;
        const callee = node.callee;
        const method = registrationMethod(callee);
        const staticMethodName = staticMemberName(callee);
        const chainedRoute = routeBuilderReceiver(
          callee.object,
          (receiver) => isRouterReceiver(receiver, bindings)
        );
        const supportedReceiver = isRouterReceiver(callee.object, bindings) || chainedRoute;
        const args = node.arguments || [];
        if (!supportedReceiver) {
          if (method && hasHandlerCandidate(args, method, chainedRoute)) {
            addUnique(limitations, 'framework_router_identity_ambiguous');
          } else if (
            callee.computed &&
            isStaticPath(args[0]) &&
            args.slice(1).some((argument) =>
              argument?.type === 'FunctionExpression' ||
              argument?.type === 'ArrowFunctionExpression' ||
              argument?.type === 'Identifier' ||
              argument?.type === 'MemberExpression'
            )
          ) {
            addUnique(limitations, 'dynamic_route_registration_detected');
            addUnique(limitations, 'framework_router_identity_ambiguous');
          }
          return;
        }

        if (!method) {
          if (callee.computed || staticMethodName === null) {
            addUnique(limitations, 'dynamic_route_registration_detected');
          }
          return;
        }

        let handlerStart = chainedRoute ? 0 : 1;
        if (chainedRoute) {
          const routePath = callee.object.arguments?.[0];
          if (!isStaticPath(routePath)) {
            addUnique(limitations, 'dynamic_route_registration_detected');
          }
          if (method === 'use') {
            addUnique(limitations, 'dynamic_route_registration_detected');
            return;
          }
        } else if (method === 'use') {
          if (!args.length) return;
          const first = args[0];
          const firstIsPath = isStaticPath(first);
          const firstIsCandidate = first?.type === 'FunctionExpression' ||
            first?.type === 'ArrowFunctionExpression' ||
            first?.type === 'Identifier' ||
            first?.type === 'MemberExpression' ||
            first?.type === 'ArrayExpression';
          if (firstIsPath) {
            handlerStart = 1;
          } else if (firstIsCandidate) {
            const resolved = first.type === 'ArrayExpression'
              ? null
              : resolveFunctionReference(first, modulePath, options);
            if (resolved?.status === 'resolved' || first.type === 'ArrayExpression') {
              handlerStart = 0;
            } else if (args.length > 1) {
              handlerStart = 1;
              addUnique(limitations, 'dynamic_route_registration_detected');
            } else {
              handlerStart = 0;
            }
          } else {
            handlerStart = 1;
            addUnique(limitations, 'dynamic_route_registration_detected');
          }
        } else if (!args.length || !isStaticPath(args[0])) {
          addUnique(limitations, 'dynamic_route_registration_detected');
        }

        const routeLocation = getNodeLocation(node);
        for (const argument of args.slice(handlerStart)) {
          for (const candidate of flattenHandlerCandidates(argument)) {
            if (candidate.spread) {
              addUnique(limitations, 'dynamic_route_registration_detected');
              continue;
            }
            const resolved = resolveFunctionReference(candidate.node, modulePath, options);
            if (resolved.status === 'external') {
              addUnique(limitations, 'framework_handler_external_boundary');
              continue;
            }
            if (resolved.status !== 'resolved') {
              addUnique(limitations, resolved.status === 'ambiguous'
                ? 'framework_handler_ambiguous'
                : 'framework_handler_unresolved');
              continue;
            }
            addEntry(entriesByModule, resolved, {
              modulePath,
              line: routeLocation.line,
              column: routeLocation.column,
              method,
              importExport: resolved.importExport
            });
          }
        }
      }
    });
    if (traversal.nodeLimitExceeded || traversal.depthLimitExceeded) {
      addUnique(limitations, 'framework_discovery_traversal_limit_exceeded');
    }
  }

  return {
    entriesByModule,
    limitations,
    stoppedForDuration,
    entryPointCount: [...entriesByModule.values()]
      .reduce((count, entries) => count + entries.size, 0)
  };
}
