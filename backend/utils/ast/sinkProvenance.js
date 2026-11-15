import { getMemberExpressionPath } from './traversal.js';

const FUNCTION_SCOPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
  'ObjectMethod',
  'ClassMethod',
  'ClassPrivateMethod'
]);
const BLOCK_SCOPES = new Set(['Program', 'BlockStatement', 'CatchClause']);
const CHILD_PROCESS_APIS = new Set([
  'exec',
  'execSync',
  'spawn',
  'spawnSync',
  'execFile',
  'execFileSync'
]);

function propertyName(node) {
  if (!node) return null;
  if (node.type === 'Identifier' || node.type === 'PrivateName') {
    return node.name || node.id?.name || null;
  }
  if (node.type === 'StringLiteral' || node.type === 'Literal') {
    return typeof node.value === 'string' ? node.value : null;
  }
  return null;
}

function memberRootName(node) {
  let current = node;
  while (current?.type === 'MemberExpression' || current?.type === 'OptionalMemberExpression') {
    current = current.object;
  }
  return current?.type === 'Identifier' ? current.name : null;
}

function isScopeNode(node) {
  return BLOCK_SCOPES.has(node?.type) || FUNCTION_SCOPES.has(node?.type);
}

function nearestFunctionScope(scope) {
  let current = scope;
  while (current) {
    if (current.node.type === 'Program' || FUNCTION_SCOPES.has(current.node.type)) return current;
    current = current.parent;
  }
  return scope;
}

function bindPattern(scope, pattern, binding) {
  if (!pattern) return;
  if (pattern.type === 'Identifier') {
    registerBinding(scope, pattern.name, binding);
  } else if (pattern.type === 'AssignmentPattern') {
    bindPattern(scope, pattern.left, binding);
  } else if (pattern.type === 'RestElement') {
    bindPattern(scope, pattern.argument, binding);
  } else if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties || []) {
      bindPattern(scope, property.value || property.argument, binding);
    }
  } else if (pattern.type === 'ArrayPattern') {
    for (const element of pattern.elements || []) bindPattern(scope, element, binding);
  }
}

function registerBinding(scope, name, binding) {
  if (!name || !scope) return;
  const existing = scope.bindings.get(name);
  if (!existing) {
    scope.bindings.set(name, binding);
    return;
  }
  if (existing.kind !== binding.kind ||
      existing.source !== binding.source ||
      existing.importedName !== binding.importedName ||
      existing.targetName !== binding.targetName) {
    scope.bindings.set(name, { kind: 'ambiguous' });
  }
}

function lookupBinding(scope, name) {
  for (let current = scope; current; current = current.parent) {
    if (current.bindings.has(name)) return current.bindings.get(name);
  }
  return null;
}

function findBindingScope(scope, name) {
  for (let current = scope; current; current = current.parent) {
    if (current.bindings.has(name)) return current;
  }
  return null;
}

function assignmentValue(node, scope) {
  if (node?.type === 'Identifier') {
    return {
      kind: 'alias',
      targetName: node.name,
      targetScope: scope
    };
  }
  if (node?.type === 'FunctionExpression' || node?.type === 'ArrowFunctionExpression') {
    return { kind: 'function', implementation: node };
  }
  return { kind: 'ambiguous' };
}

function sameAssignmentValue(left, right) {
  if (left?.kind !== right?.kind) return false;
  if (left.kind === 'alias') {
    return left.targetName === right.targetName &&
      left.targetScope === right.targetScope;
  }
  if (left.kind === 'function') {
    return left.implementation === right.implementation;
  }
  return false;
}

function objectMethodNames(node) {
  if (node?.type !== 'ObjectExpression') return null;
  const methods = new Set();
  for (const property of node.properties || []) {
    if (property.type === 'SpreadElement') continue;
    const name = propertyName(property.key);
    const value = property.value || property;
    if (name && (property.type === 'ObjectMethod' ||
        value.type === 'FunctionExpression' || value.type === 'ArrowFunctionExpression')) {
      methods.add(name);
    }
  }
  return methods;
}

function classMethodNames(node) {
  if (!node || !['ClassDeclaration', 'ClassExpression'].includes(node.type)) return null;
  const methods = new Set();
  for (const member of node.body?.body || []) {
    if (FUNCTION_SCOPES.has(member.type)) {
      const name = propertyName(member.key);
      if (name) methods.add(name);
    }
  }
  return methods;
}

function callProvenance(node, scope) {
  const callee = node?.callee;
  if (!callee) return { status: 'unknown', resolution: 'unresolved' };

  if (callee.type === 'SequenceExpression') {
    const last = callee.expressions?.[callee.expressions.length - 1];
    if (last?.type === 'Identifier') {
      return callProvenance({ callee: last }, scope);
    }
  }

  if (callee.type === 'Identifier') {
    return identifierProvenance(callee.name, scope);
  }

  if (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') {
    const rootName = memberRootName(callee);
    const binding = rootName ? lookupBinding(scope, rootName) : null;
    const api = propertyName(callee.property);
    if (binding?.kind === 'object' && binding.methods?.has(api)) {
      return { status: 'locally_defined', resolution: 'local_object_method', api };
    }
    if (binding?.kind === 'import') {
      if ((binding.source === 'node:child_process' || binding.source === 'child_process') &&
          CHILD_PROCESS_APIS.has(api)) {
        return {
          status: 'supported_external_api',
          resolution: 'verified_module_specifier',
          module: binding.source,
          api
        };
      }
      return {
        status: 'external_unresolved',
        resolution: 'module_specifier_only',
        module: binding.source || null,
        api
      };
    }
    if (binding?.kind === 'ambiguous') return { status: 'ambiguous', resolution: 'ambiguous_binding' };
    if (binding?.kind === 'class_instance' && binding.methods?.has(api)) {
      return { status: 'locally_defined', resolution: 'local_class_method', api };
    }
    const path = getMemberExpressionPath(callee);
    if (path === 'global.eval' || path === 'window.eval' || path === 'globalThis.eval') {
      const globalName = memberRootName(callee);
      return lookupBinding(scope, globalName)
        ? { status: 'unknown', resolution: 'shadowed_global_object', api: 'eval' }
        : { status: 'global_builtin', resolution: 'global_object', api: 'eval' };
    }
  }

  return { status: 'unknown', resolution: 'unresolved' };
}

function identifierProvenance(name, scope, resolving = new Set()) {
  const binding = lookupBinding(scope, name);
  if (!binding) {
    return name === 'eval'
      ? { status: 'global_builtin', resolution: 'implicit_global', api: 'eval' }
      : { status: 'unknown', resolution: 'unresolved', api: name };
  }
  if (binding.kind === 'import') {
    if ((binding.source === 'node:child_process' || binding.source === 'child_process') &&
        CHILD_PROCESS_APIS.has(binding.importedName)) {
      return {
        status: 'supported_external_api',
        resolution: 'verified_module_specifier',
        module: binding.source,
        api: binding.importedName
      };
    }
    return {
      status: 'external_unresolved',
      resolution: 'module_specifier_only',
      module: binding.source || null,
      api: binding.importedName || name
    };
  }
  if (binding.kind === 'ambiguous') {
    return { status: 'ambiguous', resolution: 'ambiguous_binding', api: name };
  }
  if (binding.kind === 'alias') {
    if (resolving.has(binding)) {
      return { status: 'ambiguous', resolution: 'cyclic_alias', api: name };
    }
    resolving.add(binding);
    const target = identifierProvenance(
      binding.targetName,
      binding.targetScope,
      resolving
    );
    resolving.delete(binding);
    if (target.status === 'global_builtin' ||
        target.status === 'supported_external_api' ||
        target.status === 'external_unresolved') {
      return { ...target, resolution: 'resolved_alias', alias: name };
    }
    if (target.status === 'locally_defined') {
      return { ...target, resolution: 'local_function_alias', alias: name };
    }
    return { status: 'unknown', resolution: 'unresolved_alias', api: target.api || name };
  }
  if (binding.kind === 'function') {
    return { status: 'locally_defined', resolution: 'local_function', api: name };
  }
  if (binding.kind === 'object' || binding.kind === 'class_instance') {
    return { status: 'unknown', resolution: 'non_callable_local_binding', api: name };
  }
  return {
    status: 'unknown',
    resolution: binding.kind === 'parameter' ? 'parameter_binding' : 'local_variable',
    api: name
  };
}

export function createSinkProvenanceResolver(ast) {
  const nodeScopes = new WeakMap();
  const declarationRanges = [];
  const callNodesByStart = new Map();
  const assignments = [];
  const root = ast?.type === 'File' ? ast.program : ast;
  if (!root) return {
    resolveCall: () => ({ status: 'unknown', resolution: 'ast_unavailable' }),
    resolveAtOffset: () => ({ status: 'unknown', resolution: 'ast_unavailable' }),
    isDeclarationAtOffset: () => false
  };

  const rootScope = { node: root, parent: null, bindings: new Map() };
  const collect = (node, parentScope, parent = null) => {
    if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;
    let scope = parentScope;
    if (node !== root && isScopeNode(node)) {
      scope = { node, parent: parentScope, bindings: new Map() };
      if (FUNCTION_SCOPES.has(node.type)) {
        if (node.type === 'FunctionExpression' && node.id?.name) {
          registerBinding(scope, node.id.name, { kind: 'function' });
        }
        for (const parameter of node.params || []) {
          bindPattern(scope, parameter, { kind: 'parameter' });
        }
      } else if (node.type === 'CatchClause') {
        bindPattern(scope, node.param, { kind: 'parameter' });
      }
    }
    nodeScopes.set(node, scope);

    if (node.type === 'ImportDeclaration') {
      for (const specifier of node.specifiers || []) {
        const importedName = specifier.type === 'ImportSpecifier'
          ? propertyName(specifier.imported)
          : specifier.type === 'ImportNamespaceSpecifier' ? '*' : 'default';
        registerBinding(scope, specifier.local?.name, {
          kind: 'import',
          source: node.source?.value || null,
          importedName
        });
      }
    } else if (node.type === 'FunctionDeclaration' && node.id?.name) {
      registerBinding(parentScope, node.id.name, { kind: 'function' });
    } else if (node.type === 'ClassDeclaration' && node.id?.name) {
      registerBinding(parentScope, node.id.name, {
        kind: 'class',
        methods: classMethodNames(node)
      });
    } else if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
      const targetScope = parent?.kind === 'var' ? nearestFunctionScope(scope) : scope;
      const methods = objectMethodNames(node.init);
      if (methods) {
        registerBinding(targetScope, node.id.name, { kind: 'object', methods });
      } else if (node.init?.type === 'Identifier') {
        registerBinding(targetScope, node.id.name, {
          kind: 'alias',
          targetName: node.init.name,
          targetScope: scope
        });
      } else if (node.init?.type === 'FunctionExpression' ||
          node.init?.type === 'ArrowFunctionExpression') {
        registerBinding(targetScope, node.id.name, { kind: 'function' });
      } else if (node.init?.type === 'NewExpression' &&
          node.init.callee?.type === 'Identifier') {
        const classBinding = lookupBinding(scope, node.init.callee.name);
        registerBinding(targetScope, node.id.name, classBinding?.kind === 'class'
          ? { kind: 'class_instance', methods: classBinding.methods }
          : { kind: 'variable' });
      } else {
        registerBinding(targetScope, node.id.name, { kind: 'variable' });
      }
    } else if (node.type === 'FunctionExpression' && node.id?.name) {
      registerBinding(scope, node.id.name, { kind: 'function' });
    } else if (node.type === 'AssignmentExpression' &&
        node.operator === '=' && node.left?.type === 'Identifier') {
      assignments.push({
        name: node.left.name,
        scope,
        value: assignmentValue(node.right, scope)
      });
    } else if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      if (Number.isInteger(node.start)) {
        callNodesByStart.set(node.start, { node, scope });
      }
    }

    if (node.type === 'ObjectMethod' || node.type === 'ClassMethod' ||
        node.type === 'ClassPrivateMethod') {
      declarationRanges.push({ start: node.key?.start, end: node.key?.end });
    } else if (node.type === 'FunctionDeclaration' && node.id?.name) {
      declarationRanges.push({ start: node.id.start, end: node.id.end });
    }
    for (const key of Object.keys(node)) {
      if (['loc', 'range', 'comments', 'tokens'].includes(key)) continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) collect(item, scope, node);
      } else if (child && typeof child === 'object' && typeof child.type === 'string') {
        collect(child, scope, node);
      }
    }
  };
  collect(root, rootScope);
  for (const assignment of assignments) {
    const bindingScope = findBindingScope(assignment.scope, assignment.name);
    const binding = bindingScope?.bindings.get(assignment.name);
    if (!binding) continue;

    if (binding.kind === 'variable') {
      Object.assign(binding, assignment.value);
      continue;
    }

    if (binding.kind === 'alias' || binding.kind === 'function') {
      if (sameAssignmentValue(binding, assignment.value)) continue;
      bindingScope.bindings.set(assignment.name, { kind: 'ambiguous' });
      continue;
    }

    if (binding.kind !== 'ambiguous') {
      bindingScope.bindings.set(assignment.name, { kind: 'ambiguous' });
    }
  }

  const resolveCall = (node) => callProvenance(node, nodeScopes.get(node) || rootScope);
  return {
    resolveCall,
    resolveAtOffset(offset) {
      const entry = callNodesByStart.get(offset);
      return entry
        ? callProvenance(entry.node, entry.scope)
        : { status: 'unknown', resolution: 'no_ast_call_match' };
    },
    getCallAtOffset(offset) {
      const entry = callNodesByStart.get(offset);
      if (!entry) return null;
      return {
        start: entry.node.start,
        end: entry.node.end,
        callee: getMemberExpressionPath(entry.node.callee),
        provenance: callProvenance(entry.node, entry.scope)
      };
    },
    getCallDescriptors() {
      return [...callNodesByStart.values()]
        .map(({ node, scope }) => ({
          start: node.start,
          end: node.end,
          callee: getMemberExpressionPath(node.callee),
          provenance: callProvenance(node, scope)
        }))
        .sort((left, right) => left.start - right.start || left.end - right.end);
    },
    getDeclarationRanges() {
      return declarationRanges
        .filter((range) => Number.isInteger(range.start) && Number.isInteger(range.end))
        .map((range) => ({ ...range }))
        .sort((left, right) => left.start - right.start);
    },
    isDeclarationAtOffset(offset) {
      return declarationRanges.some((range) => offset >= range.start && offset < range.end);
    }
  };
}
