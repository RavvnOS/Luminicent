import { PARSER_LIMITS } from './parser.js';

/**
 * Extracts line and column coordinates from a Babel AST node.
 */
export function getNodeLocation(node) {
  if (!node || !node.loc) {
    return { line: null, column: null, endLine: null, endColumn: null };
  }
  return {
    line: node.loc.start ? node.loc.start.line : null,
    column: node.loc.start ? node.loc.start.column : null,
    endLine: node.loc.end ? node.loc.end.line : null,
    endColumn: node.loc.end ? node.loc.end.column : null
  };
}

/**
 * Checks if a node is an Identifier with the specified name.
 */
export function isIdentifierNamed(node, name) {
  if (!node) return false;
  return node.type === 'Identifier' && node.name === name;
}

/**
 * Checks if a node represents a string literal.
 */
export function isStringLiteral(node) {
  if (!node) return false;
  if (node.type === 'StringLiteral') return true;
  if (node.type === 'Literal' && typeof node.value === 'string') return true;
  return false;
}

/**
 * Extracts string value from a string literal node, or null if not a string literal.
 */
export function getStringValue(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'Literal' && typeof node.value === 'string') return String(node.value);
  return null;
}

/**
 * Resolves a MemberExpression path into a dotted string, e.g. "child_process.exec" or "db.query".
 */
export function getMemberExpressionPath(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const objectPath = getMemberExpressionPath(node.object);
    let propName = null;
    if (node.property.type === 'Identifier') {
      propName = node.property.name;
    } else if (node.computed && isStringLiteral(node.property)) {
      propName = getStringValue(node.property);
    }
    if (objectPath && propName) {
      return `${objectPath}.${propName}`;
    }
  }
  return null;
}

/**
 * Checks if a CallExpression or NewExpression matches a callee identifier, path, or pattern.
 */
export function isCallTo(node, target) {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (!callee) return false;

  // Direct identifier call, e.g. eval(...)
  if (callee.type === 'Identifier') {
    if (typeof target === 'string') return callee.name === target;
    if (target instanceof RegExp) return target.test(callee.name);
  }

  // MemberExpression call, e.g. child_process.exec(...)
  if (callee.type === 'MemberExpression') {
    const fullPath = getMemberExpressionPath(callee);
    if (fullPath) {
      if (typeof target === 'string') return fullPath === target || fullPath.endsWith(`.${target}`);
      if (target instanceof RegExp) return target.test(fullPath);
    }
    let propName = null;
    if (callee.property.type === 'Identifier') propName = callee.property.name;
    else if (callee.computed && isStringLiteral(callee.property)) propName = getStringValue(callee.property);
    if (propName) {
      if (typeof target === 'string') return propName === target;
      if (target instanceof RegExp) return target.test(propName);
    }
  }

  return false;
}

/**
 * Checks if a NewExpression is constructing the specified constructor name.
 */
export function isNewExpression(node, constructorName) {
  if (!node || node.type !== 'NewExpression') return false;
  const callee = node.callee;
  if (!callee) return false;
  if (callee.type === 'Identifier') {
    return callee.name === constructorName;
  }
  const fullPath = getMemberExpressionPath(callee);
  return fullPath === constructorName || fullPath?.endsWith(`.${constructorName}`);
}

/**
 * Checks if an expression contains dynamic string concatenation or template interpolation.
 */
export function isDynamicStringExpression(node) {
  if (!node) return false;

  // Template literal with dynamic expressions, e.g. `SELECT * FROM ${table}`
  if (node.type === 'TemplateLiteral') {
    return Array.isArray(node.expressions) && node.expressions.length > 0;
  }

  // Binary expression with '+', e.g. "SELECT * FROM users WHERE id = " + userId
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    // Check if either side is a string and the other is dynamic
    const hasString = isStringLiteral(node.left) || isStringLiteral(node.right) ||
                      node.left.type === 'TemplateLiteral' || node.right.type === 'TemplateLiteral' ||
                      isDynamicStringExpression(node.left) || isDynamicStringExpression(node.right);
    const hasDynamic = !isStringLiteral(node.left) || !isStringLiteral(node.right);
    return hasString && hasDynamic;
  }

  return false;
}

/**
 * Extracts raw snippet or formatted representation of an AST node for evidence.
 */
export function getNodeEvidence(node, sourceCode = '') {
  if (!node) return '';
  if (sourceCode && node.start !== undefined && node.end !== undefined) {
    const slice = sourceCode.slice(node.start, node.end).trim();
    if (slice.length > 120) {
      return slice.slice(0, 117) + '...';
    }
    return slice;
  }
  if (node.type === 'CallExpression' && node.callee) {
    const name = getMemberExpressionPath(node.callee) || node.callee.name || 'call';
    return `${name}(...)`;
  }
  if (node.type === 'NewExpression' && node.callee) {
    const name = getMemberExpressionPath(node.callee) || node.callee.name || 'Constructor';
    return `new ${name}(...)`;
  }
  return node.type;
}

/**
 * Traverses an AST with depth and node count bounds.
 *
 * @param {Object} rootNode - The root Babel AST node
 * @param {Object} visitors - Object containing visitor functions keyed by node type or enter/leave
 * @param {Object} options - Options including maxDepth and maxNodes
 * @returns {Object} Traversal summary: { nodeCount, maxDepthReached, depthLimitExceeded, nodeLimitExceeded }
 */
export function walkAST(rootNode, visitors = {}, options = {}) {
  const maxDepth = options.maxDepth || PARSER_LIMITS.maxDepth;
  const maxNodes = options.maxNodes || PARSER_LIMITS.maxNodes;

  let totalNodes = 0;
  let maxDepthReached = 0;
  let depthLimitExceeded = false;
  let nodeLimitExceeded = false;

  const context = {
    shouldStop: false,
    stop() {
      this.shouldStop = true;
    }
  };

  function traverse(node, parent, depth) {
    if (!node || typeof node !== 'object' || context.shouldStop) return;
    if (typeof node.type !== 'string') return;

    totalNodes++;
    if (depth > maxDepthReached) {
      maxDepthReached = depth;
    }

    if (totalNodes > maxNodes) {
      nodeLimitExceeded = true;
      context.shouldStop = true;
      return;
    }

    if (depth > maxDepth) {
      depthLimitExceeded = true;
      return; // Do not descend deeper
    }

    // Call generic enter
    if (visitors.enter) {
      visitors.enter(node, parent, context);
      if (context.shouldStop) return;
    }

    // Call type-specific visitor
    if (visitors[node.type]) {
      visitors[node.type](node, parent, context);
      if (context.shouldStop) return;
    }

    // Iterate over child AST nodes
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range' || key === 'comments' || key === 'tokens') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object' && typeof item.type === 'string') {
            traverse(item, node, depth + 1);
            if (context.shouldStop) return;
          }
        }
      } else if (child && typeof child === 'object' && typeof child.type === 'string') {
        traverse(child, node, depth + 1);
        if (context.shouldStop) return;
      }
    }

    // Call generic leave
    if (visitors.leave) {
      visitors.leave(node, parent, context);
    }
  }

  traverse(rootNode, null, 1);

  return {
    nodeCount: totalNodes,
    maxDepthReached,
    depthLimitExceeded,
    nodeLimitExceeded
  };
}
