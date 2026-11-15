import { getNodeLocation, getStringValue } from '../traversal.js';

/**
 * Recognized Express/HTTP request objects and properties.
 */
export const REQUEST_ROOT_IDENTIFIERS = Object.freeze(new Set([
  'req',
  'request',
  'ctx'
]));

export const TAINT_PROPERTIES = Object.freeze(new Set([
  'query',
  'params',
  'body',
  'headers',
  'cookies',
  'signedCookies'
]));

/**
 * Extracts a normalized member path array from an AST node, e.g.
 * req.query.name -> ['req', 'query', 'name']
 * req['query']['name'] -> ['req', 'query', 'name']
 * ctx.request.body.name -> ['ctx', 'request', 'body', 'name']
 *
 * @param {Object} node - AST node
 * @returns {Array<string>|null} Array of path segment strings or null
 */
export function extractMemberSegments(node) {
  if (!node) return null;

  if (node.type === 'Identifier') {
    return [node.name];
  }

  if (node.type === 'MemberExpression') {
    const objectSegments = extractMemberSegments(node.object);
    if (!objectSegments) return null;

    let propName = null;
    if (node.property.type === 'Identifier' && !node.computed) {
      propName = node.property.name;
    } else if (node.computed) {
      if (node.property.type === 'StringLiteral') {
        propName = node.property.value;
      } else if (node.property.type === 'Literal' && typeof node.property.value === 'string') {
        propName = node.property.value;
      }
    }

    if (propName) {
      return [...objectSegments, propName];
    }
  }

  return null;
}

/**
 * Checks whether an AST node represents an untrusted taint source.
 *
 * Examples of recognized sources:
 * - req.query, req.query.id, req.query['id']
 * - req.params, req.params.user
 * - req.body, req.body.data.item
 * - req.headers, req.headers.token
 * - req.cookies, req.signedCookies
 * - request.query, request.body, etc.
 * - ctx.request.body, ctx.query, ctx.params
 *
 * @param {Object} node - AST node to inspect
 * @param {string} sourceCode - Raw source code for snippet extraction
 * @returns {Object|null} Taint source descriptor or null if not a source
 */
export function inspectTaintSource(node, sourceCode = '') {
  if (!node) return null;

  const segments = extractMemberSegments(node);
  if (!segments || segments.length < 2) return null;

  const root = segments[0];
  if (!REQUEST_ROOT_IDENTIFIERS.has(root)) return null;

  let propertyIndex = 1;
  // Handle ctx.request.body
  if (root === 'ctx' && segments[1] === 'request' && segments.length >= 3) {
    propertyIndex = 2;
  }

  const property = segments[propertyIndex];
  if (!TAINT_PROPERTIES.has(property)) return null;

  const loc = getNodeLocation(node);
  const exprStr = sourceCode && node.start !== undefined && node.end !== undefined
    ? sourceCode.slice(node.start, node.end).trim()
    : segments.join('.');

  return {
    isSource: true,
    root,
    property,
    path: segments.join('.'),
    segments,
    subProperty: segments.slice(propertyIndex + 1).join('.') || null,
    expression: exprStr,
    line: loc.line,
    column: loc.column
  };
}

/**
 * Inspects variable declarator patterns for source destructuring, e.g.
 * const { id, name } = req.query;
 * const { user: { email } } = req.body;
 *
 * @param {Object} patternNode - Declarator id pattern node
 * @param {Object} initNode - Declarator init node
 * @param {string} sourceCode - Raw source code
 * @returns {Array<Object>} List of extracted tainted bindings
 */
export function inspectDestructuredSources(patternNode, initNode, sourceCode = '') {
  const bindings = [];
  if (!patternNode || !initNode) return bindings;

  const sourceInfo = inspectTaintSource(initNode, sourceCode);
  if (!sourceInfo) return bindings;

  function traversePattern(pattern, parentPath) {
    if (!pattern) return;

    if (pattern.type === 'Identifier') {
      const loc = getNodeLocation(pattern);
      bindings.push({
        variableName: pattern.name,
        source: {
          expression: `${sourceInfo.expression}.${parentPath || pattern.name}`,
          path: `${sourceInfo.path}.${parentPath || pattern.name}`,
          line: loc.line || sourceInfo.line,
          column: loc.column || sourceInfo.column
        }
      });
    } else if (pattern.type === 'ObjectPattern') {
      for (const prop of pattern.properties || []) {
        if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
          const keyName = prop.key.type === 'Identifier' ? prop.key.name : getStringValue(prop.key);
          const nextPath = parentPath ? `${parentPath}.${keyName}` : keyName;
          traversePattern(prop.value, nextPath);
        } else if (prop.type === 'RestElement' && prop.argument?.type === 'Identifier') {
          const loc = getNodeLocation(prop.argument);
          bindings.push({
            variableName: prop.argument.name,
            source: {
              expression: `${sourceInfo.expression} (rest)`,
              path: sourceInfo.path,
              line: loc.line || sourceInfo.line,
              column: loc.column || sourceInfo.column
            }
          });
        }
      }
    } else if (pattern.type === 'ArrayPattern') {
      pattern.elements?.forEach((elem, index) => {
        if (!elem) return;
        const nextPath = parentPath ? `${parentPath}[${index}]` : `[${index}]`;
        traversePattern(elem, nextPath);
      });
    }
  }

  traversePattern(patternNode, '');
  return bindings;
}
