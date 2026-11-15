import {
  getNodeLocation,
  getMemberExpressionPath,
  isStringLiteral,
  getStringValue,
  isCallTo,
  isNewExpression
} from '../traversal.js';
import { SINK_CONTEXTS } from './taintSanitizers.js';

const CHILD_PROCESS_API_NAMES = new Set([
  'exec',
  'execSync',
  'spawn',
  'spawnSync',
  'execFile',
  'execFileSync'
]);

/**
 * Extracts options properties from an ObjectExpression AST node.
 */
export function extractOptionsFromObjectNode(optionsNode) {
  if (!optionsNode || optionsNode.type !== 'ObjectExpression') return null;
  const opts = {};
  for (const prop of optionsNode.properties || []) {
    if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
      const keyName = prop.key.type === 'Identifier' ? prop.key.name : getStringValue(prop.key);
      if (keyName === 'shell') {
        if (prop.value.type === 'BooleanLiteral') {
          opts.shell = prop.value.value;
        } else if (prop.value.type === 'StringLiteral') {
          opts.shell = prop.value.value.length > 0;
        } else if (prop.value.type === 'Literal') {
          opts.shell = Boolean(prop.value.value);
        } else if (prop.value.type === 'Identifier') {
          if (prop.value.name === 'true') opts.shell = true;
          else if (prop.value.name === 'false') opts.shell = false;
          else opts.shell = 'ambiguous';
        } else {
          opts.shell = 'ambiguous';
        }
      } else if (keyName) {
        opts[keyName] = true;
      }
    }
  }
  return opts;
}

/**
 * Resolves an options descriptor from an AST node (inline ObjectExpression or Identifier via lexical scope).
 */
export function extractOptionsFromNode(optionsNode, scope = null) {
  if (!optionsNode) return null;
  if (optionsNode.type === 'ObjectExpression') {
    return extractOptionsFromObjectNode(optionsNode);
  }
  if (optionsNode.type === 'Identifier' && scope && typeof scope.getOption === 'function') {
    return scope.getOption(optionsNode.name);
  }
  return null;
}

/**
 * Inspects an AST CallExpression or NewExpression to determine if it is a security-sensitive sink.
 *
 * @param {Object} node - AST node (CallExpression or NewExpression)
 * @param {string} sourceCode - Raw source code
 * @param {Map|null} aliases - Aliased imports map
 * @param {TaintScope|null} scope - Current lexical scope for variable-backed options resolution
 * @returns {Object|null} Sink descriptor or null
 */
export function inspectSecuritySink(
  node,
  sourceCode = '',
  aliases = null,
  scope = null,
  sinkProvenanceResolver = null
) {
  if (!node) return null;

  const loc = getNodeLocation(node);
  const args = node.arguments || [];
  const sinkProvenance = sinkProvenanceResolver?.resolveCall(node) || {
    status: 'unknown',
    resolution: 'provenance_not_available'
  };
  const sinkSpan = Number.isInteger(node.start) && Number.isInteger(node.end)
    ? { start: node.start, end: node.end }
    : null;
  const sinkExpression = node.callee?.start !== undefined && node.callee?.end !== undefined
    ? sourceCode.slice(node.callee.start, node.callee.end)
    : null;

  // ==========================================
  // 1. SQL INJECTION SINKS
  // ==========================================
  if (node.type === 'CallExpression' && node.callee) {
    const calleePath = getMemberExpressionPath(node.callee);
    let propName = null;
    if (node.callee.property) {
      propName = node.callee.property.type === 'Identifier'
        ? node.callee.property.name
        : getStringValue(node.callee.property);
    }

    const isSqlMethod = /^(?:query|execute|executemany|raw)$/i.test(propName || '') ||
                        (calleePath && /\.(?:query|execute|executemany|raw)$/i.test(calleePath));

    if (isSqlMethod && args.length > 0 && sinkProvenance.status !== 'locally_defined') {
      const queryArg = args[0];
      // Check if parameterized: static SQL string with a separate parameters argument
      const isStaticQueryString = isStringLiteral(queryArg);
      const hasParametersArg = args.length > 1;

      return {
        isSink: true,
        sinkType: SINK_CONTEXTS.SQL,
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        category: 'injection',
        cwe: ['CWE-89'],
        severity: 'High',
        confidence: 'medium',
        title: 'Potentially unsafe dynamic SQL construction',
        description: 'A SQL statement appears to be dynamically constructed and passed to a database execution API. This pattern alone does not establish attacker control or exploitability.',
        remediation: 'Use a parameterized query with values supplied separately; avoid interpolating or concatenating values into SQL syntax.',
        recommendation: 'Use a parameterized query with values supplied separately; avoid interpolating or concatenating values into SQL syntax.',
        targetArgIndices: [0], // Only the SQL statement itself (index 0) is vulnerable to injection
        isParameterized: isStaticQueryString && hasParametersArg,
        line: loc.line,
        column: loc.column,
        sourceSpan: sinkSpan,
        sinkExpression,
        sinkProvenance,
        expression: sourceCode && node.start !== undefined && node.end !== undefined
          ? sourceCode.slice(node.start, node.end).trim()
          : `${calleePath || propName || 'db.query'}(...)`
      };
    }
  }

  // ==========================================
  // 2. OS COMMAND INJECTION SINKS
  // ==========================================
  if (node.type === 'CallExpression' && node.callee) {
    const calleePath = getMemberExpressionPath(node.callee) || '';
    let methodName = null;
    if (node.callee.type === 'Identifier') {
      const resolvedChildProcessApi = [
        'supported_external_api',
        'external_unresolved'
      ].includes(sinkProvenance.status) &&
        CHILD_PROCESS_API_NAMES.has(sinkProvenance.api)
        ? sinkProvenance.api
        : null;
      methodName = resolvedChildProcessApi ||
        (aliases && aliases.get(node.callee.name)) ||
        node.callee.name;
    } else if (node.callee.property) {
      methodName = node.callee.property.type === 'Identifier'
        ? node.callee.property.name
        : getStringValue(node.callee.property);
    }

    const isChildProcessCall =
      /^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(methodName || '') ||
      /(?:child_process|childProcess)\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(calleePath);

    if (isChildProcessCall && args.length > 0 &&
        sinkProvenance.status !== 'locally_defined') {
      const isShellDirect = /^(?:exec|execSync)$/.test(methodName);
      const isSpawnLike = /^(?:spawn|spawnSync|execFile|execFileSync)$/.test(methodName);
      let optionsArg = null;
      let hasShell = false;
      let targetArgIndices = [0];
      let isSecondArgOptions = false;

      if (isShellDirect) {
        optionsArg = args[1];
        const opts = extractOptionsFromNode(optionsArg, scope);
        // By default, exec/execSync invoke a shell (/bin/sh or cmd.exe)
        hasShell = opts && opts.shell === false ? false : true;
        targetArgIndices = [0];
      } else if (isSpawnLike) {
        if (args.length >= 3) {
          optionsArg = args[2];
          const opts = extractOptionsFromNode(optionsArg, scope);
          hasShell = opts ? (opts.shell === true) : false;
          targetArgIndices = [0, 1];
        } else if (args.length === 2) {
          const secondArg = args[1];
          let isOptions = false;
          let opts = null;
          if (secondArg.type === 'ObjectExpression') {
            isOptions = true;
            opts = extractOptionsFromObjectNode(secondArg);
          } else if (secondArg.type === 'Identifier' && scope && typeof scope.getOption === 'function' && scope.getOption(secondArg.name)) {
            isOptions = true;
            opts = scope.getOption(secondArg.name);
          }

          if (isOptions) {
            hasShell = opts ? (opts.shell === true) : false;
            targetArgIndices = [0];
            isSecondArgOptions = true;
          } else {
            hasShell = false;
            targetArgIndices = [0, 1];
          }
        } else {
          hasShell = false;
          targetArgIndices = [0];
        }
      }

      return {
        isSink: true,
        sinkType: SINK_CONTEXTS.COMMAND,
        ruleId: 'LUM-INJ-002',
        checkId: 'os_command_injection_pattern_search',
        category: 'injection',
        cwe: hasShell ? ['CWE-78'] : ['CWE-88'],
        severity: 'High',
        confidence: 'medium',
        title: hasShell
          ? 'Potentially unsafe command construction via shell execution'
          : 'Potentially unsafe command construction',
        description: hasShell
          ? 'A shell-based command execution API receives a value associated with user input. This pattern alone does not establish attacker control or exploitability.'
          : 'A process execution API receives a value associated with user input. This pattern alone does not establish attacker control or exploitability.',
        remediation: 'Avoid shell command strings; use an argument-array API with a fixed executable and validate each argument against an allowlist.',
        recommendation: 'Avoid shell command strings; use an argument-array API with a fixed executable and validate each argument against an allowlist.',
        targetArgIndices,
        isShellDirect,
        isSpawnLike,
        hasShell,
        isSecondArgOptions,
        methodName,
        line: loc.line,
        column: loc.column,
        sourceSpan: sinkSpan,
        sinkExpression,
        sinkProvenance,
        expression: sourceCode && node.start !== undefined && node.end !== undefined
          ? sourceCode.slice(node.start, node.end).trim()
          : `${methodName || 'child_process'}(...)`
      };
    }
  }

  // ==========================================
  // 3. DYNAMIC EXECUTION SINKS
  // ==========================================
  // Direct or indirect eval()
  if (node.type === 'CallExpression' && node.callee) {
    if (args.length > 0 &&
        sinkProvenance.status === 'global_builtin' &&
        sinkProvenance.api === 'eval') {
      return {
        isSink: true,
        sinkType: SINK_CONTEXTS.DYNAMIC_CODE,
        ruleId: 'LUM-DYN-001',
        checkId: 'dynamic_code_execution_pattern_search',
        category: 'dynamic_execution',
        cwe: ['CWE-95'],
        severity: 'High',
        title: 'Tainted input reaches eval()',
        description: 'Potentially untrusted user input flows into eval(), triggering arbitrary code execution in the caller scope.',
        remediation: 'Eliminate eval(). Parse data with JSON.parse() or use explicit lookup tables instead of dynamic code evaluation.',
        targetArgIndices: [0],
        line: loc.line,
        column: loc.column,
        sourceSpan: sinkSpan,
        sinkExpression,
        sinkProvenance,
        expression: 'eval(...)'
      };
    }
  }

  // Function constructor: new Function(...) or Function(...)
  if (isNewExpression(node, 'Function') || (isCallTo(node, 'Function') && node.callee.name === 'Function')) {
    if (args.length > 0) {
      // Any argument to Function constructor can supply function code
      return {
        isSink: true,
        sinkType: SINK_CONTEXTS.DYNAMIC_CODE,
        ruleId: 'LUM-DYN-002',
        checkId: 'dynamic_code_execution_pattern_search',
        category: 'dynamic_execution',
        cwe: ['CWE-95'],
        severity: 'High',
        title: 'Tainted input reaches Function constructor',
        description: 'Potentially untrusted user input flows into Function(), compiling dynamic code at runtime.',
        remediation: 'Avoid dynamic function compilation. Use static function declarations, arrow functions, or mapped handlers.',
        targetArgIndices: args.map((_, i) => i),
        line: loc.line,
        column: loc.column,
        sourceSpan: sinkSpan,
        sinkExpression,
        sinkProvenance,
        expression: 'Function(...)'
      };
    }
  }

  // Node.js vm API
  if (node.type === 'CallExpression' && node.callee) {
    const calleePath = getMemberExpressionPath(node.callee);
    if (calleePath && /^vm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction|Script)$/.test(calleePath)) {
      if (args.length > 0) {
        return {
          isSink: true,
          sinkType: SINK_CONTEXTS.DYNAMIC_CODE,
          ruleId: 'LUM-DYN-003',
          checkId: 'dynamic_code_execution_pattern_search',
          category: 'dynamic_execution',
          cwe: ['CWE-95'],
          severity: 'High',
          title: 'Tainted input reaches Node.js vm execution API',
          description: 'Potentially untrusted user input flows into a Node.js vm execution function.',
          remediation: 'Avoid evaluating untrusted input in vm contexts; Node.js vm is not a security boundary.',
          targetArgIndices: [0],
          line: loc.line,
          column: loc.column,
          sourceSpan: sinkSpan,
          sinkExpression,
          sinkProvenance,
          expression: `${calleePath}(...)`
        };
      }
    }
  }

  // Timer APIs with string argument: setTimeout(codeString, ...)
  if (node.type === 'CallExpression' && node.callee) {
    const calleeName = node.callee.type === 'Identifier' ? node.callee.name : getMemberExpressionPath(node.callee);
    if (/^(?:setTimeout|setInterval|setImmediate)$/.test(calleeName || '') && args.length > 0) {
      const firstArg = args[0];
      // Only string arguments trigger code evaluation
      if (firstArg.type !== 'FunctionExpression' && firstArg.type !== 'ArrowFunctionExpression') {
        return {
          isSink: true,
          sinkType: SINK_CONTEXTS.DYNAMIC_CODE,
          ruleId: 'LUM-DYN-004',
          checkId: 'dynamic_code_execution_pattern_search',
          category: 'dynamic_execution',
          cwe: ['CWE-95'],
          severity: 'High',
          title: 'Tainted input passed to timer API as code',
          description: 'Potentially untrusted user input flows to a timer API (setTimeout/setInterval) as a code string.',
          remediation: 'Pass a function or arrow function callback to timer APIs instead of a string.',
          targetArgIndices: [0],
          line: loc.line,
          column: loc.column,
          sourceSpan: sinkSpan,
          sinkExpression,
          sinkProvenance,
          expression: `${calleeName}(...)`
        };
      }
    }
  }

  // ==========================================
  // 4. UNSAFE DESERIALIZATION SINKS
  // ==========================================
  if (node.type === 'CallExpression' && node.callee) {
    const calleePath = getMemberExpressionPath(node.callee);
    const isUnserialize = (calleePath && /(?:nodeSerialize|serialize)\.unserialize$/i.test(calleePath)) ||
                          (node.callee.type === 'Identifier' && node.callee.name === 'unserialize');
    if (isUnserialize && args.length > 0) {
      return {
        isSink: true,
        sinkType: SINK_CONTEXTS.DESERIALIZATION,
        ruleId: 'LUM-DES-005',
        checkId: 'unsafe_deserialization_pattern_search',
        category: 'deserialization',
        cwe: ['CWE-502'],
        severity: 'High',
        title: 'Tainted input reaches unsafe object deserialization',
        description: 'Potentially untrusted user input flows into an unsafe deserialization function.',
        remediation: 'Use JSON.parse() with strict schema validation instead of arbitrary object deserialization.',
        targetArgIndices: [0],
        line: loc.line,
        column: loc.column,
        sourceSpan: sinkSpan,
        sinkExpression,
        sinkProvenance,
        expression: `${calleePath || 'unserialize'}(...)`
      };
    }
  }

  return null;
}
