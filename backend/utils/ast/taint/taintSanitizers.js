import { getMemberExpressionPath } from '../traversal.js';

/**
 * Supported sink context types for sanitization check.
 */
export const SINK_CONTEXTS = Object.freeze({
  SQL: 'sql',
  COMMAND: 'command',
  DYNAMIC_CODE: 'dynamic_code',
  DESERIALIZATION: 'deserialization'
});

/**
 * Context-sensitive sanitizers and validators.
 */
/**
 * Value transformations (e.g. numeric scalar conversions).
 * These functions transform their input into a scalar number or primitive
 * that cannot contain SQL injection or shell metacharacters.
 */
export const NUMERIC_CONVERSIONS = new Set([
  'parseInt',
  'parseFloat',
  'Number',
  'Math.floor',
  'Math.ceil',
  'Math.round',
  'Math.abs',
  'Math.trunc',
  'Math.min',
  'Math.max'
]);

/**
 * SQL sanitizers with sufficient implementation and execution-context evidence.
 */
export const SQL_SPECIFIC_SANITIZERS = new Set([
]);

/**
 * Boolean validator functions.
 * NOTE: These functions return boolean (true/false) indicators of validity;
 * they do NOT transform, sanitize, or escape the original input. Without
 * path-sensitive control-flow guard modeling, invoking a boolean validator
 * does NOT cleanse the underlying variable.
 */
export const BOOLEAN_VALIDATORS = new Set([
  'validator.isNumeric',
  'validator.isInt',
  'validator.isUUID',
  'validator.isAlphanumeric',
  'validator.isEmail',
  'validator.isIP',
  'validator.isPort',
  'validator.isURL'
]);

/**
 * Incompatible sanitizers (e.g. HTML encoders do NOT sanitize SQL or command injection).
 */
export const HTML_ONLY_SANITIZERS = new Set([
  'DOMPurify.sanitize',
  'validator.escape',
  'escapeHtml',
  'escapeHTML',
  'he.encode',
  'xss'
]);

/**
 * Evaluates whether an expression node applies an effective sanitizer for a specific sink context.
 *
 * @param {Object} node - AST node (CallExpression, UnaryExpression, etc.)
 * @param {string} sinkContext - One of SINK_CONTEXTS ('sql', 'command', etc.)
 * @returns {Object} { isSanitized: boolean, sanitizerName: string|null, isBooleanValidation?: boolean, isIncompatible: boolean, rationale: string }
 */
export function evaluateSanitizer(node, sinkContext, options = {}) {
  if (!node) {
    return { isSanitized: false, sanitizerName: null, isIncompatible: false, rationale: 'No sanitizer applied' };
  }

  // Unary numeric coercion, e.g. +userInput
  if (node.type === 'UnaryExpression' && node.operator === '+') {
    return {
      isSanitized: true,
      sanitizerName: 'Unary + coercion',
      context: 'numeric_scalar',
      isIncompatible: false,
      rationale: 'Unary numeric coercion forces value to primitive number'
    };
  }

  // Binary bitwise coercion, e.g. userInput | 0
  if (node.type === 'BinaryExpression' && (node.operator === '|' || node.operator === '>>' || node.operator === '<<')) {
    return {
      isSanitized: true,
      sanitizerName: `Bitwise ${node.operator} coercion`,
      context: 'numeric_scalar',
      isIncompatible: false,
      rationale: 'Bitwise operation forces value to 32-bit integer'
    };
  }

  if (node.type === 'CallExpression' && node.callee) {
    let callName = null;
    if (node.callee.type === 'Identifier') {
      callName = node.callee.name;
    } else if (node.callee.type === 'MemberExpression') {
      callName = getMemberExpressionPath(node.callee);
      if (!callName && node.callee.property?.type === 'Identifier') {
        callName = node.callee.property.name;
      }
    }

    if (!callName) {
      return { isSanitized: false, sanitizerName: null, isIncompatible: false, rationale: 'Unknown call expression' };
    }

    // Check Boolean validators: These return boolean results and DO NOT mutate or cleanse the input!
    if (BOOLEAN_VALIDATORS.has(callName)) {
      return {
        isSanitized: false,
        sanitizerName: callName,
        isBooleanValidation: true,
        isIncompatible: false,
        rationale: `Boolean validator '${callName}()' returns boolean result and does not transform or escape the input string; without path-sensitive guard modeling, input retains taint conservatively`
      };
    }

    // Check HTML-only sanitizers (incompatible with SQL/Command)
    if (HTML_ONLY_SANITIZERS.has(callName) || /DOMPurify|escapeHtml|escapeHTML/i.test(callName)) {
      if (sinkContext === SINK_CONTEXTS.SQL || sinkContext === SINK_CONTEXTS.COMMAND) {
        return {
          isSanitized: false,
          sanitizerName: callName,
          isIncompatible: true,
          rationale: `HTML sanitizer '${callName}' does not sanitize inputs for ${sinkContext} sinks`
        };
      }
    }

    // Numeric conversions sanitize SQL and command inputs (value transformation)
    if (NUMERIC_CONVERSIONS.has(callName)) {
      return {
        isSanitized: true,
        sanitizerName: callName,
        context: 'numeric_scalar',
        isIncompatible: false,
        rationale: `Numeric conversion via ${callName}() produces safe scalar number`
      };
    }

    // Generic unknown sanitizers (e.g. clean(), sanitize(), validate(), escape())
    if (/^(?:sanitize|clean|filter|validate|escape)$/i.test(callName)) {
      return {
        isSanitized: false,
        sanitizerName: callName,
        isIncompatible: false,
        rationale: `Generic sanitizer '${callName}()' cannot be assumed safe without verified implementation context`
      };
    }
  }

  return {
    isSanitized: false,
    sanitizerName: null,
    isIncompatible: false,
    rationale: 'No recognized context-appropriate sanitizer'
  };
}

/**
 * Evaluates whether a taint record is effectively sanitized for a given sink context.
 *
 * @param {Object} record - TaintRecord instance
 * @param {string|null} sinkContext - One of SINK_CONTEXTS or null
 * @param {string|null} [argRole=null] - Role of the argument ('shell_command', 'shell_argument', 'command_argument', 'command_executable')
 * @returns {boolean} True if safe/cleansed for the context, false if taint remains
 */
export function isTaintSanitized(record, sinkContext = null, argRole = null) {
  if (!record || !record.sanitization || !record.sanitization.sanitized) {
    return false;
  }
  const sanCtx = record.sanitization.context;
  // If no sink context is known (intermediate variable assignment), only universal
  // sanitizers are considered fully safe. Context-specific sanitizers (e.g. 'sql', 'html')
  // must retain their taint record so downstream sinks can evaluate context compatibility.
  if (!sinkContext) {
    return sanCtx === 'all';
  }
  if (!sanCtx || sanCtx === 'all') {
    return true;
  }
  if (sanCtx === 'numeric_scalar') {
    if (sinkContext === SINK_CONTEXTS.SQL) {
      return true;
    }
    if (sinkContext === SINK_CONTEXTS.COMMAND) {
      // Numeric transformation neutralizes shell metacharacters in shell execution,
      // but does NOT neutralize target-program argument semantics, flag injection,
      // or executable path control in non-shell execution.
      return argRole === 'shell_command' || argRole === 'shell_argument';
    }
    return false;
  }
  return sanCtx === sinkContext;
}
