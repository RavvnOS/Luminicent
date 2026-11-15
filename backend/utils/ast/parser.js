import path from 'node:path';
import { parse as babelParse } from '@babel/parser';

export const PARSER_LIMITS = Object.freeze({
  maxSourceBytes: 2 * 1024 * 1024, // 2 MB limit per file
  maxDepth: 120,
  maxNodes: 100_000
});

export const JS_TS_EXTENSIONS = new Set([
  '.js', '.jsx', '.mjs', '.cjs',
  '.ts', '.tsx', '.mts', '.cts'
]);

export function isSupportedJsTsFile(filePath) {
  if (!filePath) return false;
  const ext = path.extname(String(filePath).toLowerCase());
  return JS_TS_EXTENSIONS.has(ext);
}

export function isTypeScriptFile(filePath) {
  if (!filePath) return false;
  const ext = path.extname(String(filePath).toLowerCase());
  return ext === '.ts' || ext === '.tsx' || ext === '.mts' || ext === '.cts';
}

export function isJsxFile(filePath) {
  if (!filePath) return false;
  const ext = path.extname(String(filePath).toLowerCase());
  return ext === '.jsx' || ext === '.tsx';
}

/**
 * Parses JavaScript or TypeScript source code into a Babel AST.
 *
 * @param {string} code - The source code to parse
 * @param {Object} options - Parser options
 * @returns {Object} Parse result: { ast, parseStatus: 'success'|'partial'|'failed', errors, isPartial, recoveredErrors }
 */
export function parseSource(code, options = {}) {
  if (typeof code !== 'string') {
    return {
      ast: null,
      parseStatus: 'failed',
      errors: [{ message: 'Code must be a string' }],
      isPartial: true,
      recoveredErrors: []
    };
  }

  const maxBytes = options.maxSourceBytes || PARSER_LIMITS.maxSourceBytes;
  const sourceBufferLength = Buffer.byteLength(code, 'utf8');
  if (sourceBufferLength > maxBytes) {
    return {
      ast: null,
      parseStatus: 'skipped',
      errors: [{
        code: 'SOURCE_SIZE_EXCEEDED',
        message: `File size (${sourceBufferLength} bytes) exceeds AST parser limit of ${maxBytes} bytes`
      }],
      isPartial: true,
      recoveredErrors: []
    };
  }

  if (code.trim().length === 0) {
    return {
      ast: {
        type: 'Program',
        body: [],
        loc: { start: { line: 1, column: 0 }, end: { line: 1, column: 0 } }
      },
      parseStatus: 'success',
      errors: [],
      isPartial: false,
      recoveredErrors: []
    };
  }

  const filePath = options.filePath || '';
  const isTs = isTypeScriptFile(filePath) || options.isTypeScript;
  const isJsx = isJsxFile(filePath) || options.isJsx;

  const plugins = [
    'asyncGenerators',
    'bigInt',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'doExpressions',
    'dynamicImport',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'functionBind',
    'functionSent',
    'importMeta',
    'nullishCoalescingOperator',
    'numericSeparator',
    'objectRestSpread',
    'optionalCatchBinding',
    'optionalChaining',
    'topLevelAwait',
    'importAttributes'
  ];

  if (isTs) {
    plugins.push(['typescript', { dts: false }]);
  }
  if (isJsx || !isTs) {
    plugins.push('jsx');
  }

  const parserOptions = {
    sourceType: options.sourceType || 'unambiguous',
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowImportExportEverywhere: true,
    errorRecovery: options.errorRecovery !== false, // Resilient parser for incomplete/malformed code
    attachComment: false,
    ranges: true,
    tokens: false,
    plugins
  };

  try {
    const ast = babelParse(code, parserOptions);

    const recovered = Array.isArray(ast.errors) && ast.errors.length > 0
      ? ast.errors.map(err => ({
          message: err.message,
          line: err.loc?.line,
          column: err.loc?.column
        }))
      : [];

    return {
      ast,
      parseStatus: recovered.length > 0 ? 'partial' : 'success',
      errors: recovered,
      isPartial: recovered.length > 0,
      recoveredErrors: recovered
    };
  } catch (fatalError) {
    // Non-recoverable fatal syntax error
    const line = fatalError.loc?.line || 1;
    const column = fatalError.loc?.column || 0;
    return {
      ast: null,
      parseStatus: 'failed',
      errors: [{
        code: 'PARSE_SYNTAX_ERROR',
        message: fatalError.message,
        line,
        column
      }],
      isPartial: true,
      recoveredErrors: []
    };
  }
}
