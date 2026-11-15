import { parseSource, isSupportedJsTsFile, PARSER_LIMITS } from './parser.js';
import { walkAST, isDynamicStringExpression, isStringLiteral } from './traversal.js';
import {
  detectDynamicExecution,
  detectCommandExecution,
  detectSqlInjection,
  detectUnsafeDeserialization
} from './recognizers.js';
import { analyzeAstTaint } from './taint/taintAnalyzer.js';
import { createSinkProvenanceResolver } from './sinkProvenance.js';
import { createSinkIdentity } from '../findingIdentity.js';

/**
 * Analyzes JavaScript or TypeScript source code using structural AST analysis.
 *
 * @param {string} code - The source code to analyze
 * @param {Object} options - Options including filePath, relativePath, limits
 * @returns {Object} Analysis result: { findings, parseStatus, errors, isPartial, metrics }
 */
export function analyzeAstSource(code, options = {}) {
  const filePath = options.filePath || options.relativePath || 'source.js';
  const relativePath = options.relativePath || filePath;
  const startTime = Date.now();

  const parseResult = parseSource(code, {
    filePath,
    maxSourceBytes: options.maxSourceBytes || PARSER_LIMITS.maxSourceBytes,
    errorRecovery: options.errorRecovery !== false
  });

  if (!parseResult.ast) {
    return {
      findings: [],
      parseStatus: parseResult.parseStatus,
      errors: parseResult.errors,
      isPartial: true,
      metrics: {
        nodeCount: 0,
        maxDepth: 0,
        parseTimeMs: Date.now() - startTime
      }
    };
  }

  // Pre-pass: identify variables assigned dynamic SQL expressions
  const dynamicSqlVariables = new Map();
  const SQL_KEYWORD_REGEX = /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|FROM|WHERE)\b/i;

  walkAST(parseResult.ast, {
    VariableDeclarator(node) {
      if (node.id && node.id.type === 'Identifier' && node.init) {
        if (isDynamicStringExpression(node.init)) {
          const initStr = code.slice(node.init.start || 0, node.init.end || 0);
          if (SQL_KEYWORD_REGEX.test(initStr)) {
            dynamicSqlVariables.set(node.id.name, {
              line: node.loc ? node.loc.start.line : 1,
              column: node.loc ? node.loc.start.column : 0
            });
          }
        }
      }
    },
    AssignmentExpression(node) {
      if (node.left && node.left.type === 'Identifier' && node.right) {
        if (isDynamicStringExpression(node.right)) {
          const rightStr = code.slice(node.right.start || 0, node.right.end || 0);
          if (SQL_KEYWORD_REGEX.test(rightStr)) {
            dynamicSqlVariables.set(node.left.name, {
              line: node.loc ? node.loc.start.line : 1,
              column: node.loc ? node.loc.start.column : 0
            });
          }
        }
      }
    }
  }, options);

  const context = {
    dynamicSqlVariables,
    filePath,
    relativePath
  };
  const sinkProvenanceResolver = createSinkProvenanceResolver(parseResult.ast);
  context.sinkProvenanceResolver = sinkProvenanceResolver;

  const rawFindings = [];
  const addCallFindings = (node, findings) => {
    const sinkProvenance = sinkProvenanceResolver.resolveCall(node);
    const sinkExpression = node.callee?.start !== undefined && node.callee?.end !== undefined
      ? code.slice(node.callee.start, node.callee.end)
      : null;
    for (const finding of findings) {
      rawFindings.push({
        ...finding,
        sourceSpan: Number.isInteger(node.start) && Number.isInteger(node.end)
          ? { start: node.start, end: node.end }
          : null,
        sinkExpression,
        sinkProvenance,
        sinkIdentity: createSinkIdentity({
          ...finding,
          file: relativePath,
          sourceSpan: Number.isInteger(node.start) && Number.isInteger(node.end)
            ? { start: node.start, end: node.end }
            : null
        }),
        producerOrigins: ['ast_pattern']
      });
    }
  };

  // Security pattern detection pass
  const traversalResult = walkAST(parseResult.ast, {
    CallExpression(node) {
      addCallFindings(node, detectDynamicExecution(node, code, context));
      addCallFindings(node, detectCommandExecution(node, code, context));
      addCallFindings(node, detectSqlInjection(node, code, context));
      addCallFindings(node, detectUnsafeDeserialization(node, code, context));
    },
    NewExpression(node) {
      addCallFindings(node, detectDynamicExecution(node, code, context));
    }
  }, options);

  // AST intra-function taint analysis pass
  const taintResult = options.skipTaintAnalysis
    ? { findings: [], coverageStatus: 'skipped', limitations: [], metrics: {} }
    : analyzeAstTaint(parseResult.ast, {
      code,
      filePath,
      relativePath,
      sinkProvenanceResolver,
      ...(options.taintOptions || {})
    });

  // Enrich existing recognizer findings or add new taint-confirmed findings
  for (const tf of taintResult.findings) {
    const existing = rawFindings.find(
      (rf) => rf.ruleId === tf.ruleId &&
        rf.sourceSpan?.start === tf.sourceSpan?.start &&
        rf.sourceSpan?.end === tf.sourceSpan?.end
    );
    if (existing) {
      existing.isTaintConfirmed = true;
      existing.taintTrace = tf.taintTrace;
      existing.line = tf.line;
      existing.column = tf.column;
      existing.sourceSpan = tf.sourceSpan || existing.sourceSpan;
      existing.sinkExpression = tf.sinkExpression || existing.sinkExpression;
      existing.sinkProvenance = tf.sinkProvenance || existing.sinkProvenance;
      existing.sinkIdentity = createSinkIdentity({
        ...existing,
        file: relativePath
      });
      existing.findingFingerprint = existing.sinkIdentity;
      existing.producerOrigins = [...new Set([
        ...(existing.producerOrigins || []),
        'ast_taint'
      ])].sort();
      if (!existing.confidence) {
        existing.confidence = tf.confidence;
      }
      existing.evidence = tf.evidence;
    } else {
      rawFindings.push({
        ...tf,
        sinkIdentity: createSinkIdentity({ ...tf, file: relativePath }),
        findingFingerprint: createSinkIdentity({ ...tf, file: relativePath }),
        producerOrigins: [...new Set([
          ...(tf.producerOrigins || []),
          'ast_taint'
        ])].sort()
      });
    }
  }

  // Normalize and deduplicate findings internally
  const seenFindings = new Set();
  const normalizedFindings = [];

  for (const raw of rawFindings) {
    const dedupeKey = Number.isInteger(raw.sourceSpan?.start) &&
      Number.isInteger(raw.sourceSpan?.end)
      ? `${raw.ruleId}:${relativePath}:${raw.sourceSpan.start}:${raw.sourceSpan.end}`
      : null;
    if (dedupeKey && seenFindings.has(dedupeKey)) continue;
    if (dedupeKey) seenFindings.add(dedupeKey);

    normalizedFindings.push({
      ...raw,
      file: relativePath,
      sinkIdentity: createSinkIdentity({ ...raw, file: relativePath }),
      findingFingerprint: createSinkIdentity({ ...raw, file: relativePath }) ||
        raw.findingFingerprint,
      sinkIdentityStatus: createSinkIdentity({ ...raw, file: relativePath })
        ? 'resolved'
        : 'unresolved',
      locations: [{
        file: relativePath,
        line: raw.line,
        ...(Number.isInteger(raw.column) ? { column: raw.column } : {}),
        ...(raw.sourceSpan ? { start: raw.sourceSpan.start, end: raw.sourceSpan.end } : {})
      }],
      occurrences: 1,
      origin: raw.origin || 'ast_analysis'
    });
  }

  return {
    findings: normalizedFindings,
    parseStatus: parseResult.parseStatus,
    errors: parseResult.errors,
    isPartial: parseResult.isPartial || traversalResult.depthLimitExceeded || traversalResult.nodeLimitExceeded || taintResult.coverageStatus === 'partial',
    metrics: {
      nodeCount: traversalResult.nodeCount,
      maxDepth: traversalResult.maxDepthReached,
      parseTimeMs: Date.now() - startTime,
      taint: taintResult.metrics
    },
    limitations: taintResult.limitations,
    sinkProvenance: {
      calls: sinkProvenanceResolver.getCallDescriptors(),
      declarations: sinkProvenanceResolver.getDeclarationRanges()
    }
  };
}
