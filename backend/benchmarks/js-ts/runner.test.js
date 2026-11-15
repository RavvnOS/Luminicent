import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  calculateMetrics,
  evaluateCase,
  summarizeOutcomes
} from './runner.js';
import { parseSource } from '../../utils/ast/parser.js';

const manifestPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cases.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

test('benchmark manifest has unique, categorized, explicitly labeled cases', () => {
  const ids = manifest.cases.map((benchmarkCase) => benchmarkCase.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(manifest.cases.every((benchmarkCase) =>
    benchmarkCase.category &&
    ['vulnerable', 'safe', 'partial', 'unsupported'].includes(benchmarkCase.expectedOutcome) &&
    benchmarkCase.files &&
    benchmarkCase.rationale
  ));
  assert.ok(manifest.cases.some((benchmarkCase) =>
    benchmarkCase.id === 'sql-two-sinks-one-line' &&
    benchmarkCase.expectedFindings.length === 2
  ));
  assert.ok(manifest.cases.some((benchmarkCase) =>
    benchmarkCase.expectedOutcome === 'partial'
  ));
  assert.ok(manifest.cases.some((benchmarkCase) =>
    benchmarkCase.id === 'sql-dynamic-import-partial-multi-sink' &&
    benchmarkCase.expectedOutcome === 'partial' &&
    benchmarkCase.expectedFindings.length === 2
  ));
  assert.ok(manifest.cases.some((benchmarkCase) =>
    benchmarkCase.expectedOutcome === 'unsupported'
  ));
  const expectedFindings = manifest.cases.flatMap((benchmarkCase) =>
    benchmarkCase.expectedFindings || []
  );
  assert.equal(expectedFindings.length, 19);
  assert.ok(expectedFindings.every((expected) =>
    (expected.identityStatus === 'verified' &&
      Number.isInteger(expected.sourceSpan?.start) &&
      Number.isInteger(expected.sourceSpan?.end) &&
      expected.sourceSpan.end > expected.sourceSpan.start) ||
    (expected.identityStatus === 'unverified' &&
      typeof expected.identityUnverifiedReason === 'string')
  ));

  const verified = expectedFindings.filter((expected) =>
    expected.identityStatus === 'verified'
  );
  const unverified = expectedFindings.filter((expected) =>
    expected.identityStatus === 'unverified'
  );
  assert.equal(verified.length, 15);
  assert.equal(unverified.length, 4);
  for (const benchmarkCase of manifest.cases) {
    for (const expected of benchmarkCase.expectedFindings || []) {
      if (expected.identityStatus !== 'verified') continue;
      const source = benchmarkCase.files[expected.file];
      const ast = parseSource(source, { filePath: expected.file }).ast;
      const calls = [];
      const walk = (node) => {
        if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;
        if (['CallExpression', 'NewExpression'].includes(node.type)) calls.push(node);
        for (const [key, value] of Object.entries(node)) {
          if (['loc', 'range', 'tokens', 'comments'].includes(key)) continue;
          if (Array.isArray(value)) value.forEach(walk);
          else if (value && typeof value === 'object' && typeof value.type === 'string') {
            walk(value);
          }
        }
      };
      walk(ast);
      assert.equal(calls.filter((call) =>
        call.start === expected.sourceSpan.start &&
        call.end === expected.sourceSpan.end &&
        call.loc.start.line === expected.line &&
        (!expected.sinkContains ||
          source.slice(call.start, call.end).includes(expected.sinkContains))
      ).length, 1, `${benchmarkCase.id} expected span must identify exactly one sink call`);
    }
  }
});

test('benchmark matches separate expected sinks on the same line independently', () => {
  const benchmarkCase = {
    id: 'two-sinks',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Two independent sinks',
    expectedFindings: [
      {
        ruleId: 'LUM-INJ-001',
        file: 'src/app.js',
        line: 4,
        identityStatus: 'verified',
        sourceSpan: { start: 20, end: 48 },
        requireTaintTrace: true,
        sourceContains: 'req',
        sinkContains: 'first'
      },
      {
        ruleId: 'LUM-INJ-001',
        file: 'src/app.js',
        line: 4,
        identityStatus: 'verified',
        sourceSpan: { start: 60, end: 90 },
        requireTaintTrace: true,
        sourceContains: 'req',
        sinkContains: 'second'
      }
    ]
  };
  const makeFinding = (sinkExpression) => ({
    ruleId: 'LUM-INJ-001',
    checkId: 'sql_injection_pattern_search',
    file: 'src/app.js',
    line: 4,
    sourceSpan: sinkExpression.includes('first')
      ? { start: 20, end: 48 }
      : { start: 60, end: 90 },
    evidence: `Source: req.query.value | Sink: ${sinkExpression}`,
    taintTrace: {
      source: { expression: 'req.query.value' },
      sink: { expression: sinkExpression },
      steps: []
    }
  });
  const result = evaluateCase(benchmarkCase, {
    issues: [
      makeFinding("db.query('SELECT ' + first)"),
      makeFinding("db.query('SELECT ' + second)")
    ],
    scan: {
      checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }]
    }
  });

  assert.equal(result.expectationStatus, 'as_expected');
  assert.equal(result.matchedExpectedFindings.length, 2);
  assert.equal(result.missingExpectedFindings.length, 0);
  assert.equal(result.incompleteEvidence.length, 0);
});

test('detection matching does not require complete taint evidence', () => {
  const result = evaluateCase({
    id: 'detected-without-trace',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Detection identity exists while required trace evidence is absent',
    expectedFindings: [{
      ruleId: 'LUM-INJ-001',
      file: 'src/app.js',
      line: 4,
      identityStatus: 'verified',
      sourceSpan: { start: 20, end: 48 },
      requireTaintTrace: true
    }]
  }, {
    issues: [{
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'src/app.js',
      line: 4,
      sourceSpan: { start: 20, end: 48 },
      evidence: 'SQL sink detected'
    }],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });
  const metrics = calculateMetrics([result]);

  assert.equal(result.matchedExpectedFindings.length, 1);
  assert.equal(result.missingExpectedFindings.length, 0);
  assert.equal(result.incompleteEvidence.length, 1);
  assert.deepEqual(result.findingOutcomes, { truePositives: 1, falsePositives: 0, falseNegatives: 0 });
  assert.equal(metrics.findingLevel.falseNegatives, 0);
  assert.deepEqual(metrics.evidenceCompleteness, {
    complete: 0,
    expected: 1,
    rate: 0,
    denominator: 1,
    scope: 'matched detections in cases included in supported accuracy'
  });
});

test('benchmark requires exact sink identity for verified detection', () => {
  const result = evaluateCase({
    id: 'identity-required',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Line coordinates alone do not establish which sink was detected',
    expectedFindings: [{
      ruleId: 'LUM-INJ-001',
      file: 'src/app.js',
      line: 4,
      identityStatus: 'verified',
      sourceSpan: { start: 20, end: 48 }
    }]
  }, {
    issues: [{
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'src/app.js',
      line: 4,
      evidence: 'Same line, but sink identity is unavailable'
    }],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });
  const metrics = calculateMetrics([result]);

  assert.equal(result.matchedExpectedFindings.length, 0);
  assert.equal(result.missingExpectedFindings.length, 1);
  assert.equal(result.identityUnverifiedFindingCount, 1);
  assert.deepEqual(result.findingOutcomes, {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 1
  });
  assert.equal(metrics.detectionEvidence.matchedDetections, 0);
  assert.equal(metrics.detectionEvidence.missingDetections, 1);
});

test('identity-unverified expectations and findings never count as verified detection', () => {
  const result = evaluateCase({
    id: 'unverified-identity',
    category: 'credential_indicators',
    expectedOutcome: 'vulnerable',
    checkId: 'secret_pattern_search',
    rationale: 'Text finding has no stable sink span',
    expectedFindings: [{
      ruleId: 'LUM-SEC-002',
      file: 'src/credentials.js',
      line: 1,
      identityStatus: 'unverified',
      identityUnverifiedReason: 'The credential analyzer does not report a stable span.'
    }]
  }, {
    issues: [{
      ruleId: 'LUM-SEC-002',
      checkId: 'secret_pattern_search',
      file: 'src/credentials.js',
      line: 1,
      evidence: 'Redacted credential finding'
    }],
    scan: { checks: [{ id: 'secret_pattern_search', status: 'completed' }] }
  });
  const metrics = calculateMetrics([result]);

  assert.equal(result.expectationStatus, 'identity_unverified');
  assert.equal(result.excludedFromAccuracy, true);
  assert.equal(result.matchedExpectedFindings.length, 0);
  assert.equal(result.identityUnverifiedExpectationCount, 1);
  assert.equal(result.identityUnverifiedFindingCount, 1);
  assert.deepEqual(result.findingOutcomes, {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0
  });
  assert.equal(metrics.detectionEvidence.verifiedExpectedSinks, 0);
  assert.equal(metrics.detectionEvidence.identityUnverifiedExpectations, 1);
  assert.equal(metrics.findingLevel.precision, null);
  assert.equal(metrics.findingLevel.recall, null);
});

test('provenance expectations are evaluated independently from sink detection', () => {
  const expectedProvenance = {
    status: 'supported_external_api',
    resolution: 'verified_module_specifier',
    api: 'exec',
    callee: 'exec',
    confidence: 'high'
  };
  const benchmarkCase = (id) => ({
    id,
    category: 'command_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'os_command_injection_pattern_search',
    rationale: 'Provenance is evidence independent of exact sink detection',
    expectedFindings: [{
      ruleId: 'LUM-INJ-002',
      file: 'src/app.js',
      line: 4,
      identityStatus: 'verified',
      sourceSpan: { start: 20, end: 48 },
      sinkProvenance: expectedProvenance,
      requireTaintTrace: true
    }]
  });
  const finding = (sinkProvenance, taintTrace = {
    source: { expression: 'req.query.command' },
    sink: { expression: 'exec(command)' },
    steps: []
  }) => ({
    ruleId: 'LUM-INJ-002',
    checkId: 'os_command_injection_pattern_search',
    file: 'src/app.js',
    line: 4,
    sourceSpan: { start: 20, end: 48 },
    sinkIdentity: 'sink-v1:src/app.js:os_command_injection_pattern_search:LUM-INJ-002:20:48',
    sinkExpression: 'exec',
    sinkProvenance,
    taintTrace,
    evidence: 'Tainted child process execution'
  });
  const evaluate = (id, reportFinding) => evaluateCase(benchmarkCase(id), {
    issues: [reportFinding],
    scan: { checks: [{ id: 'os_command_injection_pattern_search', status: 'completed' }] }
  });
  const missingProvenance = evaluate('missing-provenance', finding(undefined));
  const wrongProvenance = evaluate('wrong-provenance-status', finding({
    ...expectedProvenance,
    status: 'external_unresolved'
  }));
  const wrongResolution = evaluate('wrong-provenance-resolution', finding({
    ...expectedProvenance,
    resolution: 'module_specifier_only'
  }));
  const wrongApi = evaluate('wrong-provenance-api', finding({
    ...expectedProvenance,
    api: 'spawn'
  }));
  const wrongConfidence = evaluate('wrong-provenance-confidence', finding({
    ...expectedProvenance,
    confidence: 'low'
  }));
  const correctProvenance = evaluate('correct-provenance', finding(expectedProvenance));
  const missingTrace = evaluate('missing-trace-valid-provenance',
    finding(expectedProvenance, null));
  const metrics = calculateMetrics([
    missingProvenance,
    wrongProvenance,
    wrongResolution,
    wrongApi,
    wrongConfidence,
    correctProvenance,
    missingTrace
  ]);

  for (const result of [
    missingProvenance,
    wrongProvenance,
    wrongResolution,
    wrongApi,
    wrongConfidence,
    correctProvenance,
    missingTrace
  ]) {
    assert.equal(result.matchedExpectedFindings.length, 1);
    assert.equal(result.missingExpectedFindings.length, 0);
    assert.equal(result.findingOutcomes.falseNegatives, 0);
  }
  assert.equal(missingProvenance.incompleteEvidence.length, 1);
  assert.equal(wrongProvenance.incompleteEvidence.length, 1);
  assert.equal(wrongResolution.incompleteEvidence.length, 1);
  assert.equal(wrongApi.incompleteEvidence.length, 1);
  assert.equal(wrongConfidence.incompleteEvidence.length, 1);
  assert.equal(correctProvenance.incompleteEvidence.length, 0);
  assert.equal(missingTrace.incompleteEvidence.length, 1);
  assert.deepEqual(metrics.detectionEvidence, {
    verifiedExpectedSinks: 7,
    identityUnverifiedExpectations: 0,
    matchedDetections: 7,
    missingDetections: 0,
    evidenceCompleteDetections: 1,
    evidenceIncompleteDetections: 6,
    identityUnverifiedFindings: 0,
    evidenceCompletenessDenominator: 7
  });
});

test('benchmark sink matching uses source span and does not count producer duplicates twice', () => {
  const benchmarkCase = {
    id: 'one-sink-two-producers',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Pattern and taint producers refer to one sink',
    expectedFindings: [{
      ruleId: 'LUM-INJ-001',
      file: 'src/app.js',
      line: 4,
      identityStatus: 'verified',
      sourceSpan: { start: 20, end: 48 },
      requireTaintTrace: true,
      sourceContains: 'req',
      sinkContains: 'db.query'
    }]
  };
  const shared = {
    ruleId: 'LUM-INJ-001',
    checkId: 'sql_injection_pattern_search',
    file: 'src/app.js',
    line: 4,
    sourceSpan: { start: 20, end: 48 },
    sinkIdentity: 'sink-v1:src/app.js:sql_injection_pattern_search:LUM-INJ-001:20:48',
    sinkExpression: 'db.query(sql)',
    evidence: 'SQL injection sink'
  };
  const result = evaluateCase(benchmarkCase, {
    issues: [
      { ...shared, producerOrigins: ['pattern'] },
      {
        ...shared,
        isTaintConfirmed: true,
        producerOrigins: ['ast_taint'],
        taintTrace: {
          source: { expression: 'req.query.value' },
          sink: { expression: 'db.query(sql)' },
          steps: []
        }
      }
    ],
    scan: {
      checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }]
    }
  });

  assert.equal(result.findingCount, 1);
  assert.equal(result.findings[0].caseId, benchmarkCase.id);
  assert.deepEqual(result.findings[0].producerOrigins, ['ast_taint', 'pattern']);
  assert.equal(result.expectationStatus, 'as_expected');
  assert.equal(result.missingExpectedFindings.length, 0);
});

test('benchmark retains alternate evidence for duplicate producer identities', () => {
  const expectedSink = {
    ruleId: 'LUM-INJ-001',
    file: 'src/app.js',
    line: 4,
    identityStatus: 'verified',
    sourceSpan: { start: 20, end: 48 },
    requireTaintTrace: true,
    sourceContains: 'second',
    sinkContains: 'second'
  };
  const makeFinding = (source, sink) => ({
    ruleId: 'LUM-INJ-001',
    checkId: 'sql_injection_pattern_search',
    file: 'src/app.js',
    line: 4,
    sourceSpan: { start: 20, end: 48 },
    isTaintConfirmed: true,
    producerOrigins: ['ast_taint'],
    evidence: 'SQL injection sink',
    taintTrace: {
      source: { expression: source },
      sink: { expression: sink },
      steps: []
    }
  });
  const result = evaluateCase({
    id: 'alternate-producer-evidence',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Either source trace may satisfy evidence for one identified sink',
    expectedFindings: [expectedSink]
  }, {
    issues: [
      makeFinding('req.query.first', 'db.query(first)'),
      makeFinding('req.query.second', 'db.query(second)')
    ],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });

  assert.equal(result.findingCount, 1);
  assert.equal(result.findings[0].alternateTraces.length, 1);
  assert.equal(result.incompleteEvidence.length, 0);
});

test('benchmark rejects a same-line finding whose sink span identifies another call', () => {
  const result = evaluateCase({
    id: 'wrong-sink-span',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Expected one exact call',
    expectedFindings: [{
      ruleId: 'LUM-INJ-001',
      file: 'src/app.js',
      line: 4,
      identityStatus: 'verified',
      sourceSpan: { start: 20, end: 48 }
    }]
  }, {
    issues: [{
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'src/app.js',
      line: 4,
      sourceSpan: { start: 60, end: 90 },
      evidence: 'Different SQL sink'
    }],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });

  assert.equal(result.expectationStatus, 'mismatch');
  assert.equal(result.missingExpectedFindings.length, 1);
  assert.equal(result.unexpectedFindings.length, 1);
});

test('partial and unsupported labels never count as clean accuracy cases', () => {
  const partialResult = evaluateCase({
    id: 'partial',
    category: 'sql_injection',
    expectedOutcome: 'partial',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Incomplete graph',
    expectedFindings: []
  }, {
    issues: [],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'partial' }] }
  });
  const unsupportedResult = evaluateCase({
    id: 'unsupported',
    category: 'sql_injection',
    expectedOutcome: 'unsupported',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Unmodeled source',
    expectedFindings: []
  }, {
    issues: [],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });

  assert.equal(partialResult.excludedFromAccuracy, true);
  assert.equal(partialResult.expectationStatus, 'partial_as_expected');
  assert.equal(unsupportedResult.excludedFromAccuracy, true);
  assert.equal(unsupportedResult.expectationStatus, 'excluded_unsupported');
  const metrics = calculateMetrics([partialResult, unsupportedResult]);
  assert.equal(metrics.caseLevel.excluded, 2);
  assert.equal(metrics.caseLevel.trueNegatives, 0);
  assert.equal(metrics.analysis.unsupportedCaseCount, 1);
});

test('partial multi-sink case reports a missed sink outside supported accuracy totals', () => {
  const result = evaluateCase({
    id: 'partial-two-sinks-one-detected',
    category: 'sql_injection',
    expectedOutcome: 'partial',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Partial graph reports only one of two expected sinks',
    expectedFindings: [
      {
        ruleId: 'LUM-INJ-001',
        file: 'src/app.js',
        line: 4,
        identityStatus: 'verified',
        sourceSpan: { start: 20, end: 48 },
        sinkContains: 'first'
      },
      {
        ruleId: 'LUM-INJ-001',
        file: 'src/app.js',
        line: 4,
        identityStatus: 'verified',
        sourceSpan: { start: 60, end: 90 },
        sinkContains: 'second'
      }
    ]
  }, {
    issues: [{
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'src/app.js',
      line: 4,
      sourceSpan: { start: 20, end: 48 },
      evidence: 'SQL sink',
      sinkExpression: 'db.query(first)',
      taintTrace: {
        source: { expression: 'req.query.first' },
        sink: { expression: 'db.query(first)' },
        steps: []
      }
    }],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'partial' }] }
  });
  const metrics = calculateMetrics([result]);

  assert.equal(result.analysisStatus, 'partial');
  assert.equal(result.expectationStatus, 'partial_incomplete');
  assert.equal(result.excludedFromAccuracy, true);
  assert.equal(result.matchedExpectedFindings.length, 1);
  assert.equal(result.missingExpectedFindings.length, 1);
  assert.deepEqual(result.findingOutcomes, { truePositives: 1, falsePositives: 0, falseNegatives: 1 });
  assert.deepEqual(metrics.findingLevel, {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    precision: null,
    recall: null,
    denominators: { precision: 0, recall: 0 }
  });
  assert.deepEqual(metrics.analysis.partialFindingLevel, {
    truePositives: 1,
    falsePositives: 0,
    falseNegatives: 1
  });
  assert.equal(metrics.analysis.partialCases, 1);
  assert.equal(metrics.analysis.unsupportedCaseCount, 0);
});

test('failed and skipped checks remain visible and are excluded from clean accuracy', () => {
  const makeCase = (id) => ({
    id,
    category: 'sql_injection',
    expectedOutcome: 'safe',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Check did not complete',
    expectedFindings: []
  });
  const failed = evaluateCase(makeCase('failed-case'), {
    issues: [],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'failed' }] }
  });
  const skipped = evaluateCase(makeCase('skipped-case'), {
    issues: [],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'skipped' }] }
  });
  const metrics = calculateMetrics([failed, skipped]);

  assert.equal(failed.excludedFromAccuracy, true);
  assert.equal(failed.expectationStatus, 'analysis_incomplete');
  assert.equal(skipped.excludedFromAccuracy, true);
  assert.equal(skipped.expectationStatus, 'analysis_incomplete');
  assert.equal(metrics.caseLevel.trueNegatives, 0);
  assert.equal(metrics.caseLevel.excluded, 2);
  assert.equal(metrics.analysis.statusCounts.failed, 1);
  assert.equal(metrics.analysis.statusCounts.skipped, 1);
});

test('metrics separate case and sink-level outcomes and expose undefined ratios', () => {
  const result = evaluateCase({
    id: 'one-missed-sink',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'Two sinks',
    expectedFindings: [
      {
        ruleId: 'LUM-INJ-001',
        file: 'src/app.js',
        line: 3,
        identityStatus: 'verified',
        sourceSpan: { start: 20, end: 48 }
      },
      {
        ruleId: 'LUM-INJ-001',
        file: 'src/app.js',
        line: 3,
        identityStatus: 'verified',
        sourceSpan: { start: 60, end: 90 }
      }
    ]
  }, {
    issues: [{
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'src/app.js',
      line: 3,
      sourceSpan: { start: 20, end: 48 },
      evidence: 'SQL sink (<redacted>)'
    }],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });
  const metrics = calculateMetrics([result]);
  assert.equal(metrics.findingLevel.truePositives, 1);
  assert.equal(metrics.findingLevel.falseNegatives, 1);
  assert.equal(metrics.caseLevel.truePositives, 1);
  assert.equal(metrics.caseLevel.falseNegatives, 0);
  assert.equal(metrics.evidenceCompleteness.complete, 1);
  assert.equal(metrics.evidenceCompleteness.expected, 1);
  assert.equal(metrics.evidenceCompleteness.rate, 1);
  assert.equal(metrics.findingLevel.denominators.precision, 1);
  assert.equal(metrics.findingLevel.denominators.recall, 2);
  assert.equal(calculateMetrics([]).findingLevel.precision, null);
  assert.equal(calculateMetrics([]).findingLevel.recall, null);
  assert.equal(calculateMetrics([]).evidenceCompleteness.rate, null);
  assert.equal(calculateMetrics([]).caseLevel.precision, null);
  assert.equal(calculateMetrics([]).caseLevel.recall, null);
  assert.equal(calculateMetrics([]).analysis.completionRate, null);
});

test('extra findings do not turn a vulnerable case into a case-level false positive', () => {
  const result = evaluateCase({
    id: 'one-expected-one-extra',
    category: 'sql_injection',
    expectedOutcome: 'vulnerable',
    checkId: 'sql_injection_pattern_search',
    rationale: 'One real sink and one unexpected report',
    expectedFindings: [{
      ruleId: 'LUM-INJ-001',
      file: 'src/app.js',
      line: 3,
      identityStatus: 'verified',
      sourceSpan: { start: 20, end: 48 }
    }]
  }, {
    issues: [
      {
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        file: 'src/app.js',
        line: 3,
        sourceSpan: { start: 20, end: 48 },
        evidence: 'Expected SQL sink'
      },
      {
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        file: 'src/app.js',
        line: 4,
        sourceSpan: { start: 60, end: 90 },
        evidence: 'Unexpected SQL report'
      }
    ],
    scan: { checks: [{ id: 'sql_injection_pattern_search', status: 'completed' }] }
  });
  const metrics = calculateMetrics([result]);

  assert.equal(metrics.caseLevel.truePositives, 1);
  assert.equal(metrics.caseLevel.falsePositives, 0);
  assert.equal(metrics.findingLevel.falsePositives, 1);
});

test('category outcome summaries are deterministic and retain every outcome label', () => {
  assert.deepEqual(summarizeOutcomes([
    { category: 'sql_injection', expectedOutcome: 'safe' },
    { category: 'sql_injection', expectedOutcome: 'vulnerable' },
    { category: 'dynamic_code_execution', expectedOutcome: 'partial' }
  ]), {
    dynamic_code_execution: { partial: 1 },
    sql_injection: { safe: 1, vulnerable: 1 }
  });
});
