import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeProduction } from '../../utils/productionAnalyzer.js';
import { reconcileFindingsBySinkIdentity } from '../../utils/findingIdentity.js';

export const BENCHMARK_VERSION = '1.3.0';
export const EXPECTED_OUTCOMES = new Set([
  'vulnerable',
  'safe',
  'partial',
  'unsupported'
]);

const manifestPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cases.json');
const BASE_PROJECT_FILES = Object.freeze({
  Dockerfile: 'FROM node:22-alpine\nUSER node\nHEALTHCHECK CMD true\n',
  '.dockerignore': 'node_modules\n',
  'README.md': 'Benchmark fixture project\n',
  'package.json': JSON.stringify({ name: 'luminicent-js-ts-benchmark', version: '1.0.0' }),
  'package-lock.json': JSON.stringify({
    name: 'luminicent-js-ts-benchmark',
    lockfileVersion: 3,
    packages: { '': { name: 'luminicent-js-ts-benchmark', version: '1.0.0' } }
  })
});
const QUIET_LOGGER = Object.freeze({ info() {}, warn() {}, error() {} });
const FIXED_NOW = () => new Date('2026-01-01T00:00:00.000Z');
const ANALYZER_OUTCOMES = new Set([
  'completed',
  'partial',
  'failed',
  'unsupported',
  'skipped'
]);

function assertManifest(manifest) {
  if (manifest?.benchmarkVersion !== BENCHMARK_VERSION || !Array.isArray(manifest.cases)) {
    throw new Error(`Invalid benchmark manifest or unsupported benchmark version: ${manifest?.benchmarkVersion}`);
  }
  const ids = new Set();
  for (const benchmarkCase of manifest.cases) {
    if (!benchmarkCase?.id || ids.has(benchmarkCase.id)) {
      throw new Error(`Missing or duplicate benchmark case id: ${benchmarkCase?.id || '<empty>'}`);
    }
    ids.add(benchmarkCase.id);
    if (!EXPECTED_OUTCOMES.has(benchmarkCase.expectedOutcome)) {
      throw new Error(`Invalid expected outcome for ${benchmarkCase.id}`);
    }
    if (!benchmarkCase.category || !benchmarkCase.checkId || !benchmarkCase.rationale ||
        !benchmarkCase.files || typeof benchmarkCase.files !== 'object') {
      throw new Error(`Incomplete benchmark case metadata: ${benchmarkCase.id}`);
    }
    if (benchmarkCase.expectedOutcome === 'vulnerable' &&
        !benchmarkCase.expectedFindings?.length) {
      throw new Error(`Vulnerable case has no expected findings: ${benchmarkCase.id}`);
    }
    if (benchmarkCase.expectedOutcome === 'safe' &&
        (benchmarkCase.expectedFindings?.length || 0) > 0) {
      throw new Error(`Safe case must not declare expected findings: ${benchmarkCase.id}`);
    }
    for (const expected of benchmarkCase.expectedFindings || []) {
      const hasSpan = Number.isInteger(expected.sourceSpan?.start) &&
        Number.isInteger(expected.sourceSpan?.end) &&
        expected.sourceSpan.end > expected.sourceSpan.start;
      if (expected.identityStatus === 'verified' && !hasSpan && !expected.sinkIdentity) {
        throw new Error(`Verified expected finding has no stable sink identity: ${benchmarkCase.id}`);
      }
      if (expected.identityStatus === 'unverified' &&
          !expected.identityUnverifiedReason) {
        throw new Error(`Unverified expected finding needs a reason: ${benchmarkCase.id}`);
      }
      if (!['verified', 'unverified'].includes(expected.identityStatus)) {
        throw new Error(`Expected finding identity status is missing or invalid: ${benchmarkCase.id}`);
      }
    }
  }
}

function writeCaseFiles(projectRoot, files) {
  for (const [relativePath, content] of Object.entries(files)) {
    if (typeof content !== 'string' || path.isAbsolute(relativePath)) {
      throw new Error(`Invalid benchmark fixture path or content: ${relativePath}`);
    }
    const destination = path.resolve(projectRoot, relativePath);
    const rel = path.relative(projectRoot, destination);
    if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
      throw new Error(`Benchmark fixture path escapes its temporary project: ${relativePath}`);
    }
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, content, 'utf8');
  }
}

function reportedRuleIds(finding) {
  return new Set([finding.ruleId, ...(finding.ruleIds || [])].filter(Boolean));
}

function findingLocations(finding) {
  const locations = Array.isArray(finding.locations) ? finding.locations : [];
  return locations.length
    ? locations
    : [{ file: finding.file, line: finding.line }];
}

function findingHasExpectedRule(finding, expected) {
  const allowedRules = expected.acceptedRuleIds || [expected.ruleId];
  const actualRules = reportedRuleIds(finding);
  return allowedRules.some((ruleId) => actualRules.has(ruleId));
}

function evidenceMatchesExpectation(finding, expected) {
  const traces = [
    finding.taintTrace,
    ...(finding.taintTrace?.alternatePaths || []),
    ...(finding.alternateTaintTraces || [])
  ].filter(Boolean);
  const requiresTraceEvidence = expected.requireTaintTrace ||
    expected.sourceContains ||
    expected.sinkContains ||
    expected.requireCrossFileStep;
  if (requiresTraceEvidence && !traces.some((trace) =>
    (!expected.requireTaintTrace || (trace.source && trace.sink)) &&
    (!expected.sourceContains ||
      String(trace.source?.expression || '').includes(expected.sourceContains)) &&
    (!expected.sinkContains ||
      String(trace.sink?.expression || finding.sinkExpression || '')
        .includes(expected.sinkContains)) &&
    (!expected.requireCrossFileStep ||
      trace.steps?.some((step) =>
        step.fromModule && step.toModule && step.fromModule !== step.toModule
      ))
  )) return false;
  if (expected.expectedCwe && !finding.cwe?.includes(expected.expectedCwe)) return false;
  if (expected.evidenceContains &&
      !String(finding.evidence || '').includes(expected.evidenceContains)) return false;
  const provenanceExpectation = expected.sinkProvenance || expected.provenance;
  if (provenanceExpectation) {
    const provenance = finding.sinkProvenance;
    if (!provenance) return false;
    for (const field of ['status', 'resolution', 'api', 'confidence']) {
      if (Object.hasOwn(provenanceExpectation, field) &&
          provenance[field] !== provenanceExpectation[field]) return false;
    }
    if (Object.hasOwn(provenanceExpectation, 'callee') &&
        (provenance.callee || finding.sinkExpression) !== provenanceExpectation.callee) {
      return false;
    }
  }
  if (Object.hasOwn(expected, 'sinkProvenanceConfidence') &&
      finding.sinkProvenance?.confidence !== expected.sinkProvenanceConfidence) {
    return false;
  }
  return Boolean(finding.evidence);
}

function locationMatches(finding, expected) {
  return findingLocations(finding).some((location) =>
    location.file === expected.file &&
    location.line === expected.line &&
    (expected.column === undefined || location.column === expected.column)
  );
}

function sinkIdentityMatches(finding, expected) {
  if (expected.identityStatus === 'unverified') return false;
  if (expected.sinkIdentity) return finding.sinkIdentity === expected.sinkIdentity;
  if (expected.sourceSpan) {
    return finding.sourceSpan?.start === expected.sourceSpan.start &&
      finding.sourceSpan?.end === expected.sourceSpan.end;
  }
  return false;
}

function expectedSinkMatchesFinding(finding, expected) {
  if (!findingHasExpectedRule(finding, expected) ||
      !locationMatches(finding, expected) ||
      !sinkIdentityMatches(finding, expected)) {
    return false;
  }
  return true;
}

function uniqueSinkFindings(findings) {
  return reconcileFindingsBySinkIdentity(findings);
}

function safeFindingSummary(finding, index, caseId) {
  const trace = finding.taintTrace;
  return {
    caseId,
    index,
    ruleId: finding.ruleId || null,
    ruleIds: [...reportedRuleIds(finding)].sort(),
    checkId: finding.checkId || null,
    file: finding.file || null,
    line: finding.line ?? null,
    column: finding.column ?? null,
    sourceSpan: finding.sourceSpan || null,
    sinkIdentity: finding.sinkIdentity || null,
    sinkIdentityStatus: finding.sinkIdentityStatus || null,
    sinkExpression: finding.sinkExpression || null,
    sinkProvenance: finding.sinkProvenance || null,
    producerOrigins: finding.producerOrigins || null,
    locations: findingLocations(finding).map(({ file, line, column, start, end }) => ({
      file,
      line,
      ...(column !== undefined ? { column } : {}),
      ...(start !== undefined ? { start } : {}),
      ...(end !== undefined ? { end } : {})
    })),
    cwe: [...(finding.cwe || [])].sort(),
    isTaintConfirmed: finding.isTaintConfirmed === true,
    evidenceVariants: finding.evidenceVariants || null,
    evidence: typeof finding.evidence === 'string' ? finding.evidence : null,
    trace: trace ? {
      sourceExpression: trace.source?.expression || null,
      sourceFile: trace.source?.file || null,
      sinkExpression: trace.sink?.expression || null,
      sinkFile: trace.sink?.file || null,
      crossFile: Boolean(trace.steps?.some((step) =>
        step.fromModule && step.toModule && step.fromModule !== step.toModule
      )),
      stepCount: trace.steps?.length || 0
    } : null,
    alternateTraces: [
      ...(trace?.alternatePaths || []),
      ...(finding.alternateTaintTraces || [])
    ].map((alternate) => ({
      sourceExpression: alternate.source?.expression || null,
      sourceFile: alternate.source?.file || null,
      sinkExpression: alternate.sink?.expression || null,
      sinkFile: alternate.sink?.file || null,
      crossFile: Boolean(alternate.steps?.some((step) =>
        step.fromModule && step.toModule && step.fromModule !== step.toModule
      )),
      stepCount: alternate.steps?.length || 0
    }))
  };
}

export function evaluateCase(benchmarkCase, report, error = null) {
  const check = report?.scan?.checks?.find((item) => item.id === benchmarkCase.checkId);
  const analysisStatus = error
    ? 'failed'
    : ANALYZER_OUTCOMES.has(check?.status)
      ? check.status
      : 'failed';
  const rawCandidates = (report?.issues || [])
    .filter((finding) => finding.checkId === benchmarkCase.checkId);
  const candidates = uniqueSinkFindings(rawCandidates);
  const findings = candidates.map((finding, index) =>
    safeFindingSummary(finding, index, benchmarkCase.id)
  );
  const expectations = benchmarkCase.expectedFindings || [];
  const verifiedExpectations = expectations.filter((expected) =>
    expected.identityStatus === 'verified' ||
    (expected.identityStatus === undefined &&
      (expected.sinkIdentity || expected.sourceSpan))
  );
  const identityUnverifiedExpectations = expectations.filter((expected) =>
    !verifiedExpectations.includes(expected)
  );
  const verifiedCandidateIndexes = new Set(candidates
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) =>
      finding.sinkIdentityStatus === 'resolved' && finding.sinkIdentity
    )
    .map(({ index }) => index));
  const identityUnverifiedFindingCount = candidates.length - verifiedCandidateIndexes.size;
  const matchedFindingIndexes = new Set();
  const matchedExpectedFindings = [];
  const missingExpectedFindings = [];
  const incompleteEvidence = [];
  const evidenceFindings = [];

  for (const expected of verifiedExpectations) {
    const matchIndex = candidates.findIndex((finding, index) =>
      verifiedCandidateIndexes.has(index) &&
      !matchedFindingIndexes.has(index) &&
      expectedSinkMatchesFinding(finding, expected)
    );
    if (matchIndex < 0) {
      missingExpectedFindings.push(expected);
      continue;
    }
    matchedFindingIndexes.add(matchIndex);
    matchedExpectedFindings.push(expected);
    const complete = evidenceMatchesExpectation(candidates[matchIndex], expected);
    evidenceFindings.push({
      expectedFinding: expected,
      findingIndex: matchIndex,
      status: complete ? 'complete' : 'incomplete'
    });
    if (!complete) {
      incompleteEvidence.push(expected);
    }
  }

  const unexpectedFindings = findings.filter((_finding, index) =>
    verifiedCandidateIndexes.has(index) && !matchedFindingIndexes.has(index)
  );
  const excludedFromAccuracy = benchmarkCase.expectedOutcome === 'partial' ||
    benchmarkCase.expectedOutcome === 'unsupported' ||
    (benchmarkCase.expectedOutcome !== 'partial' &&
      benchmarkCase.expectedOutcome !== 'unsupported' &&
      analysisStatus !== 'completed') ||
    identityUnverifiedFindingCount > 0 ||
    (verifiedExpectations.length === 0 && identityUnverifiedExpectations.length > 0);
  let expectationStatus;
  if (error) {
    expectationStatus = 'execution_failed';
  } else if (benchmarkCase.expectedOutcome === 'unsupported') {
    expectationStatus = 'excluded_unsupported';
  } else if (benchmarkCase.expectedOutcome === 'partial') {
    expectationStatus = analysisStatus !== 'partial'
      ? 'outcome_not_reproduced'
      : missingExpectedFindings.length || unexpectedFindings.length
        ? 'partial_incomplete'
        : identityUnverifiedExpectations.length
          ? 'partial_identity_unverified'
          : 'partial_as_expected';
  } else if (analysisStatus !== 'completed') {
    expectationStatus = 'analysis_incomplete';
  } else if (missingExpectedFindings.length || unexpectedFindings.length) {
    expectationStatus = 'mismatch';
  } else if (identityUnverifiedExpectations.length) {
    expectationStatus = verifiedExpectations.length
      ? 'as_expected_with_identity_unverified'
      : 'identity_unverified';
  } else {
    expectationStatus = 'as_expected';
  }

  return {
    id: benchmarkCase.id,
    category: benchmarkCase.category,
    expectedOutcome: benchmarkCase.expectedOutcome,
    checkId: benchmarkCase.checkId,
    rationale: benchmarkCase.rationale,
    analysisStatus,
    analysisReason: check?.reason?.code || (error ? 'analyzer_execution_failed' : null),
    expectationStatus,
    excludedFromAccuracy,
    findingCount: findings.length,
    expectedFindingCount: expectations.length,
    verifiedExpectedFindingCount: verifiedExpectations.length,
    identityUnverifiedExpectationCount: identityUnverifiedExpectations.length,
    identityUnverifiedFindingCount,
    findingOutcomes: {
      truePositives: matchedExpectedFindings.length,
      falsePositives: unexpectedFindings.length,
      falseNegatives: missingExpectedFindings.length
    },
    expectedFindings: expectations,
    identityUnverifiedExpectations,
    findings,
    matchedExpectedFindings,
    missingExpectedFindings,
    unexpectedFindings,
    incompleteEvidence,
    evidenceFindings
  };
}

function ratio(numerator, denominator) {
  return denominator === 0 ? null : Number((numerator / denominator).toFixed(4));
}

export function calculateMetrics(caseResults) {
  const cases = {
    truePositives: 0,
    trueNegatives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    excluded: 0
  };
  const findings = {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0
  };
  let expectedEvidenceCount = 0;
  let completeEvidenceCount = 0;
  const partialFindingLevel = {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0
  };
  const detectionEvidence = {
    verifiedExpectedSinks: 0,
    identityUnverifiedExpectations: 0,
    matchedDetections: 0,
    missingDetections: 0,
    evidenceCompleteDetections: 0,
    evidenceIncompleteDetections: 0,
    identityUnverifiedFindings: 0
  };

  for (const result of caseResults) {
    const matchedCount = result.matchedExpectedFindings.length;
    const missingCount = result.missingExpectedFindings.length;
    detectionEvidence.verifiedExpectedSinks += result.verifiedExpectedFindingCount ??
      matchedCount + missingCount;
    detectionEvidence.identityUnverifiedExpectations +=
      result.identityUnverifiedExpectationCount || 0;
    detectionEvidence.matchedDetections += matchedCount;
    detectionEvidence.missingDetections += missingCount;
    detectionEvidence.evidenceCompleteDetections +=
      matchedCount - result.incompleteEvidence.length;
    detectionEvidence.evidenceIncompleteDetections += result.incompleteEvidence.length;
    detectionEvidence.identityUnverifiedFindings +=
      result.identityUnverifiedFindingCount || 0;

    if (result.analysisStatus === 'partial') {
      partialFindingLevel.truePositives += result.findingOutcomes.truePositives;
      partialFindingLevel.falsePositives += result.findingOutcomes.falsePositives;
      partialFindingLevel.falseNegatives += result.findingOutcomes.falseNegatives;
    }
    if (result.excludedFromAccuracy) {
      cases.excluded += 1;
      continue;
    }

    const unexpectedCount = result.unexpectedFindings.length;
    expectedEvidenceCount += matchedCount;
    completeEvidenceCount += matchedCount - result.incompleteEvidence.length;

    findings.truePositives += matchedCount;
    findings.falseNegatives += missingCount;
    findings.falsePositives += unexpectedCount;

    if (result.expectedOutcome === 'vulnerable') {
      if (matchedCount > 0) cases.truePositives += 1;
      else cases.falseNegatives += 1;
    } else if (result.expectedOutcome === 'safe') {
      if (result.findingCount === 0) cases.trueNegatives += 1;
      else cases.falsePositives += 1;
    }
  }

  const statusCounts = Object.fromEntries([...ANALYZER_OUTCOMES].map((status) => [
    status,
    caseResults.filter((item) => item.analysisStatus === status).length
  ]));
  const supportedCases = caseResults.filter((item) =>
    item.expectedOutcome !== 'unsupported'
  );
  const completionDenominator = supportedCases.length;
  const findingPrecisionDenominator = findings.truePositives + findings.falsePositives;
  const findingRecallDenominator = findings.truePositives + findings.falseNegatives;
  const casePrecisionDenominator = cases.truePositives + cases.falsePositives;
  const caseRecallDenominator = cases.truePositives + cases.falseNegatives;

  return {
    caseLevel: {
      ...cases,
      precision: ratio(cases.truePositives, casePrecisionDenominator),
      recall: ratio(cases.truePositives, caseRecallDenominator),
      denominators: {
        precision: casePrecisionDenominator,
        recall: caseRecallDenominator
      }
    },
    findingLevel: {
      ...findings,
      precision: ratio(findings.truePositives, findingPrecisionDenominator),
      recall: ratio(findings.truePositives, findingRecallDenominator),
      denominators: {
        precision: findingPrecisionDenominator,
        recall: findingRecallDenominator
      }
    },
    evidenceCompleteness: {
      complete: completeEvidenceCount,
      expected: expectedEvidenceCount,
      rate: ratio(completeEvidenceCount, expectedEvidenceCount),
      denominator: expectedEvidenceCount,
      scope: 'matched detections in cases included in supported accuracy'
    },
    detectionEvidence: {
      ...detectionEvidence,
      evidenceCompletenessDenominator:
        detectionEvidence.matchedDetections
    },
    analysis: {
      statusCounts,
      supportedCaseCount: completionDenominator,
      completedSupportedCases: supportedCases.filter((item) =>
        item.analysisStatus === 'completed'
      ).length,
      completionRate: ratio(
        supportedCases.filter((item) => item.analysisStatus === 'completed').length,
        completionDenominator
      ),
      completionDenominator,
      partialCases: supportedCases.filter((item) => item.analysisStatus === 'partial').length,
      partialAnalysisRate: ratio(
        supportedCases.filter((item) => item.analysisStatus === 'partial').length,
        completionDenominator
      ),
      partialAnalysisDenominator: completionDenominator,
      unsupportedCaseCount: caseResults.filter((item) =>
        item.expectedOutcome === 'unsupported'
      ).length,
      partialFindingLevel
    }
  };
}

export function summarizeOutcomes(caseResults) {
  const summary = {};
  for (const item of caseResults) {
    summary[item.category] ||= {};
    summary[item.category][item.expectedOutcome] =
      (summary[item.category][item.expectedOutcome] || 0) + 1;
  }
  return Object.fromEntries(Object.entries(summary).sort(([left], [right]) =>
    left.localeCompare(right)
  ).map(([category, outcomes]) => [
    category,
    Object.fromEntries(Object.entries(outcomes).sort(([left], [right]) =>
      left.localeCompare(right)
    ))
  ]));
}

export async function runBenchmark(options = {}) {
  const manifest = options.manifest || JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assertManifest(manifest);
  const caseResults = [];

  for (const benchmarkCase of manifest.cases) {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-js-ts-case-'));
    let report = null;
    let error = null;
    try {
      writeCaseFiles(projectRoot, {
        ...BASE_PROJECT_FILES,
        ...benchmarkCase.files
      });
      report = await (options.analyzeProduction || analyzeProduction)(
        projectRoot,
        'unused-benchmark-image',
        null,
        {
          staticOnly: true,
          osvEnabled: false,
          fetch: async () => {
            throw new Error('Network access is disabled in the benchmark runner');
          },
          logger: QUIET_LOGGER,
          now: FIXED_NOW
        }
      );
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    } finally {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
    const result = evaluateCase(benchmarkCase, report, error);
    if (error) result.error = error;
    caseResults.push(result);
  }

  const mismatches = caseResults.filter((item) =>
    ![
      'as_expected',
      'as_expected_with_identity_unverified',
      'identity_unverified',
      'partial_as_expected',
      'partial_identity_unverified',
      'excluded_unsupported'
    ].includes(item.expectationStatus)
  );
  return {
    benchmark: {
      name: 'Luminicent JavaScript/TypeScript security regression benchmark',
      version: manifest.benchmarkVersion,
      analyzer: 'existing analyzeProduction static analyzer',
      networkAccess: 'disabled'
    },
    caseCount: caseResults.length,
    categoryOutcomeCounts: summarizeOutcomes(caseResults),
    metrics: calculateMetrics(caseResults),
    mismatchCount: mismatches.length,
    cases: caseResults
  };
}
