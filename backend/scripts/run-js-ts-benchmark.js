import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { BENCHMARK_VERSION, runBenchmark } from '../benchmarks/js-ts/runner.js';

function parseArgs(args) {
  const options = { failOnMismatch: false, jsonOut: null };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--json-out') {
      const destination = args[index + 1];
      if (!destination || destination.startsWith('--')) {
        throw new Error('--json-out requires a file path');
      }
      options.jsonOut = path.resolve(destination);
      index += 1;
    } else if (args[index] === '--fail-on-mismatch') {
      options.failOnMismatch = true;
    } else if (args[index] === '--help' || args[index] === '-h') {
      options.help = true;
    } else {
      throw new Error(`Unknown option: ${args[index]}`);
    }
  }
  return options;
}

function printHelp() {
  console.log([
    'Usage: node scripts/run-js-ts-benchmark.js [--json-out <path>] [--fail-on-mismatch]',
    '',
    'Runs the checked-in JavaScript/TypeScript benchmark against analyzeProduction.',
    'Network access is disabled. JSON defaults to a versioned file in the OS temp directory.'
  ].join('\n'));
}

function printSummary(report, jsonPath) {
  console.log(`Luminicent JS/TS benchmark ${report.benchmark.version}: ${report.caseCount} cases`);
  for (const [category, outcomes] of Object.entries(report.categoryOutcomeCounts)) {
    const breakdown = Object.entries(outcomes)
      .map(([outcome, count]) => `${outcome}=${count}`)
      .join(', ');
    console.log(`  ${category}: ${breakdown}`);
  }
  const caseMetrics = report.metrics.caseLevel;
  const findingMetrics = report.metrics.findingLevel;
  console.log(
    `Case metrics: TP=${caseMetrics.truePositives} TN=${caseMetrics.trueNegatives} ` +
    `FP=${caseMetrics.falsePositives} FN=${caseMetrics.falseNegatives} ` +
    `precision=${caseMetrics.precision ?? 'unavailable'}(${caseMetrics.denominators.precision}) ` +
    `recall=${caseMetrics.recall ?? 'unavailable'}(${caseMetrics.denominators.recall})`
  );
  console.log(
    `Finding metrics: TP=${findingMetrics.truePositives} FP=${findingMetrics.falsePositives} ` +
    `FN=${findingMetrics.falseNegatives} precision=${findingMetrics.precision ?? 'unavailable'} ` +
    `recall=${findingMetrics.recall ?? 'unavailable'} ` +
    `denominators=${findingMetrics.denominators.precision}/${findingMetrics.denominators.recall}`
  );
  const detectionEvidence = report.metrics.detectionEvidence;
  console.log(
    `Verified sinks: expected=${detectionEvidence.verifiedExpectedSinks} ` +
    `identity-unverified-expectations=${detectionEvidence.identityUnverifiedExpectations} ` +
    `matched=${detectionEvidence.matchedDetections} missing=${detectionEvidence.missingDetections} ` +
    `identity-unverified-findings=${detectionEvidence.identityUnverifiedFindings}`
  );
  console.log(
    `Matched evidence: complete=${detectionEvidence.evidenceCompleteDetections} ` +
    `incomplete=${detectionEvidence.evidenceIncompleteDetections} ` +
    `denominator=${detectionEvidence.evidenceCompletenessDenominator}`
  );
  const evidence = report.metrics.evidenceCompleteness;
  console.log(
    `Evidence completeness: ${evidence.complete}/${evidence.expected} ` +
    `rate=${evidence.rate ?? 'unavailable'}`
  );
  console.log(
    `Analysis: complete=${report.metrics.analysis.completedSupportedCases}/` +
    `${report.metrics.analysis.supportedCaseCount} ` +
    `partial=${report.metrics.analysis.partialCases} ` +
    `failed=${report.metrics.analysis.statusCounts.failed} ` +
    `skipped=${report.metrics.analysis.statusCounts.skipped} ` +
    `unsupported-checks=${report.metrics.analysis.statusCounts.unsupported} ` +
    `unsupported-labels=${report.metrics.analysis.unsupportedCaseCount}`
  );
  const partialFindings = report.metrics.analysis.partialFindingLevel;
  console.log(
    `Partial-case findings (excluded from accuracy): TP=${partialFindings.truePositives} ` +
    `FP=${partialFindings.falsePositives} FN=${partialFindings.falseNegatives}`
  );
  console.log(`Expectation mismatches: ${report.mismatchCount}`);
  console.log(`JSON report: ${jsonPath}`);
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
    return;
  }
  if (args.help) {
    printHelp();
    return;
  }

  const defaultJsonPath = path.join(
    os.tmpdir(),
    `luminicent-js-ts-benchmark-${BENCHMARK_VERSION}.json`
  );
  const jsonPath = args.jsonOut || defaultJsonPath;
  try {
    const report = await runBenchmark();
    fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
    fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    printSummary(report, jsonPath);
    if (args.failOnMismatch && report.mismatchCount > 0) process.exitCode = 1;
  } catch (error) {
    console.error(`Benchmark failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] &&
    pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
