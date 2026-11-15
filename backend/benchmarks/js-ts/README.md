# JavaScript/TypeScript security regression benchmark

Benchmark version: **1.3.0**

This small, labeled corpus exercises the existing `analyzeProduction` static
analyzer. It is a regression baseline, not a representative sample of
real-world applications and not a claim about real-world precision or recall.
Cases are defined in [`cases.json`](./cases.json); each includes its expected
outcome, relevant check, fixture source, expected finding locations/evidence,
and rationale. Every expected finding explicitly declares whether its sink
identity is verified.

## Run

From the `backend` directory:

```powershell
node scripts/run-js-ts-benchmark.js
```

The runner prints a concise category and metric summary. Its machine-readable
JSON report is written by default to the operating system temporary directory
as `luminicent-js-ts-benchmark-1.3.0.json`. To choose another report location:

```powershell
node scripts/run-js-ts-benchmark.js --json-out "$env:TEMP\luminicent-js-ts-benchmark.json"
```

Use `--fail-on-mismatch` to return a nonzero exit code when a supported
vulnerable/safe expectation differs from observed results, or when an expected
partial outcome is not reported as partial. Expected-unsupported cases are
always excluded from accuracy scoring.

The runner creates isolated temporary project directories, invokes the
existing production analyzer with `staticOnly: true` and OSV disabled, and
removes each fixture directory after analysis. The injected fetch function
throws if called; the benchmark does not require network access, install
fixture dependencies, execute fixture code, or write result files into the
repository unless an explicit in-repository `--json-out` path is selected.
The benchmark output intentionally omits scan timestamps and timing fields to
keep report data deterministic.

## Labels and metrics

- `vulnerable` cases specify one or more expected sinks. Each sink is matched
  independently by rule, file, line, and exact AST source span or sink
  identity. There is no line-only fallback. Findings with the same sink
  identity from multiple analyzer producers count once; distinct spans remain
  separate.
- Expectations for which the analyzer does not provide a stable span
  (currently text/configuration findings) are labeled `identityStatus:
  "unverified"` with a reason. They are reported separately and excluded from
  verified finding-level precision/recall. Findings without stable identity
  remain visible but cannot satisfy a verified expectation.
- `safe` cases have no expected findings; findings for their relevant check are
  false positives.
- `partial` cases are excluded from supported precision/recall and are counted
  separately in analysis completeness metrics. Their per-case TP/FP/FN counts
  remain visible so missing expected sinks cannot be hidden by partial status.
- `unsupported` cases are excluded from accuracy metrics and never treated as
  clean negatives. Their actual analyzer check status is still recorded.

Case-level and finding-level TP/FP/FN are reported separately. A vulnerable
case is a case-level true positive when at least one expected sink is matched;
it is a false negative only when no expected sink matches. A safe case with any
finding is a false positive at case level. At finding level, every matched
expected sink is one TP, every missing expected sink is one FN, and every
unexpected finding is one FP. Extra findings in vulnerable cases are finding
false positives but do not negate the case-level TP. Same-identity producer
representations are reconciled before these counts.

Evidence completeness is the number of detected expected sinks satisfying their
evidence assertions divided by all detected expected sinks in scored
(non-partial, non-unsupported, completed) cases. Missing sinks affect detection
recall, not evidence completeness; an existing finding with an incomplete trace
or provenance is a detection TP and an evidence-incomplete finding. Explicit
provenance assertions check status and any specified resolution, API/callee, or
confidence value; a missing field fails that assertion.
Analysis completion and partial rates use all non-unsupported cases as their
denominator; failed and skipped cases remain visible in status counts and are
excluded from accuracy rather than treated as clean. Unsupported case count is
reported separately. Precision is TP/(TP+FP), recall is TP/(TP+FN); zero
denominators are represented as `null`. JSON reports include the numeric
denominators, verified/unverified expectation counts, matched/missing detection
counts, evidence-complete/incomplete detection counts, and analysis status
counts. Finding-level accuracy excludes partial, unsupported, failed, skipped,
and identity-unverified findings/expectations; separate reporting retains their
counts.

The corpus includes deliberate false-positive traps and a same-line,
two-sink case. A mismatch is baseline evidence to review, not a reason to alter
analyzer behavior or weaken the case expectation.

## Test the benchmark implementation

From the `backend` directory:

```powershell
node --test benchmarks/js-ts/runner.test.js
```
