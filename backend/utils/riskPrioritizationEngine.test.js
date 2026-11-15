import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { reconcileFindingsBySinkIdentity } from './findingIdentity.js';
import {
  calculateProjectRisk,
  getSeverityWeight,
  getConfidenceMultiplier,
  getCategoryWeight,
  standardizeFinding,
  compareFindings,
  compareFindingsCanonical,
  normalizePath,
  SEVERITY_WEIGHTS,
  CONFIDENCE_MULTIPLIERS,
  CATEGORY_WEIGHTS,
  CALIBRATION_CONSTANT
} from './riskPrioritizationEngine.js';

describe('Risk Prioritization Engine', () => {
  it('preserves all traces and producer origins across reconciliation orders', () => {
    const producers = ['pattern', 'ast_taint', 'project_taint'].map((origin, index) => ({
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      file: 'src/routes.js',
      sourceSpan: { start: 20, end: 48 },
      isTaintConfirmed: true,
      origin,
      sinkProvenance: {
        status: 'supported_external_api',
        api: 'query',
        module: `driver-${index}`
      },
      taintTrace: {
        source: { expression: `req.query.value${index}` },
        sink: { expression: 'db.query(sql)' },
        steps: []
      }
    }));
    const permutations = [
      producers,
      [producers[0], producers[2], producers[1]],
      [producers[1], producers[0], producers[2]],
      [producers[1], producers[2], producers[0]],
      [producers[2], producers[0], producers[1]],
      [producers[2], producers[1], producers[0]]
    ];
    const reconciled = permutations.map((items) =>
      reconcileFindingsBySinkIdentity(items)[0]
    );
    const expectedSources = [
      'req.query.value0',
      'req.query.value1',
      'req.query.value2'
    ];

    for (const finding of reconciled) {
      assert.deepEqual([
        finding.taintTrace.source.expression,
        ...(finding.alternateTaintTraces || []).map((trace) => trace.source.expression)
      ].sort(), expectedSources);
      assert.deepEqual(finding.producerOrigins, ['ast_taint', 'pattern', 'project_taint']);
      assert.equal(finding.sinkProvenance.status, 'supported_external_api');
      assert.deepEqual(finding.sinkProvenanceVariants.map((item) => item.module).sort(), [
        'driver-0',
        'driver-1',
        'driver-2'
      ]);
      assert.equal(reconcileFindingsBySinkIdentity([finding]).length, 1);
      assert.deepEqual(
        reconcileFindingsBySinkIdentity([finding])[0].alternateTaintTraces,
        finding.alternateTaintTraces
      );
    }
    assert.equal(
      new Set(reconciled.map((finding) => finding.taintTrace.source.expression)).size,
      1
    );
  });

  it('retains findings with identical fallback coordinates when spans are unavailable', () => {
    const findings = reconcileFindingsBySinkIdentity([
      {
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        file: 'src/routes.js',
        line: 4,
        column: 8,
        evidence: 'first unresolved sink'
      },
      {
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        file: 'src/routes.js',
        line: 4,
        column: 8,
        evidence: 'second unresolved sink'
      }
    ]);

    assert.equal(findings.length, 2);
    assert.ok(findings.every((finding) =>
      finding.sinkIdentityStatus === 'unresolved'
    ));
  });

  it('does not collapse unresolved findings during risk standardization', () => {
    const findings = calculateProjectRisk([
      {
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        category: 'injection',
        severity: 'High',
        confidence: 'High',
        file: 'src/routes.js',
        line: 4,
        evidence: 'same fallback report',
        sinkIdentityStatus: 'unresolved'
      },
      {
        ruleId: 'LUM-INJ-001',
        checkId: 'sql_injection_pattern_search',
        category: 'injection',
        severity: 'High',
        confidence: 'High',
        file: 'src/routes.js',
        line: 4,
        evidence: 'same fallback report',
        sinkIdentityStatus: 'unresolved'
      }
    ]).findings;

    assert.equal(findings.length, 2);
    assert.ok(findings.every((finding) =>
      finding.sinkIdentityStatus === 'unresolved'
    ));
    assert.equal(new Set(findings.map((finding) => finding.findingFingerprint)).size, 2);
  });

  describe('Weights and Multipliers', () => {
    it('returns exact severity weights for all levels', () => {
      assert.equal(getSeverityWeight('Critical'), 10.0);
      assert.equal(getSeverityWeight('High'), 6.0);
      assert.equal(getSeverityWeight('Medium'), 3.0);
      assert.equal(getSeverityWeight('Low'), 1.0);
      assert.equal(getSeverityWeight('Unknown'), 0.5);
      assert.equal(getSeverityWeight('other'), 0.5);
    });

    it('derives severity weight from numeric CVSS score when provided', () => {
      assert.equal(getSeverityWeight('Low', 9.8), 10.0); // CVSS >= 9.0 overrides to Critical weight
      assert.equal(getSeverityWeight('Low', 7.5), 6.0);  // CVSS >= 7.0 overrides to High weight
      assert.equal(getSeverityWeight('Low', 5.0), 3.0);  // CVSS >= 4.0 overrides to Medium weight
      assert.equal(getSeverityWeight('Low', 2.0), 1.0);  // CVSS > 0 overrides to Low weight
      assert.equal(getSeverityWeight('Critical', null), 10.0); // Falls back to nominal
    });

    it('returns exact confidence multipliers', () => {
      assert.equal(getConfidenceMultiplier('High'), 1.00);
      assert.equal(getConfidenceMultiplier('Medium'), 0.75);
      assert.equal(getConfidenceMultiplier('Low'), 0.35);
      assert.equal(getConfidenceMultiplier(null, 'dependency'), 1.00);
      assert.equal(getConfidenceMultiplier(null, 'configuration'), 1.00);
      assert.equal(getConfidenceMultiplier(null, 'injection'), 0.75);
    });

    it('returns exact category weights', () => {
      assert.equal(getCategoryWeight('credentials'), 1.00);
      assert.equal(getCategoryWeight('injection'), 1.00);
      assert.equal(getCategoryWeight('dependency', 'direct'), 1.00);
      assert.equal(getCategoryWeight('dependency', 'transitive'), 0.65);
      assert.equal(getCategoryWeight('network_tls'), 0.85);
      assert.equal(getCategoryWeight('configuration'), 0.50);
      assert.equal(getCategoryWeight('project_structure'), 0.50);
    });
  });

  describe('Finding Standardization', () => {
    it('standardizes raw findings with all v2 schema fields', () => {
      const raw = {
        severity: 'High',
        title: 'SQL Injection',
        description: 'Concatenation detected',
        recommendation: 'Use parameters',
        checkId: 'injection_pattern_search',
        ruleId: 'LUM-INJ-001',
        cwe: 'CWE-89',
        confidence: 'High',
        file: 'src/db.js',
        line: 14,
        evidence: "SELECT * FROM users WHERE id = '"
      };

      const std = standardizeFinding(raw, 0);
      assert.equal(std.id, 'LUM-FIND-001');
      assert.equal(std.ruleId, 'LUM-INJ-001');
      assert.equal(std.category, 'injection');
      assert.equal(std.severity, 'High');
      assert.equal(std.confidence, 'High');
      assert.deepEqual(std.cwe, ['CWE-89']);
      assert.deepEqual(std.cveIds, []);
      assert.equal(std.cvssScore, null);
      assert.equal(std.file, 'src/db.js');
      assert.equal(std.line, 14);
      assert.equal(std.origin, 'ast_analysis');
      assert.equal(std.remediation, 'Use parameters');
      assert.equal(std.recommendation, 'Use parameters');
    });

    it('standardizes dependency findings without fabricating line numbers', () => {
      const raw = {
        severity: 'High',
        title: 'Dependency vulnerability: requests (GHSA-1234)',
        description: 'Vulnerability in requests',
        recommendation: 'Upgrade to 2.31.1',
        checkId: 'dependency_vulnerability_analysis',
        dependency: {
          package: 'requests',
          installedVersion: '2.31.0',
          ecosystem: 'PyPI',
          advisoryId: 'GHSA-1234',
          cveIds: ['CVE-2023-32681'],
          cvssScore: 7.5,
          cvssVector: 'CVSS:3.1/...',
          fixedVersion: '2.31.1',
          affectedVersionRange: '>= 2.0.0, < 2.31.1',
          manifest: 'poetry.lock',
          relationship: 'direct'
        }
      };

      const std = standardizeFinding(raw, 1);
      assert.equal(std.id, 'LUM-FIND-002');
      assert.equal(std.category, 'dependency');
      assert.equal(std.ruleId, 'LUM-DEP-OSV');
      assert.equal(std.file, 'poetry.lock');
      assert.equal(std.line, null); // never fabricated
      assert.deepEqual(std.cveIds, ['CVE-2023-32681']);
      assert.equal(std.cvssScore, 7.5);
      assert.equal(std.fixedVersion, '2.31.1');
      assert.equal(std.origin, 'manifest_advisory');
    });

    it('preserves sink spans and keeps distinct same-line findings independently identified', () => {
      const result = calculateProjectRisk([
        {
          severity: 'High',
          confidence: 'High',
          category: 'injection',
          checkId: 'sql_injection_pattern_search',
          ruleId: 'LUM-INJ-001',
          file: 'src/routes.js',
          line: 4,
          column: 2,
          sourceSpan: { start: 20, end: 48 },
          sinkIdentity: 'sink-v1:src/routes.js:sql_injection_pattern_search:LUM-INJ-001:20:48',
          findingFingerprint: 'sink-v1:src/routes.js:sql_injection_pattern_search:LUM-INJ-001:20:48',
          producerOrigins: ['ast_taint', 'pattern'],
          sinkProvenance: { status: 'supported_external_api', api: 'query' },
          sinkIdentityStatus: 'resolved'
        },
        {
          severity: 'High',
          confidence: 'High',
          category: 'injection',
          checkId: 'sql_injection_pattern_search',
          ruleId: 'LUM-INJ-001',
          file: 'src/routes.js',
          line: 4,
          column: 50,
          sourceSpan: { start: 60, end: 90 },
          sinkIdentity: 'sink-v1:src/routes.js:sql_injection_pattern_search:LUM-INJ-001:60:90',
          findingFingerprint: 'sink-v1:src/routes.js:sql_injection_pattern_search:LUM-INJ-001:60:90',
          producerOrigins: ['ast_taint', 'pattern'],
          sinkProvenance: { status: 'supported_external_api', api: 'query' },
          sinkIdentityStatus: 'resolved'
        }
      ]).findings;

      assert.equal(result.length, 2);
      assert.deepEqual(result.map((finding) => finding.sourceSpan).sort((left, right) =>
        left.start - right.start
      ), [
        { start: 20, end: 48 },
        { start: 60, end: 90 }
      ]);
      assert.equal(new Set(result.map((finding) => finding.findingFingerprint)).size, 2);
      assert.equal(result[0].locations[0].column, 2);
      assert.equal(result[1].locations[0].column, 50);
      assert.ok(result.every((finding) =>
        finding.sinkProvenance?.status === 'supported_external_api' &&
        finding.sinkIdentityStatus === 'resolved'
      ));
    });
  });

  describe('Risk Calculation and Calibration', () => {
    it('Scenario 1: Baseline Clean Scan (100% complete coverage, 0 findings)', () => {
      const result = calculateProjectRisk([], { coverageComplete: true });
      assert.equal(result.riskScore, 0);
      assert.equal(result.securityScore, 100);
      assert.equal(result.riskLevel, 'Minimal');
      assert.equal(result.status, 'Excellent');
      assert.equal(result.summary.total, 0);
    });

    it('Scenario 2: Empty / Inadequately Analyzed Scan (partial coverage, 0 findings)', () => {
      const result = calculateProjectRisk([], { coverageComplete: false });
      assert.equal(result.riskScore, 0);
      assert.equal(result.securityScore, 100);
      // Critical check: Must NOT be described as Minimal or Excellent when coverage is incomplete!
      assert.equal(result.riskLevel, 'Indeterminate');
      assert.equal(result.status, 'Needs Review');
      assert.match(result.rationale, /coverage is incomplete/i);
    });

    it('Scenario 3: Single High AST finding (High confidence, direct application)', () => {
      const findings = [{
        severity: 'High',
        confidence: 'High',
        category: 'injection',
        ruleId: 'LUM-INJ-001',
        file: 'src/db.js',
        line: 12
      }];
      const result = calculateProjectRisk(findings, { coverageComplete: true });
      // w = 6.0 * 1.0 * 1.0 = 6.0.
      // R = 100 * (1 - exp(-6/30)) = 18.13% -> round 18.
      // H = 100 - 18 = 82.
      assert.equal(result.totalImpact, 6.0);
      assert.equal(result.riskScore, 18);
      assert.equal(result.securityScore, 82);
      assert.equal(result.riskLevel, 'Low');
      assert.equal(result.status, 'Good');
    });

    it('Scenario 4: Single Critical finding (High confidence, direct application)', () => {
      const findings = [{
        severity: 'Critical',
        confidence: 'High',
        category: 'credentials',
        ruleId: 'LUM-SEC-001',
        file: 'config.env',
        line: 2
      }];
      const result = calculateProjectRisk(findings, { coverageComplete: true });
      // w = 10.0 * 1.0 * 1.0 = 10.0.
      // R = 100 * (1 - exp(-10/30)) = 28.35% -> round 28.
      // H = 100 - 28 = 72.
      assert.equal(result.totalImpact, 10.0);
      assert.equal(result.riskScore, 28);
      assert.equal(result.securityScore, 72);
      assert.equal(result.riskLevel, 'Low');
      assert.equal(result.status, 'Needs Improvement');
    });

    it('Scenario 5: Five Critical findings with high confidence', () => {
      const findings = Array.from({ length: 5 }, (_, i) => ({
        severity: 'Critical',
        confidence: 'High',
        category: 'credentials',
        ruleId: `LUM-SEC-${i + 1}`,
        file: `src/secret_${i}.js`,
        line: 10
      }));
      const result = calculateProjectRisk(findings, { coverageComplete: true });
      // Total impact for 5 distinct critical rules = 5 * 10 = 50.
      // R = 100 * (1 - exp(-50/30)) = 81.11% -> round 81.
      // H = 100 - 81 = 19.
      assert.equal(result.totalImpact, 50.0);
      assert.equal(result.riskScore, 81);
      assert.equal(result.securityScore, 19);
      assert.equal(result.riskLevel, 'High');
      assert.equal(result.status, 'Poor');
    });

    it('Scenario 6: Multiple occurrences of the same rule apply diminishing returns', () => {
      const sameRuleFindings = Array.from({ length: 10 }, (_, i) => ({
        severity: 'Medium',
        confidence: 'Medium',
        category: 'configuration',
        ruleId: 'LUM-CFG-DOCKER',
        file: `Dockerfile.${i}`,
        line: 1
      }));
      const result = calculateProjectRisk(sameRuleFindings, { coverageComplete: true });
      // Base weight = 3.0 * 1.0 (config def) * 0.5 = 1.5.
      // Sum of 1.5 / (1 + 0.5*(k-1)) for k=1..10 is approx 4.87.
      // Risk is constrained, preventing low/medium inflation from reaching 100!
      assert.ok(result.totalImpact < 10.0);
      assert.ok(result.riskScore < 30);
      assert.equal(result.summary.total, 10);
    });

    it('Scenario 7: Exact duplicate findings are merged without double-counting', () => {
      const duplicates = [
        { severity: 'High', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 15, title: 'SQL Injection' },
        { severity: 'High', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 15, title: 'SQL Injection' }
      ];
      const result = calculateProjectRisk(duplicates, { coverageComplete: true });
      assert.equal(result.summary.total, 1);
      assert.equal(result.findings[0].occurrences, 1);
    });

    it('Scenario 8: Transitive dependency findings carry appropriate exposure discount', () => {
      const directDep = [{
        severity: 'High',
        category: 'dependency',
        dependency: { relationship: 'direct', advisoryId: 'GHSA-1' }
      }];
      const transitiveDep = [{
        severity: 'High',
        category: 'dependency',
        dependency: { relationship: 'transitive', advisoryId: 'GHSA-2' }
      }];

      const directResult = calculateProjectRisk(directDep, { coverageComplete: true });
      const transitiveResult = calculateProjectRisk(transitiveDep, { coverageComplete: true });

      assert.ok(transitiveResult.totalImpact < directResult.totalImpact);
      assert.equal(transitiveResult.totalImpact, 3.9);
    });

    it('Scenario 9: Unknown severity is non-zero but safely weighted', () => {
      const unknownFinding = [{
        severity: 'Unknown',
        confidence: 'High',
        category: 'configuration',
        ruleId: 'LUM-UNKNOWN-001',
        file: 'test.conf'
      }];
      const result = calculateProjectRisk(unknownFinding, { coverageComplete: true });
      // Weight = 0.5 (Unknown) * 1.0 (High) * 0.5 (Config) = 0.25
      assert.equal(result.totalImpact, 0.25);
      assert.ok(result.riskScore >= 1);
      assert.equal(result.riskLevel, 'Minimal');
    });

    it('Score boundaries remain strictly within [0, 100]', () => {
      // 50 critical findings
      const massive = Array.from({ length: 50 }, (_, i) => ({
        severity: 'Critical',
        confidence: 'High',
        category: 'credentials',
        ruleId: `LUM-MASSIVE-${i}`,
        file: `src/${i}.js`
      }));
      const result = calculateProjectRisk(massive, { coverageComplete: true });
      assert.ok(result.riskScore >= 0 && result.riskScore <= 100);
      assert.ok(result.securityScore >= 0 && result.securityScore <= 100);
      assert.equal(result.riskScore, 100);
      assert.equal(result.securityScore, 0);
      assert.equal(result.riskLevel, 'Critical');
    });
  });

  describe('Phase 4.4 Data Integrity and Prioritization Parity', () => {
    it('incomplete coverage cannot produce an unjustified Minimal risk level or Excellent/Good posture', () => {
      // 1 Low finding under partial coverage (R ~ 3, Security Score ~ 97)
      const lowFinding = [{
        severity: 'Low',
        confidence: 'Low',
        category: 'configuration',
        ruleId: 'LUM-CFG-001',
        file: 'app.config',
        line: 1
      }];
      const result = calculateProjectRisk(lowFinding, { coverageComplete: false });
      assert.ok(result.riskScore < 15, 'riskScore is low');
      assert.ok(result.securityScore >= 75, 'securityScore is high');
      // Must NOT be Minimal or Excellent/Good
      assert.equal(result.riskLevel, 'Indeterminate', 'riskLevel must be Indeterminate on incomplete coverage');
      assert.equal(result.status, 'Needs Review', 'status must be Needs Review on incomplete coverage');
      assert.match(result.rationale, /coverage is partial/i);
    });

    it('preserves distinct occurrences on different lines/files with diminishing returns', () => {
      const distinctOccurrences = [
        { severity: 'Medium', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/a.js', line: 10, title: 'SQL Injection' },
        { severity: 'Medium', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/a.js', line: 25, title: 'SQL Injection' },
        { severity: 'Medium', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/b.js', line: 5, title: 'SQL Injection' }
      ];
      const result = calculateProjectRisk(distinctOccurrences, { coverageComplete: true });
      assert.equal(result.findings.length, 3, 'All 3 distinct locations must be preserved as separate findings');
      // Occurrence multipliers: 1.0, 1/(1+0.5)=0.6667, 1/(1+1.0)=0.5
      // Base weight: 3.0 * 0.75 * 1.0 = 2.25
      // 1st finding: 2.25
      // 2nd finding: 1.5
      // 3rd finding: 1.125
      assert.equal(result.findings[0].impactWeight, 2.25);
      assert.equal(result.findings[1].impactWeight, 1.5);
      assert.equal(result.findings[2].impactWeight, 1.13);
    });

    it('preserves multiple distinct advisories for the same dependency package', () => {
      const advisories = [
        {
          severity: 'High',
          category: 'dependency',
          title: 'Advisory 1',
          dependency: { package: 'lodash', installedVersion: '4.17.15', advisoryId: 'GHSA-1111' }
        },
        {
          severity: 'Critical',
          category: 'dependency',
          title: 'Advisory 2',
          dependency: { package: 'lodash', installedVersion: '4.17.15', advisoryId: 'GHSA-2222' }
        }
      ];
      const result = calculateProjectRisk(advisories, { coverageComplete: true });
      assert.equal(result.findings.length, 2, 'Distinct advisories on same package must not be merged');
      assert.equal(result.findings[0].severity, 'Critical', 'Critical advisory prioritized first');
      assert.equal(result.findings[1].severity, 'High', 'High advisory prioritized second');
    });

    it('verifies exposed impactWeight agrees with calculated contribution', () => {
      const issues = [
        { severity: 'Critical', confidence: 'High', category: 'credentials', ruleId: 'LUM-SEC-001', file: 'creds.env' },
        { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'query.js' }
      ];
      const result = calculateProjectRisk(issues, { coverageComplete: true });
      const sumImpact = Number(result.findings.reduce((sum, f) => sum + f.impactWeight, 0).toFixed(2));
      assert.equal(result.totalImpact, sumImpact);
    });

    it('deterministic 6-tier prioritization parity in compareFindings', () => {
      const fCritical = { severity: 'Critical', confidence: 'High', title: 'A Critical' };
      const fHighDirect = { severity: 'High', confidence: 'High', cvssScore: 8.0, impactWeight: 6.0, dependency: { relationship: 'direct' }, title: 'Direct High' };
      const fHighTransitive = { severity: 'High', confidence: 'High', cvssScore: 8.0, impactWeight: 3.9, dependency: { relationship: 'transitive' }, title: 'Transitive High' };
      const fHighLowConf = { severity: 'High', confidence: 'Low', title: 'Low Conf High' };
      const fMediumHighCVSS = { severity: 'Medium', confidence: 'High', cvssScore: 6.5, title: 'Med High CVSS' };
      const fMediumLowCVSS = { severity: 'Medium', confidence: 'High', cvssScore: 4.0, title: 'Med Low CVSS' };
      const fLow = { severity: 'Low', confidence: 'High', title: 'Low' };
      const fUnknown = { severity: 'Unknown', confidence: 'Low', title: 'Unknown' };

      const unordered = [fUnknown, fLow, fHighTransitive, fCritical, fMediumLowCVSS, fHighLowConf, fMediumHighCVSS, fHighDirect];
      unordered.sort(compareFindings);

      assert.equal(unordered[0].title, 'A Critical');
      assert.equal(unordered[1].title, 'Direct High');
      assert.equal(unordered[2].title, 'Transitive High');
      assert.equal(unordered[3].title, 'Low Conf High');
      assert.equal(unordered[4].title, 'Med High CVSS');
      assert.equal(unordered[5].title, 'Med Low CVSS');
      assert.equal(unordered[6].title, 'Low');
      assert.equal(unordered[7].title, 'Unknown');
    });

    it('gracefully handles missing and malformed confidence and severity', () => {
      const finding = standardizeFinding({
        title: 'Malformed Finding',
        severity: null,
        confidence: null,
        cwe: null,
        cvssScore: 'not-a-number'
      }, 0);

      assert.equal(finding.severity, 'Unknown');
      assert.equal(finding.confidence, 'High'); // defaulted for config
      assert.deepEqual(finding.cwe, []);
      assert.equal(finding.cvssScore, null);
    });
  });

  describe('Phase 4.4 Verification: Finding ID Stability and Impact-Weight Precision', () => {
    it('merges overlapping-rule findings while preserving rule IDs and avoiding duplicate risk contribution', () => {
      const result = calculateProjectRisk([
        {
          severity: 'Medium',
          confidence: 'Medium',
          category: 'injection',
          ruleId: 'LUM-INJ-001',
          checkId: 'sql_injection_pattern_search',
          file: 'src/query.js',
          line: 12,
          title: 'Potential SQL injection',
          evidence: 'dynamic SQL query'
        },
        {
          severity: 'High',
          confidence: 'High',
          category: 'injection',
          ruleId: 'LUM-AST-001',
          checkId: 'sql_injection_pattern_search',
          file: 'src/query.js',
          line: 12,
          title: 'Potential SQL injection',
          evidence: 'dynamic SQL query'
        }
      ], { coverageComplete: true });

      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].severity, 'High');
      assert.deepEqual(result.findings[0].ruleIds, ['LUM-AST-001', 'LUM-INJ-001']);
      assert.equal(result.findings[0].occurrences, 1);
      assert.equal(result.findings[0].impactWeight, 6);
      assert.equal(result.findings[0].locations.length, 1);
    });

    it('does not merge distinct credentials with matching redacted evidence', () => {
      const result = calculateProjectRisk([
        {
          severity: 'High',
          confidence: 'High',
          category: 'credentials',
          ruleId: 'LUM-SEC-001',
          file: 'locales/pl_PL.json',
          line: 4,
          title: 'Possible hard-coded access token',
          evidence: 'access token=<redacted>',
          findingFingerprint: 'credential:secret-one'
        },
        {
          severity: 'High',
          confidence: 'High',
          category: 'credentials',
          ruleId: 'LUM-SEC-001',
          file: 'locales/pl_PL.json',
          line: 5,
          title: 'Possible hard-coded access token',
          evidence: 'access token=<redacted>',
          findingFingerprint: 'credential:secret-two'
        }
      ], { coverageComplete: true });

      assert.equal(result.findings.length, 2);
      assert.deepEqual(
        result.findings.map((finding) => finding.locations[0].line).sort(),
        [4, 5]
      );
    });

    it('produces identical finding IDs and impact weights across repeated runs with identical input', () => {
      const issues = [
        { severity: 'Critical', confidence: 'High', category: 'credentials', ruleId: 'LUM-SEC-001', file: 'config/.env', line: 10, title: 'Hardcoded API Key' },
        { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 42, title: 'SQL Injection' },
        { severity: 'Medium', confidence: 'High', category: 'configuration', ruleId: 'LUM-CFG-001', file: 'nginx.conf', line: 15, title: 'Insecure Header' }
      ];
      const run1 = calculateProjectRisk(issues, { coverageComplete: true });
      const run2 = calculateProjectRisk(issues, { coverageComplete: true });
      assert.deepEqual(run1.findings.map(f => f.id), ['LUM-FIND-001', 'LUM-FIND-002', 'LUM-FIND-003']);
      assert.deepEqual(run1.findings.map(f => f.id), run2.findings.map(f => f.id));
      assert.deepEqual(run1.findings.map(f => f.impactWeight), run2.findings.map(f => f.impactWeight));
      assert.equal(run1.riskScore, run2.riskScore);
      assert.equal(run1.totalImpact, run2.totalImpact);
    });

    it('produces identical finding IDs, weights, and ordering regardless of input array permutation', () => {
      const issueA = { severity: 'Critical', confidence: 'High', category: 'credentials', ruleId: 'LUM-SEC-001', file: 'creds.env', line: 5, title: 'API Secret' };
      const issueB = { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/query.js', line: 20, title: 'Command Injection' };
      const issueC = { severity: 'Medium', confidence: 'Low', category: 'configuration', ruleId: 'LUM-CFG-001', file: 'app.yaml', line: 12, title: 'Debug Mode' };
      const issueD = { severity: 'Low', confidence: 'High', category: 'network_tls', ruleId: 'LUM-TLS-001', file: 'server.js', line: 100, title: 'TLS 1.1 Support' };

      const order1 = [issueA, issueB, issueC, issueD];
      const order2 = [issueD, issueC, issueB, issueA];
      const order3 = [issueB, issueD, issueA, issueC];

      const res1 = calculateProjectRisk(order1, { coverageComplete: true });
      const res2 = calculateProjectRisk(order2, { coverageComplete: true });
      const res3 = calculateProjectRisk(order3, { coverageComplete: true });

      assert.deepEqual(res1.findings.map(f => f.id), ['LUM-FIND-001', 'LUM-FIND-002', 'LUM-FIND-003', 'LUM-FIND-004']);
      assert.deepEqual(res1.findings.map(f => f.id), res2.findings.map(f => f.id));
      assert.deepEqual(res2.findings.map(f => f.id), res3.findings.map(f => f.id));
      assert.deepEqual(res1.findings.map(f => f.title), res2.findings.map(f => f.title));
      assert.deepEqual(res2.findings.map(f => f.title), res3.findings.map(f => f.title));
      assert.deepEqual(res1.findings.map(f => f.impactWeight), res2.findings.map(f => f.impactWeight));
      assert.deepEqual(res2.findings.map(f => f.impactWeight), res3.findings.map(f => f.impactWeight));
      assert.equal(res1.totalImpact, res2.totalImpact);
      assert.equal(res2.totalImpact, res3.totalImpact);
    });

    it('produces identical IDs and weights regardless of file discovery order or path separators', () => {
      const run1Issues = [
        { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/z_handler.js', line: 10, title: 'SQL Injection' },
        { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/a_auth.js', line: 10, title: 'SQL Injection' }
      ];
      const run2Issues = [
        { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src\\a_auth.js', line: 10, title: 'SQL Injection' },
        { severity: 'High', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src\\z_handler.js', line: 10, title: 'SQL Injection' }
      ];

      const res1 = calculateProjectRisk(run1Issues, { coverageComplete: true });
      const res2 = calculateProjectRisk(run2Issues, { coverageComplete: true });

      assert.equal(res1.findings[0].file, 'src/a_auth.js');
      assert.equal(res1.findings[0].id, 'LUM-FIND-001');
      assert.equal(res1.findings[0].impactWeight, 4.5);
      assert.equal(res1.findings[1].file, 'src/z_handler.js');
      assert.equal(res1.findings[1].id, 'LUM-FIND-002');
      assert.equal(res1.findings[1].impactWeight, 3.0);

      assert.deepEqual(res1.findings.map(f => f.id), res2.findings.map(f => f.id));
      assert.deepEqual(res1.findings.map(f => f.file), res2.findings.map(f => f.file));
      assert.deepEqual(res1.findings.map(f => f.impactWeight), res2.findings.map(f => f.impactWeight));
    });

    it('merges duplicate representations without inflating occurrences or risk contribution', () => {
      const duplicateBatch = [
        { severity: 'High', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 15, evidence: 'query(sql)', title: 'SQLi' },
        { severity: 'High', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 15, evidence: 'query(sql)', title: 'SQLi' },
        { severity: 'High', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 15, evidence: 'query(sql)', title: 'SQLi' }
      ];
      const singleFinding = [
        { severity: 'High', ruleId: 'LUM-INJ-001', file: 'src/db.js', line: 15, evidence: 'query(sql)', title: 'SQLi' }
      ];

      const dupResult = calculateProjectRisk(duplicateBatch, { coverageComplete: true });
      const singleResult = calculateProjectRisk(singleFinding, { coverageComplete: true });

      assert.equal(dupResult.findings.length, 1);
      assert.equal(dupResult.findings[0].id, 'LUM-FIND-001');
      assert.equal(dupResult.findings[0].occurrences, 1);
      assert.equal(dupResult.findings[0].impactWeight, singleResult.findings[0].impactWeight);
      assert.equal(dupResult.totalImpact, singleResult.totalImpact);
      assert.equal(dupResult.riskScore, singleResult.riskScore);
    });

    it('assigns distinct, stable IDs and applies diminishing returns to distinct lines of the same file', () => {
      const issuesReverse = [
        { severity: 'Medium', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/api.js', line: 80, title: 'SQL Injection' },
        { severity: 'Medium', confidence: 'Medium', category: 'injection', ruleId: 'LUM-INJ-001', file: 'src/api.js', line: 20, title: 'SQL Injection' }
      ];
      const result = calculateProjectRisk(issuesReverse, { coverageComplete: true });

      assert.equal(result.findings.length, 2);
      assert.equal(result.findings[0].line, 20);
      assert.equal(result.findings[0].id, 'LUM-FIND-001');
      assert.equal(result.findings[0].impactWeight, 2.25);

      assert.equal(result.findings[1].line, 80);
      assert.equal(result.findings[1].id, 'LUM-FIND-002');
      assert.equal(result.findings[1].impactWeight, 1.50);
    });

    it('assigns distinct, stable IDs to distinct findings across different files', () => {
      const issues = [
        { severity: 'High', confidence: 'High', category: 'credentials', ruleId: 'LUM-SEC-001', file: 'src/services/billing.js', line: 5, title: 'API Key' },
        { severity: 'High', confidence: 'High', category: 'credentials', ruleId: 'LUM-SEC-001', file: 'src/services/auth.js', line: 5, title: 'API Key' }
      ];
      const result = calculateProjectRisk(issues, { coverageComplete: true });

      assert.equal(result.findings.length, 2);
      assert.equal(result.findings[0].id, 'LUM-FIND-001');
      assert.equal(result.findings[0].file, 'src/services/auth.js');
      assert.equal(result.findings[1].id, 'LUM-FIND-002');
      assert.equal(result.findings[1].file, 'src/services/billing.js');
    });

    it('handles missing or null optional metadata safely with deterministic IDs', () => {
      const sparseIssues = [
        {
          severity: null,
          confidence: null,
          category: null,
          ruleId: null,
          checkId: null,
          file: null,
          line: null,
          evidence: null,
          title: null,
          cwe: null,
          cvssScore: null
        },
        {
          severity: 'High',
          confidence: 'Medium',
          category: 'injection',
          file: 'query.js'
        }
      ];
      const result = calculateProjectRisk(sparseIssues, { coverageComplete: true });
      assert.equal(result.findings.length, 2);
      assert.equal(result.findings[0].id, 'LUM-FIND-001');
      assert.equal(result.findings[1].id, 'LUM-FIND-002');
      assert.ok(Number.isFinite(result.findings[0].impactWeight));
      assert.ok(Number.isFinite(result.findings[1].impactWeight));
      assert.ok(!Number.isNaN(result.totalImpact));
      assert.ok(!Number.isNaN(result.riskScore));
    });

    it('verifies full-precision accumulation and bounds displayed rounding deviation to <= 0.005 * N', () => {
      const findings = Array.from({ length: 7 }, (_, i) => ({
        severity: 'Medium',
        confidence: 'High',
        category: 'injection',
        ruleId: 'LUM-INJ-MATH',
        file: `src/file_${i}.js`,
        line: 10 + i,
        title: `Injection ${i}`
      }));

      const result = calculateProjectRisk(findings, { coverageComplete: true });
      const displayedSum = Number(result.findings.reduce((s, f) => s + f.impactWeight, 0).toFixed(2));
      const totalImpact = result.totalImpact;

      const maxAllowedDeviation = Number((0.005 * findings.length).toFixed(4));
      const actualDeviation = Math.abs(displayedSum - totalImpact);

      assert.ok(
        actualDeviation <= maxAllowedDeviation,
        `Rounding deviation (${actualDeviation}) must be within bounded precision <= ${maxAllowedDeviation}`
      );
      for (const f of result.findings) {
        const decimalPlaces = (String(f.impactWeight).split('.')[1] || '').length;
        assert.ok(decimalPlaces <= 2, `impactWeight ${f.impactWeight} must have at most 2 decimal places`);
      }
    });
  });

});
