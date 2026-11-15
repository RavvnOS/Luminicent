import { createHash } from 'node:crypto';

/**
 * Luminicent Risk Prioritization Engine (Phase 4.2)
 *
 * Implements the asymptotic risk-prioritization model:
 *   R = 100 * (1 - exp(-totalImpact / 30))
 * where totalImpact = sum(w_i)
 * and w_i = SeverityWeight * ConfidenceMultiplier * CategoryWeight * DiminishingMultiplier(k)
 *
 * Security Score (Health Score):
 *   H = max(0, min(100, 100 - R))
 */

export const SEVERITY_WEIGHTS = Object.freeze({
  critical: 10.0,
  high: 6.0,
  medium: 3.0,
  low: 1.0,
  unknown: 0.5
});

export const CONFIDENCE_MULTIPLIERS = Object.freeze({
  high: 1.00,
  medium: 0.75,
  low: 0.35
});

export const CATEGORY_WEIGHTS = Object.freeze({
  credentials: 1.00,
  injection: 1.00,
  deserialization: 1.00,
  dynamic_execution: 1.00,
  application: 1.00,
  dependency_direct: 1.00,
  dependency_transitive: 0.65,
  network_tls: 0.85,
  configuration: 0.50,
  project_structure: 0.50,
  docker: 0.50
});

export const CALIBRATION_CONSTANT = 30.0;

/**
 * Derives the severity weight for a finding, taking CVSS score into account if available.
 */
export function getSeverityWeight(severity, cvssScore = null) {
  if (cvssScore !== null && cvssScore !== undefined) {
    const score = Number(cvssScore);
    if (Number.isFinite(score)) {
      if (score >= 9.0) return SEVERITY_WEIGHTS.critical;
      if (score >= 7.0) return SEVERITY_WEIGHTS.high;
      if (score >= 4.0) return SEVERITY_WEIGHTS.medium;
      if (score > 0) return SEVERITY_WEIGHTS.low;
    }
  }

  const key = String(severity || '').trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(SEVERITY_WEIGHTS, key)) {
    return SEVERITY_WEIGHTS[key];
  }
  return SEVERITY_WEIGHTS.unknown;
}

/**
 * Derives the confidence multiplier.
 */
export function getConfidenceMultiplier(confidence, category = '') {
  const key = String(confidence || '').trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(CONFIDENCE_MULTIPLIERS, key)) {
    return CONFIDENCE_MULTIPLIERS[key];
  }
  // Missing or unspecified confidence defaults deterministically
  if (category === 'dependency') return CONFIDENCE_MULTIPLIERS.high;
  if (category === 'configuration' || category === 'project_structure') return CONFIDENCE_MULTIPLIERS.high;
  return CONFIDENCE_MULTIPLIERS.medium;
}

/**
 * Derives the category / exposure weight.
 */
export function getCategoryWeight(category, relationship = 'direct') {
  const cat = String(category || '').trim().toLowerCase();
  if (cat === 'dependency') {
    return relationship === 'transitive'
      ? CATEGORY_WEIGHTS.dependency_transitive
      : CATEGORY_WEIGHTS.dependency_direct;
  }
  if (Object.prototype.hasOwnProperty.call(CATEGORY_WEIGHTS, cat)) {
    return CATEGORY_WEIGHTS[cat];
  }
  return 1.00;
}

/**
 * Normalizes file paths across platforms for stable duplicate keys and sorting.
 */
export function normalizePath(p) {
  if (!p) return '';
  return String(p).replace(/\\/g, '/').replace(/^\.\//, '');
}

export function createFindingFingerprint(issue) {
  if (typeof issue.findingFingerprint === 'string' &&
      issue.findingFingerprint.length > 0) {
    return issue.findingFingerprint;
  }

  const category = String(issue.category || issue.checkId || 'unknown');
  const file = normalizePath(issue.file || issue.dependency?.manifest || '');
  const line = Number.isInteger(issue.line) ? issue.line : 0;
  const identity = category === 'dependency'
    ? [
        category,
        String(issue.dependency?.ecosystem || '').toLowerCase(),
        String(issue.dependency?.package || '').toLowerCase(),
        String(issue.dependency?.installedVersion || '').toLowerCase(),
        String(issue.dependency?.advisoryId || issue.cveIds?.[0] || issue.title || '')
      ]
    : [
        category,
        file,
        line,
        String(issue.evidence || issue.title || '').trim()
      ];
  return `LUM-FP-${createHash('sha256').update(JSON.stringify(identity)).digest('hex')}`;
}

/**
 * Normalizes and standardizes a single finding to conform to the v2 report schema.
 */
export function standardizeFinding(issue, index = 0) {
  const hasCustomId = Boolean(issue.id && !/^LUM-FIND-\d+$/i.test(String(issue.id)));
  const id = issue.id || `LUM-FIND-${String(index + 1).padStart(3, '0')}`;
  const severity = issue.severity || 'Unknown';
  let category = issue.category;
  if (!category) {
    if (issue.checkId === 'secret_pattern_search') category = 'credentials';
    else if (issue.checkId === 'injection_pattern_search') category = 'injection';
    else if (issue.checkId === 'unsafe_deserialization_pattern_search') category = 'deserialization';
    else if (issue.checkId === 'dynamic_code_execution_pattern_search') category = 'dynamic_execution';
    else if (issue.checkId === 'insecure_transport_configuration') category = 'network_tls';
    else if (issue.checkId === 'dependency_vulnerability_analysis') category = 'dependency';
    else if (issue.checkId === 'project_structure') category = 'project_structure';
    else category = 'configuration';
  }

  const ruleId = issue.ruleId || (category === 'dependency' ? 'LUM-DEP-OSV' : undefined);
  const confidence = issue.confidence || (category === 'dependency' ? 'High' : (category === 'configuration' || category === 'project_structure' ? 'High' : 'Medium'));

  // Format CWE
  let cwe = [];
  if (Array.isArray(issue.cwe)) {
    cwe = issue.cwe.filter(Boolean).map(String);
  } else if (issue.cwe) {
    cwe = [String(issue.cwe)];
  }

  // Format CVE / GHSA
  let cveIds = [];
  if (Array.isArray(issue.cveIds)) {
    cveIds = issue.cveIds.filter(Boolean).map(String);
  } else if (issue.dependency?.cveIds && Array.isArray(issue.dependency.cveIds)) {
    cveIds = issue.dependency.cveIds.filter(Boolean).map(String);
  }

  let ghsaIds = [];
  if (Array.isArray(issue.ghsaIds)) {
    ghsaIds = issue.ghsaIds.filter(Boolean).map(String);
  } else if (issue.dependency?.ghsaIds && Array.isArray(issue.dependency.ghsaIds)) {
    ghsaIds = issue.dependency.ghsaIds.filter(Boolean).map(String);
  }

  const cvssScore = issue.cvssScore !== undefined && issue.cvssScore !== null
    ? Number(issue.cvssScore)
    : (issue.dependency?.cvssScore !== undefined && issue.dependency?.cvssScore !== null ? Number(issue.dependency.cvssScore) : null);

  const cvssVector = issue.cvssVector || issue.dependency?.cvssVector || null;
  const fixedVersion = issue.fixedVersion || issue.dependency?.fixedVersion || null;
  const affectedVersionRange = issue.affectedVersionRange || issue.dependency?.affectedVersionRange || null;

  // Origin / detection method
  let origin = issue.origin;
  if (!origin) {
    if (category === 'dependency') origin = 'manifest_advisory';
    else if (issue.checkId?.includes('docker')) origin = 'dockerfile_heuristic';
    else if (category === 'configuration' || category === 'project_structure') origin = 'configuration_analysis';
    else if (issue.ruleId?.startsWith('LUM-DYN') || issue.ruleId?.startsWith('LUM-INJ')) origin = 'ast_analysis';
    else origin = 'pattern_heuristic';
  }

  const rawFile = issue.file || issue.dependency?.manifest || null;
  const file = rawFile ? normalizePath(rawFile) : null;
  const line = Number.isInteger(issue.line) ? issue.line : null;
  const recommendation = issue.recommendation || issue.remediation || '';
  const remediation = issue.remediation || recommendation;

  const normalizedLocations = Array.isArray(issue.locations)
    ? issue.locations.map(loc => ({
        file: normalizePath(loc.file),
        ...(Number.isInteger(loc.line) ? { line: loc.line } : {}),
        ...(Number.isInteger(loc.column) || (normalizePath(loc.file) === file &&
          loc.line === line && Number.isInteger(issue.column))
          ? { column: Number.isInteger(loc.column) ? loc.column : issue.column }
          : {}),
        ...(Number.isInteger(loc.start) || (normalizePath(loc.file) === file &&
          loc.line === line && Number.isInteger(issue.sourceSpan?.start))
          ? { start: Number.isInteger(loc.start) ? loc.start : issue.sourceSpan.start }
          : {}),
        ...(Number.isInteger(loc.end) || (normalizePath(loc.file) === file &&
          loc.line === line && Number.isInteger(issue.sourceSpan?.end))
          ? { end: Number.isInteger(loc.end) ? loc.end : issue.sourceSpan.end }
          : {})
      }))
    : (file ? [{
        file,
        ...(Number.isInteger(line) ? { line } : {}),
        ...(Number.isInteger(issue.column) ? { column: issue.column } : {}),
        ...(Number.isInteger(issue.sourceSpan?.start) ? { start: issue.sourceSpan.start } : {}),
        ...(Number.isInteger(issue.sourceSpan?.end) ? { end: issue.sourceSpan.end } : {})
      }] : []);
  const findingFingerprint = issue.sinkIdentityStatus === 'unresolved'
    ? `unresolved:${index}`
    : createFindingFingerprint({
        ...issue,
        category,
        file,
        line,
        evidence: issue.evidence,
        title: issue.title
      });

  return {
    id,
    _hasCustomId: hasCustomId,
    _findingFingerprint: findingFingerprint,
    findingFingerprint,
    ...(Array.isArray(issue.ruleIds) ? { ruleIds: [...new Set(issue.ruleIds.filter(Boolean).map(String))] } : {}),
    ...(Array.isArray(issue.checkIds) ? { checkIds: [...new Set(issue.checkIds.filter(Boolean).map(String))] } : {}),
    ...(Array.isArray(issue.evidenceVariants) ? { evidenceVariants: [...new Set(issue.evidenceVariants.filter(Boolean).map(String))] } : {}),
    ...(ruleId ? { ruleId } : {}),
    checkId: issue.checkId || 'static_analysis',
    category,
    title: issue.title || 'Security finding',
    description: issue.description || '',
    severity,
    confidence,
    cwe,
    cveIds,
    ghsaIds,
    cvssScore: Number.isFinite(cvssScore) ? cvssScore : null,
    cvssVector,
    affectedVersionRange,
    fixedVersion,
    evidence: issue.evidence || null,
    file,
    line,
    ...(Number.isInteger(issue.column) ? { column: issue.column } : {}),
    locations: normalizedLocations,
    occurrences: issue.occurrences || 1,
    severityRationale: issue.severityRationale || (cvssScore !== null ? `Advisory severity: ${severity} (CVSS ${cvssScore})` : `Severity assigned based on ${severity.toLowerCase()} pattern potential.`),
    remediation,
    recommendation, // preserved for v1 compatibility
    origin,
    ...(issue.dependency ? { dependency: issue.dependency } : {}),
    ...(issue.isTaintConfirmed ? { isTaintConfirmed: true } : {}),
    ...(issue.taintTrace ? { taintTrace: issue.taintTrace } : {}),
    ...(issue.sourceSpan ? { sourceSpan: { ...issue.sourceSpan } } : {}),
    ...(issue.sinkIdentity ? { sinkIdentity: issue.sinkIdentity } : {}),
    ...(issue.sinkIdentityStatus ? { sinkIdentityStatus: issue.sinkIdentityStatus } : {}),
    ...(issue.sinkExpression ? { sinkExpression: issue.sinkExpression } : {}),
    ...(issue.sinkProvenance ? { sinkProvenance: issue.sinkProvenance } : {}),
    ...(Array.isArray(issue.sinkProvenanceVariants)
      ? { sinkProvenanceVariants: issue.sinkProvenanceVariants.map((variant) => ({ ...variant })) }
      : {}),
    ...(Array.isArray(issue.producerOrigins)
      ? { producerOrigins: [...new Set(issue.producerOrigins.filter(Boolean).map(String))].sort() }
      : {}),
    ...(Array.isArray(issue.alternateTaintTraces)
      ? { alternateTaintTraces: issue.alternateTaintTraces }
      : {}),
    ...(issue.detectionMethod ? { detectionMethod: issue.detectionMethod } : {})
  };
}

/**
 * Canonical comparator to deterministically pre-sort findings before deduplication
 * and diminishing-returns occurrence calculation.
 * Ensures order independence from input array order and filesystem traversal order.
 */
export function compareFindingsCanonical(a, b) {
  const getSevRank = (s) => {
    switch (String(s || '').toLowerCase()) {
      case 'critical': return 5;
      case 'high': return 4;
      case 'medium': return 3;
      case 'low': return 2;
      case 'unknown': return 1;
      default: return 0;
    }
  };
  const getConfRank = (c) => {
    switch (String(c || '').toLowerCase()) {
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  };
  const getDepRank = (dep) => {
    if (!dep) return 0;
    const rel = String(dep.relationship || '').toLowerCase();
    if (rel === 'direct') return 2;
    if (rel === 'transitive') return 1;
    return 0;
  };

  const sevDiff = getSevRank(b.severity) - getSevRank(a.severity);
  if (sevDiff !== 0) return sevDiff;

  const confDiff = getConfRank(b.confidence) - getConfRank(a.confidence);
  if (confDiff !== 0) return confDiff;

  const cvssA = Number.isFinite(Number(a.cvssScore)) ? Number(a.cvssScore) : -1;
  const cvssB = Number.isFinite(Number(b.cvssScore)) ? Number(b.cvssScore) : -1;
  if (cvssA !== cvssB) return cvssB - cvssA;

  const sWeightA = getSeverityWeight(a.severity, a.cvssScore);
  const cMultA = getConfidenceMultiplier(a.confidence, a.category);
  const xWeightA = getCategoryWeight(a.category, a.dependency?.relationship || 'direct');
  const baseWeightA = sWeightA * cMultA * xWeightA;

  const sWeightB = getSeverityWeight(b.severity, b.cvssScore);
  const cMultB = getConfidenceMultiplier(b.confidence, b.category);
  const xWeightB = getCategoryWeight(b.category, b.dependency?.relationship || 'direct');
  const baseWeightB = sWeightB * cMultB * xWeightB;

  if (Math.abs(baseWeightB - baseWeightA) > 1e-9) return baseWeightB - baseWeightA;

  const catA = String(a.category || '');
  const catB = String(b.category || '');
  const catDiff = catA.localeCompare(catB);
  if (catDiff !== 0) return catDiff;

  const depDiff = getDepRank(b.dependency) - getDepRank(a.dependency);
  if (depDiff !== 0) return depDiff;

  const ruleA = String(a.ruleId || a.checkId || '');
  const ruleB = String(b.ruleId || b.checkId || '');
  const ruleDiff = ruleA.localeCompare(ruleB);
  if (ruleDiff !== 0) return ruleDiff;

  const fileA = normalizePath(a.file || a.dependency?.manifest || '');
  const fileB = normalizePath(b.file || b.dependency?.manifest || '');
  const fileDiff = fileA.localeCompare(fileB);
  if (fileDiff !== 0) return fileDiff;

  const lineA = Number.isInteger(a.line) && a.line > 0 ? a.line : Number.MAX_SAFE_INTEGER;
  const lineB = Number.isInteger(b.line) && b.line > 0 ? b.line : Number.MAX_SAFE_INTEGER;
  if (lineA !== lineB) return lineA - lineB;

  const titleA = String(a.title || '');
  const titleB = String(b.title || '');
  const titleDiff = titleA.localeCompare(titleB);
  if (titleDiff !== 0) return titleDiff;

  const evA = String(a.evidence || '');
  const evB = String(b.evidence || '');
  const evDiff = evA.localeCompare(evB);
  if (evDiff !== 0) return evDiff;

  const advA = String(a.dependency?.advisoryId || a.cveIds?.[0] || '');
  const advB = String(b.dependency?.advisoryId || b.cveIds?.[0] || '');
  return advA.localeCompare(advB);
}

/**
 * Calculates project-level risk assessment given findings and coverage completeness.
 *
 * @param {Array} rawIssues - List of finding/issue objects
 * @param {Object} options - Options including coverageComplete (boolean) and checkCount
 * @returns {Object} Risk evaluation result
 */
export function calculateProjectRisk(rawIssues = [], { coverageComplete = true } = {}) {
  // Step 1: Standardize all raw issues into candidate objects
  const candidates = rawIssues.map((issue, index) => standardizeFinding(issue, index));

  // Step 2: Canonical pre-sort to eliminate input array and file traversal order dependency
  candidates.sort(compareFindingsCanonical);

  // Step 3: Deduplicate exact duplicate findings & apply diminishing returns in canonical order
  const uniqueFindings = [];
  const seenExact = new Map();
  const ruleCounts = new Map();

  candidates.forEach((std) => {
    const exactKey = std._findingFingerprint;
    if (seenExact.has(exactKey)) {
      const existing = seenExact.get(exactKey);
      const incomingRuleIds = [...new Set([...(std.ruleIds || []), std.ruleId].filter(Boolean))];
      const existingRuleIds = [...new Set([...(existing.ruleIds || []), existing.ruleId].filter(Boolean))];
      existing.occurrences = Math.max(
        existing.occurrences || 1,
        std.occurrences || 1
      );
      for (const ruleId of incomingRuleIds) {
        if (!existingRuleIds.includes(ruleId)) existingRuleIds.push(ruleId);
      }
      if (existingRuleIds.length > 1) existing.ruleIds = existingRuleIds.sort();

      const incomingCheckIds = [...new Set([...(std.checkIds || []), std.checkId].filter(Boolean))];
      const existingCheckIds = [...new Set([...(existing.checkIds || []), existing.checkId].filter(Boolean))];
      for (const checkId of incomingCheckIds) {
        if (!existingCheckIds.includes(checkId)) existingCheckIds.push(checkId);
      }
      if (existingCheckIds.length > 1) existing.checkIds = existingCheckIds.sort();

      for (const cweId of std.cwe) {
        if (!existing.cwe.includes(cweId)) existing.cwe.push(cweId);
      }
      existing.cwe.sort();
      for (const id of std.cveIds) {
        if (!existing.cveIds.includes(id)) existing.cveIds.push(id);
      }
      existing.cveIds.sort();
      for (const id of std.ghsaIds) {
        if (!existing.ghsaIds.includes(id)) existing.ghsaIds.push(id);
      }
      existing.ghsaIds.sort();

      const evidenceValues = [...new Set([
        ...(existing.evidenceVariants || []),
        existing.evidence,
        ...(std.evidenceVariants || []),
        std.evidence
      ].filter(Boolean))];
      if (evidenceValues.length > 1) existing.evidenceVariants = evidenceValues;

      for (const location of std.locations) {
        const alreadyHasLoc = existing.locations.some(
          (existingLocation) =>
            normalizePath(existingLocation.file) === normalizePath(location.file) &&
            existingLocation.line === location.line
        );
        if (!alreadyHasLoc) existing.locations.push(location);
      }
      existing.locations.sort((left, right) =>
        normalizePath(left.file).localeCompare(normalizePath(right.file)) ||
        (left.line || 0) - (right.line || 0)
      );
      return;
    }

    seenExact.set(exactKey, std);

    const ruleKey = std.ruleId || std.checkId || std.category || 'generic_rule';
    const ruleOccurrences = (ruleCounts.get(ruleKey) || 0) + 1;
    ruleCounts.set(ruleKey, ruleOccurrences);

    // Diminishing returns multiplier: 1 / (1 + 0.5 * (k - 1))
    const occurrenceMultiplier = 1 / (1 + 0.5 * (ruleOccurrences - 1));

    const sWeight = getSeverityWeight(std.severity, std.cvssScore);
    const cMultiplier = getConfidenceMultiplier(std.confidence, std.category);
    const relationship = std.dependency?.relationship || 'direct';
    const xWeight = getCategoryWeight(std.category, relationship);

    const baseWeight = sWeight * cMultiplier * xWeight;
    const effectiveWeight = baseWeight * occurrenceMultiplier;

    // Preserve full double-precision floating point internally
    std._baseWeight = baseWeight;
    std._effectiveWeight = effectiveWeight;
    uniqueFindings.push(std);
  });

  // Calculate raw total impact with full double precision
  const rawTotalImpact = uniqueFindings.reduce((sum, f) => sum + f._effectiveWeight, 0);

  // Asymptotic formula: R = 100 * (1 - exp(-totalImpact / K))
  const rawRisk = 100 * (1 - Math.exp(-rawTotalImpact / CALIBRATION_CONSTANT));
  const riskScore = Math.max(0, Math.min(100, Math.round(rawRisk)));
  const securityScore = Math.max(0, Math.min(100, 100 - riskScore));

  // Risk Level
  let riskLevel;
  if (!coverageComplete && riskScore < 15) {
    riskLevel = 'Indeterminate';
  } else if (riskScore >= 90) {
    riskLevel = 'Critical';
  } else if (riskScore >= 70) {
    riskLevel = 'High';
  } else if (riskScore >= 40) {
    riskLevel = 'Medium';
  } else if (riskScore >= 15) {
    riskLevel = 'Low';
  } else {
    riskLevel = 'Minimal';
  }

  // Report Status (Health/Posture Category)
  let status;
  if (uniqueFindings.length === 0 && !coverageComplete) {
    status = 'Needs Review';
  } else if (!coverageComplete && securityScore >= 75) {
    status = 'Needs Review';
  } else if (securityScore >= 90) {
    status = 'Excellent';
  } else if (securityScore >= 75) {
    status = 'Good';
  } else if (securityScore >= 60) {
    status = 'Needs Improvement';
  } else {
    status = 'Poor';
  }

  const summary = {
    critical: uniqueFindings.filter((i) => i.severity.toLowerCase() === 'critical').length,
    high: uniqueFindings.filter((i) => i.severity.toLowerCase() === 'high').length,
    medium: uniqueFindings.filter((i) => i.severity.toLowerCase() === 'medium').length,
    low: uniqueFindings.filter((i) => i.severity.toLowerCase() === 'low').length,
    unknown: uniqueFindings.filter((i) => i.severity.toLowerCase() === 'unknown').length,
    total: uniqueFindings.length
  };

  let rationale;
  if (uniqueFindings.length === 0) {
    rationale = coverageComplete
      ? 'No security findings were detected in any completed checks across all analyzed project files and manifests.'
      : 'No security findings were identified in the completed checks, but scan coverage is incomplete; overall project posture is indeterminate.';
  } else {
    const parts = [];
    if (summary.critical > 0) parts.push(`${summary.critical} Critical`);
    if (summary.high > 0) parts.push(`${summary.high} High`);
    if (summary.medium > 0) parts.push(`${summary.medium} Medium`);
    if (summary.low > 0) parts.push(`${summary.low} Low`);
    if (summary.unknown > 0) parts.push(`${summary.unknown} Unknown`);
    rationale = `Project risk is ${riskLevel} (score ${riskScore}/100, security score ${securityScore}/100) based on ${parts.join(', ')} severity finding(s) with confidence and category weighting applied.`;
    if (!coverageComplete) {
      rationale += ' Analysis coverage is partial; additional risks may exist in uninspected scope.';
    }
  }

  // Presentation sorting: ensure findings are ordered identically across backend, frontend, and CLI
  uniqueFindings.sort(compareFindings);

  // Clean internal tracking fields and assign presentation IDs & rounded impact weights
  const cleanFindings = uniqueFindings.map((f, idx) => {
    const clean = { ...f };
    clean.id = f._hasCustomId ? f.id : `LUM-FIND-${String(idx + 1).padStart(3, '0')}`;
    clean.impactWeight = Number(f._effectiveWeight.toFixed(2));
    delete clean._exactKey;
    delete clean._findingFingerprint;
    delete clean._baseWeight;
    delete clean._effectiveWeight;
    delete clean._hasCustomId;
    return clean;
  });

  return {
    riskScore,
    riskLevel,
    securityScore,
    totalImpact: Number(rawTotalImpact.toFixed(2)),
    formula: `R = 100 * (1 - exp(-totalImpact / ${CALIBRATION_CONSTANT}))`,
    calibrationConstant: CALIBRATION_CONSTANT,
    status,
    summary,
    rationale,
    findings: cleanFindings
  };
}

/**
 * Deterministically orders findings using unified 6-tier prioritization semantics:
 * 1. Severity rank (Critical > High > Medium > Low > Unknown)
 * 2. Confidence rank (High > Medium > Low)
 * 3. CVSS score descending
 * 4. Risk contribution (impactWeight / _effectiveWeight) descending
 * 5. Direct versus transitive dependency
 * 6. Deterministic title and ID tie-breaker
 */
export function compareFindings(a, b) {
  const getSevRank = (s) => {
    switch (String(s || '').toLowerCase()) {
      case 'critical': return 5;
      case 'high': return 4;
      case 'medium': return 3;
      case 'low': return 2;
      case 'unknown': return 1;
      default: return 0;
    }
  };
  const getConfRank = (c) => {
    switch (String(c || '').toLowerCase()) {
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  };
  const getDepRank = (dep) => {
    if (!dep) return 0;
    const rel = String(dep.relationship || '').toLowerCase();
    if (rel === 'direct') return 2;
    if (rel === 'transitive') return 1;
    return 0;
  };

  const sevDiff = getSevRank(b.severity) - getSevRank(a.severity);
  if (sevDiff !== 0) return sevDiff;

  const confDiff = getConfRank(b.confidence) - getConfRank(a.confidence);
  if (confDiff !== 0) return confDiff;

  const cvssA = Number.isFinite(Number(a.cvssScore)) ? Number(a.cvssScore) : -1;
  const cvssB = Number.isFinite(Number(b.cvssScore)) ? Number(b.cvssScore) : -1;
  if (cvssA !== cvssB) return cvssB - cvssA;

  const weightA = Number.isFinite(Number(a.impactWeight ?? a._effectiveWeight)) ? Number(a.impactWeight ?? a._effectiveWeight) : 0;
  const weightB = Number.isFinite(Number(b.impactWeight ?? b._effectiveWeight)) ? Number(b.impactWeight ?? b._effectiveWeight) : 0;
  if (weightA !== weightB) return weightB - weightA;

  const depDiff = getDepRank(b.dependency) - getDepRank(a.dependency);
  if (depDiff !== 0) return depDiff;

  const titleA = String(a.title || a.id || '');
  const titleB = String(b.title || b.id || '');
  const titleComp = titleA.localeCompare(titleB);
  if (titleComp !== 0) return titleComp;

  const fileA = normalizePath(a.file || a.dependency?.manifest || '');
  const fileB = normalizePath(b.file || b.dependency?.manifest || '');
  const fileDiff = fileA.localeCompare(fileB);
  if (fileDiff !== 0) return fileDiff;

  const lineA = Number.isInteger(a.line) && a.line > 0 ? a.line : Number.MAX_SAFE_INTEGER;
  const lineB = Number.isInteger(b.line) && b.line > 0 ? b.line : Number.MAX_SAFE_INTEGER;
  if (lineA !== lineB) return lineA - lineB;

  const ruleA = String(a.ruleId || a.checkId || '');
  const ruleB = String(b.ruleId || b.checkId || '');
  const ruleDiff = ruleA.localeCompare(ruleB);
  if (ruleDiff !== 0) return ruleDiff;

  return String(a.id || '').localeCompare(String(b.id || ''));
}
