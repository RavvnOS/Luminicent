function normalizePath(file) {
  return String(file || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

export function createSinkIdentity(finding) {
  const span = finding?.sourceSpan;
  if (!finding?.ruleId || !finding?.checkId || !finding?.file ||
      !Number.isInteger(span?.start) || !Number.isInteger(span?.end) ||
      span.end <= span.start) return null;
  return [
    'sink-v1',
    normalizePath(finding.file),
    finding.checkId,
    finding.ruleId,
    span.start,
    span.end
  ].join(':');
}

function traceKey(trace) {
  return JSON.stringify(trace || null);
}

function uniqueTraces(traces) {
  const byKey = new Map();
  for (const trace of traces.filter(Boolean)) {
    byKey.set(traceKey(trace), trace);
  }
  return [...byKey.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, trace]) => trace);
}

function mergeSameSink(existing, incoming) {
  const preferred = incoming.isTaintConfirmed && !existing.isTaintConfirmed
    ? incoming
    : existing;
  const secondary = preferred === existing ? incoming : existing;
  const producerOrigins = [...new Set([
    ...(existing.producerOrigins || (existing.origin ? [existing.origin] : [])),
    ...(incoming.producerOrigins || (incoming.origin ? [incoming.origin] : []))
  ])].sort();
  const evidenceVariants = [...new Set([
    ...(existing.evidenceVariants || []),
    ...(incoming.evidenceVariants || []),
    existing.evidence,
    incoming.evidence
  ].filter((value) => typeof value === 'string' && value.length > 0))].sort();
  const traces = uniqueTraces([
    existing.taintTrace,
    ...(existing.taintTrace?.alternatePaths || []),
    ...(existing.alternateTaintTraces || []),
    incoming.taintTrace,
    ...(incoming.taintTrace?.alternatePaths || []),
    ...(incoming.alternateTaintTraces || [])
  ]);
  const primaryTrace = preferred.taintTrace || traces[0] || null;
  const merged = {
    ...secondary,
    ...preferred,
    sinkIdentity: createSinkIdentity(preferred),
    findingFingerprint: createSinkIdentity(preferred),
    producerOrigins,
    evidenceVariants,
    sinkIdentityStatus: 'resolved',
    isTaintConfirmed: Boolean(existing.isTaintConfirmed || incoming.isTaintConfirmed)
  };
  if (primaryTrace) {
    merged.taintTrace = primaryTrace;
    merged.alternateTaintTraces = traces.filter((trace) =>
      traceKey(trace) !== traceKey(primaryTrace)
    );
  } else {
    delete merged.alternateTaintTraces;
  }
  const provenanceVariants = uniqueTraces([
    ...(existing.sinkProvenanceVariants || []),
    existing.sinkProvenance,
    ...(incoming.sinkProvenanceVariants || []),
    incoming.sinkProvenance
  ]);
  if (provenanceVariants.length) {
    merged.sinkProvenance = preferred.sinkProvenance ||
      existing.sinkProvenance || incoming.sinkProvenance;
    merged.sinkProvenanceVariants = provenanceVariants;
  }
  return merged;
}

export function reconcileFindingsBySinkIdentity(findings) {
  const ordered = [...findings].sort((left, right) =>
    String(createSinkIdentity(left) || '').localeCompare(String(createSinkIdentity(right) || '')) ||
    String(left.origin || '').localeCompare(String(right.origin || '')) ||
    String(left.evidence || '').localeCompare(String(right.evidence || '')) ||
    JSON.stringify(left).localeCompare(JSON.stringify(right))
  );
  const byIdentity = new Map();
  const unreconciled = [];
  for (const finding of ordered) {
    const sinkIdentity = createSinkIdentity(finding);
    if (!sinkIdentity) {
      unreconciled.push({
        ...finding,
        sinkIdentity: null,
        findingFingerprint: null,
        sinkIdentityStatus: 'unresolved'
      });
      continue;
    }
    const identified = {
      ...finding,
      sinkIdentity,
      findingFingerprint: sinkIdentity,
      sinkIdentityStatus: 'resolved'
    };
    const existing = byIdentity.get(sinkIdentity);
    byIdentity.set(
      sinkIdentity,
      existing ? mergeSameSink(existing, identified) : identified
    );
  }
  return [...byIdentity.values(), ...unreconciled].sort((left, right) =>
    normalizePath(left.file).localeCompare(normalizePath(right.file)) ||
    (left.sourceSpan?.start ?? Number.MAX_SAFE_INTEGER) -
      (right.sourceSpan?.start ?? Number.MAX_SAFE_INTEGER) ||
    String(left.ruleId || '').localeCompare(String(right.ruleId || '')) ||
    String(left.evidence || '').localeCompare(String(right.evidence || '')) ||
    JSON.stringify(left).localeCompare(JSON.stringify(right))
  );
}
