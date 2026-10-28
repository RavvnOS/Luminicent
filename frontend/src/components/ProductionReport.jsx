import './ProductionReport.css'

const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
const safeText = (value, fallback = '') =>
  typeof value === 'string' || typeof value === 'number' ? String(value) : fallback

export default function ProductionReport({ report }) {
  if (!report) return null
  if (!isRecord(report)) {
    return <p role="alert">Invalid report payload. Security coverage is indeterminate.</p>
  }

  const rawIssues = Array.isArray(report.issues) ? report.issues : []
  const issues = rawIssues.filter(isRecord)
  const malformedIssues = !Array.isArray(report.issues) || issues.length !== rawIssues.length ||
    issues.some((issue) => typeof issue.checkId !== 'string')
  const issueCountsByCheck = new Map()
  issues.forEach((issue) => {
    if (typeof issue.checkId === 'string') {
      issueCountsByCheck.set(issue.checkId, (issueCountsByCheck.get(issue.checkId) || 0) + 1)
    }
  })
  const rawChecks = Array.isArray(report.scan?.checks) ? report.scan.checks : []
  const legacyReport = !isRecord(report.scan) || !Array.isArray(report.scan.checks)
  const expectedCheckIds = [
    'dockerfile_presence',
    'dockerfile_configuration',
    'dockerignore_configuration',
    'environment_configuration',
    'image_metadata',
    'runtime_inspection',
    'secret_pattern_search',
    'insecure_transport_configuration',
    'dangerous_application_configuration',
    'project_structure',
    'owasp_top_10',
    'dynamic_vulnerability_testing',
    'dependency_vulnerability_analysis',
    'exploit_verification'
  ]
  const unimplementedCheckIds = new Set([
    'owasp_top_10',
    'dynamic_vulnerability_testing',
    'exploit_verification'
  ])
  const recognizedStatuses = new Set([
    'passed', 'findings', 'failed', 'unsupported', 'skipped', 'incomplete'
  ])
  const checks = rawChecks.map((rawCheck, index) => {
    const check = isRecord(rawCheck) ? rawCheck : {}
    const legacyStatus = {
      completed: 'passed',
      not_performed: 'skipped',
      partial: 'incomplete'
    }[check?.status]
    let status = recognizedStatuses.has(check?.status)
      ? check.status
      : legacyStatus || 'invalid'
    const id = typeof check.id === 'string' ? check.id : ''
    const issueCount = id ? issueCountsByCheck.get(id) || 0 : 0
    const declaredFindingCount = check.findingCount
    const invalidFindingCount = declaredFindingCount !== undefined &&
      (!Number.isInteger(declaredFindingCount) || declaredFindingCount < 0 ||
        declaredFindingCount !== issueCount)
    if (!isRecord(rawCheck) || !id || invalidFindingCount ||
      unimplementedCheckIds.has(id) && status !== 'unsupported' ||
      status === 'passed' && issueCount > 0 ||
      status === 'findings' && Math.max(issueCount, declaredFindingCount || 0) === 0) {
      status = 'invalid'
    }
    return { ...check, id: id || `invalid-check-${index}`, status }
  })
  const coverage = {
    passed: 0,
    findings: 0,
    failed: 0,
    skipped: 0,
    unsupported: 0,
    incomplete: 0,
    invalid: 0
  }
  const countedCheckIds = new Set()
  checks.forEach((check) => {
    if (!expectedCheckIds.includes(check.id) || countedCheckIds.has(check.id)) {
      coverage.invalid += 1
      return
    }
    countedCheckIds.add(check.id)
    coverage[check.status] += 1
  })
  coverage.invalid += expectedCheckIds.filter((id) => !countedCheckIds.has(id)).length
  const hasCoverageMetadata = checks.length > 0 &&
    checks.every((check) => [check.name, check.scope, check.explanation]
      .every((value) => typeof value === 'string' && value.trim().length > 0)) &&
    !malformedIssues
  const checkIds = checks.map((check) => check.id)
  const hasExpectedChecks = checkIds.length === expectedCheckIds.length &&
    new Set(checkIds).size === checkIds.length &&
    expectedCheckIds.every((id) => checkIds.includes(id))
  const hasConsistentIssueAttribution = issues.every((issue) =>
    typeof issue.checkId === 'string' &&
    expectedCheckIds.includes(issue.checkId) &&
    checks.some((check) => check.id === issue.checkId &&
      ['findings', 'failed', 'incomplete'].includes(check.status))
  )
  const hasIncompleteChecks = checks.some(({ status }) =>
    ['failed', 'skipped', 'unsupported', 'incomplete', 'invalid'].includes(status)
  )
  const scanMetadataValid = typeof report.scan?.findingsDetected === 'boolean' &&
    Number.isInteger(report.scan?.findingCount) &&
    report.scan.findingCount === issues.length &&
    report.scan.findingsDetected === (issues.length > 0) &&
    hasConsistentIssueAttribution &&
    [...issueCountsByCheck.values()].reduce((sum, count) => sum + count, 0) === issues.length
  const findingsPresent = issues.length > 0 || report.scan?.findingsDetected === true
  const recommendations = Array.isArray(report.recommendations)
    ? report.recommendations.filter((recommendation) =>
      typeof recommendation === 'string' || typeof recommendation === 'number')
    : []
  const assessmentIsPartial = report.scan?.status !== 'completed' ||
    hasIncompleteChecks || !hasCoverageMetadata || !hasExpectedChecks ||
    !scanMetadataValid
  const assessment = assessmentIsPartial
    ? `${findingsPresent ? 'Findings were reported. ' : ''}${legacyReport ? 'Legacy report: coverage metadata is unavailable. ' : ''}Partial or indeterminate result: checks may have failed, been skipped, be unsupported, or have invalid/missing coverage details. No findings in performed checks does not establish that the application is secure.`
    : findingsPresent
      ? 'Checks completed with findings. Review the reported issues; a completed scan does not establish that the application is secure.'
      : safeText(report.scan?.assessment,
      'Checks completed within their stated scopes. No findings does not establish that the application is secure.'
    )

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical':
        return '#ff4444'
      case 'High':
        return '#ff9800'
      case 'Medium':
        return '#ffc107'
      case 'Low':
        return '#4caf50'
      default:
        return '#9e9e9e'
    }
  }

  const getSeverityBgColor = (severity) => {
    switch (severity) {
      case 'Critical':
        return '#ffebee'
      case 'High':
        return '#fff3e0'
      case 'Medium':
        return '#fffde7'
      case 'Low':
        return '#e8f5e9'
      default:
        return '#f5f5f5'
    }
  }

  const getScoreColor = (score) => {
    if (score >= 80) return '#4caf50'
    if (score >= 60) return '#ffc107'
    if (score >= 40) return '#ff9800'
    return '#ff4444'
  }

  return (
    <div className="production-report">
      <h2>📊 Production Readiness Report</h2>
      
      <div className="report-header">
        <div className="score-box">
          <div className="score-circle" style={{ borderColor: getScoreColor(report.score) }}>
            <div className="score-value" style={{ color: getScoreColor(report.score) }}>
              {Number.isFinite(report.score) ? report.score : 'N/A'}
            </div>
            <div className="score-label">Score</div>
          </div>
        </div>
        
        <div className="status-info">
          <div className="status-badge" style={{ 
            backgroundColor: assessmentIsPartial
              ? '#8a5a00'
              : findingsPresent ? '#8a3030'
                : report.status === 'PASS' ? '#4caf50' : '#ff4444',
            color: 'white'
          }}>
            {assessmentIsPartial
              ? 'PARTIAL / INDETERMINATE'
              : findingsPresent ? 'FINDINGS REPORTED' : safeText(report.status, 'Unknown status')}
          </div>
          <p className="total-issues">
            {issues.length} issue{issues.length !== 1 ? 's' : ''} found
          </p>
          <p className="total-issues">
            Overall assessment: {assessmentIsPartial
              ? 'Partial'
              : findingsPresent ? 'Findings reported' : 'Checks completed'}
          </p>
          <p className="coverage-assessment" role={assessmentIsPartial ? 'alert' : 'status'}>
            {assessment}
          </p>
        </div>
      </div>

      <section className="report-section coverage-summary" aria-labelledby="coverage-heading">
        <h3 id="coverage-heading">Security check coverage</h3>
        <p className="coverage-limitation">
          This report summarizes only the checks listed below. It is not a complete security assessment.
        </p>
        <dl className="coverage-counts">
          {[
            ['Expected checks', expectedCheckIds.length],
            ['Passed', coverage.passed],
            ['With findings', coverage.findings],
            ['Failed', coverage.failed],
            ['Skipped', coverage.skipped],
            ['Unsupported', coverage.unsupported],
            ['Incomplete', coverage.incomplete],
            ...(coverage.invalid ? [['Invalid or missing records', coverage.invalid]] : [])
          ].map(([label, count]) => (
            <div className="coverage-count" key={label}>
              <dt>{label}</dt>
              <dd>{count}</dd>
            </div>
          ))}
        </dl>
        {checks.length === 0 ? (
          <p role="alert">
            {legacyReport
              ? 'Legacy report: check coverage metadata is unavailable. This report must not be interpreted as clean.'
              : 'Coverage metadata is missing. This report must not be interpreted as clean.'}
          </p>
        ) : (
          <>
            {!hasExpectedChecks && (
              <p role="alert">The report is missing, duplicating, or contains unexpected checks. Coverage is indeterminate.</p>
            )}
            <ul className="coverage-checks">
            {checks.map((check) => {
              const findings = issues.filter((issue) => issue.checkId === check.id)
              return (
                <li className={`coverage-check coverage-check-${check.status}`} key={check.id || check.name}>
                  <div className="coverage-check-heading">
                    <strong>{safeText(check.name, check.id || 'Unnamed check')}</strong>
                    <span className="coverage-check-status">Status: {check.status}</span>
                  </div>
                    <p><strong>Scope:</strong> {safeText(check.scope, 'Scope metadata was not provided.')}</p>
                    <p>{safeText(check.explanation, 'Explanation metadata was not provided.')}</p>
                  {findings.length > 0 && (
                    <ul>
                      {findings.map((issue, index) => (
                        <li key={`${issue.title || 'finding'}-${index}`}>
                            {safeText(issue.title, 'Finding')}: {safeText(issue.description, 'Details unavailable.')}
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              )
            })}
            </ul>
          </>
        )}
      </section>

      {isRecord(report.docker) && Object.keys(report.docker).length > 0 && (
        <div className="report-section">
          <h3>🐳 Docker Information</h3>
          <div className="info-grid">
            {report.docker.imageId && (
              <div className="info-item">
                <span className="info-label">Image ID:</span>
                <span className="info-value">{safeText(report.docker.imageId).substring(0, 20)}...</span>
              </div>
            )}
            {report.docker.sizeMB && (
              <div className="info-item">
                <span className="info-label">Image Size:</span>
                <span className="info-value">{safeText(report.docker.sizeMB, 'Unknown')} MB</span>
              </div>
            )}
            {report.docker.created && (
              <div className="info-item">
                <span className="info-label">Created:</span>
                <span className="info-value">{new Date(safeText(report.docker.created)).toLocaleDateString()}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {isRecord(report.runtime) && Object.keys(report.runtime).length > 0 && (
        <div className="report-section">
          <h3>⚙️ Runtime Information</h3>
          <div className="info-grid">
            {report.runtime.status && (
              <div className="info-item">
                <span className="info-label">Status:</span>
                <span className="info-value">{safeText(report.runtime.status, 'Unknown')}</span>
              </div>
            )}
            {report.runtime.running !== undefined && (
              <div className="info-item">
                <span className="info-label">Running:</span>
                <span className="info-value">{typeof report.runtime.running === 'boolean'
                  ? report.runtime.running ? 'Yes' : 'No'
                  : 'Unknown'}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {issues.length > 0 && (
        <div className="report-section">
          <h3>⚠️ Issues Found ({issues.length})</h3>
          <div className="issues-list">
            {issues.map((issue, index) => (
              <div
                key={index}
                className="issue-item"
                style={{ backgroundColor: getSeverityBgColor(safeText(issue.severity)) }}
              >
                <div className="issue-header">
                  <span
                    className="issue-severity"
                    style={{ 
                      backgroundColor: getSeverityColor(safeText(issue.severity)),
                      color: 'white'
                    }}
                  >
                    {safeText(issue.severity, 'Unknown')}
                  </span>
                  <h4 className="issue-title">{safeText(issue.title, 'Untitled finding')}</h4>
                </div>
                {issue.ruleId && (
                  <p className="issue-description"><strong>Rule:</strong> {safeText(issue.ruleId)}</p>
                )}
                {issue.file && (
                  <p className="issue-description">
                    <strong>Location:</strong> {safeText(issue.file)}
                    {Number.isInteger(issue.line) && issue.line > 0 ? `:${issue.line}` : ''}
                  </p>
                )}
                {issue.evidence && (
                  <p className="issue-description">
                    <strong>Evidence:</strong> {safeText(issue.evidence, 'Redacted evidence unavailable.')}
                  </p>
                )}
                <p className="issue-description">{safeText(issue.description, 'Details unavailable.')}</p>
                {isRecord(issue.dependency) && (
                  <p className="issue-description">
                    Affected dependency: {safeText(issue.dependency.package, 'unknown')}@{safeText(issue.dependency.installedVersion, 'unknown')}
                    {' '}({safeText(issue.dependency.relationship, 'unknown')}) | Advisory: {safeText(issue.dependency.advisoryId, 'unknown')}
                    {issue.dependency.fixedVersion && (
                      <> | Fixed version: {safeText(issue.dependency.fixedVersion)}</>
                    )}
                  </p>
                )}
                {issue.recommendation && (
                  <div className="issue-recommendation">
                    <strong>💡 Fix:</strong> {safeText(issue.recommendation)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {recommendations.length > 0 && (
        <div className="report-section">
          <h3>✅ Recommendations ({recommendations.length})</h3>
          <div className="recommendations-list">
            {recommendations.map((rec, index) => (
              <div key={index} className="recommendation-item">
                <span className="rec-number">{index + 1}</span>
                <span className="rec-text">{safeText(rec)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {isRecord(report.project) && (
        <div className="report-section">
          <h3>📁 Project Information</h3>
          <div className="info-grid">
            {report.project.dockerfile && (
              <div className="info-item">
                <span className="info-label">Dockerfile:</span>
                <span className="info-value">✅ Present</span>
              </div>
            )}
            {report.project.dockerignore && (
              <div className="info-item">
                <span className="info-label">.dockerignore:</span>
                <span className="info-value">✅ Present</span>
              </div>
            )}
            {report.project.env !== undefined && (
              <div className="info-item">
                <span className="info-label">.env:</span>
                <span className="info-value">{report.project.env ? '✅ Present' : '❌ Missing'}</span>
              </div>
            )}
            {report.project.envExample !== undefined && (
              <div className="info-item">
                <span className="info-label">.env.example:</span>
                <span className="info-value">{report.project.envExample ? '✅ Present' : '❌ Missing'}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
