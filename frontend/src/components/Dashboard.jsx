import { useState } from 'react'
import FileUploader from './FileUploader'
import GithubConnector from './GithubConnector'
import LivePipeline from './LivePipeline'
import TerminalViewer from './TerminalViewer'
import ProductionReport from './ProductionReport'
import './Dashboard.css'

export default function Dashboard({ socket, sessionId, setSessionId, status, progress, logs, errorMessage, productionReport, onUploadStart, onUploadComplete, onStop }) {
  const [uploadedFile, setUploadedFile] = useState(null)
  const [deploySource, setDeploySource] = useState(() => {
    const urlParams = new URLSearchParams(window.location.search)
    if (urlParams.has('github_token') || urlParams.has('github_error') || localStorage.getItem('github_token')) {
      return 'github'
    }
    return 'upload'
  }) // 'upload' or 'github'

  const handleUploadStart = (file) => {
    setUploadedFile(file)
    return onUploadStart?.()
  }

  const handleUploadComplete = (newSessionId, report) => {
    setSessionId(newSessionId)
    onUploadComplete?.(newSessionId, report)
  }

  const handleGithubDeployStart = async () => {
    setUploadedFile({ name: 'GitHub Repository' })
    return onUploadStart?.()
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>🚀 DevOps Deployment Simulator</h1>
        <p>Simulate CI/CD pipelines with Docker</p>
      </div>

      <div className="dashboard-layout">
        <div className="left-panel">
          <div className="panel-section">
            <div className="source-selector">
              <button 
                className={`source-btn ${deploySource === 'upload' ? 'active' : ''}`}
                onClick={() => setDeploySource('upload')}
              >
                📦 Upload Zip
              </button>
              <button 
                className={`source-btn ${deploySource === 'github' ? 'active' : ''}`}
                onClick={() => setDeploySource('github')}
              >
                🐙 GitHub Repo
              </button>
            </div>

            {deploySource === 'upload' ? (
              <>
                <h2 style={{ marginTop: '10px' }}>Upload Application</h2>
                <FileUploader 
                  socket={socket}
                  onUploadStart={handleUploadStart}
                  onUploadComplete={handleUploadComplete}
                />
              </>
            ) : (
              <>
                <h2 style={{ marginTop: '10px' }}>Connect & Deploy</h2>
                <GithubConnector 
                  onDeployStart={handleGithubDeployStart}
                  onDeployComplete={handleUploadComplete}
                />
              </>
            )}

            {errorMessage && (
              <div className="error-message">
                <p>{errorMessage}</p>
              </div>
            )}
          </div>
        </div>

        {sessionId && (
          <div className="right-panel">
            <div className="panel-section">
              <h2>Pipeline Execution</h2>
              <LivePipeline
                status={status}
                progress={progress}
                sessionId={sessionId}
                onStop={onStop}
              />
            </div>
          </div>
        )}
      </div>

      {(sessionId || logs.length > 0) && (
        <div className="logs-section">
          <h2>Execution Logs</h2>
          <TerminalViewer logs={logs} />
        </div>
      )}

      {productionReport && (
        <div className="report-section">
          <ProductionReport report={productionReport} />
        </div>
      )}
    </div>
  )
}
