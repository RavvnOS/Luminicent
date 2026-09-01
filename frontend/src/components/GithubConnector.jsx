import { useState, useEffect } from 'react'
import { BACKEND_URL } from '../config'
import './GithubConnector.css'

export default function GithubConnector({ onDeployStart, onDeployComplete }) {
  const [user, setUser] = useState(null)
  const [repos, setRepos] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [authError, setAuthError] = useState('')
  const [selectedRepo, setSelectedRepo] = useState(null)
  const [branches, setBranches] = useState([])
  const [selectedBranch, setSelectedBranch] = useState('main')
  const [fetchingBranches, setFetchingBranches] = useState(false)
  const [deploying, setDeploying] = useState(false)

  const loadRepos = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/github/repos?page=1&per_page=100`, {
        credentials: 'include'
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || 'Unable to load repositories.')
      }

      const data = await res.json()
      setRepos(Array.isArray(data) ? data : [])
      return data
    } catch (error) {
      console.error('Failed to load repos:', error)
      setAuthError(error.message)
      setRepos([])
      return []
    }
  }

  const loadSession = async () => {
    setLoading(true)
    setAuthError('')

    try {
      const response = await fetch(`${BACKEND_URL}/api/github/user`, {
        credentials: 'include'
      })

      if (!response.ok) {
        if (response.status === 401) {
          setUser(null)
          setRepos([])
          setSelectedRepo(null)
          return
        }
        throw new Error('GitHub session could not be verified.')
      }

      const data = await response.json()
      setUser(data)
      await loadRepos()
    } catch (error) {
      console.error('GitHub auth check failed:', error)
      setAuthError(error.message || 'GitHub authentication failed.')
      setUser(null)
      setRepos([])
      setSelectedRepo(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const urlError = urlParams.get('github_error')
    const urlStatus = urlParams.get('github_status')

    if (urlError) {
      setAuthError(decodeURIComponent(urlError))
    }

    if (urlStatus === 'success' || urlError) {
      window.history.replaceState({}, document.title, window.location.pathname)
    }

    loadSession()
  }, [])

  const handleGithubLogin = () => {
    window.location.href = `${BACKEND_URL}/api/github/login`
  }

  const handleLogout = async () => {
    try {
      await fetch(`${BACKEND_URL}/api/github/logout`, {
        method: 'POST',
        credentials: 'include'
      })
    } catch (error) {
      console.warn('Logout request failed:', error)
    }

    setUser(null)
    setRepos([])
    setSelectedRepo(null)
    setBranches([])
    setSelectedBranch('main')
    setAuthError('')
  }

  const handleSelectRepo = async (repo) => {
    setSelectedRepo(repo)
    setFetchingBranches(true)
    setBranches([])
    setSelectedBranch(repo.default_branch || 'main')

    try {
      const res = await fetch(`${BACKEND_URL}/api/github/branches?owner=${encodeURIComponent(repo.owner.login)}&repo=${encodeURIComponent(repo.name)}`, {
        credentials: 'include'
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to fetch branch list.')
      }

      const branchData = await res.json()
      setBranches(branchData)
      const defaultBranch = repo.default_branch || (branchData.length > 0 ? branchData[0].name : 'main')
      setSelectedBranch(defaultBranch)
    } catch (error) {
      console.error('Error fetching branches:', error)
      setAuthError(error.message)
    } finally {
      setFetchingBranches(false)
    }
  }

  const handleDeploy = async () => {
    if (!selectedRepo) return

    setDeploying(true)
    const sessionId = onDeployStart()

    try {
      const response = await fetch(`${BACKEND_URL}/api/github/deploy`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          owner: selectedRepo.owner.login,
          repo: selectedRepo.name,
          branch: selectedBranch,
          sessionId
        })
      })

      const data = await response.json()
      if (response.ok) {
        onDeployComplete(data.sessionId, data.report)
      } else {
        throw new Error(data.error || 'Deployment failed.')
      }
    } catch (error) {
      console.error('Deployment request failed:', error)
      setAuthError(error.message)
    } finally {
      setDeploying(false)
    }
  }

  const filteredRepos = repos.filter((repo) => {
    const haystack = `${repo.name} ${repo.full_name} ${repo.description || ''}`.toLowerCase()
    return haystack.includes(searchQuery.toLowerCase())
  })

  if (loading) {
    return (
      <div className="github-loading">
        <div className="spinner" />
        <p>Loading GitHub details...</p>
      </div>
    )
  }

  return (
    <div className="github-connector">
      {!user ? (
        <div className="auth-container">
          <p className="auth-subtitle">Connect your GitHub account to deploy repositories directly.</p>

          <button className="github-btn" onClick={handleGithubLogin}>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true">
              <path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.867 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
            Continue with GitHub
          </button>

          {authError && (
            <div className="auth-error-banner" role="alert">
              <div className="error-text-content">
                <p className="error-title">Authentication error</p>
                <p className="error-desc">{authError}</p>
              </div>
              <button className="close-error-btn" onClick={() => setAuthError('')} aria-label="Dismiss error">×</button>
            </div>
          )}
        </div>
      ) : (
        <div className="repo-container">
          <div className="profile-header">
            <div className="user-profile">
              <img className="avatar" src={user.avatar_url} alt={`${user.login} avatar`} />
              <div className="user-profile-info">
                <h4>GitHub</h4>
                <p>@{user.login}</p>
              </div>
            </div>
            <button className="logout-btn" onClick={handleLogout}>Log out</button>
          </div>

          {authError && (
            <div className="auth-error-banner" role="alert">
              <div className="error-text-content">
                <p className="error-title">GitHub error</p>
                <p className="error-desc">{authError}</p>
              </div>
              <button className="close-error-btn" onClick={() => setAuthError('')} aria-label="Dismiss error">×</button>
            </div>
          )}

          <div className="search-bar">
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search repositories..."
            />
          </div>

          <div className="repo-actions">
            <button className="submit-btn" onClick={loadRepos} disabled={loading}>
              {loading ? 'Refreshing...' : 'Refresh repositories'}
            </button>
          </div>

          {filteredRepos.length === 0 ? (
            <div className="no-repos">No repositories found for this account.</div>
          ) : (
            <div className="repo-list">
              {filteredRepos.map((repo) => (
                <div
                  key={repo.id}
                  className={`repo-item ${selectedRepo?.id === repo.id ? 'selected' : ''}`}
                  onClick={() => handleSelectRepo(repo)}
                >
                  <div className="repo-info">
                    <div className="repo-name-row">
                      <span className="repo-name">{repo.name}</span>
                      <span className={`repo-badge ${repo.private ? 'private' : 'public'}`}>
                        {repo.private ? 'Private' : 'Public'}
                      </span>
                    </div>
                    <p className="repo-desc">{repo.full_name}</p>
                    <div className="repo-meta">
                      <span>{repo.default_branch || 'main'}</span>
                      <span>{repo.description || 'No description'}</span>
                    </div>
                  </div>
                  <button className="select-btn" type="button">Select</button>
                </div>
              ))}
            </div>
          )}

          {selectedRepo && (
            <div className="selected-repo-panel">
              <div className="selected-repo-header">
                <strong>{selectedRepo.full_name}</strong>
                <span>{selectedRepo.private ? 'Private' : 'Public'}</span>
              </div>

              <div className="form-group">
                <label htmlFor="branch-select">Branch</label>
                <select
                  id="branch-select"
                  value={selectedBranch}
                  onChange={(event) => setSelectedBranch(event.target.value)}
                >
                  {branches.length === 0 ? (
                    <option value={selectedRepo.default_branch || 'main'}>{selectedRepo.default_branch || 'main'}</option>
                  ) : (
                    branches.map((branch) => (
                      <option key={branch.name} value={branch.name}>{branch.name}</option>
                    ))
                  )}
                </select>
              </div>

              <button className="submit-btn" onClick={handleDeploy} disabled={deploying || fetchingBranches}>
                {deploying ? 'Deploying...' : `Deploy ${selectedRepo.name}`}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
