(() => {
  const state = {
    sessionId: null,
    status: 'IDLE',
    progress: 0,
    logs: [],
    report: null,
    metrics: null,
    socket: null,
    uploadRequest: null,
    deployController: null,
    stopRequested: false,
    repos: [],
    user: null,
    selectedRepo: null,
    branches: [],
    selectedBranch: 'main',
    githubLoaded: false,
    githubLoading: false,
    lastLog: null,
    lastLogAt: 0,
  };

  const byId = (id) => document.getElementById(id);
  const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);

  function showError(message, target = 'global-error') {
    const alert = byId(target);
    if (!alert) return;
    if (target === 'global-error') alert.textContent = message || '';
    else byId('github-error-message').textContent = message || '';
    alert.hidden = !message;
  }

  function appendLog(type, message) {
    const value = typeof message === 'string' ? message : message?.message || message?.data || message?.output || '';
    if (!value) return;
    const normalizedType = String(type || 'info').toLowerCase();
    const key = `${normalizedType}:${value}`;
    const now = Date.now();
    if (state.lastLog === key && now - state.lastLogAt < 500) return;
    state.lastLog = key;
    state.lastLogAt = now;
    state.logs.push({ type: normalizedType, data: value });
    if (state.logs.length > 2000) state.logs.splice(0, state.logs.length - 2000);
    renderLogs();
  }

  function renderLogs() {
    const output = byId('terminal-output');
    if (state.logs.length === 0) {
      output.innerHTML = '<div class="log-line idle">Waiting for terminal output...</div>';
    } else {
      output.innerHTML = state.logs.map((log) => `<div class="log-line ${escapeHTML(log.type)}"><span class="log-type">[${escapeHTML(log.type.toUpperCase())}]</span><span class="log-content">${escapeHTML(log.data)}</span></div>`).join('');
    }
    output.scrollTop = output.scrollHeight;
    byId('logs-section').hidden = !state.sessionId && state.logs.length === 0;
  }

  const stageForStatus = (status) => {
    if (['UPLOADING', 'DOWNLOAD', 'FETCH_REPO'].includes(status)) return 'upload';
    if (['EXTRACTING', 'EXTRACTED'].includes(status)) return 'extract';
    if (['STARTING_BUILD', 'BUILD_LOG', 'BUILD_IMAGE', 'BUILD_FAILED'].includes(status)) return 'build';
    if (['RUN_CONTAINER', 'CONTAINER_STARTING', 'CONTAINER_RUNNING', 'RUNTIME_LOG', 'RUNNING', 'STOPPING'].includes(status)) return 'run';
    if (['CLEANUP', 'FINISHED'].includes(status)) return 'finish';
    return status === 'ERROR' || status === 'CONTAINER_FAILED' ? 'error' : 'upload';
  };

  const detailForStatus = (status) => ({
    UPLOADING: 'Preparing upload and assigning a session.',
    DOWNLOAD: 'Downloading the selected GitHub repository.',
    EXTRACTING: 'Extracting the package and validating its Dockerfile.',
    EXTRACTED: 'Package extracted successfully.',
    STARTING_BUILD: 'Building the Docker image from your application.',
    BUILD_LOG: 'Docker image build is in progress.',
    BUILD_IMAGE: 'Docker image build completed.',
    BUILD_FAILED: 'Image build failed. Check the logs for details.',
    RUN_CONTAINER: 'Launching the container and starting its runtime.',
    CONTAINER_RUNNING: 'Container is running successfully.',
    RUNTIME_LOG: 'Streaming runtime logs from the container.',
    RUNNING: 'Container is running and logs are streaming.',
    STOPPING: 'Stopping the active simulation session.',
    CLEANUP: 'Stopping and removing the container.',
    FINISHED: 'Simulation finished successfully.',
    ERROR: 'An error occurred during the deployment pipeline.',
    CLEANUP_ERROR: 'The deployment could not be cleaned up.',
  })[status] || 'Waiting for pipeline activity.';

  function updatePipeline(status, percent) {
    state.status = status || state.status;
    if (Number.isFinite(Number(percent))) state.progress = Math.max(0, Math.min(100, Number(percent)));
    byId('pipeline-panel').hidden = !state.sessionId;
    byId('session-id').textContent = state.sessionId || '';
    const statusBadge = byId('deployment-status');
    statusBadge.textContent = state.status;
    statusBadge.className = `status-badge ${state.status.toLowerCase()}`;
    byId('status-detail').textContent = detailForStatus(state.status);
    byId('deployment-progress').value = state.progress;
    byId('deployment-progress-value').textContent = `${state.progress}%`;

    const currentStage = stageForStatus(state.status);
    const order = ['upload', 'extract', 'build', 'run', 'finish'];
    document.querySelectorAll('.pipeline-stage').forEach((stage) => {
      const stageId = stage.dataset.stage;
      const stageIndex = order.indexOf(stageId);
      const currentIndex = order.indexOf(currentStage);
      stage.classList.toggle('active', stageId === currentStage);
      stage.classList.toggle('complete', currentIndex >= 0 && stageIndex < currentIndex);
      stage.classList.toggle('failed', currentStage === 'error' && stageId === (state.status === 'BUILD_FAILED' ? 'build' : 'run'));
      const loader = stage.querySelector('.stage-loader');
      if (stageId === currentStage && !loader && !['FINISHED', 'ERROR', 'BUILD_FAILED', 'CLEANUP_ERROR'].includes(state.status)) {
        const indicator = document.createElement('span');
        indicator.className = 'stage-loader';
        indicator.setAttribute('aria-hidden', 'true');
        stage.append(indicator);
      } else if ((stageId !== currentStage || ['FINISHED', 'ERROR', 'BUILD_FAILED', 'CLEANUP_ERROR'].includes(state.status)) && loader) {
        loader.remove();
      }
    });
    document.querySelectorAll('.pipeline-connector').forEach((connector, index) => {
      const currentIndex = order.indexOf(currentStage);
      connector.classList.toggle('complete', currentIndex > index);
    });

    const terminal = ['FINISHED', 'ERROR', 'BUILD_FAILED', 'CONTAINER_FAILED', 'CLEANUP_ERROR'].includes(state.status);
    byId('stop-deployment').hidden = !state.sessionId || terminal;
    byId('stop-deployment').disabled = state.status === 'STOPPING';
  }

  function beginSession() {
    const sessionId = Date.now().toString();
    state.sessionId = sessionId;
    state.logs = [];
    state.report = null;
    state.metrics = null;
    state.stopRequested = false;
    byId('report-section').hidden = true;
    byId('runtime-metrics').hidden = true;
    showError('');
    renderLogs();
    updatePipeline('UPLOADING', 0);
    if (state.socket?.connected) state.socket.emit('joinSession', { sessionId });
    return sessionId;
  }

  function completeSession(sessionId, report) {
    state.sessionId = sessionId || state.sessionId;
    if (state.socket?.connected && state.sessionId) state.socket.emit('joinSession', { sessionId: state.sessionId });
    if (report) {
      renderReport(report);
      if (['IDLE', 'UPLOADING', 'EXTRACTING', 'EXTRACTED'].includes(state.status)) {
        updatePipeline('RUNNING', Math.max(state.progress, 80));
      }
    } else if (state.status === 'UPLOADING') {
      updatePipeline('EXTRACTING', state.progress);
    }
  }

  function formatBytes(value) {
    const number = Number(value) || 0;
    if (number < 1024) return `${number} B`;
    if (number < 1024 * 1024) return `${(number / 1024).toFixed(1)} KB`;
    return `${(number / (1024 * 1024)).toFixed(1)} MB`;
  }

  function renderMetrics(metrics) {
    if (!metrics || typeof metrics !== 'object') return;
    state.metrics = metrics;
    byId('runtime-metrics').hidden = false;
    byId('metric-cpu').textContent = `${Number(metrics.cpuUsage || 0).toFixed(2)}%`;
    const memory = Number(metrics.memoryUsage || 0);
    const limit = Number(metrics.memoryLimit || 0);
    const percentage = Number(metrics.memoryPercent || 0);
    byId('metric-memory').textContent = `${formatBytes(memory)}${limit ? ` / ${formatBytes(limit)} (${percentage.toFixed(1)}%)` : ''}`;
    byId('metric-rx').textContent = formatBytes(metrics.networkRx);
    byId('metric-tx').textContent = formatBytes(metrics.networkTx);
  }

  function connectSocket() {
    if (typeof window.io !== 'function') {
      showError('Realtime client could not load. Deployment status and logs may be unavailable.');
      return;
    }
    const socket = window.io({
      path: '/socket.io',
      transports: ['polling', 'websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 10000,
    });
    state.socket = socket;
    socket.on('connect', () => {
      showError('');
      if (state.sessionId) socket.emit('joinSession', { sessionId: state.sessionId });
    });
    socket.on('connect_error', () => showError('Unable to connect to backend realtime updates. Live logs may be unavailable.'));
    socket.on('disconnect', (reason) => {
      if (reason !== 'io client disconnect') showError('Realtime connection to the backend was interrupted.');
    });
    socket.on('status', (data = {}) => {
      if (state.sessionId && data.sessionId && data.sessionId !== state.sessionId) return;
      if (!state.sessionId && data.sessionId) return;
      updatePipeline(data.status || 'IDLE', data.percent);
      if (data.message) appendLog(data.type || 'status', data.message);
      if (['ERROR', 'BUILD_FAILED', 'CONTAINER_FAILED', 'CLEANUP_ERROR'].includes(data.status)) {
        showError(data.error || data.message || 'An error occurred during deployment.');
      }
    });
    socket.on('terminal_output', (data = {}) => {
      if (data.sessionId && state.sessionId && data.sessionId !== state.sessionId) return;
      appendLog(data.type || 'runtime', data.message || data.data);
    });
    socket.on('build_log', (data = {}) => {
      if (data.sessionId && state.sessionId && data.sessionId !== state.sessionId) return;
      appendLog('build', data.data);
    });
    socket.on('runtime_log', (data = {}) => {
      if (data.sessionId && state.sessionId && data.sessionId !== state.sessionId) return;
      appendLog('runtime', data.data);
    });
    socket.on('docker_stats', (data = {}) => {
      if (data.sessionId && state.sessionId && data.sessionId !== state.sessionId) return;
      renderMetrics(data.metrics);
    });
    socket.on('CONTAINER_METRICS', (data = {}) => {
      if (data.sessionId && state.sessionId && data.sessionId !== state.sessionId) return;
      renderMetrics(data.metrics);
    });
    socket.on('production-report', (data = {}) => {
      const incomingSessionId = data.sessionId || state.sessionId;
      if (state.sessionId && incomingSessionId && incomingSessionId !== state.sessionId) return;
      const report = data.report || data;
      if (report && typeof report === 'object') {
        renderReport(report);
        if (['IDLE', 'UPLOADING', 'EXTRACTING', 'EXTRACTED'].includes(state.status)) {
          updatePipeline('RUNNING', Math.max(state.progress, 80));
        }
      }
    });
  }

  function setSource(source) {
    const github = source === 'github';
    byId('upload-panel').hidden = github;
    byId('github-panel').hidden = !github;
    document.querySelectorAll('.source-btn').forEach((button) => {
      const active = button.dataset.source === source;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', String(active));
      button.tabIndex = active ? 0 : -1;
    });
    if (github && !state.githubLoaded) loadGitHubSession();
  }

  async function requestJSON(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { credentials: 'same-origin', ...options });
    } catch (_error) {
      throw new Error('Backend unavailable. Check that the backend service is running.');
    }
    const bodyText = await response.text();
    let data = {};
    if (bodyText) {
      try { data = JSON.parse(bodyText); } catch (_error) { data = {}; }
    }
    if (!response.ok) {
      const error = new Error(data.error || `Request failed with status ${response.status}.`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function setGithubLoading(loading) {
    state.githubLoading = loading;
    byId('github-loading').hidden = !loading;
    byId('github-auth').hidden = loading || Boolean(state.user);
    byId('github-repositories').hidden = loading || !state.user;
  }

  async function loadGitHubSession() {
    state.githubLoaded = true;
    setGithubLoading(true);
    showError('', 'github-error');
    try {
      const user = await requestJSON('/api/github/user');
      state.user = user;
      byId('github-avatar').src = safeAvatarURL(user.avatar_url);
      byId('github-avatar').alt = `${user.login || 'GitHub user'} avatar`;
      byId('github-login-name').textContent = `@${user.login || ''}`;
      setGithubLoading(false);
      await loadRepositories();
    } catch (error) {
      state.user = null;
      setGithubLoading(false);
      if (error.status !== 401) showError(error.message, 'github-error');
    }
  }

  function safeAvatarURL(value) {
    try {
      const url = new URL(value);
      return url.protocol === 'https:' && url.hostname === 'avatars.githubusercontent.com' ? url.href : '';
    } catch (_error) {
      return '';
    }
  }

  async function loadRepositories() {
    if (!state.user) return;
    const refresh = byId('repo-refresh');
    refresh.disabled = true;
    refresh.textContent = 'Loading repositories...';
    try {
      const repos = await requestJSON('/api/github/repos?page=1&per_page=100');
      state.repos = Array.isArray(repos) ? repos : [];
      renderRepositories();
      showError('', 'github-error');
    } catch (error) {
      if (error.status === 401) {
        state.user = null;
        state.repos = [];
        setGithubLoading(false);
      }
      showError(error.message, 'github-error');
    } finally {
      refresh.disabled = false;
      refresh.textContent = 'Refresh repositories';
    }
  }

  function renderRepositories() {
    const query = byId('repo-search').value.trim().toLowerCase();
    const matches = state.repos.map((repo, index) => ({ repo, index })).filter(({ repo }) => {
      const haystack = `${repo.name || ''} ${repo.full_name || ''} ${repo.description || ''}`.toLowerCase();
      return haystack.includes(query);
    });
    byId('repo-list').innerHTML = matches.map(({ repo, index }) => `
      <article class="repo-item ${state.selectedRepo?.id === repo.id ? 'selected' : ''}">
        <div class="repo-info">
          <div class="repo-name-row"><span class="repo-name">${escapeHTML(repo.name)}</span><span class="repo-badge ${repo.private ? 'private' : 'public'}">${repo.private ? 'Private' : 'Public'}</span></div>
          <p class="repo-full-name">${escapeHTML(repo.full_name)}</p>
          <div class="repo-meta"><span>${escapeHTML(repo.default_branch || 'main')}</span><span>${escapeHTML(repo.description || 'No description')}</span></div>
        </div>
        <button class="select-btn" type="button" data-repo-index="${index}" aria-label="Select ${escapeHTML(repo.full_name || repo.name)}">Select</button>
      </article>`).join('');
    byId('repo-empty').hidden = matches.length !== 0;
  }

  async function selectRepository(index) {
    const repo = state.repos[index];
    if (!repo) return;
    state.selectedRepo = repo;
    state.branches = [];
    state.selectedBranch = repo.default_branch || 'main';
    byId('selected-repo-name').textContent = repo.full_name || repo.name;
    byId('selected-repo-visibility').textContent = repo.private ? 'Private' : 'Public';
    byId('selected-repo-panel').hidden = false;
    byId('branch-loading').hidden = false;
    byId('deploy-repo').disabled = true;
    renderRepositories();
    renderBranchOptions();
    showError('', 'github-error');
    try {
      const params = new URLSearchParams({ owner: repo.owner?.login || '', repo: repo.name || '' });
      const branches = await requestJSON(`/api/github/branches?${params.toString()}`);
      state.branches = Array.isArray(branches) ? branches : [];
      const defaultBranch = state.branches.find((branch) => branch.default)?.name || repo.default_branch || state.branches[0]?.name || 'main';
      state.selectedBranch = defaultBranch;
      renderBranchOptions();
    } catch (error) {
      showError(error.message, 'github-error');
    } finally {
      byId('branch-loading').hidden = true;
      byId('deploy-repo').disabled = !state.selectedRepo || !state.selectedBranch;
    }
  }

  function renderBranchOptions() {
    const select = byId('branch-select');
    const options = state.branches.length ? state.branches : [{ name: state.selectedBranch || 'main' }];
    select.innerHTML = options.map((branch) => `<option value="${escapeHTML(branch.name)}">${escapeHTML(branch.name)}</option>`).join('');
    select.value = state.selectedBranch;
  }

  async function deployRepository() {
    if (!state.selectedRepo || !state.selectedBranch) return;
    showError('', 'github-error');
    const sessionId = beginSession();
    const controller = new AbortController();
    state.deployController = controller;
    const button = byId('deploy-repo');
    button.disabled = true;
    button.textContent = 'Deploying...';
    try {
      const data = await requestJSON('/api/github/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner: state.selectedRepo.owner?.login,
          repo: state.selectedRepo.name,
          branch: state.selectedBranch,
          sessionId,
        }),
        signal: controller.signal,
      });
      completeSession(data.sessionId, data.report);
    } catch (error) {
      if (!state.stopRequested && error.name !== 'AbortError') {
        updatePipeline('ERROR', state.progress);
        showError(error.message, 'github-error');
      }
    } finally {
      state.deployController = null;
      button.disabled = false;
      button.textContent = state.selectedRepo ? `Deploy ${state.selectedRepo.name}` : 'Deploy repository';
    }
  }

  function renderReport(report) {
    state.report = report;
    const issues = Array.isArray(report.issues) ? report.issues : [];
    const recommendations = Array.isArray(report.recommendations) ? report.recommendations : [];
    const score = Number(report.score) || 0;
    const scoreColor = score >= 80 ? '#4caf50' : score >= 60 ? '#ffc107' : score >= 40 ? '#ff9800' : '#ff4444';
    const counts = ['Critical', 'High', 'Medium', 'Low'].map((severity) => ({
      severity,
      count: issues.filter((issue) => String(issue.severity).toLowerCase() === severity.toLowerCase()).length,
    }));
    const information = (values) => `<div class="info-grid">${values.filter(([, value]) => value !== undefined && value !== null && value !== '').map(([label, value]) => `<div class="info-item"><span class="info-label">${escapeHTML(label)}</span><span class="info-value">${escapeHTML(value)}</span></div>`).join('')}</div>`;
    const docker = report.docker && typeof report.docker === 'object' ? report.docker : {};
    const runtime = report.runtime && typeof report.runtime === 'object' ? report.runtime : {};
    const project = report.project && typeof report.project === 'object' ? report.project : {};
    const issueCards = issues.map((issue) => {
      const severity = String(issue.severity || 'Other').toLowerCase();
      return `<article class="issue-item ${escapeHTML(severity)}"><div class="issue-header"><span class="issue-severity ${escapeHTML(severity)}">${escapeHTML(issue.severity || 'Other')}</span><h4 class="issue-title">${escapeHTML(issue.title)}</h4></div><p class="issue-description">${escapeHTML(issue.description)}</p>${issue.recommendation ? `<p class="issue-recommendation"><strong>Fix:</strong> ${escapeHTML(issue.recommendation)}</p>` : ''}</article>`;
    }).join('');
    const recCards = recommendations.map((rec, index) => `<div class="recommendation-item"><span class="rec-number">${index + 1}</span><span class="rec-text">${escapeHTML(rec)}</span></div>`).join('');
    const reportStatus = String(report.status || 'UNKNOWN');
    byId('report-section').innerHTML = `<div class="production-report">
      <h2>📊 Production Readiness Report</h2>
      <div class="report-header"><div class="score-circle" style="border-color:${scoreColor};color:${scoreColor}"><span class="score-value">${escapeHTML(report.score ?? 0)}</span><span class="score-label">Score</span></div><div class="status-info"><span class="report-status ${reportStatus === 'PASS' ? 'pass' : 'fail'}">${escapeHTML(reportStatus)}</span><p class="total-issues">${issues.length} issue${issues.length === 1 ? '' : 's'} found</p><div class="severity-counts">${counts.map((item) => `<span class="severity-count">${item.severity}: ${item.count}</span>`).join('')}</div></div></div>
      ${Object.keys(docker).length ? `<section class="report-card"><h3>🐳 Docker Information</h3>${information([['Image ID', docker.imageId ? `${String(docker.imageId).substring(0, 20)}...` : ''], ['Image Size', docker.sizeMB ? `${docker.sizeMB} MB` : ''], ['Created', docker.created ? new Date(docker.created).toLocaleDateString() : '']])}</section>` : ''}
      ${Object.keys(runtime).length ? `<section class="report-card"><h3>⚙️ Runtime Information</h3>${information([['Status', runtime.status], ['Running', runtime.running === undefined ? '' : runtime.running ? 'Yes' : 'No']])}</section>` : ''}
      ${issues.length ? `<section class="report-card"><h3>⚠️ Issues Found (${issues.length})</h3><div class="issues-list">${issueCards}</div></section>` : ''}
      ${recommendations.length ? `<section class="report-card"><h3>✅ Recommendations (${recommendations.length})</h3><div class="recommendations-list">${recCards}</div></section>` : ''}
      ${Object.keys(project).length ? `<section class="report-card"><h3>📁 Project Information</h3>${information([['Dockerfile', project.dockerfile === undefined ? '' : project.dockerfile ? 'Present' : 'Missing'], ['.dockerignore', project.dockerignore === undefined ? '' : project.dockerignore ? 'Present' : 'Missing'], ['.env', project.env === undefined ? '' : project.env ? 'Present' : 'Missing'], ['.env.example', project.envExample === undefined ? '' : project.envExample ? 'Present' : 'Missing']])}</section>` : ''}
    </div>`;
    byId('report-section').hidden = false;
  }

  function uploadFile(file) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      showError('Please select a .zip file.');
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      showError('The ZIP file exceeds the 100 MB upload limit.');
      return;
    }
    showError('');
    const sessionId = beginSession();
    const form = new FormData();
    form.append('file', file);
    form.append('sessionId', sessionId);
    const xhr = new XMLHttpRequest();
    state.uploadRequest = xhr;
    byId('upload-progress').hidden = false;
    byId('upload-file-name').textContent = `Uploading ${file.name}`;
    byId('upload-progress-bar').value = 0;
    byId('upload-progress-value').textContent = '0%';
    xhr.open('POST', '/api/upload');
    xhr.withCredentials = true;
    xhr.upload.addEventListener('progress', (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.round((event.loaded / event.total) * 100);
      byId('upload-progress-bar').value = percent;
      byId('upload-progress-value').textContent = `${percent}%`;
    });
    xhr.addEventListener('load', () => {
      state.uploadRequest = null;
      byId('upload-progress').hidden = true;
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch (_error) { data = {}; }
      if (xhr.status < 200 || xhr.status >= 300) {
        updatePipeline('ERROR', state.progress);
        showError(data.error || `Upload failed with status ${xhr.status}.`);
        return;
      }
      completeSession(data.sessionId, data.report);
    });
    xhr.addEventListener('error', () => {
      state.uploadRequest = null;
      byId('upload-progress').hidden = true;
      updatePipeline('ERROR', state.progress);
      if (!state.stopRequested) showError('Upload failed because the backend could not be reached.');
    });
    xhr.addEventListener('abort', () => {
      state.uploadRequest = null;
      byId('upload-progress').hidden = true;
    });
    xhr.send(form);
  }

  async function stopDeployment() {
    if (!state.sessionId || state.status === 'STOPPING') return;
    state.stopRequested = true;
    updatePipeline('STOPPING', state.progress);
    state.uploadRequest?.abort();
    state.deployController?.abort();
    try {
      await requestJSON('/api/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: state.sessionId }),
      });
      updatePipeline('FINISHED', state.progress);
    } catch (error) {
      updatePipeline('ERROR', state.progress);
      showError(error.message);
    }
  }

  function initialize() {
    document.querySelectorAll('.source-btn').forEach((button) => button.addEventListener('click', () => setSource(button.dataset.source)));
    byId('zip-file').addEventListener('change', (event) => {
      const file = event.target.files?.[0];
      if (file) uploadFile(file);
      event.target.value = '';
    });
    const dropZone = byId('drop-zone');
    dropZone.addEventListener('dragover', (event) => { event.preventDefault(); dropZone.classList.add('dragging'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
    dropZone.addEventListener('drop', (event) => {
      event.preventDefault();
      dropZone.classList.remove('dragging');
      uploadFile(event.dataTransfer.files?.[0]);
    });
    byId('repo-search').addEventListener('input', renderRepositories);
    byId('repo-refresh').addEventListener('click', loadRepositories);
    byId('repo-list').addEventListener('click', (event) => {
      const button = event.target.closest('[data-repo-index]');
      if (button) selectRepository(Number(button.dataset.repoIndex));
    });
    byId('branch-select').addEventListener('change', (event) => { state.selectedBranch = event.target.value; });
    byId('deploy-repo').addEventListener('click', deployRepository);
    byId('github-logout').addEventListener('click', async () => {
      try { await requestJSON('/api/github/logout', { method: 'POST' }); } catch (_error) { showError('Logout request failed.', 'github-error'); }
      state.user = null;
      state.repos = [];
      state.selectedRepo = null;
      state.branches = [];
      state.githubLoaded = true;
      byId('selected-repo-panel').hidden = true;
      setGithubLoading(false);
    });
    byId('github-error-close').addEventListener('click', () => showError('', 'github-error'));
    byId('stop-deployment').addEventListener('click', stopDeployment);

    const params = new URLSearchParams(window.location.search);
    const githubMessage = params.get('github_error');
    const source = params.has('github_status') || githubMessage ? 'github' : 'upload';
    setSource(source);
    if (githubMessage) showError(githubMessage, 'github-error');
    if (params.has('github_status') || githubMessage) window.history.replaceState({}, document.title, window.location.pathname);
    connectSocket();
  }

  document.addEventListener('DOMContentLoaded', initialize, { once: true });
})();