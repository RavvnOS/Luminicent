import express from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import AdmZip from 'adm-zip';
import axios from 'axios';
import {
  normalizeRepoRoot,
  ensureDockerfile,
  findBuildContext,
  validateGithubRepo
} from '../utils/dockerfileHelper.js';
import { analyzeProduction } from '../utils/productionAnalyzer.js';

const router = express.Router();
const oauthStateStore = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;

const getCookieValue = (req, name) => {
  const cookieHeader = req.headers.cookie || '';
  const cookie = cookieHeader
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : null;
};

const clearCookie = (res, name, options = {}) => {
  if (!res || typeof res.clearCookie !== 'function') return;
  res.clearCookie(name, {
    httpOnly: true,
    sameSite: process.env.SESSION_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'none' : 'lax'),
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    ...options
  });
};

const setGithubStateCookie = (res, value) => {
  res.cookie('luminicent_github_state', value, {
    httpOnly: true,
    sameSite: process.env.SESSION_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'none' : 'lax'),
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  });
};

const getGithubConfig = (req) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;

  const host = req ? (req.get('x-forwarded-host') || req.get('host')) : null;
  const protocol = req ? (req.get('x-forwarded-proto') || req.protocol || 'http') : 'http';
  const basePath = req && req.baseUrl ? req.baseUrl : '/api/github';

  const callbackUrl = process.env.GITHUB_CALLBACK_URL || process.env.GITHUB_REDIRECT_URI || (host ? `${protocol}://${host}${basePath}/callback` : 'http://localhost:5000/api/github/callback');
  const defaultFrontend = host ? `${protocol}://${host.replace(/:5000$/, ':5173')}` : 'http://localhost:5173';
  const frontendUrl = process.env.FRONTEND_URL || defaultFrontend;

  return { clientId, clientSecret, callbackUrl, frontendUrl };
};

const getGithubAuthHeaders = (token) => ({
  Authorization: `Bearer ${token}`,
  Accept: 'application/vnd.github+json',
  'User-Agent': 'Luminicent',
  'X-GitHub-Api-Version': '2022-11-28'
});

const getGithubSession = (req) => {
  if (!req || !req.session || !req.session.githubAuth || !req.session.githubAuth.accessToken) {
    return null;
  }
  return req.session.githubAuth;
};

const destroyGithubSession = (req, res) => {
  if (req && req.session) {
    delete req.session.githubAuth;
    req.session.save(() => {});
    req.session.destroy(() => {});
  }
  if (res && typeof res.clearCookie === 'function') {
    clearCookie(res, process.env.SESSION_COOKIE_NAME || 'luminicent_session');
    clearCookie(res, 'luminicent_github_session');
    clearCookie(res, 'luminicent_github_state');
  }
};

const pruneStateStore = () => {
  const now = Date.now();
  for (const [state, timestamp] of oauthStateStore.entries()) {
    if (now - timestamp > STATE_TTL_MS) {
      oauthStateStore.delete(state);
    }
  }
};

function getGithubJson(url, token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Luminicent',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };
    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => {
        responseBody += chunk;
      });
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(responseBody));
          } else {
            let errorMsg = `GitHub API error: ${res.statusCode}`;
            try {
              const errObj = JSON.parse(responseBody);
              errorMsg = errObj.message || errorMsg;
            } catch (error) {
              // Ignore parse errors and fall back to the HTTP status message.
            }
            reject(new Error(errorMsg));
          }
        } catch (error) {
          reject(new Error(`Failed to parse GitHub response: ${responseBody.substring(0, 200)}`));
        }
      });
    });

    req.on('error', (error) => reject(error));
    req.end();
  });
}

function downloadZipball(url, destPath, token) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Luminicent',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };
    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request(options, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
        const nextUrl = res.headers.location;
        if (!nextUrl) {
          reject(new Error('GitHub redirect was missing a Location header.'));
          return;
        }
        downloadZipball(nextUrl, destPath, token)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        let responseBody = '';
        res.on('data', (chunk) => {
          responseBody += chunk;
        });
        res.on('end', () => {
          let errorMsg = `GitHub download error: ${res.statusCode}`;
          try {
            const errObj = JSON.parse(responseBody);
            errorMsg = errObj.message || errorMsg;
          } catch (error) {
            // Ignore parse errors and fall back to the HTTP status message.
          }
          reject(new Error(errorMsg));
        });
        return;
      }

      const fileStream = fs.createWriteStream(destPath);
      res.pipe(fileStream);

      fileStream.on('finish', () => {
        fileStream.close();
        resolve(destPath);
      });

      fileStream.on('error', (error) => {
        fs.unlink(destPath, () => {});
        reject(error);
      });
    });

    req.on('error', (error) => {
      fs.unlink(destPath, () => {});
      reject(error);
    });

    req.end();
  });
}

const cleanupPath = (targetPath) => {
  if (!targetPath) return;
  try {
    if (fs.existsSync(targetPath)) {
      fs.rmSync(targetPath, { recursive: true, force: true });
    }
  } catch (cleanupError) {
    console.error(`Cleanup error for ${targetPath}:`, cleanupError);
  }
};

const handleGithubApiError = (error, fallbackMessage) => {
  const status = error?.response?.status;
  const message = error?.response?.data?.message || fallbackMessage;

  if (status === 401 || status === 403) {
    return new Error('GitHub session expired or is no longer authorized. Please log in again.');
  }

  if (status === 429) {
    return new Error('GitHub API rate limit reached. Please try again shortly.');
  }

  if (message && typeof message === 'string') {
    return new Error(message);
  }

  return new Error(fallbackMessage);
};

router.get('/login', (req, res) => {
  const { clientId, callbackUrl, frontendUrl } = getGithubConfig(req);

  if (!clientId || clientId === 'your_github_client_id_here') {
    const errorMessage = encodeURIComponent('GitHub OAuth is not configured on this server. Add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to the backend environment.');
    return res.redirect(`${frontendUrl}/?github_error=${errorMessage}`);
  }

  pruneStateStore();
  const state = crypto.randomBytes(18).toString('hex');
  oauthStateStore.set(state, Date.now());
  setGithubStateCookie(res, state);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callbackUrl,
    scope: 'repo read:user',
    state,
    allow_signup: 'true'
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

router.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const { clientId, clientSecret, callbackUrl, frontendUrl } = getGithubConfig(req);
  const cookieState = getCookieValue(req, 'luminicent_github_state');

  destroyGithubSession(req, res);

  if (!clientId || clientId === 'your_github_client_id_here' || !clientSecret) {
    const errorMessage = encodeURIComponent('GitHub OAuth credentials are missing or invalid on the server.');
    return res.redirect(`${frontendUrl}/?github_error=${errorMessage}`);
  }

  if (!code) {
    return res.redirect(`${frontendUrl}/?github_error=${encodeURIComponent('GitHub authorization code is required.')}`);
  }

  pruneStateStore();
  if (!state || !cookieState || state !== cookieState || !oauthStateStore.has(String(state))) {
    return res.redirect(`${frontendUrl}/?github_error=${encodeURIComponent('GitHub login failed: state validation mismatch.')}`);
  }

  oauthStateStore.delete(String(state));

  try {
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: callbackUrl
    }, {
      headers: {
        Accept: 'application/json',
        'User-Agent': 'Luminicent'
      }
    });

    if (tokenResponse.data.error) {
      throw new Error(tokenResponse.data.error_description || tokenResponse.data.error);
    }

    const accessToken = tokenResponse.data.access_token;
    if (!accessToken) {
      throw new Error('GitHub did not return an access token.');
    }

    const userResponse = await axios.get('https://api.github.com/user', {
      headers: getGithubAuthHeaders(accessToken)
    });

    req.session.githubAuth = {
      accessToken,
      login: userResponse.data.login,
      avatarUrl: userResponse.data.avatar_url,
      name: userResponse.data.name,
      id: userResponse.data.id,
      scopes: tokenResponse.data.scope || 'repo read:user'
    };

    await new Promise((resolve, reject) => {
      req.session.save((error) => {
        if (error) reject(error);
        else resolve();
      });
    });

    return res.redirect(`${frontendUrl}/?github_status=success`);
  } catch (error) {
    console.error('GitHub OAuth callback error:', error.response?.data || error.message);
    const message = error.response?.data?.error_description || error.response?.data?.message || error.message || 'Unable to complete GitHub login.';
    return res.redirect(`${frontendUrl}/?github_error=${encodeURIComponent(message)}`);
  }
});

router.post('/logout', (req, res) => {
  destroyGithubSession(req, res);
  return res.json({ success: true, message: 'GitHub session cleared.' });
});

router.get('/logout', (req, res) => {
  return router.handle({ ...req, method: 'POST' }, res);
});

router.get('/user', async (req, res) => {
  const session = getGithubSession(req);

  if (!session) {
    return res.status(401).json({ error: 'Not authenticated with GitHub.' });
  }

  try {
    const response = await axios.get('https://api.github.com/user', {
      headers: getGithubAuthHeaders(session.accessToken)
    });

    return res.json({
      id: response.data.id,
      login: response.data.login,
      name: response.data.name,
      avatar_url: response.data.avatar_url,
      html_url: response.data.html_url,
      type: response.data.type
    });
  } catch (error) {
    destroyGithubSession(req, res);
    return res.status(401).json({ error: 'GitHub session expired or was revoked.' });
  }
});

router.get('/repos', async (req, res) => {
  const session = getGithubSession(req);

  if (!session) {
    return res.status(401).json({ error: 'Not authenticated with GitHub.' });
  }

  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const perPage = Math.min(100, Math.max(1, Number(req.query.per_page || 30)));

    const response = await axios.get(`https://api.github.com/user/repos?per_page=${perPage}&page=${page}&sort=updated`, {
      headers: getGithubAuthHeaders(session.accessToken)
    });

    const repos = response.data.map((repo) => ({
      id: repo.id,
      name: repo.name,
      full_name: repo.full_name,
      private: repo.private,
      default_branch: repo.default_branch,
      html_url: repo.html_url,
      description: repo.description,
      owner: {
        login: repo.owner?.login || null
      }
    }));

    return res.json(repos);
  } catch (error) {
    const message = handleGithubApiError(error, 'Unable to load GitHub repositories.');
    if (error?.response?.status === 401) {
      destroyGithubSession(req, res);
    }
    return res.status(error?.response?.status === 401 ? 401 : 500).json({ error: message.message });
  }
});

router.get('/branches', async (req, res) => {
  const session = getGithubSession(req);
  const { owner, repo } = req.query;

  if (!owner || !repo) {
    return res.status(400).json({ error: 'owner and repo query parameters are required.' });
  }

  if (!session) {
    return res.status(401).json({ error: 'Not authenticated with GitHub.' });
  }

  try {
    const repoMeta = await axios.get(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: getGithubAuthHeaders(session.accessToken)
    });

    if (!repoMeta.data?.default_branch) {
      return res.status(404).json({ error: 'Repository metadata is unavailable.' });
    }

    const branchesResponse = await axios.get(`https://api.github.com/repos/${owner}/${repo}/branches`, {
      headers: getGithubAuthHeaders(session.accessToken)
    });

    return res.json(branchesResponse.data.map((branch) => ({
      name: branch.name,
      protected: branch.protected,
      default: branch.name === repoMeta.data.default_branch
    })));
  } catch (error) {
    const message = handleGithubApiError(error, 'Unable to load repository branches.');
    if (error?.response?.status === 401) {
      destroyGithubSession(req, res);
    }
    return res.status(error?.response?.status === 401 ? 401 : 500).json({ error: message.message });
  }
});

router.post('/deploy', async (req, res) => {
  const session = getGithubSession(req);
  const { owner, repo, branch, sessionId: providedSessionId } = req.body;

  if (!session) {
    return res.status(401).json({ error: 'Not authenticated with GitHub.' });
  }

  if (!owner || !repo || !branch) {
    return res.status(400).json({ error: 'owner, repo, and branch are required.' });
  }

  let cleanOwner, cleanRepo;
  try {
    ({ owner: cleanOwner, repo: cleanRepo } = validateGithubRepo(owner, repo));
  } catch (validationError) {
    return res.status(400).json({ error: validationError.message });
  }

  const sessionId = providedSessionId || Date.now().toString();
  const zipPath = path.join('uploads', `${sessionId}.zip`);
  const extractPath = path.join('uploads', sessionId);
  const dockerOrchestrator = req.orchestrator;

  dockerOrchestrator.createSession(sessionId, {
    owner: cleanOwner,
    repo: cleanRepo,
    branch,
    status: 'FETCH_REPO'
  });

  try {
    const repoMeta = await axios.get(`https://api.github.com/repos/${cleanOwner}/${cleanRepo}`, {
      headers: getGithubAuthHeaders(session.accessToken)
    });

    if (!repoMeta.data || repoMeta.data.private === true && repoMeta.data.permissions?.pull !== true) {
      throw new Error('This repository is not accessible with the current GitHub authorization.');
    }

    fs.mkdirSync(path.dirname(zipPath), { recursive: true });

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'DOWNLOAD',
      stage: 'upload',
      type: 'info',
      percent: 5,
      message: `Downloading repository archive ${cleanOwner}/${cleanRepo} (branch: ${branch})...`
    });

    const zipballUrl = `https://api.github.com/repos/${cleanOwner}/${cleanRepo}/zipball/${encodeURIComponent(branch)}`;
    await downloadZipball(zipballUrl, zipPath, session.accessToken);

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'EXTRACTING',
      stage: 'extract',
      type: 'info',
      percent: 15,
      message: 'Extracting repository package...'
    });

    fs.mkdirSync(extractPath, { recursive: true });
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractPath, true);

    const repoRoot = normalizeRepoRoot(extractPath);
    const buildContext = findBuildContext(repoRoot);
    const dockerfilePath = ensureDockerfile(buildContext);

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'EXTRACTED',
      stage: 'extract',
      type: 'success',
      percent: 25,
      message: `Repository extracted. Using Dockerfile at ${path.relative(buildContext, dockerfilePath)}`
    });

    const imageName = `devops-sim-${sessionId}`;
    await dockerOrchestrator.buildImage(buildContext, imageName, sessionId, dockerfilePath);
    const container = await dockerOrchestrator.runContainer(imageName, sessionId);
    const report = await analyzeProduction(buildContext, imageName, container);

    dockerOrchestrator.emit(sessionId, 'production-report', {
      sessionId,
      report
    });

    dockerOrchestrator.streamLogs(container, sessionId);

    dockerOrchestrator.emitStatus(sessionId, {
      status: 'RUNNING',
      stage: 'container',
      type: 'success',
      percent: 85,
      message: 'Container is running and logs are streaming.'
    });

    res.json({
      success: true,
      sessionId,
      report,
      message: 'Simulation started'
    });

    setTimeout(async () => {
      await dockerOrchestrator.cleanup(sessionId);
      cleanupPath(extractPath);
    }, 120000);
  } catch (error) {
    console.error('GitHub deployment error:', error);
    dockerOrchestrator.emitStatus(sessionId, {
      status: 'ERROR',
      stage: 'error',
      type: 'error',
      message: error.message,
      error: error.message
    });
    cleanupPath(extractPath);
    return res.status(500).json({ error: error.message || 'Unable to deploy the selected GitHub repository.' });
  } finally {
    cleanupPath(zipPath);
  }
});

router.get('/deployments', (req, res) => {
  const deployments = req.orchestrator.getDeploymentHistory();
  res.json(deployments);
});

router.get('/deployments/:sessionId', (req, res) => {
  const session = req.orchestrator.getSessionInfo(req.params.sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Deployment session not found' });
  }
  res.json(session);
});

export default router;
