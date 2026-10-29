import express from 'express';
import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import axios from 'axios';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { UPLOAD_LIMITS } from './upload.js';
import { validateGithubRepo } from '../utils/dockerfileHelper.js';
import {
  createApiTokenMiddleware,
  getAuthenticatedUserId,
  resolveGithubUrlConfig
} from '../utils/accessControl.js';

const STATE_TTL_MS = 10 * 60 * 1000;

const clearCookie = (res, name, options = {}) => {
  if (!res || typeof res.clearCookie !== 'function') return;
  const secure = process.env.SESSION_SECURE === undefined
    ? process.env.NODE_ENV === 'production'
    : process.env.SESSION_SECURE === 'true';
  res.clearCookie(name, {
    httpOnly: true,
    sameSite: process.env.SESSION_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'none' : 'lax'),
    secure,
    path: '/',
    ...options
  });
};

const getGithubConfig = () => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  return {
    clientId,
    clientSecret,
    ...resolveGithubUrlConfig(process.env)
  };
};

const frontendRedirect = (frontendUrl, values) => {
  const redirect = new URL('/', frontendUrl);
  for (const [key, value] of Object.entries(values)) {
    redirect.searchParams.set(key, value);
  }
  return redirect.toString();
};

const saveSession = (req) => new Promise((resolve, reject) => {
  req.session.save((error) => error ? reject(error) : resolve());
});

const regenerateSession = (req) => new Promise((resolve, reject) => {
  req.session.regenerate((error) => error ? reject(error) : resolve());
});

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
    req.session.destroy(() => {});
  }
  if (res && typeof res.clearCookie === 'function') {
    clearCookie(res, process.env.SESSION_COOKIE_NAME || 'luminicent_session');
    clearCookie(res, 'luminicent_github_session');
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

function downloadZipball(url, destPath, token, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const succeed = () => {
      if (settled) return;
      settled = true;
      resolve(destPath);
    };
    if (signal?.aborted) {
      fail(signal.reason || new Error('GitHub archive download cancelled'));
      return;
    }
    const urlObj = new URL(url);
    if (urlObj.protocol !== 'https:' ||
        !['api.github.com', 'github.com', 'codeload.github.com'].includes(urlObj.hostname)) {
      fail(new Error('GitHub archive redirect target is not permitted'));
      return;
    }
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
          fail(new Error('GitHub redirect was missing a Location header.'));
          return;
        }
        const redirectUrl = new URL(nextUrl, urlObj);
        const redirectToken = redirectUrl.hostname === 'api.github.com' ? token : null;
        res.resume();
        downloadZipball(redirectUrl.toString(), destPath, redirectToken, signal)
          .then(succeed)
          .catch(fail);
        return;
      }

      if (res.statusCode !== 200) {
        const responseChunks = [];
        let responseBytes = 0;
        res.on('data', (chunk) => {
          const retained = chunk.subarray(0, Math.max(0, 64 * 1024 - responseBytes));
          if (retained.length > 0) {
            responseChunks.push(retained);
            responseBytes += retained.length;
          }
        });
        res.on('end', () => {
          const responseBody = Buffer.concat(responseChunks).toString('utf8');
          let errorMsg = `GitHub download error: ${res.statusCode}`;
          try {
            const errObj = JSON.parse(responseBody);
            errorMsg = errObj.message || errorMsg;
          } catch (error) {
            // Ignore parse errors and fall back to the HTTP status message.
          }
          fail(new Error(errorMsg));
        });
        return;
      }

      const fileStream = fs.createWriteStream(destPath);
      let downloadedBytes = 0;
      const byteLimit = new Transform({
        transform(chunk, _encoding, callback) {
          downloadedBytes += chunk.length;
          if (downloadedBytes > UPLOAD_LIMITS.compressedBytes) {
            callback(new Error('GitHub archive exceeds compressed size limit'));
            return;
          }
          callback(null, chunk);
        }
      });
      void pipeline(res, byteLimit, fileStream).then(succeed).catch(fail);
    });

    req.on('error', fail);
    const abort = () => req.destroy(signal.reason || new Error('GitHub archive download cancelled'));
    signal?.addEventListener('abort', abort, { once: true });
    const requestTimer = setTimeout(
      () => req.destroy(new Error('GitHub archive download timed out')),
      30000
    );
    requestTimer.unref?.();
    req.once('close', () => {
      clearTimeout(requestTimer);
      signal?.removeEventListener('abort', abort);
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
    console.error('GitHub deployment cleanup failed', {
      code: cleanupError.code || cleanupError.name || 'UNKNOWN'
    });
  }
};

export const cleanupFailedDeployment = async ({
  orchestrator,
  sessionRegistry,
  sessionId,
  sessionToken,
  ownerId,
  orchestrationStarted,
  logger = console
}) => {
  const revokeCapability = async () => {
    try {
      await sessionRegistry.delete(sessionId, sessionToken, ownerId);
    } catch (error) {
      logger.error('GitHub deployment capability cleanup failed', {
        sessionId,
        code: error.code || error.name || 'UNKNOWN'
      });
    }
  };

  if (!orchestrationStarted) {
    try {
      orchestrator.discardSessionRecord(sessionId);
    } catch (discardError) {
      logger.error('GitHub deployment session record cleanup failed', {
        sessionId,
        code: discardError.code || discardError.name || 'UNKNOWN'
      });
      try {
        await orchestrator.cleanup(sessionId);
      } catch (cleanupError) {
        logger.error('GitHub deployment cleanup failed', {
          sessionId,
          code: cleanupError.code || cleanupError.name || 'UNKNOWN'
        });
      }
    } finally {
      await revokeCapability();
    }
    return;
  }

  try {
    await orchestrator.cleanup(sessionId);
    await revokeCapability();
  } catch (cleanupError) {
    logger.error('GitHub deployment cleanup failed', {
      sessionId,
      code: cleanupError.code || cleanupError.name || 'UNKNOWN'
    });
  }
};

const handleGithubApiError = (error, fallbackMessage) => {
  const status = error?.response?.status;

  if (status === 401 || status === 403) {
    return new Error('GitHub session expired or is no longer authorized. Please log in again.');
  }

  if (status === 429) {
    return new Error('GitHub API rate limit reached. Please try again shortly.');
  }

  return new Error(fallbackMessage);
};

export const createGithubRouter = ({
  httpClient = axios,
  apiTokenMiddleware = createApiTokenMiddleware(),
  logger = console
} = {}) => {
const router = express.Router();

router.get('/login', async (req, res) => {
  let config;
  try {
    config = getGithubConfig();
  } catch {
    return res.status(500).json({ error: 'GitHub OAuth URL configuration is invalid.' });
  }
  const { clientId, callbackUrl, frontendUrl } = config;

  if (!clientId || clientId === 'your_github_client_id_here' || !process.env.GITHUB_CLIENT_SECRET) {
    return res.redirect(frontendRedirect(frontendUrl, {
      github_error: 'GitHub OAuth credentials are not configured on this server.'
    }));
  }

  const state = crypto.randomBytes(18).toString('hex');
  req.session.githubOAuthState = { value: state, createdAt: Date.now() };
  try {
    await saveSession(req);
  } catch (error) {
    req.session.destroy(() => {});
    return res.status(500).json({ error: 'Unable to start GitHub login.' });
  }

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
  let config;
  try {
    config = getGithubConfig();
  } catch {
    return res.status(500).json({ error: 'GitHub OAuth URL configuration is invalid.' });
  }
  const { clientId, clientSecret, callbackUrl, frontendUrl } = config;

  if (!clientId || clientId === 'your_github_client_id_here' || !clientSecret) {
    return res.redirect(frontendRedirect(frontendUrl, {
      github_error: 'GitHub OAuth credentials are not configured on this server.'
    }));
  }

  if (typeof code !== 'string' || code.length === 0 || code.length > 2048) {
    return res.redirect(frontendRedirect(frontendUrl, {
      github_error: 'GitHub authorization response is invalid.'
    }));
  }

  const pendingState = req.session?.githubOAuthState;
  if (typeof state !== 'string' || !pendingState ||
      pendingState.value !== state ||
      Date.now() - pendingState.createdAt > STATE_TTL_MS) {
    return res.redirect(frontendRedirect(frontendUrl, {
      github_error: 'GitHub login failed. Please try again.'
    }));
  }

  delete req.session.githubOAuthState;
  try {
    await saveSession(req);
  } catch (error) {
    logger.error('GitHub OAuth state could not be consumed', {
      code: error.code || error.name || 'UNKNOWN'
    });
    return res.redirect(frontendRedirect(frontendUrl, {
      github_error: 'GitHub login failed. Please try again.'
    }));
  }

  try {
    const tokenResponse = await httpClient.post('https://github.com/login/oauth/access_token', {
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

    if (tokenResponse.data?.error) {
      throw new Error('GitHub token exchange failed');
    }

    const accessToken = tokenResponse.data?.access_token;
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      throw new Error('GitHub token response was invalid');
    }

    const userResponse = await httpClient.get('https://api.github.com/user', {
      headers: getGithubAuthHeaders(accessToken)
    });

    await regenerateSession(req);
    req.session.githubAuth = {
      accessToken,
      login: userResponse.data.login,
      avatarUrl: userResponse.data.avatar_url,
      name: userResponse.data.name,
      id: userResponse.data.id,
      scopes: tokenResponse.data.scope || 'repo read:user'
    };

    await saveSession(req);

    return res.redirect(frontendRedirect(frontendUrl, { github_status: 'success' }));
  } catch (error) {
    logger.error('GitHub OAuth callback failed', {
      code: error.code || error.name || 'UNKNOWN'
    });
    return res.redirect(frontendRedirect(frontendUrl, {
      github_error: 'Unable to complete GitHub login. Please try again.'
    }));
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
    const response = await httpClient.get('https://api.github.com/user', {
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

    const response = await httpClient.get(`https://api.github.com/user/repos?per_page=${perPage}&page=${page}&sort=updated`, {
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
    const repoMeta = await httpClient.get(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: getGithubAuthHeaders(session.accessToken)
    });

    if (!repoMeta.data?.default_branch) {
      return res.status(404).json({ error: 'Repository metadata is unavailable.' });
    }

    const branchesResponse = await httpClient.get(`https://api.github.com/repos/${owner}/${repo}/branches`, {
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

router.post('/deploy', apiTokenMiddleware, async (req, res) => {
  const session = getGithubSession(req);
  const body = req.body;
  const allowedFields = new Set(['owner', 'repo', 'branch', 'sessionId', 'sessionToken']);
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some((key) => !allowedFields.has(key))) {
    return res.status(400).json({ error: 'Invalid deployment request.' });
  }
  const {
    owner,
    repo,
    branch,
    sessionId: providedSessionId,
    sessionToken
  } = req.body || {};

  if (!session) {
    return res.status(401).json({ error: 'Not authenticated with GitHub.' });
  }
  const ownerId = getAuthenticatedUserId(req);
  if (!ownerId) {
    return res.status(401).json({ error: 'Authenticated user session required' });
  }
  let sessionValid;
  try {
    sessionValid = req.sessionRegistry &&
      await req.sessionRegistry.verify(providedSessionId, sessionToken, ownerId);
  } catch {
    return res.status(503).json({ error: 'Persistent scan storage is unavailable' });
  }
  if (!sessionValid) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  if (typeof owner !== 'string' || owner.length > 39
    || typeof repo !== 'string' || repo.length > 100
    || typeof branch !== 'string' || branch.length === 0 || branch.length > 255
    || /[\u0000-\u001f\u007f]/.test(branch)) {
    return res.status(400).json({ error: 'owner, repo, and branch are required.' });
  }

  let cleanOwner, cleanRepo;
  try {
    ({ owner: cleanOwner, repo: cleanRepo } = validateGithubRepo(owner, repo));
  } catch (validationError) {
    return res.status(400).json({ error: validationError.message });
  }

  const sessionId = providedSessionId;
  try {
    await req.sessionRegistry.delete(sessionId, sessionToken, ownerId);
  } catch {
    return res.status(503).json({ error: 'Persistent scan storage is unavailable' });
  }
  return res.status(503).json({
    error: 'Isolated scan worker is unavailable; project scans are disabled'
  });
});

router.get('/deployments/:sessionId', apiTokenMiddleware, async (req, res) => {
  const ownerId = getAuthenticatedUserId(req);
  if (!ownerId) {
    return res.status(401).json({ error: 'Authenticated user session required' });
  }
  if (!req.scanRecordStore) {
    return res.status(503).json({ error: 'Persistent scan storage is unavailable' });
  }
  let record;
  try {
    record = await req.scanRecordStore.get(req.params.sessionId, ownerId);
  } catch {
    return res.status(503).json({ error: 'Persistent scan storage is unavailable' });
  }
  if (!record) return res.status(404).json({ error: 'Scan not found' });
  const { ownerId: _ownerId, ...scan } = record;
  return res.json({ scan });
});

return router;
};

const router = createGithubRouter();
export default router;
