import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import session from 'express-session';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { cleanupFailedDeployment, createGithubRouter } from './githubRoutes.js';
import {
  configureProxyTrust,
  createSessionCookieOptions,
  createInMemorySessionRegistry,
  validateSecurityConfig
} from '../utils/accessControl.js';

const API_TOKEN = Buffer.from('github-api-test-fixture-32-bytes!!').toString('base64url');
const OAUTH_SESSION_SECRET = Buffer.from('oauth-session-test-fixture-32-bytes!').toString('base64url');
const GITHUB_OWNER_ID = '12345';

const setOAuthEnvironment = (testContext) => {
  const values = {
    NODE_ENV: 'production',
    HOST: '127.0.0.1',
    LUMINICENT_TRUSTED_TLS_PROXY: 'true',
    LUMINICENT_LOCAL_ONLY: 'false',
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'false',
    LUMINICENT_EXECUTION_MODE: 'disabled',
    LUMINICENT_BUILD_NETWORK: 'none',
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET: OAUTH_SESSION_SECRET,
    SESSION_SECURE: 'true',
    SESSION_SAME_SITE: 'none',
    SESSION_COOKIE_NAME: 'oauth_test_session',
    FRONTEND_URL: 'https://app.example.test',
    CORS_ORIGIN: 'https://app.example.test',
    GITHUB_CALLBACK_URL: 'https://api.example.test/api/github/callback',
    GITHUB_REDIRECT_URI: 'https://api.example.test/api/github/callback',
    GITHUB_CLIENT_ID: 'test-client-id',
    GITHUB_CLIENT_SECRET: 'test-provider-secret'
  };
  const previous = new Map(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  testContext.after(() => {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
};

const startOAuthTestApp = async (testContext, httpClient, logged = []) => {
  setOAuthEnvironment(testContext);
  const securityConfig = validateSecurityConfig(process.env);
  const backendApp = express();
  configureProxyTrust(backendApp, securityConfig);
  backendApp.use(session({
    name: process.env.SESSION_COOKIE_NAME,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: createSessionCookieOptions(process.env, securityConfig)
  }));
  backendApp.use('/api/github', createGithubRouter({
    httpClient,
    logger: { error: (...args) => logged.push(args) }
  }));
  const backend = http.createServer(backendApp);
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');

  const proxy = http.createServer((incoming, outgoing) => {
    const upstream = http.request({
      host: '127.0.0.1',
      port: backend.address().port,
      method: incoming.method,
      path: incoming.url,
      headers: {
        ...incoming.headers,
        host: 'api.example.test',
        'x-forwarded-host': 'app.example.test',
        'x-forwarded-proto': 'https'
      }
    }, (response) => {
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    upstream.on('error', () => {
      outgoing.statusCode = 502;
      outgoing.end();
    });
    incoming.pipe(upstream);
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  testContext.after(async () => {
    await Promise.all([backend, proxy].map((server) => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    })));
  });

  return {
    backendUrl: `http://127.0.0.1:${backend.address().port}`,
    proxyUrl: `http://127.0.0.1:${proxy.address().port}`
  };
};

const createRegistrySession = () => {
  const registry = createInMemorySessionRegistry({ sweepIntervalMs: 60_000 });
  const credentials = registry.create(GITHUB_OWNER_ID);
  return { registry, ownerId: GITHUB_OWNER_ID, ...credentials };
};

const startGithubServer = async (testContext, failureStage, cleanupFails = false) => {
  const uploadsRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-github-test-'));
  const sessionRegistry = createInMemorySessionRegistry({ sweepIntervalMs: 60_000 });
  const credentials = sessionRegistry.create(GITHUB_OWNER_ID);
  let githubUserId = Number(GITHUB_OWNER_ID);
  const records = new Map();
  const scanRecords = new Map();
  const resources = new Set();
  const cleanupCalls = [];
  const discardCalls = [];
  const logged = [];
  const calls = { github: 0, archive: 0, build: 0, run: 0 };
  const failure = Object.assign(new Error('private upstream detail'), { code: 'MOCK_FAILURE' });
  const orchestrator = {
    isExecutionEnabled() {
      return failureStage !== 'execution-disabled';
    },
    createSession(sessionId) {
      if (failureStage === 'session-record') throw failure;
      records.set(sessionId, { sessionId });
    },
    emitStatus() {},
    emit() {},
    discardSessionRecord(sessionId) {
      discardCalls.push(sessionId);
      records.delete(sessionId);
    },
    async buildImage(_context, _imageName, sessionId) {
      calls.build += 1;
      resources.add(`image:${sessionId}`);
      if (failureStage === 'build') throw failure;
    },
    async runContainer(_imageName, sessionId) {
      calls.run += 1;
      if (failureStage === 'runtime') throw failure;
      resources.add(`container:${sessionId}`);
      return {};
    },
    async cleanup(sessionId) {
      cleanupCalls.push(sessionId);
      if (cleanupFails) throw Object.assign(new Error('cleanup detail'), { code: 'MOCK_CLEANUP' });
      for (const resource of [...resources]) {
        if (resource.endsWith(`:${sessionId}`)) resources.delete(resource);
      }
      records.delete(sessionId);
    }
  };
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.sessionRegistry = sessionRegistry;
    req.scanRecordStore = {
      async get(id, ownerId) {
        const record = scanRecords.get(id);
        return record?.ownerId === ownerId ? { ...record } : null;
      }
    };
    req.orchestrator = orchestrator;
    req.session = {
      githubAuth: { id: githubUserId, accessToken: 'test-github-access-token' }
    };
    next();
  });
  app.use('/api/github', createGithubRouter({
    apiTokenMiddleware: (_req, _res, next) => next(),
    httpClient: {
      async get() {
        calls.github += 1;
        if (failureStage === 'before-orchestration') throw failure;
        return { data: { private: false } };
      }
    },
    async downloadArchive(_url, destination) {
      calls.archive += 1;
      fs.writeFileSync(destination, 'mock archive');
    },
    async safeExtract(_archive, destination) {
      fs.writeFileSync(path.join(destination, 'Dockerfile'), 'FROM scratch\n');
    },
    normalizeRoot: (root) => root,
    locateBuildContext: (root) => root,
    prepareDockerfile: (root) => path.join(root, 'Dockerfile'),
    uploadsDirectory: () => uploadsRoot,
    scheduleCleanup: () => ({ unref() {} }),
    logger: { error: (...args) => logged.push(args) }
  }));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  testContext.after(async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    sessionRegistry.close();
    fs.rmSync(uploadsRoot, { recursive: true, force: true });
  });

  const deploy = (extraFields = {}) => fetch(`http://127.0.0.1:${server.address().port}/api/github/deploy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      owner: 'safe-owner',
      repo: 'safe-repo',
      branch: 'main',
      sessionId: credentials.sessionId,
      sessionToken: credentials.sessionToken,
      ...extraFields
    })
  });
  const deploymentStatus = (sessionId, sessionToken) => fetch(
    `http://127.0.0.1:${server.address().port}/api/github/deployments/${sessionId}`,
    {
      headers: {
        Authorization: `Bearer ${API_TOKEN}`,
        'X-Luminicent-Session-Token': sessionToken
      }
    }
  );
  return {
    credentials,
    setGithubUserId(value) { githubUserId = value; },
    deploy,
    deploymentStatus,
    sessionRegistry,
    scanRecords,
    records,
    resources,
    cleanupCalls,
    discardCalls,
    logged,
    calls,
    failure
  };
};

test('pre-orchestration deployment failure discards the session and capability idempotently', async (t) => {
  const { registry, ownerId, sessionId, sessionToken } = createRegistrySession();
  t.after(() => registry.close());
  const records = new Map([[sessionId, { sessionId }]]);
  let cleanupCalls = 0;
  const orchestrator = {
    discardSessionRecord(id) {
      records.delete(id);
    },
    async cleanup() {
      cleanupCalls += 1;
    }
  };

  await cleanupFailedDeployment({
    orchestrator,
    sessionRegistry: registry,
    sessionId,
    sessionToken,
    ownerId,
    orchestrationStarted: false,
    logger: { error() {} }
  });
  await cleanupFailedDeployment({
    orchestrator,
    sessionRegistry: registry,
    sessionId,
    sessionToken,
    ownerId,
    orchestrationStarted: false,
    logger: { error() {} }
  });

  assert.equal(records.has(sessionId), false);
  assert.equal(registry.verify(sessionId, sessionToken, ownerId), false);
  assert.equal(cleanupCalls, 0);
});

test('post-orchestration failure uses resource cleanup and does not directly discard the session', async (t) => {
  const { registry, ownerId, sessionId, sessionToken } = createRegistrySession();
  t.after(() => registry.close());
  let cleanupCalls = 0;
  let discardCalls = 0;
  const orchestrator = {
    discardSessionRecord() {
      discardCalls += 1;
    },
    async cleanup(id) {
      cleanupCalls += 1;
      assert.equal(id, sessionId);
    }
  };

  await cleanupFailedDeployment({
    orchestrator,
    sessionRegistry: registry,
    sessionId,
    sessionToken,
    ownerId,
    orchestrationStarted: true,
    logger: { error() {} }
  });

  assert.equal(cleanupCalls, 1);
  assert.equal(discardCalls, 0);
  assert.equal(registry.verify(sessionId, sessionToken, ownerId), false);
});

test('cleanup failure is logged without replacing deployment failure', async (t) => {
  const { registry, ownerId, sessionId, sessionToken } = createRegistrySession();
  t.after(() => registry.close());
  const logged = [];
  const orchestrator = {
    discardSessionRecord() {
      throw Object.assign(new Error('record cleanup failed'), { code: 'RECORD_CLEANUP_FAILED' });
    },
    async cleanup() {
      throw Object.assign(new Error('resource cleanup failed'), { code: 'RESOURCE_CLEANUP_FAILED' });
    }
  };
  const deploymentError = new Error('original deployment failure');
  let caughtError;

  try {
    throw deploymentError;
  } catch (error) {
    await cleanupFailedDeployment({
      orchestrator,
      sessionRegistry: registry,
      sessionId,
      sessionToken,
      ownerId,
      orchestrationStarted: false,
      logger: { error: (...args) => logged.push(args) }
    });
    caughtError = error;
  }

  assert.equal(caughtError, deploymentError);
  assert.equal(registry.verify(sessionId, sessionToken, ownerId), false);
  assert.deepEqual(logged.map((entry) => entry[1].code), [
    'RECORD_CLEANUP_FAILED',
    'RESOURCE_CLEANUP_FAILED'
  ]);
});

test('GitHub deploy fails closed before repository access or inline execution', async (t) => {
  const server = await startGithubServer(t, 'build');
  const response = await server.deploy();
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: 'Isolated scan worker is unavailable; project scans are disabled'
  });
  assert.equal(server.sessionRegistry.verify(
    server.credentials.sessionId,
    server.credentials.sessionToken,
    GITHUB_OWNER_ID
  ), false);
  assert.equal(server.calls.github, 0);
  assert.equal(server.calls.archive, 0);
  assert.equal(server.calls.build, 0);
  assert.equal(server.calls.run, 0);
  assert.equal(server.records.size, 0);
  assert.equal(server.cleanupCalls.length, 0);
  assert.equal(server.resources.size, 0);
  assert.equal(JSON.stringify(server.logged).includes('private upstream detail'), false);
});

test('GitHub deploy rejects client-controlled commands and worker configuration', async (t) => {
  const server = await startGithubServer(t, 'build');
  const response = await server.deploy({
    command: 'run arbitrary code',
    hostPath: 'C:\\private',
    privileged: true,
    workerConfig: { network: 'unrestricted' },
    ownerId: 'attacker',
    userId: 'attacker'
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'Invalid deployment request.' });
  assert.equal(server.calls.github, 0);
  assert.equal(server.calls.archive, 0);
  assert.equal(server.calls.build, 0);
  assert.equal(server.calls.run, 0);
});

test('GitHub deployment status is owner-bound and hides owner metadata', async (t) => {
  const server = await startGithubServer(t, 'build');
  server.setGithubUserId(67890);
  const otherUserStatus = await server.deploymentStatus(
    server.credentials.sessionId,
    server.credentials.sessionToken
  );
  assert.equal(otherUserStatus.status, 404);
  assert.deepEqual(await otherUserStatus.json(), { error: 'Scan not found' });

  server.scanRecords.set(server.credentials.sessionId, {
    id: server.credentials.sessionId,
    version: 1,
    ownerId: GITHUB_OWNER_ID,
    source: 'github',
    status: 'queued',
    versionNumber: 1,
    createdAt: '2026-03-01T10:00:00.000Z',
    updatedAt: '2026-03-01T10:00:00.000Z'
  });
  server.setGithubUserId(Number(GITHUB_OWNER_ID));
  const ownerStatus = await server.deploymentStatus(
    server.credentials.sessionId,
    server.credentials.sessionToken
  );
  assert.equal(ownerStatus.status, 200);
  assert.deepEqual(await ownerStatus.json(), {
    scan: {
      id: server.credentials.sessionId,
      version: 1,
      source: 'github',
      status: 'queued',
      versionNumber: 1,
      createdAt: '2026-03-01T10:00:00.000Z',
      updatedAt: '2026-03-01T10:00:00.000Z'
    }
  });

  server.setGithubUserId(67890);
  const deniedStatus = await server.deploymentStatus(
    server.credentials.sessionId,
    server.credentials.sessionToken
  );
  assert.equal(deniedStatus.status, 404);
  assert.deepEqual(await deniedStatus.json(), { error: 'Scan not found' });
  const otherUserDeploy = await server.deploy();
  assert.equal(otherUserDeploy.status, 404);
  assert.deepEqual(await otherUserDeploy.json(), { error: 'Scan not found' });
  assert.equal(server.calls.github, 0);
  assert.equal(server.sessionRegistry.verify(
    server.credentials.sessionId,
    server.credentials.sessionToken,
    GITHUB_OWNER_ID
  ), true);
  assert.equal(server.sessionRegistry.verify(
    server.credentials.sessionId,
    server.credentials.sessionToken,
    '67890'
  ), false);

  const unknownStatus = await server.deploymentStatus(
    '95d07d30-29bc-4f4e-a120-05f3479f851c',
    'unknown-capability'
  );
  assert.equal(unknownStatus.status, 404);
  assert.deepEqual(await unknownStatus.json(), { error: 'Scan not found' });
});

test('GitHub deployment operations reject missing or malformed authenticated identity', async (t) => {
  const server = await startGithubServer(t, 'build');
  server.setGithubUserId('untrusted-name');
  const response = await server.deploy();
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), {
    error: 'Authenticated user session required'
  });
  assert.equal(server.calls.github, 0);
  assert.equal(server.sessionRegistry.verify(
    server.credentials.sessionId,
    server.credentials.sessionToken,
    GITHUB_OWNER_ID
  ), true);
  const statusResponse = await server.deploymentStatus(
    server.credentials.sessionId,
    server.credentials.sessionToken
  );
  assert.equal(statusResponse.status, 401);
  assert.deepEqual(await statusResponse.json(), {
    error: 'Authenticated user session required'
  });
});

test('OAuth keeps the session through a loopback proxy and uses only configured URLs', async (t) => {
  const providerCalls = [];
  const app = await startOAuthTestApp(t, {
    async post(url, body) {
      providerCalls.push({ url, body });
      return { data: { access_token: 'mock-access-token', scope: 'repo read:user' } };
    },
    async get(url, options) {
      providerCalls.push({ url, authorization: options.headers.Authorization });
      return {
        data: {
          id: 17,
          login: 'test-user',
          name: 'Test User',
          avatar_url: 'https://avatars.example.test/test.png',
          html_url: 'https://github.com/test-user',
          type: 'User'
        }
      };
    }
  });

  const directLogin = await fetch(`${app.backendUrl}/api/github/login`, {
    headers: {
      'x-forwarded-host': 'attacker.example',
      'x-forwarded-proto': 'http'
    },
    redirect: 'manual'
  });
  const directAuthorizationUrl = new URL(directLogin.headers.get('location'));
  assert.equal(directAuthorizationUrl.hostname, 'github.com');
  assert.equal(
    directAuthorizationUrl.searchParams.get('redirect_uri'),
    'https://api.example.test/api/github/callback'
  );
  assert.equal(directAuthorizationUrl.searchParams.has('attacker.example'), false);

  const login = await fetch(`${app.proxyUrl}/api/github/login`, {
    headers: {
      'x-forwarded-host': 'evil.example',
      'x-forwarded-proto': 'http'
    },
    redirect: 'manual'
  });
  assert.equal(login.status, 302);
  const authorizationUrl = new URL(login.headers.get('location'));
  const state = authorizationUrl.searchParams.get('state');
  assert.ok(state);
  assert.equal(
    authorizationUrl.searchParams.get('redirect_uri'),
    'https://api.example.test/api/github/callback'
  );
  const initialCookie = login.headers.get('set-cookie');
  assert.match(initialCookie, /;\s*Secure/i);
  assert.match(initialCookie, /;\s*HttpOnly/i);
  assert.match(initialCookie, /;\s*SameSite=None/i);

  const callback = await fetch(
    `${app.proxyUrl}/api/github/callback?code=mock-authorization-code&state=${encodeURIComponent(state)}`,
    {
      headers: { cookie: initialCookie.split(';')[0] },
      redirect: 'manual'
    }
  );
  assert.equal(callback.status, 302);
  const frontendRedirect = new URL(callback.headers.get('location'));
  assert.equal(frontendRedirect.origin, 'https://app.example.test');
  assert.equal(frontendRedirect.searchParams.get('github_status'), 'success');
  assert.equal(frontendRedirect.searchParams.has('next'), false);
  const rotatedCookie = callback.headers.get('set-cookie');
  assert.ok(rotatedCookie);
  assert.match(rotatedCookie, /;\s*Secure/i);

  const user = await fetch(`${app.proxyUrl}/api/github/user`, {
    headers: { cookie: rotatedCookie.split(';')[0] }
  });
  assert.equal(user.status, 200);
  assert.equal((await user.json()).login, 'test-user');
  assert.deepEqual(providerCalls[0], {
    url: 'https://github.com/login/oauth/access_token',
    body: {
      client_id: 'test-client-id',
      client_secret: 'test-provider-secret',
      code: 'mock-authorization-code',
      redirect_uri: 'https://api.example.test/api/github/callback'
    }
  });
  assert.ok(providerCalls.some((call) =>
    call.url === 'https://api.github.com/user' &&
    call.authorization === 'Bearer mock-access-token'
  ));
});

test('OAuth failure redirects with sanitized text and consumes the state', async (t) => {
  const logged = [];
  const app = await startOAuthTestApp(t, {
    async post() {
      throw Object.assign(new Error('upstream authorization-code-secret'), {
        code: 'MOCK_PROVIDER_FAILURE',
        response: {
          data: {
            error: 'invalid_grant',
            error_description: 'provider-secret-description'
          }
        }
      });
    },
    async get() {
      throw new Error('must not fetch a user after a failed token exchange');
    }
  }, logged);

  const login = await fetch(`${app.proxyUrl}/api/github/login`, { redirect: 'manual' });
  const state = new URL(login.headers.get('location')).searchParams.get('state');
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const callback = await fetch(
    `${app.proxyUrl}/api/github/callback?code=authorization-code-secret&state=${state}`,
    { headers: { cookie }, redirect: 'manual' }
  );
  const location = new URL(callback.headers.get('location'));
  assert.equal(location.origin, 'https://app.example.test');
  assert.equal(
    location.searchParams.get('github_error'),
    'Unable to complete GitHub login. Please try again.'
  );
  assert.equal(location.href.includes('authorization-code-secret'), false);
  assert.equal(location.href.includes('provider-secret-description'), false);
  assert.equal(JSON.stringify(logged).includes('authorization-code-secret'), false);
  assert.equal(JSON.stringify(logged).includes('provider-secret-description'), false);

  const replay = await fetch(
    `${app.proxyUrl}/api/github/callback?code=another-code&state=${state}`,
    { headers: { cookie }, redirect: 'manual' }
  );
  assert.equal(
    new URL(replay.headers.get('location')).searchParams.get('github_error'),
    'GitHub login failed. Please try again.'
  );
});
