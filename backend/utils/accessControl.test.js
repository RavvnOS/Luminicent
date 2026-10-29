import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createApiTokenMiddleware,
  configureProxyTrust,
  createInMemorySessionRegistry,
  createSessionCookieOptions,
  getAuthenticatedUserId,
  isValidConfiguredSecret,
  registerSessionSocketHandlers,
  resolveGithubUrlConfig,
  validateSecurityConfig
} from './accessControl.js';
import express from 'express';

const API_TOKEN = Buffer.from('api-token-test-fixture-32-bytes!!').toString('base64url');
const SESSION_SECRET = Buffer.from('session-secret-test-fixture-32-bytes').toString('base64url');
const OWNER_A = '12345';
const OWNER_B = '67890';

const invokeMiddleware = (middleware, authorization) => {
  let nextCalled = false;
  const response = {
    statusCode: 200,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    }
  };
  middleware({ get: () => authorization }, response, () => { nextCalled = true; });
  return { ...response, nextCalled };
};

test('API authentication rejects missing or invalid bearer credentials', () => {
  const middleware = createApiTokenMiddleware({ getToken: () => API_TOKEN });
  assert.equal(invokeMiddleware(middleware).statusCode, 401);
  assert.equal(invokeMiddleware(middleware, 'Bearer incorrect-token').statusCode, 401);
  assert.equal(invokeMiddleware(middleware, `Bearer ${API_TOKEN}`).nextCalled, true);
  assert.equal(isValidConfiguredSecret('x'.repeat(48)), false);
  const predictableDiverseBytes = Buffer.from(
    Uint8Array.from({ length: 32 }, (_value, index) => index)
  ).toString('base64url');
  assert.match(predictableDiverseBytes, /[A-Za-z]/);
  assert.match(predictableDiverseBytes, /[0-9]/);
  assert.equal(isValidConfiguredSecret(predictableDiverseBytes), false);
  assert.equal(isValidConfiguredSecret('replace-with-a-long-random-secret'), false);
  assert.equal(isValidConfiguredSecret(''), false);
});

test('secret configuration requires distinct canonical 32-byte values without logging them', () => {
  const baseConfig = {
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    NODE_ENV: 'development',
    SESSION_SECURE: 'false',
    CORS_ORIGIN: 'http://localhost:5173'
  };
  assert.equal(isValidConfiguredSecret(API_TOKEN), true);
  assert.equal(isValidConfiguredSecret(SESSION_SECRET), true);
  assert.throws(
    () => validateSecurityConfig({
      ...baseConfig,
      SESSION_SECRET: API_TOKEN
    }),
    (error) => {
      assert.match(error.message, /must be different values/);
      assert.doesNotMatch(error.message, new RegExp(API_TOKEN));
      return true;
    }
  );
  assert.throws(
    () => validateSecurityConfig({ ...baseConfig, LUMINICENT_API_TOKEN: 'weak-value' }),
    (error) => {
      assert.match(error.message, /at least 32 bytes/);
      assert.doesNotMatch(error.message, /weak-value/);
      return true;
    }
  );
});

test('local loopback configuration remains valid for development', () => {
  const config = {
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    NODE_ENV: 'development',
    SESSION_SECURE: 'false',
    CORS_ORIGIN: 'http://localhost:5173'
  };
  for (const host of ['127.0.0.1', '127.0.0.2', '::1', 'localhost']) {
    assert.deepEqual(validateSecurityConfig({ ...config, HOST: host }), {
      host: host === 'localhost' ? '127.0.0.1' : host,
      localOnly: false,
      composeLocalOnly: false,
      tlsProxyMode: false,
      executionMode: 'disabled',
      buildNetwork: 'none'
    });
  }
});

test('remote bindings fail closed unless using the loopback-published Compose topology', () => {
  const production = {
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    NODE_ENV: 'production',
    SESSION_SECURE: 'true',
    CORS_ORIGIN: 'https://app.example.test'
  };
  for (const host of ['0.0.0.0', '192.0.2.10', '::']) {
    assert.throws(
      () => validateSecurityConfig({ ...production, HOST: host }),
      /Non-loopback binding/
    );
    assert.throws(
      () => validateSecurityConfig({
        ...production,
        HOST: host,
        LUMINICENT_TRUSTED_TLS_PROXY: 'true'
      }),
      /Trusted TLS proxy mode requires a 127\.0\.0\.1/
    );
  }

  assert.throws(
    () => validateSecurityConfig({
      ...production,
      HOST: '127.0.0.1'
    }),
    /must explicitly select local-only mode or trusted TLS proxy mode/
  );
  assert.throws(() => validateSecurityConfig({
    ...production,
    HOST: '0.0.0.0',
    LUMINICENT_LOCAL_ONLY: 'true'
  }), /Non-loopback binding/);
  assert.throws(() => validateSecurityConfig({
    ...production,
    HOST: '127.0.0.1',
    LUMINICENT_TRUSTED_TLS_PROXY: 'sometimes'
  }), /must be "true" or "false"/);

  assert.deepEqual(validateSecurityConfig({
    ...production,
    HOST: '0.0.0.0',
    LUMINICENT_LOCAL_ONLY: 'true',
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'true',
    SESSION_SECURE: 'false',
    SESSION_SAME_SITE: 'lax',
    CORS_ORIGIN: 'http://localhost:5173'
  }), {
    host: '0.0.0.0',
    localOnly: true,
    composeLocalOnly: true,
    tlsProxyMode: false,
    executionMode: 'disabled',
    buildNetwork: 'none'
  });
});

test('trusted TLS proxy mode requires a loopback listener and valid production settings', () => {
  const proxyConfig = {
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    HOST: '127.0.0.1',
    NODE_ENV: 'production',
    SESSION_SECURE: 'true',
    SESSION_SAME_SITE: 'none',
    FRONTEND_URL: 'https://app.example.test',
    GITHUB_CALLBACK_URL: 'https://api.example.test/api/github/callback',
    GITHUB_REDIRECT_URI: 'https://api.example.test/api/github/callback',
    CORS_ORIGIN: 'https://app.example.test',
    LUMINICENT_TRUSTED_TLS_PROXY: 'true'
  };
  assert.deepEqual(validateSecurityConfig(proxyConfig), {
    host: '127.0.0.1',
    localOnly: false,
    composeLocalOnly: false,
    tlsProxyMode: true,
    executionMode: 'disabled',
    buildNetwork: 'none'
  });
  const app = express();
  const securityConfig = validateSecurityConfig(proxyConfig);
  configureProxyTrust(app, securityConfig);
  assert.equal(app.get('trust proxy'), '127.0.0.1');
  assert.deepEqual(createSessionCookieOptions(proxyConfig, securityConfig), {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 86400000,
    path: '/',
    domain: undefined
  });
  assert.throws(() => validateSecurityConfig({
    ...proxyConfig,
    SESSION_SECURE: 'false'
  }), /Trusted TLS proxy mode/);
  assert.throws(() => validateSecurityConfig({
    ...proxyConfig,
    CORS_ORIGIN: 'https://app.example.test/path'
  }), /CORS_ORIGIN/);
  assert.throws(() => validateSecurityConfig({
    ...proxyConfig,
    LUMINICENT_TRUSTED_TLS_PROXY: 'false'
  }), /must explicitly select local-only mode or trusted TLS proxy mode/);
  assert.throws(() => validateSecurityConfig({
    ...proxyConfig,
    LUMINICENT_LOCAL_ONLY: 'true'
  }), /Trusted TLS proxy mode/);
  for (const host of ['127.0.0.2', '::1']) {
    assert.throws(() => validateSecurityConfig({
      ...proxyConfig,
      HOST: host
    }), /Trusted TLS proxy mode requires a 127\.0\.0\.1/);
  }
  assert.throws(() => validateSecurityConfig({
    ...proxyConfig,
    SESSION_SAME_SITE: undefined
  }), /explicit SESSION_SAME_SITE/);
  assert.throws(() => validateSecurityConfig({
    ...proxyConfig,
    SESSION_SECURE: 'false'
  }), /Trusted TLS proxy mode/);
});

test('proxy trust stays disabled by default and URL settings reject unsafe or contradictory values', () => {
  const app = express();
  configureProxyTrust(app, { tlsProxyMode: false });
  assert.equal(app.get('trust proxy'), false);

  const valid = {
    NODE_ENV: 'production',
    LUMINICENT_TRUSTED_TLS_PROXY: 'true',
    FRONTEND_URL: 'https://app.example.test',
    CORS_ORIGIN: 'https://app.example.test',
    GITHUB_CALLBACK_URL: 'https://api.example.test:8443/api/github/callback',
    GITHUB_REDIRECT_URI: 'https://api.example.test:8443/api/github/callback'
  };
  assert.deepEqual(resolveGithubUrlConfig(valid), {
    frontendUrl: 'https://app.example.test',
    callbackUrl: 'https://api.example.test:8443/api/github/callback',
    corsOrigins: ['https://app.example.test']
  });
  for (const invalid of [
    { FRONTEND_URL: 'javascript:alert(1)' },
    { FRONTEND_URL: 'https://app.example.test/continue' },
    { FRONTEND_URL: 'https://user@app.example.test' },
    { FRONTEND_URL: 'https://app.example.test:99999' },
    { CORS_ORIGIN: 'https://other.example.test' },
    { CORS_ORIGIN: 'https://app.example.test/path' },
    { GITHUB_CALLBACK_URL: 'http://api.example.test/api/github/callback' },
    { GITHUB_CALLBACK_URL: 'https://api.example.test/redirect?next=https://evil.test' },
    { GITHUB_REDIRECT_URI: 'https://evil.example.test/api/github/callback' }
  ]) {
    assert.throws(() => resolveGithubUrlConfig({ ...valid, ...invalid }));
  }
});

test('Compose local-only bind requires both explicit topology flags', () => {
  const composeConfig = {
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    HOST: '0.0.0.0',
    NODE_ENV: 'production',
    SESSION_SECURE: 'false',
    SESSION_SAME_SITE: 'lax',
    CORS_ORIGIN: 'http://localhost:5173',
    LUMINICENT_LOCAL_ONLY: 'true',
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'true'
  };
  assert.throws(() => validateSecurityConfig({
    ...composeConfig,
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'false'
  }), /Non-loopback binding/);
  assert.throws(() => validateSecurityConfig({
    ...composeConfig,
    LUMINICENT_LOCAL_ONLY: 'false'
  }), /Non-loopback binding/);
  assert.throws(() => validateSecurityConfig({
    ...composeConfig,
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'enabled'
  }), /must be "true" or "false"/);
});

test('execution defaults disabled and trusted-local requires an explicitly local-only topology', () => {
  const local = {
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    HOST: '127.0.0.1',
    NODE_ENV: 'development',
    SESSION_SECURE: 'false',
    CORS_ORIGIN: 'http://localhost:5173',
    LUMINICENT_LOCAL_ONLY: 'true'
  };
  assert.deepEqual(validateSecurityConfig(local), {
    host: '127.0.0.1',
    localOnly: true,
    composeLocalOnly: false,
    tlsProxyMode: false,
    executionMode: 'disabled',
    buildNetwork: 'none'
  });
  assert.deepEqual(validateSecurityConfig({
    ...local,
    LUMINICENT_EXECUTION_MODE: 'trusted-local',
    LUMINICENT_BUILD_NETWORK: 'default'
  }), {
    host: '127.0.0.1',
    localOnly: true,
    composeLocalOnly: false,
    tlsProxyMode: false,
    executionMode: 'trusted-local',
    buildNetwork: 'default'
  });
  assert.throws(() => validateSecurityConfig({
    ...local,
    LUMINICENT_BUILD_NETWORK: 'default'
  }), /requires trusted-local execution mode/);
  assert.deepEqual(validateSecurityConfig({
    LUMINICENT_API_TOKEN: API_TOKEN,
    SESSION_SECRET,
    HOST: '0.0.0.0',
    NODE_ENV: 'production',
    SESSION_SECURE: 'false',
    SESSION_SAME_SITE: 'lax',
    CORS_ORIGIN: 'http://localhost:5173',
    LUMINICENT_LOCAL_ONLY: 'true',
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'true',
    LUMINICENT_EXECUTION_MODE: 'trusted-local',
    LUMINICENT_BUILD_NETWORK: 'none'
  }), {
    host: '0.0.0.0',
    localOnly: true,
    composeLocalOnly: true,
    tlsProxyMode: false,
    executionMode: 'trusted-local',
    buildNetwork: 'none'
  });
  assert.throws(() => validateSecurityConfig({
    ...local,
    LUMINICENT_EXECUTION_MODE: 'public'
  }), /LUMINICENT_EXECUTION_MODE must be/);
  assert.throws(() => validateSecurityConfig({
    ...local,
    LUMINICENT_EXECUTION_MODE: 'trusted-local',
    LUMINICENT_LOCAL_ONLY: 'false'
  }), /trusted-local execution requires/);
  assert.throws(() => validateSecurityConfig({
    ...local,
    LUMINICENT_EXECUTION_MODE: 'trusted-local',
    LUMINICENT_LOCAL_ONLY: 'false',
    LUMINICENT_TRUSTED_TLS_PROXY: 'true',
    NODE_ENV: 'production',
    SESSION_SECURE: 'true',
    CORS_ORIGIN: 'https://app.example.test'
  }), /trusted-local execution requires/);
  assert.throws(() => validateSecurityConfig({
    ...local,
    LUMINICENT_BUILD_NETWORK: 'host'
  }), /LUMINICENT_BUILD_NETWORK must be/);
});

test('session socket capabilities isolate logs, status, and reports between clients', async (t) => {
  const registry = createInMemorySessionRegistry();
  t.after(() => registry.close());
  const connections = new Set();
  let connectionHandler;
  const io = {
    on(_event, handler) {
      connectionHandler = handler;
    },
    to(room) {
      return {
        emit(event, payload) {
          for (const connection of connections) {
            if (connection.rooms.has(room)) connection.received.push([event, payload]);
          }
        }
      };
    }
  };
  registerSessionSocketHandlers(io, registry);
  const connect = (ownerId) => {
    const socketHandlers = new Map();
    const connection = {
      data: {},
      request: { session: { githubAuth: { id: Number(ownerId), accessToken: 'test-token' } } },
      rooms: new Set(),
      received: [],
      on(event, handler) {
        socketHandlers.set(event, handler);
      },
      join(room) { connection.rooms.add(room); },
      leave(room) { connection.rooms.delete(room); }
    };
    connections.add(connection);
    connectionHandler(connection);
    return (payload) => new Promise((resolve) => {
      socketHandlers.get('joinSession')(payload, resolve);
    });
  };

  const sessionA = registry.create(OWNER_A);
  const sessionB = registry.create(OWNER_B);
  const clientAJoin = connect(OWNER_A);
  const clientBJoin = connect(OWNER_B);
  const unauthenticatedJoin = connect(null);
  assert.deepEqual(await clientAJoin(sessionA), { success: true });
  assert.deepEqual(await clientBJoin(sessionB), { success: true });
  assert.deepEqual(await unauthenticatedJoin(sessionA), {
    success: false,
    error: 'Session access denied'
  });
  assert.deepEqual(await clientBJoin({
    sessionId: sessionA.sessionId,
    sessionToken: sessionB.sessionToken
  }), { success: false, error: 'Session access denied' });
  assert.deepEqual(await clientBJoin({
    sessionId: sessionA.sessionId,
    sessionToken: sessionA.sessionToken
  }), { success: false, error: 'Session access denied' });
  for (const event of ['terminal_output', 'status', 'production-report']) {
    io.to(sessionA.sessionId).emit(event, { sessionId: sessionA.sessionId });
    io.to(sessionB.sessionId).emit(event, { sessionId: sessionB.sessionId });
  }
  const [clientA, clientB] = [...connections];
  assert.equal(clientA.received.length, 3);
  assert.equal(clientB.received.length, 3);
  assert.ok(clientA.received.every(([, payload]) => payload.sessionId === sessionA.sessionId));
  assert.ok(clientB.received.every(([, payload]) => payload.sessionId === sessionB.sessionId));
});

test('session records are capacity-bounded and expire', (t) => {
  let now = 1000;
  const deletedSessions = [];
  const registry = createInMemorySessionRegistry({
    ttlMs: 100,
    maxSessions: 1,
    now: () => now,
    sweepIntervalMs: 60_000,
    onDelete: (sessionId) => deletedSessions.push(sessionId)
  });
  t.after(() => registry.close());
  const session = registry.create(OWNER_A);
  assert.throws(() => registry.create(OWNER_B), { code: 'SESSION_CAPACITY' });
  now += 101;
  assert.equal(registry.verify(session.sessionId, session.sessionToken, OWNER_A), false);
  assert.equal(registry.size, 0);
  assert.deepEqual(deletedSessions, [session.sessionId]);
  assert.doesNotThrow(() => registry.create(OWNER_B));
});

test('session ownership is derived from a valid server-side GitHub session', () => {
  assert.equal(getAuthenticatedUserId({
    session: { githubAuth: { id: 12345, accessToken: 'server-side-token' } }
  }), OWNER_A);
  for (const session of [
    undefined,
    {},
    { githubAuth: { id: 12345 } },
    { githubAuth: { id: 'not-a-provider-id', accessToken: 'token' } },
    { githubAuth: { id: 0, accessToken: 'token' } },
    { githubAuth: { id: 12345, accessToken: '' } }
  ]) {
    assert.equal(getAuthenticatedUserId({ session }), null);
  }
});

test('session capabilities require matching authenticated owner and cannot be deleted cross-user', (t) => {
  const registry = createInMemorySessionRegistry();
  t.after(() => registry.close());
  assert.throws(() => registry.create(), /authenticated owner/);
  assert.throws(() => registry.create({ ownerId: OWNER_A }), /authenticated owner/);
  const owned = registry.create(OWNER_A);
  assert.equal(registry.verify(owned.sessionId, owned.sessionToken, OWNER_A), true);
  assert.equal(registry.verify(owned.sessionId, owned.sessionToken, OWNER_B), false);
  assert.equal(registry.verify(owned.sessionId, owned.sessionToken), false);
  assert.equal(registry.verify('../unknown', owned.sessionToken, OWNER_A), false);
  assert.equal(registry.has(owned.sessionId, OWNER_A), true);
  assert.equal(registry.has(owned.sessionId, OWNER_B), false);
  assert.equal(registry.delete(owned.sessionId, owned.sessionToken, OWNER_B), false);
  assert.equal(registry.verify(owned.sessionId, owned.sessionToken, OWNER_A), true);
  assert.equal(registry.delete(owned.sessionId, owned.sessionToken, OWNER_A), true);
});
