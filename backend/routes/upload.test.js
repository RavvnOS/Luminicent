import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import express from 'express';
import { createApiTokenMiddleware, createInMemorySessionRegistry } from '../utils/accessControl.js';
import { deflateRawSync } from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createUploadRouter, UPLOAD_LIMITS } from './upload.js';

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = (crc & 1) ? (0xEDB88320 ^ (crc >>> 1)) : (crc >>> 1);
  }
  return crc >>> 0;
});

const crc32 = (buffer) => {
  let crc = 0xFFFFFFFF;
  for (const byte of buffer) {
    crc = crcTable[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
};

const makeZip = (files) => {
  const localRecords = [];
  const centralRecords = [];
  let localOffset = 0;

  for (const file of files) {
    const name = Buffer.from(file.name);
    const data = Buffer.from(file.data ?? '');
    const compressed = deflateRawSync(data);
    const checksum = crc32(data);
    const declaredSize = file.declaredSize ?? data.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034B50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(declaredSize, 22);
    local.writeUInt16LE(name.length, 26);
    localRecords.push(local, name, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014B50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(declaredSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(
      file.externalAttributes ??
        (file.name.endsWith('/') ? 0x41ED0010 : 0x81A40000),
      38
    );
    central.writeUInt32LE(localOffset, 42);
    centralRecords.push(central, name);
    localOffset += local.length + name.length + compressed.length;
  }

  const centralDirectory = Buffer.concat(centralRecords);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054B50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localRecords, centralDirectory, end]);
};

const API_TOKEN = Buffer.from('upload-api-test-fixture-32-bytes!!').toString('base64url');

const startUploadServer = async (testContext, archiveLimits = UPLOAD_LIMITS, options = {}) => {
  const uploadsRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-upload-test-'));
  const sessionRegistry = createInMemorySessionRegistry();
  let identity = Object.hasOwn(options, 'identity')
    ? options.identity
    : { id: 12345, accessToken: 'server-side-test-token' };
  const app = express();
  app.use((req, _res, next) => {
    req.session = identity ? { githubAuth: identity } : {};
    req.orchestrator = {
      emitStatus() {},
      emit() {},
      isExecutionEnabled: () => options.executionEnabled !== false,
      async buildImage() {},
      async runContainer() { return {}; },
      async streamLogs() {},
      async cleanup() {},
      ...options.orchestrator
    };
    next();
  });
  app.use('/api', createUploadRouter({
    uploadsRoot,
    archiveLimits,
    logger: options.logger || { warn() {}, error() {} },
    sessionRegistry: options.sessionRegistry === false ? null : sessionRegistry,
    apiTokenMiddleware: createApiTokenMiddleware({ getToken: () => API_TOKEN })
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

  const createSession = async (authorized = true, body) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/sessions`, {
      method: 'POST',
      headers: {
        ...(authorized ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' })
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    return response;
  };
  const uploadWithSession = async (contents, session, signal, authorized = true, fields = {}) => {
    const form = new FormData();
    form.append('file', new Blob([contents], { type: 'application/zip' }), 'project.zip');
    for (const [name, value] of Object.entries(fields)) {
      form.append(name, String(value));
    }
    return fetch(`http://127.0.0.1:${server.address().port}/api/upload`, {
      method: 'POST',
      body: form,
      signal,
      headers: {
        ...(authorized ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
        ...(session ? {
          'X-Luminicent-Session-Id': session.sessionId,
          'X-Luminicent-Session-Token': session.sessionToken
        } : {})
      }
    });
  };
  const cleanupWithSession = (session, authorized = true) => fetch(
    `http://127.0.0.1:${server.address().port}/api/cleanup`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authorized ? { Authorization: `Bearer ${API_TOKEN}` } : {})
      },
      body: JSON.stringify(session)
    }
  );

  return {
    uploadsRoot,
    sessionRegistry,
    createSession,
    cleanupWithSession,
    uploadWithSession,
    setIdentity(value) { identity = value; },
    upload: async (contents, signal) => {
      const sessionResponse = await createSession();
      assert.equal(sessionResponse.status, 201);
      return uploadWithSession(contents, await sessionResponse.json(), signal);
    }
  };
};

const assertRejectedAndClean = async (server, archive, expectedStatus, expectedMessage) => {
  const response = await server.upload(archive);
  assert.equal(response.status, expectedStatus);
  assert.deepEqual(await response.json(), { error: expectedMessage });
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
};

const restrictedMessage = 'Invalid or unsupported ZIP archive';
const limitMessage = 'Archive exceeds resource limits';

test('requires API authentication to create a session or upload a project', async (t) => {
  const server = await startUploadServer(t);
  const createResponse = await server.createSession(false);
  assert.equal(createResponse.status, 401);
  assert.deepEqual(await createResponse.json(), { error: 'Authentication required' });

  const uploadResponse = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    null,
    undefined,
    false
  );
  assert.equal(uploadResponse.status, 401);
  assert.deepEqual(await uploadResponse.json(), { error: 'Authentication required' });
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});

test('requires a valid server-side GitHub identity to create a session', async (t) => {
  const server = await startUploadServer(t, UPLOAD_LIMITS, { identity: { login: 'attacker' } });
  const response = await server.createSession();
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Authenticated user session required' });
});

test('session creation fails closed when persistent storage is not injected', async (t) => {
  const server = await startUploadServer(t, UPLOAD_LIMITS, { sessionRegistry: false });
  const response = await server.createSession();
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Persistent scan storage is unavailable' });
});

test('session creation rejects client-supplied owner and user IDs', async (t) => {
  const server = await startUploadServer(t);
  const response = await server.createSession(true, {
    ownerId: '67890',
    userId: '67890'
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'Invalid session request' });
  assert.equal(server.sessionRegistry.size, 0);
});

test('requires a valid per-session capability before accepting an upload', async (t) => {
  const server = await startUploadServer(t);
  const sessionResponse = await server.createSession();
  const session = await sessionResponse.json();
  const denied = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    { ...session, sessionToken: 'wrong-session-capability' }
  );
  assert.equal(denied.status, 404);
  assert.deepEqual(await denied.json(), { error: 'Scan not found' });
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});

test('a different authenticated user cannot upload or clean up another user session', async (t) => {
  let cleanupCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    orchestrator: { async cleanup() { cleanupCalls += 1; } }
  });
  const session = await (await server.createSession()).json();
  server.setIdentity({ id: 67890, accessToken: 'other-user-session' });
  const uploadResponse = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    session
  );
  const cleanupResponse = await server.cleanupWithSession(session);
  assert.equal(uploadResponse.status, 404);
  assert.deepEqual(await uploadResponse.json(), { error: 'Scan not found' });
  assert.equal(cleanupResponse.status, 404);
  assert.deepEqual(await cleanupResponse.json(), { error: 'Scan not found' });
  assert.equal(cleanupCalls, 0);
  server.setIdentity({ id: 12345, accessToken: 'owner-session' });
  assert.equal(server.sessionRegistry.verify(session.sessionId, session.sessionToken, '12345'), true);
});

test('unauthenticated requests cannot use an otherwise valid scan capability', async (t) => {
  let cleanupCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    orchestrator: { async cleanup() { cleanupCalls += 1; } }
  });
  const session = await (await server.createSession()).json();
  server.setIdentity(null);
  const uploadResponse = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    session
  );
  const cleanupResponse = await server.cleanupWithSession(session);
  assert.equal(uploadResponse.status, 401);
  assert.deepEqual(await uploadResponse.json(), { error: 'Authenticated user session required' });
  assert.equal(cleanupResponse.status, 401);
  assert.deepEqual(await cleanupResponse.json(), { error: 'Authenticated user session required' });
  assert.equal(cleanupCalls, 0);
  server.setIdentity({ id: 12345, accessToken: 'owner-session' });
  assert.equal(server.sessionRegistry.verify(session.sessionId, session.sessionToken, '12345'), true);
});

test('rejects client-supplied commands, paths, and worker settings in multipart fields', async (t) => {
  let buildCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    orchestrator: { async buildImage() { buildCalls += 1; } }
  });
  const session = await (await server.createSession()).json();
  const response = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    session,
    undefined,
    true,
    {
      command: 'arbitrary command',
      hostPath: 'C:\\private',
      privileged: true,
      workerConfig: '{"unrestricted":true}'
    }
  );
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'Invalid upload' });
  assert.equal(buildCalls, 0);
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});

test('refuses upload execution and revokes its capability when execution mode is disabled', async (t) => {
  const server = await startUploadServer(t, UPLOAD_LIMITS, { executionEnabled: false });
  const session = await (await server.createSession()).json();
  const response = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    session
  );
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /Project execution is disabled/);
  assert.equal((await server.cleanupWithSession(session)).status, 404);
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});

test('cleanup requires the matching session capability', async (t) => {
  let cleanupCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    orchestrator: { async cleanup() { cleanupCalls += 1; } }
  });
  const sessionA = await (await server.createSession()).json();
  const sessionB = await (await server.createSession()).json();

  const ownerOverride = await server.cleanupWithSession({
    ...sessionA,
    ownerId: '67890',
    userId: '67890'
  });
  assert.equal(ownerOverride.status, 400);
  assert.deepEqual(await ownerOverride.json(), { error: 'Invalid cleanup request' });

  const unauthorized = await server.cleanupWithSession({
    sessionId: sessionA.sessionId,
    sessionToken: sessionB.sessionToken
  });
  assert.equal(unauthorized.status, 404);
  assert.equal(cleanupCalls, 0);

  const authorized = await server.cleanupWithSession(sessionA);
  assert.equal(authorized.status, 200);
  assert.equal(cleanupCalls, 1);
});

test('rejects a safely extracted archive when the isolated worker is unavailable', async (t) => {
  let buildCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    orchestrator: { async buildImage() { buildCalls += 1; } }
  });
  const sessionResponse = await server.createSession();
  const session = await sessionResponse.json();
  const response = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    session
  );
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.deepEqual(body, {
    error: 'Isolated scan worker is unavailable; project scans are disabled'
  });
  assert.equal(buildCalls, 0);
  assert.equal(server.sessionRegistry.verify(session.sessionId, session.sessionToken, '12345'), false);
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});

test('does not invoke analysis or build when the isolated worker is unavailable', async (t) => {
  let analyzeCalls = 0;
  let buildCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    analyze: async () => { analyzeCalls += 1; return {}; },
    orchestrator: { async buildImage() { buildCalls += 1; } }
  });
  const response = await server.upload(makeZip([{ name: 'package.json', data: '{}' }]));
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.match(body.error, /Isolated scan worker is unavailable/);
  assert.equal(analyzeCalls, 0);
  assert.equal(buildCalls, 0);
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});

test('rejects malformed ZIP archives with a sanitized response and cleanup', async (t) => {
  const server = await startUploadServer(t);
  await assertRejectedAndClean(server, Buffer.from('not a ZIP'), 400, restrictedMessage);
});

test('revokes the upload session capability after an extraction failure before orchestration', async (t) => {
  const server = await startUploadServer(t);
  const session = await (await server.createSession()).json();
  const response = await server.uploadWithSession(Buffer.from('not a ZIP'), session);

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: restrictedMessage });
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
  const laterCleanup = await server.cleanupWithSession(session);
  assert.equal(laterCleanup.status, 404);
});

test('rejects absolute, drive-prefixed, UNC, and traversal entry paths', async (t) => {
  const server = await startUploadServer(t);
  for (const name of ['/absolute.txt', 'C:\\outside.txt', '\\\\server\\share.txt', '../outside.txt']) {
    await assertRejectedAndClean(server, makeZip([{ name, data: 'unsafe' }]), 400, restrictedMessage);
  }
});

test('rejects duplicate normalized entry paths', async (t) => {
  const server = await startUploadServer(t);
  const archive = makeZip([
    { name: 'src/file.txt', data: 'one' },
    { name: 'src//file.txt', data: 'two' }
  ]);
  await assertRejectedAndClean(server, archive, 400, restrictedMessage);
});

test('rejects unsupported ZIP entry types', async (t) => {
  const server = await startUploadServer(t);
  const archive = makeZip([{
    name: 'link',
    data: 'target',
    externalAttributes: 0xA1FF0000
  }]);
  await assertRejectedAndClean(server, archive, 400, restrictedMessage);
});

test('rejects excessive path nesting', async (t) => {
  const server = await startUploadServer(t, { ...UPLOAD_LIMITS, pathDepth: 2 });
  await assertRejectedAndClean(
    server,
    makeZip([{ name: 'one/two/three.txt', data: 'content' }]),
    413,
    limitMessage
  );
});

test('rejects an archive that exceeds the entry-count limit', async (t) => {
  const server = await startUploadServer(t, { ...UPLOAD_LIMITS, entries: 2 });
  await assertRejectedAndClean(
    server,
    makeZip([
      { name: 'one.txt', data: '1' },
      { name: 'two.txt', data: '2' },
      { name: 'three.txt', data: '3' }
    ]),
    413,
    limitMessage
  );
});

test('enforces individual expanded-file limits against streamed bytes', async (t) => {
  const server = await startUploadServer(t, { ...UPLOAD_LIMITS, fileBytes: 3 });
  await assertRejectedAndClean(
    server,
    makeZip([{ name: 'large.txt', data: '1234', declaredSize: 2 }]),
    413,
    limitMessage
  );
});

test('enforces cumulative expanded-size limits against streamed bytes', async (t) => {
  const server = await startUploadServer(t, { ...UPLOAD_LIMITS, expandedBytes: 3 });
  await assertRejectedAndClean(
    server,
    makeZip([
      { name: 'first.txt', data: '12', declaredSize: 2 },
      { name: 'second.txt', data: '34', declaredSize: 1 }
    ]),
    413,
    limitMessage
  );
});

test('enforces the compressed upload limit', async (t) => {
  const server = await startUploadServer(t, { ...UPLOAD_LIMITS, compressedBytes: 1 });
  await assertRejectedAndClean(
    server,
    makeZip([{ name: 'file.txt', data: 'content' }]),
    413,
    'Upload exceeds the configured compressed upload limit'
  );
});

test('cleans the request-owned extraction workspace after rejection', async (t) => {
  const server = await startUploadServer(t);
  await assertRejectedAndClean(
    server,
    makeZip([{ name: '../outside.txt', data: 'must not be written' }]),
    400,
    restrictedMessage
  );
});

test('worker unavailability is sanitized and does not invoke Docker cleanup', async (t) => {
  const loggedErrors = [];
  let cleanupCalls = 0;
  const server = await startUploadServer(t, UPLOAD_LIMITS, {
    orchestrator: {
      async buildImage() { throw new Error('should not run'); },
      async cleanup() { cleanupCalls += 1; }
    },
    logger: { warn() {}, error: (...args) => loggedErrors.push(args) }
  });
  const session = await (await server.createSession()).json();
  const response = await server.uploadWithSession(
    makeZip([{ name: 'package.json', data: '{}' }]),
    session
  );
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: 'Isolated scan worker is unavailable; project scans are disabled'
  });
  assert.equal(cleanupCalls, 0);
  assert.equal(JSON.stringify(loggedErrors).includes('should not run'), false);
  assert.deepEqual(fs.readdirSync(server.uploadsRoot), []);
});
