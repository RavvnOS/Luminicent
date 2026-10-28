import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { isIP } from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createClient } from 'redis';
import {
  createRedisScanRecordStore,
  createRedisSessionRegistry,
  validateRedisConfiguration
} from '../utils/redisPersistence.js';

const OWNER_A = '12345';
const OWNER_B = '67890';
const integrationUrl = process.env.REDIS_INTEGRATION_URL;
const restartProbe = process.env.REDIS_RESTART_PROBE;
const restartPrefix = process.env.REDIS_RESTART_PREFIX;
const restartId = process.env.REDIS_RESTART_SCAN_ID;
const backendDirectory = fileURLToPath(new URL('..', import.meta.url));

const runBackendWithRedisUrl = async (redisUrl) => {
  const generatedSecret = () => randomBytes(32).toString('base64url');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: backendDirectory,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: '0',
      NODE_ENV: 'development',
      LUMINICENT_API_TOKEN: generatedSecret(),
      SESSION_SECRET: generatedSecret(),
      LUMINICENT_EXECUTION_MODE: 'disabled',
      LUMINICENT_BUILD_NETWORK: 'none',
      LUMINICENT_LOCAL_ONLY: 'false',
      LUMINICENT_COMPOSE_LOCAL_ONLY: 'false',
      LUMINICENT_TRUSTED_TLS_PROXY: 'false',
      FRONTEND_URL: 'http://localhost:5173',
      CORS_ORIGIN: 'http://localhost:5173',
      REDIS_URL: redisUrl
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { output += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { output += chunk; });
  const exitPromise = once(child, 'exit').then(([code]) => code);
  const timeout = setTimeout(() => child.kill(), 12_000);
  let exitCode;
  try {
    exitCode = await exitPromise;
  } finally {
    clearTimeout(timeout);
  }
  return { exitCode, output };
};

test('backend startup aborts on missing or unreachable Redis without fallback', async () => {
  const missing = await runBackendWithRedisUrl('');
  assert.equal(missing.exitCode, 1);
  assert.match(missing.output, /REDIS_URL is required for persistent session and scan storage/);
  assert.doesNotMatch(missing.output, /in-memory session|memory store|fallback/i);

  const unavailable = await runBackendWithRedisUrl('redis://127.0.0.1:1');
  assert.equal(unavailable.exitCode, 1);
  assert.match(unavailable.output, /Persistent Redis storage is unavailable; startup aborted/);
  assert.doesNotMatch(unavailable.output, /in-memory session|memory store|fallback/i);
});

const validateIntegrationUrl = (value) => {
  const validated = validateRedisConfiguration({
    REDIS_URL: value,
    NODE_ENV: 'test'
  });
  const url = new URL(validated);
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const ipVersion = isIP(host);
  if (host !== 'localhost' &&
      !(ipVersion === 4 && Number(host.split('.')[0]) === 127) &&
      !(ipVersion === 6 && host === '::1')) {
    throw new Error('Redis integration tests require a loopback-only Redis URL');
  }
  return validated;
};

const createConnectedClient = async (url) => {
  const client = createClient({ url });
  client.on('error', () => {});
  await client.connect();
  return client;
};

const cleanPrefix = async (client, prefix) => {
  const keys = [];
  for await (const key of client.scanIterator({ MATCH: `${prefix}:*`, COUNT: 100 })) {
    keys.push(key);
    if (keys.length >= 100) {
      await client.del(keys);
      keys.length = 0;
    }
  }
  if (keys.length > 0) await client.del(keys);
};

const closeClient = async (client) => {
  if (!client?.isOpen) return;
  await client.close();
};

test('real Redis AOF restart recovery probe', {
  skip: !['seed', 'verify'].includes(restartProbe)
}, async (t) => {
  assert.ok(integrationUrl, 'REDIS_INTEGRATION_URL is required for restart verification');
  assert.match(restartPrefix || '', /^luminicent-restart-it-[A-Za-z0-9_-]{1,58}$/);
  const client = await createConnectedClient(validateIntegrationUrl(integrationUrl));
  t.after(async () => {
    if (restartProbe === 'verify') await cleanPrefix(client, restartPrefix);
    await closeClient(client);
  });
  const store = createRedisScanRecordStore({
    client,
    keyPrefix: restartPrefix,
    retentionSeconds: 300
  });

  if (restartProbe === 'seed') {
    const record = await store.create({ ownerId: OWNER_A, source: 'upload' });
    t.diagnostic(`Restart recovery probe scan ID: ${record.id}`);
    return;
  }

  assert.match(restartId || '', /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  const recovered = await store.get(restartId, OWNER_A);
  assert.ok(recovered, 'scan record must survive the Redis process restart');
  assert.equal(recovered.status, 'queued');
  assert.equal(recovered.source, 'upload');
});

test('real Redis owner-scoped persistence, atomic capacity, expiry, retention, and outage behavior', {
  skip: !integrationUrl || ['seed', 'verify'].includes(restartProbe)
    ? 'Set REDIS_INTEGRATION_URL to a disposable loopback Redis service'
    : false
}, async (t) => {
  const url = validateIntegrationUrl(integrationUrl);
  const prefix = `luminicent-it-${randomUUID().replace(/-/g, '')}`;
  const clientA = await createConnectedClient(url);
  const clientB = await createConnectedClient(url);
  t.after(async () => {
    await cleanPrefix(clientA, prefix);
    await Promise.all([closeClient(clientA), closeClient(clientB)]);
  });

  const registryA = createRedisSessionRegistry({
    client: clientA,
    keyPrefix: prefix,
    ttlMs: 1800,
    maxSessions: 3
  });
  const registryB = createRedisSessionRegistry({
    client: clientB,
    keyPrefix: prefix,
    ttlMs: 1800,
    maxSessions: 3
  });
  t.after(() => {
    registryA.close();
    registryB.close();
  });

  const capability = await registryA.create(OWNER_A);
  assert.equal(await registryB.verify(
    capability.sessionId,
    capability.sessionToken,
    OWNER_A
  ), true);
  const rawCapabilityRecord = JSON.parse(await clientA.get(
    `${prefix}:{${OWNER_A}}:capability:${capability.sessionId}`
  ));
  assert.notEqual(rawCapabilityRecord.tokenDigest, capability.sessionToken);
  assert.equal(await registryB.getRemainingTtlMs(
    capability.sessionId,
    OWNER_A
  ) > 0, true);
  assert.equal(await registryB.verify(
    capability.sessionId,
    capability.sessionToken,
    OWNER_B
  ), false);
  assert.equal(await registryB.delete(
    capability.sessionId,
    capability.sessionToken,
    OWNER_B
  ), false);
  assert.equal(await registryB.verify(
    capability.sessionId,
    capability.sessionToken,
    OWNER_A
  ), true);
  await clientA.set(`${prefix}:{${OWNER_A}}:capabilities`, 'wrong-key-type');
  await assert.rejects(registryA.delete(
    capability.sessionId,
    capability.sessionToken,
    OWNER_A
  ), { code: 'PERSISTENCE_UNAVAILABLE' });
  assert.equal(await registryB.verify(
    capability.sessionId,
    capability.sessionToken,
    OWNER_A
  ), true);
  await clientA.del(`${prefix}:{${OWNER_A}}:capabilities`);
  assert.equal(await registryA.delete(
    capability.sessionId,
    capability.sessionToken,
    OWNER_A
  ), true);
  assert.equal(await registryB.verify(
    capability.sessionId,
    capability.sessionToken,
    OWNER_A
  ), false);

  const concurrentCreations = await Promise.allSettled(
    Array.from({ length: 12 }, (_, index) =>
      (index % 2 === 0 ? registryA : registryB).create(OWNER_A))
  );
  assert.equal(concurrentCreations.filter((result) => result.status === 'fulfilled').length, 3);
  assert.equal(concurrentCreations.filter((result) =>
    result.status === 'rejected' && result.reason.code === 'SESSION_CAPACITY'
  ).length, 9);
  for (const result of concurrentCreations) {
    if (result.status === 'fulfilled') {
      assert.equal(await registryB.verify(
        result.value.sessionId,
        result.value.sessionToken,
        OWNER_A
      ), true);
    }
  }
  const expiredCapability = concurrentCreations.find(
    (result) => result.status === 'fulfilled'
  ).value;
  assert.equal((await registryA.create(OWNER_B)).sessionId.length, 36);
  await new Promise((resolve) => setTimeout(resolve, 2100));
  assert.equal(await registryB.verify(
    expiredCapability.sessionId,
    expiredCapability.sessionToken,
    OWNER_A
  ), false);
  assert.equal(await registryB.has(expiredCapability.sessionId, OWNER_A), false);
  assert.equal(await registryB.delete(
    expiredCapability.sessionId,
    expiredCapability.sessionToken,
    OWNER_A
  ), false);
  await clientA.set(`${prefix}:{${OWNER_A}}:capabilities`, 'wrong-key-type');
  await assert.rejects(registryA.create(OWNER_A), {
    code: 'PERSISTENCE_UNAVAILABLE'
  });
  let partialCapabilityKeys = 0;
  for await (const _key of clientA.scanIterator({
    MATCH: `${prefix}:{${OWNER_A}}:capability:*`,
    COUNT: 100
  })) {
    partialCapabilityKeys += 1;
  }
  assert.equal(partialCapabilityKeys, 0);
  await clientA.del(`${prefix}:{${OWNER_A}}:capabilities`);

  const recordsA = createRedisScanRecordStore({
    client: clientA,
    keyPrefix: prefix,
    retentionSeconds: 30
  });
  const recordsB = createRedisScanRecordStore({
    client: clientB,
    keyPrefix: prefix,
    retentionSeconds: 30
  });
  const record = await recordsA.create({ ownerId: OWNER_A, source: 'github' });
  assert.deepEqual(await recordsB.get(record.id, OWNER_A), record);
  const defaultRetentionMs = await clientA.pTTL(`${prefix}:scan-record:${record.id}`);
  assert.ok(defaultRetentionMs > 30 * 24 * 60 * 60 * 1000 - 5000);
  assert.ok(defaultRetentionMs <= 30 * 24 * 60 * 60 * 1000);
  assert.equal(await recordsB.get(record.id, OWNER_B), null);
  assert.equal(Object.hasOwn(recordsA, 'list'), false);
  assert.equal(await recordsB.transition({
    id: record.id,
    ownerId: OWNER_B,
    expectedStatus: 'queued',
    status: 'running'
  }), null);
  await assert.rejects(recordsB.transition({
    id: record.id,
    ownerId: OWNER_A,
    expectedStatus: 'queued',
    status: 'completed'
  }), /Invalid scan record transition/);
  assert.equal((await recordsA.get(record.id, OWNER_A)).status, 'queued');

  const corruptedId = randomUUID();
  await clientA.set(`${prefix}:scan-record:${corruptedId}`, JSON.stringify({
    id: corruptedId,
    ownerId: OWNER_A,
    status: 'completed',
    source: 'upload'
  }), { EX: 30 });
  await assert.rejects(recordsB.get(corruptedId, OWNER_A), /Invalid scan record/);

  const expiringRecords = createRedisScanRecordStore({
    client: clientA,
    keyPrefix: prefix,
    retentionSeconds: 2
  });
  const expiringRecord = await expiringRecords.create({
    ownerId: OWNER_A,
    source: 'upload'
  });
  assert.ok(await clientA.pTTL(`${prefix}:scan-record:${expiringRecord.id}`) > 0);
  await new Promise((resolve) => setTimeout(resolve, 2300));
  assert.equal(await recordsB.get(expiringRecord.id, OWNER_A), null);

  const outageClient = await createConnectedClient(url);
  const outageRegistry = createRedisSessionRegistry({
    client: outageClient,
    keyPrefix: prefix
  });
  outageClient.destroy();
  await assert.rejects(
    outageRegistry.verify(record.id, 'not-a-capability', OWNER_A),
    { code: 'PERSISTENCE_UNAVAILABLE' }
  );
  await assert.rejects(
    outageRegistry.create(OWNER_A),
    { code: 'PERSISTENCE_UNAVAILABLE' }
  );
  const outageStore = createRedisScanRecordStore({
    client: outageClient,
    keyPrefix: prefix
  });
  await assert.rejects(
    outageStore.create({ ownerId: OWNER_A, source: 'upload' }),
    { code: 'PERSISTENCE_UNAVAILABLE' }
  );
  await assert.rejects(
    outageStore.get(record.id, OWNER_A),
    { code: 'PERSISTENCE_UNAVAILABLE' }
  );
  outageRegistry.close();
});
