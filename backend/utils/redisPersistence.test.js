import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createRedisScanRecordStore,
  createRedisSessionRegistry,
  validateRedisConfiguration
} from './redisPersistence.js';

class RedisContractMock {
  values = new Map();
  sortedSets = new Map();

  async eval(script, { keys, arguments: args }) {
    if (script.includes('luminicent:create-capability')) {
      const [ttl, max, value, sessionId] = args;
      const now = Date.now();
      const index = this.sortedSets.get(keys[1]) || new Map();
      for (const [id, expiresAt] of index) {
        if (expiresAt <= Number(now)) index.delete(id);
      }
      this.sortedSets.set(keys[1], index);
      if (index.size >= Number(max)) return 0;
      if (this.values.has(keys[0])) return -1;
      const record = JSON.parse(value);
      record.expiresAt = now + Number(ttl);
      this.values.set(keys[0], {
        value: JSON.stringify(record),
        expiresAt: now + Number(ttl)
      });
      index.set(sessionId, Number(now) + Number(ttl));
      return 1;
    }
    if (script.includes('luminicent:get-owned')) {
      const entry = this.values.get(keys[0]);
      if (!entry || entry.expiresAt <= Date.now()) return null;
      const record = JSON.parse(entry.value);
      return record.ownerId === args[0] ? entry.value : null;
    }
    if (script.includes('luminicent:delete-capability')) {
      const entry = this.values.get(keys[0]);
      if (!entry) return 0;
      const record = JSON.parse(entry.value);
      if (record.ownerId !== args[0] || record.tokenDigest !== args[1]) return 0;
      this.values.delete(keys[0]);
      this.sortedSets.get(keys[1])?.delete(args[2]);
      return 1;
    }
    if (script.includes('luminicent:create-scan-record')) {
      if (this.values.has(keys[0])) return 0;
      this.values.set(keys[0], { value: args[0], expiresAt: Infinity });
      return 1;
    }
    if (script.includes('luminicent:transition-scan-record')) {
      const entry = this.values.get(keys[0]);
      if (!entry) return null;
      const record = JSON.parse(entry.value);
      if (record.ownerId !== args[0] || record.id !== args[1] ||
          record.status !== args[2]) return null;
      const updated = JSON.parse(args[3]);
      entry.value = JSON.stringify(updated);
      return entry.value;
    }
    throw new Error('Unknown Redis script');
  }
}

const OWNER_A = '12345';
const OWNER_B = '67890';
const SCAN_ID = '123e4567-e89b-42d3-a456-426614174000';

test('Redis URL is mandatory and public production requires TLS', () => {
  assert.throws(() => validateRedisConfiguration({}), /REDIS_URL is required/);
  assert.throws(() => validateRedisConfiguration({ REDIS_URL: 'http://localhost:6379' }), /redis:\/\/ or rediss:\/\//);
  assert.throws(() => validateRedisConfiguration({
    REDIS_URL: 'redis://cache.example.test:6379',
    NODE_ENV: 'production'
  }), /TLS-protected, authenticated REDIS_URL/);
  assert.throws(() => validateRedisConfiguration({
    REDIS_URL: 'redis://user:password@cache.example.test:6379',
    NODE_ENV: 'production'
  }), /TLS-protected, authenticated REDIS_URL/);
  assert.throws(() => validateRedisConfiguration({
    REDIS_URL: 'rediss://cache.example.test:6380',
    NODE_ENV: 'production'
  }), /TLS-protected, authenticated REDIS_URL/);
  assert.equal(validateRedisConfiguration({
    REDIS_URL: 'redis://redis:6379',
    NODE_ENV: 'production',
    LUMINICENT_LOCAL_ONLY: 'true',
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'true'
  }), 'redis://redis:6379');
  assert.throws(() => validateRedisConfiguration({
    REDIS_URL: 'redis://redis:6379',
    NODE_ENV: 'production',
    LUMINICENT_COMPOSE_LOCAL_ONLY: 'true'
  }), /TLS-protected, authenticated REDIS_URL/);
  assert.equal(validateRedisConfiguration({
    REDIS_URL: 'rediss://default:secret@cache.example.test:6380',
    NODE_ENV: 'production'
  }), 'rediss://default:secret@cache.example.test:6380');
});

test('Redis persistence limits and namespaces are bounded', () => {
  const redis = new RedisContractMock();
  assert.throws(() => createRedisSessionRegistry({
    client: redis,
    ttlMs: 24 * 60 * 60 * 1000 + 1
  }), /limits must be positive safe integers/);
  assert.throws(() => createRedisSessionRegistry({
    client: redis,
    maxSessions: 100_001
  }), /limits must be positive safe integers/);
  assert.throws(() => createRedisSessionRegistry({
    client: redis,
    keyPrefix: 'unsafe:namespace'
  }), /key prefix is invalid/);
  assert.throws(() => createRedisScanRecordStore({
    client: redis,
    retentionSeconds: 366 * 24 * 60 * 60
  }), /retention must be a positive safe integer/);
});

test('owner-scoped capabilities survive registry recreation and fail closed', async () => {
  const redis = new RedisContractMock();
  const firstRegistry = createRedisSessionRegistry({
    client: redis,
    maxSessions: 1
  });
  const credentials = await firstRegistry.create(OWNER_A);
  await assert.rejects(firstRegistry.create(OWNER_A), { code: 'SESSION_CAPACITY' });
  firstRegistry.close();

  const restartedRegistry = createRedisSessionRegistry({
    client: redis,
    maxSessions: 1
  });
  assert.equal(await restartedRegistry.verify(
    credentials.sessionId,
    credentials.sessionToken,
    OWNER_A
  ), true);
  assert.equal(await restartedRegistry.verify(
    credentials.sessionId,
    credentials.sessionToken,
    OWNER_B
  ), false);
  assert.equal(await restartedRegistry.has(credentials.sessionId, OWNER_B), false);
  assert.equal(await restartedRegistry.delete(
    credentials.sessionId,
    credentials.sessionToken,
    OWNER_B
  ), false);
  assert.equal(await restartedRegistry.delete(
    credentials.sessionId,
    credentials.sessionToken,
    OWNER_A
  ), true);
  assert.equal(await restartedRegistry.verify(
    credentials.sessionId,
    credentials.sessionToken,
    OWNER_A
  ), false);
});

test('Redis capability operations surface storage outages instead of allowing access', async () => {
  const registry = createRedisSessionRegistry({
    client: { async eval() { throw new Error('connection unavailable'); } }
  });
  await assert.rejects(registry.verify(SCAN_ID, 'token', OWNER_A), {
    code: 'PERSISTENCE_UNAVAILABLE'
  });
  await assert.rejects(registry.create(OWNER_A), {
    code: 'PERSISTENCE_UNAVAILABLE'
  });
});

test('scan records reject untrusted fields and enforce owner-scoped lifecycle transitions', async () => {
  const now = '2026-03-01T10:00:00.000Z';
  const store = createRedisScanRecordStore({
    client: new RedisContractMock(),
    now: () => Date.parse(now)
  });
  await assert.rejects(store.create({
    ownerId: OWNER_A,
    source: 'upload',
    createdAt: now,
    command: 'arbitrary command'
  }), /Invalid scan record creation request/);
  const record = await store.create({ ownerId: OWNER_A, source: 'upload' });
  assert.notEqual(record.id, SCAN_ID);
  assert.equal(record.status, 'queued');
  assert.equal(await store.get(record.id, OWNER_B), null);
  assert.deepEqual(await store.get(record.id, OWNER_A), record);
  assert.equal(await store.transition({
    id: record.id,
    ownerId: OWNER_B,
    expectedStatus: 'queued',
    status: 'running'
  }), null);
  const running = await store.transition({
    id: record.id,
    ownerId: OWNER_A,
    expectedStatus: 'queued',
    status: 'running'
  });
  assert.equal(running.status, 'running');
  assert.equal(running.versionNumber, 2);
  assert.equal(await store.transition({
    id: record.id,
    ownerId: OWNER_A,
    expectedStatus: 'queued',
    status: 'running'
  }), null);
  const completed = await store.transition({
    id: record.id,
    ownerId: OWNER_A,
    expectedStatus: 'running',
    status: 'completed'
  });
  assert.equal(completed.status, 'completed');
  await assert.rejects(store.transition({
    id: record.id,
    ownerId: OWNER_A,
    expectedStatus: 'completed',
    status: 'running'
  }), /Invalid scan record transition/);
});
