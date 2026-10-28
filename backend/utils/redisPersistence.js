import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const SESSION_TTL_MS = 15 * 60 * 1000;
const MAX_ACTIVE_SESSIONS = 1000;
const MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ACTIVE_SESSION_LIMIT = 100_000;
const MAX_SCAN_RETENTION_SECONDS = 365 * 24 * 60 * 60;
const OWNER_ID_PATTERN = /^[1-9]\d{0,19}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY_PREFIX_PATTERN = /^[A-Za-z0-9_-]{1,80}$/;
const digest = (value) => createHash('sha256').update(value).digest('hex');
const validOwnerId = (value) =>
  (typeof value === 'string' && OWNER_ID_PATTERN.test(value)) ||
  (Number.isSafeInteger(value) && value > 0);

const runPersistentOperation = async (operation) => {
  try {
    return await operation();
  } catch {
    const error = new Error('Persistent Redis operation failed');
    error.code = 'PERSISTENCE_UNAVAILABLE';
    throw error;
  }
};

const CREATE_CAPABILITY = `
-- luminicent:create-capability
local indexType = redis.call('TYPE', KEYS[2]).ok
if indexType ~= 'none' and indexType ~= 'zset' then
  return redis.error_reply('invalid capability index key type')
end
local ttl = tonumber(ARGV[2])
local max = tonumber(ARGV[3])
if not ttl or ttl < 1 or ttl ~= math.floor(ttl) or
   not max or max < 1 or max ~= math.floor(max) then
  return redis.error_reply('invalid capability limits')
end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('ZCARD', KEYS[2]) >= max then
  return 0
end
local record = cjson.decode(ARGV[4])
if type(record.ownerId) ~= 'string' or type(record.tokenDigest) ~= 'string' then
  return redis.error_reply('invalid capability record')
end
record.expiresAt = now + ttl
if redis.call('SET', KEYS[1], cjson.encode(record), 'PX', ttl, 'NX') then
  redis.call('ZADD', KEYS[2], record.expiresAt, ARGV[5])
  redis.call('PEXPIRE', KEYS[2], ttl * 2)
  return 1
end
return -1
`;

const GET_OWNED = `
-- luminicent:get-owned
if redis.call('PTTL', KEYS[1]) <= 0 then return nil end
local value = redis.call('GET', KEYS[1])
if not value then return nil end
local record = cjson.decode(value)
if record.ownerId ~= ARGV[1] then return nil end
return value
`;

const DELETE_CAPABILITY = `
-- luminicent:delete-capability
local indexType = redis.call('TYPE', KEYS[2]).ok
if indexType ~= 'none' and indexType ~= 'zset' then
  return redis.error_reply('invalid capability index key type')
end
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
local record = cjson.decode(value)
if record.ownerId ~= ARGV[1] or record.tokenDigest ~= ARGV[2] then return 0 end
redis.call('ZREM', KEYS[2], ARGV[3])
redis.call('DEL', KEYS[1])
return 1
`;

const CREATE_SCAN_RECORD = `
-- luminicent:create-scan-record
if redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX') then return 1 end
return 0
`;

const TRANSITION_SCAN_RECORD = `
-- luminicent:transition-scan-record
local value = redis.call('GET', KEYS[1])
if not value then return nil end
local record = cjson.decode(value)
if record.ownerId ~= ARGV[1] or record.id ~= ARGV[2] or record.status ~= ARGV[3] then return nil end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return nil end
local updated = cjson.decode(ARGV[4])
redis.call('SET', KEYS[1], cjson.encode(updated), 'PX', ttl)
return cjson.encode(updated)
`;

const readOwned = async (client, key, ownerId) => {
  const value = await runPersistentOperation(() => client.eval(GET_OWNED, {
    keys: [key],
    arguments: [String(ownerId)]
  }));
  if (typeof value !== 'string') return null;
  try {
    return JSON.parse(value);
  } catch {
    throw new Error('Persistent record is malformed');
  }
};

const validateCapabilityRecord = (record, ownerId) => {
  const keys = ['version', 'ownerId', 'tokenDigest', 'expiresAt'];
  if (!record || typeof record !== 'object' || Array.isArray(record) ||
      Object.keys(record).some((key) => !keys.includes(key)) ||
      record.version !== 1 || record.ownerId !== ownerId ||
      typeof record.tokenDigest !== 'string' || !/^[0-9a-f]{64}$/.test(record.tokenDigest) ||
      !Number.isSafeInteger(record.expiresAt)) {
    throw new Error('Persistent capability record is malformed');
  }
  return record;
};

export const validateRedisConfiguration = (env = process.env) => {
  const value = env.REDIS_URL;
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error('REDIS_URL is required for persistent session and scan storage');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('REDIS_URL must be a valid Redis URL');
  }
  if (!['redis:', 'rediss:'].includes(url.protocol) || !url.hostname ||
      url.search || url.hash) {
    throw new Error('REDIS_URL must use redis:// or rediss:// without query or fragment');
  }
  const composeLocalOnly = env.LUMINICENT_LOCAL_ONLY === 'true' &&
    env.LUMINICENT_COMPOSE_LOCAL_ONLY === 'true';
  if (env.NODE_ENV === 'production' && !composeLocalOnly &&
      (url.protocol !== 'rediss:' || !url.password)) {
    throw new Error('Public production deployments require a TLS-protected, authenticated REDIS_URL');
  }
  return value;
};

export const createRedisSessionRegistry = ({
  client,
  keyPrefix = 'luminicent',
  ttlMs = SESSION_TTL_MS,
  maxSessions = MAX_ACTIVE_SESSIONS,
  onDelete = () => {}
} = {}) => {
  if (!client || typeof client.eval !== 'function') {
    throw new TypeError('A connected Redis client is required for session persistence');
  }
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_SESSION_TTL_MS ||
      !Number.isSafeInteger(maxSessions) || maxSessions <= 0 ||
      maxSessions > MAX_ACTIVE_SESSION_LIMIT) {
    throw new TypeError('Session persistence limits must be positive safe integers');
  }
  if (!KEY_PREFIX_PATTERN.test(keyPrefix)) {
    throw new TypeError('Session persistence key prefix is invalid');
  }
  const sessionKey = (id, ownerId) => `${keyPrefix}:{${ownerId}}:capability:${id}`;
  const ownerIndexKey = (ownerId) => `${keyPrefix}:{${ownerId}}:capabilities`;
  let closed = false;

  const verify = async (sessionId, token, ownerId) => {
    const normalizedOwnerId = validOwnerId(ownerId) ? String(ownerId) : null;
    if (closed || typeof sessionId !== 'string' || !UUID_PATTERN.test(sessionId) ||
        typeof token !== 'string' || !normalizedOwnerId) return false;
    const stored = await readOwned(client, sessionKey(sessionId, normalizedOwnerId), normalizedOwnerId);
    if (!stored) return false;
    const record = validateCapabilityRecord(stored, normalizedOwnerId);
    const suppliedDigest = Buffer.from(digest(token), 'hex');
    const storedDigest = Buffer.from(record.tokenDigest, 'hex');
    return suppliedDigest.length === storedDigest.length &&
      timingSafeEqual(suppliedDigest, storedDigest);
  };

  return {
    async create(ownerId) {
      if (closed) throw new Error('Session registry is closed');
      if (!validOwnerId(ownerId)) {
        throw new TypeError('An authenticated owner is required to create a session');
      }
      const normalizedOwnerId = String(ownerId);
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const sessionId = randomUUID();
        const sessionToken = randomBytes(32).toString('base64url');
        const record = JSON.stringify({
          version: 1,
          ownerId: normalizedOwnerId,
          tokenDigest: digest(sessionToken)
        });
        const result = await runPersistentOperation(() => client.eval(CREATE_CAPABILITY, {
          keys: [sessionKey(sessionId, normalizedOwnerId), ownerIndexKey(normalizedOwnerId)],
          arguments: [
            String(ttlMs),
            String(maxSessions),
            record,
            sessionId
          ]
        }));
        if (result === 1) return { sessionId, sessionToken };
        if (result === 0) {
          const error = new Error('Session capacity reached; retry after an active session expires or is cleaned up');
          error.code = 'SESSION_CAPACITY';
          throw error;
        }
      }
      throw new Error('Unable to allocate a unique session capability');
    },
    verify,
    async has(sessionId, ownerId) {
      if (closed || typeof sessionId !== 'string' || !UUID_PATTERN.test(sessionId) ||
          !validOwnerId(ownerId)) return false;
      const normalizedOwnerId = String(ownerId);
      const record = await readOwned(client, sessionKey(sessionId, normalizedOwnerId), normalizedOwnerId);
      if (!record) return false;
      validateCapabilityRecord(record, normalizedOwnerId);
      return true;
    },
    async getRemainingTtlMs(sessionId, ownerId) {
      if (closed || typeof sessionId !== 'string' || !UUID_PATTERN.test(sessionId) ||
          !validOwnerId(ownerId)) return null;
      const normalizedOwnerId = String(ownerId);
      const stored = await readOwned(client, sessionKey(sessionId, normalizedOwnerId), normalizedOwnerId);
      if (!stored) return null;
      validateCapabilityRecord(stored, normalizedOwnerId);
      const remaining = await runPersistentOperation(() =>
        client.pTTL(sessionKey(sessionId, normalizedOwnerId)));
      return Number.isSafeInteger(remaining) && remaining > 0 ? remaining : null;
    },
    async delete(sessionId, token, ownerId) {
      if (closed || typeof sessionId !== 'string' || !UUID_PATTERN.test(sessionId) ||
          typeof token !== 'string' || !validOwnerId(ownerId)) return false;
      const normalizedOwnerId = String(ownerId);
      const deleted = await runPersistentOperation(() => client.eval(DELETE_CAPABILITY, {
        keys: [sessionKey(sessionId, normalizedOwnerId), ownerIndexKey(normalizedOwnerId)],
        arguments: [normalizedOwnerId, digest(token), sessionId]
      }));
      if (deleted === 1) onDelete(sessionId);
      return deleted === 1;
    },
    close() {
      closed = true;
    }
  };
};

const SCAN_STATES = new Set(['queued', 'running', 'completed', 'failed', 'cancelled', 'unavailable']);
const ALLOWED_TRANSITIONS = {
  queued: new Set(['running', 'failed', 'cancelled', 'unavailable']),
  running: new Set(['completed', 'failed', 'cancelled']),
  completed: new Set(),
  failed: new Set(),
  cancelled: new Set(),
  unavailable: new Set()
};

const validateScanRecord = (record) => {
  const allowedFields = new Set([
    'id', 'version', 'ownerId', 'source', 'status', 'versionNumber',
    'createdAt', 'updatedAt', 'failureCode'
  ]);
  if (!record || typeof record !== 'object' || Array.isArray(record) ||
      Object.keys(record).some((key) => !allowedFields.has(key)) ||
      record.version !== 1 || typeof record.id !== 'string' || !UUID_PATTERN.test(record.id) ||
      typeof record.ownerId !== 'string' || !validOwnerId(record.ownerId) ||
      !['upload', 'github'].includes(record.source) ||
      !SCAN_STATES.has(record.status) ||
      !Number.isSafeInteger(record.versionNumber) || record.versionNumber < 1 ||
      typeof record.createdAt !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(record.createdAt) ||
      !Number.isFinite(Date.parse(record.createdAt)) ||
      typeof record.updatedAt !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(record.updatedAt) ||
      !Number.isFinite(Date.parse(record.updatedAt))) {
    throw new TypeError('Invalid scan record');
  }
  if (record.failureCode !== undefined &&
      !['worker_unavailable', 'worker_failed', 'timeout', 'cancelled', 'invalid_output'].includes(record.failureCode)) {
    throw new TypeError('Invalid scan failure code');
  }
  const failureCodesByStatus = {
    failed: new Set(['worker_failed', 'timeout', 'invalid_output']),
    cancelled: new Set(['cancelled']),
    unavailable: new Set(['worker_unavailable'])
  };
  const allowedFailureCodes = failureCodesByStatus[record.status];
  if ((allowedFailureCodes && !allowedFailureCodes.has(record.failureCode)) ||
      (!allowedFailureCodes && record.failureCode !== undefined)) {
    throw new TypeError('Failure code is inconsistent with scan status');
  }
};

export const createRedisScanRecordStore = ({
  client,
  keyPrefix = 'luminicent',
  retentionSeconds = 30 * 24 * 60 * 60,
  now = Date.now
} = {}) => {
  if (!client || typeof client.eval !== 'function') {
    throw new TypeError('A connected Redis client is required for scan-record persistence');
  }
  if (!Number.isSafeInteger(retentionSeconds) || retentionSeconds <= 0 ||
      retentionSeconds > MAX_SCAN_RETENTION_SECONDS) {
    throw new TypeError('Scan-record retention must be a positive safe integer');
  }
  if (!KEY_PREFIX_PATTERN.test(keyPrefix)) {
    throw new TypeError('Scan-record persistence key prefix is invalid');
  }
  const keyFor = (id) => `${keyPrefix}:scan-record:${id}`;

  return {
    async create(input) {
      if (!input || typeof input !== 'object' || Array.isArray(input) ||
          Object.keys(input).some((key) => !['ownerId', 'source'].includes(key)) ||
          !validOwnerId(input.ownerId) ||
          !['upload', 'github'].includes(input.source)) {
        throw new TypeError('Invalid scan record creation request');
      }
      const createdAt = new Date(now()).toISOString();
      const normalizedRecord = {
        id: randomUUID(),
        version: 1,
        ownerId: String(input.ownerId),
        source: input.source,
        status: 'queued',
        versionNumber: 1,
        createdAt,
        updatedAt: createdAt
      };
      validateScanRecord(normalizedRecord);
      const value = JSON.stringify(normalizedRecord);
      const result = await runPersistentOperation(() => client.eval(CREATE_SCAN_RECORD, {
        keys: [keyFor(normalizedRecord.id)],
        arguments: [value, String(retentionSeconds)]
      }));
      if (result !== 1) throw new Error('Scan record already exists');
      return normalizedRecord;
    },
    async get(id, ownerId) {
      if (typeof id !== 'string' || !UUID_PATTERN.test(id) || !validOwnerId(ownerId)) {
        return null;
      }
      const record = await readOwned(client, keyFor(id), String(ownerId));
      if (!record) return null;
      validateScanRecord(record);
      if (record.id !== id) throw new Error('Persistent scan record ID does not match its key');
      return record;
    },
    async transition({ id, ownerId, expectedStatus, status, failureCode }) {
      if (typeof id !== 'string' || !UUID_PATTERN.test(id) || !validOwnerId(ownerId) ||
          !SCAN_STATES.has(expectedStatus) || !SCAN_STATES.has(status) ||
          !ALLOWED_TRANSITIONS[expectedStatus].has(status)) {
        throw new TypeError('Invalid scan record transition');
      }
      if (failureCode !== undefined &&
          !['worker_unavailable', 'worker_failed', 'timeout', 'cancelled', 'invalid_output'].includes(failureCode)) {
        throw new TypeError('Invalid scan failure code');
      }
      const key = keyFor(id);
      const current = await readOwned(client, key, String(ownerId));
      if (!current || current.id !== id || current.status !== expectedStatus) return null;
      const updated = {
        ...current,
        status,
        updatedAt: new Date(now()).toISOString(),
        versionNumber: current.versionNumber + 1
      };
      delete updated.failureCode;
      if (failureCode !== undefined) updated.failureCode = failureCode;
      validateScanRecord(updated);
      const result = await runPersistentOperation(() => client.eval(TRANSITION_SCAN_RECORD, {
        keys: [key],
        arguments: [String(ownerId), id, expectedStatus, JSON.stringify(updated)]
      }));
      if (typeof result !== 'string') return null;
      const persisted = JSON.parse(result);
      validateScanRecord(persisted);
      return persisted;
    }
  };
};
