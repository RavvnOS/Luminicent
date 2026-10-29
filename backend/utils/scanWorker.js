import { randomUUID } from 'node:crypto';

const SCAN_JOB_SCHEMA_VERSION = 1;
const SCAN_WORKER_MESSAGE_SCHEMA_VERSION = 1;
const SCAN_JOB_STATES = new Set([
  'queued',
  'running',
  'succeeded',
  'failed',
  'cancelled'
]);
const FAILURE_CODES = new Set([
  'worker_crashed',
  'worker_timeout',
  'worker_unavailable',
  'invalid_worker_output',
  'scan_failed'
]);
const SCAN_SOURCES = new Set(['upload', 'github']);
const OWNER_ID_PATTERN = /^[1-9]\d{0,19}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const JOB_KEYS = new Set([
  'schemaVersion',
  'jobId',
  'sessionId',
  'ownerId',
  'source',
  'createdAt',
  'updatedAt',
  'state',
  'failureCode'
]);
const WORKER_MESSAGE_KEYS = new Set([
  'schemaVersion',
  'jobId',
  'state',
  'sentAt',
  'failureCode'
]);

const isPlainObject = (value) => value !== null
  && typeof value === 'object'
  && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype
    || Object.getPrototypeOf(value) === null);

const hasOnlyKeys = (value, allowedKeys) => Object.keys(value)
  .every((key) => allowedKeys.has(key));

const isTimestamp = (value) => typeof value === 'string'
  && Number.isFinite(Date.parse(value))
  && new Date(value).toISOString() === value;

const validateScanJob = (job) => {
  if (!isPlainObject(job) || !hasOnlyKeys(job, JOB_KEYS)) {
    throw new TypeError('Invalid scan job schema');
  }
  if (job.schemaVersion !== SCAN_JOB_SCHEMA_VERSION
    || !UUID_PATTERN.test(job.jobId)
    || !UUID_PATTERN.test(job.sessionId)
    || typeof job.ownerId !== 'string'
    || !OWNER_ID_PATTERN.test(job.ownerId)
    || !SCAN_SOURCES.has(job.source)
    || !isTimestamp(job.createdAt)
    || !isTimestamp(job.updatedAt)
    || !SCAN_JOB_STATES.has(job.state)
    || (job.failureCode !== undefined && !FAILURE_CODES.has(job.failureCode))) {
    throw new TypeError('Invalid scan job fields');
  }
  if ((job.state === 'failed') !== (job.failureCode !== undefined)) {
    throw new TypeError('Invalid scan job failure state');
  }
  return job;
};

const validateWorkerMessage = (message) => {
  if (!isPlainObject(message) || !hasOnlyKeys(message, WORKER_MESSAGE_KEYS)) {
    throw new TypeError('Invalid worker message schema');
  }
  if (message.schemaVersion !== SCAN_WORKER_MESSAGE_SCHEMA_VERSION
    || !UUID_PATTERN.test(message.jobId)
    || !['running', 'succeeded', 'failed', 'cancelled'].includes(message.state)
    || !isTimestamp(message.sentAt)
    || (message.failureCode !== undefined && !FAILURE_CODES.has(message.failureCode))) {
    throw new TypeError('Invalid worker message fields');
  }
  if ((message.state === 'failed') !== (message.failureCode !== undefined)) {
    throw new TypeError('Invalid worker message failure state');
  }
  return message;
};

const ALLOWED_TRANSITIONS = Object.freeze({
  queued: new Set(['running', 'failed', 'cancelled']),
  running: new Set(['succeeded', 'failed', 'cancelled']),
  succeeded: new Set(),
  failed: new Set(),
  cancelled: new Set()
});

export const createScanJob = (input) => {
  if (!isPlainObject(input)
    || !hasOnlyKeys(input, new Set(['sessionId', 'ownerId', 'source']))) {
    throw new TypeError('Invalid scan job input');
  }
  const { sessionId, ownerId, source } = input;
  if (!UUID_PATTERN.test(sessionId)
    || typeof ownerId !== 'string'
    || !OWNER_ID_PATTERN.test(ownerId)
    || !SCAN_SOURCES.has(source)) {
    throw new TypeError('Invalid scan job input');
  }
  const timestamp = new Date().toISOString();
  return Object.freeze({
    schemaVersion: SCAN_JOB_SCHEMA_VERSION,
    jobId: randomUUID(),
    sessionId,
    ownerId,
    source,
    createdAt: timestamp,
    updatedAt: timestamp,
    state: 'queued'
  });
};

export const transitionScanJob = (job, state, failureCode) => {
  validateScanJob(job);
  if (!SCAN_JOB_STATES.has(state) || !ALLOWED_TRANSITIONS[job.state].has(state)) {
    throw new TypeError('Invalid scan job state transition');
  }
  if ((state === 'failed') !== (failureCode !== undefined)
    || (failureCode !== undefined && !FAILURE_CODES.has(failureCode))) {
    throw new TypeError('Invalid scan job failure code');
  }
  return Object.freeze({
    ...job,
    state,
    updatedAt: new Date().toISOString(),
    ...(failureCode === undefined ? {} : { failureCode })
  });
};

export const applyScanWorkerMessage = (job, rawMessage) => {
  validateScanJob(job);
  const message = validateWorkerMessage(rawMessage);
  if (message.jobId !== job.jobId) {
    throw new TypeError('Worker message job mismatch');
  }
  return transitionScanJob(job, message.state, message.failureCode);
};

export const scanJobBelongsToSession = (job, sessionId) => {
  validateScanJob(job);
  return typeof sessionId === 'string' && job.sessionId === sessionId;
};

export const scanJobBelongsToOwner = (job, ownerId) => {
  validateScanJob(job);
  return typeof ownerId === 'string' && job.ownerId === ownerId;
};

export const scanWorker = Object.freeze({
  getStatus() {
    return Object.freeze({
      state: 'unavailable',
      reason: 'isolated_worker_not_configured'
    });
  },
  isAvailable() {
    return false;
  },
  async submit(rawJob) {
    validateScanJob(rawJob);
    throw Object.assign(new Error('Isolated scan worker is unavailable'), {
      code: 'SCAN_WORKER_UNAVAILABLE'
    });
  },
  async cancel(rawJob) {
    validateScanJob(rawJob);
    throw Object.assign(new Error('Isolated scan worker is unavailable'), {
      code: 'SCAN_WORKER_UNAVAILABLE'
    });
  }
});
