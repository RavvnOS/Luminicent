import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  applyScanWorkerMessage,
  createScanJob,
  scanJobBelongsToOwner,
  scanJobBelongsToSession,
  scanWorker,
  transitionScanJob
} from './scanWorker.js';

const sessionId = '95d07d30-29bc-4f4e-a120-05f3479f851c';
const ownerId = '12345';
const workerMessage = (job, state, extra = {}) => ({
  schemaVersion: 1,
  jobId: job.jobId,
  state,
  sentAt: new Date().toISOString(),
  ...extra
});

test('creates a server-identified, constrained scan job', () => {
  const job = createScanJob({ sessionId, ownerId, source: 'upload' });
  assert.equal(job.schemaVersion, 1);
  assert.match(job.jobId, /^[0-9a-f-]{36}$/i);
  assert.equal(job.sessionId, sessionId);
  assert.equal(job.ownerId, ownerId);
  assert.equal(typeof job.createdAt, 'string');
  assert.equal(job.updatedAt, job.createdAt);
  assert.equal(job.source, 'upload');
  assert.equal(job.state, 'queued');
  assert.equal(Object.isFrozen(job), true);
  assert.deepEqual(Object.keys(job).sort(), [
    'createdAt',
    'jobId',
    'ownerId',
    'schemaVersion',
    'sessionId',
    'source',
    'state',
    'updatedAt'
  ]);
});

test('rejects invalid client-derived job fields and identifiers', () => {
  assert.throws(() => createScanJob({
    sessionId,
    ownerId,
    source: 'upload',
    command: 'arbitrary command'
  }), /Invalid scan job input/);
  assert.throws(() => createScanJob({
    sessionId: '../other-user',
    ownerId,
    source: 'upload'
  }), /Invalid scan job input/);
  assert.throws(() => createScanJob({
    sessionId,
    ownerId,
    source: 'docker'
  }), /Invalid scan job input/);
  assert.throws(() => createScanJob({
    sessionId,
    ownerId: 'not-an-identity',
    source: 'upload'
  }), /Invalid scan job input/);
});

test('validates bounded lifecycle transitions and failure codes', () => {
  const job = createScanJob({ sessionId, ownerId, source: 'github' });
  const running = applyScanWorkerMessage(job, workerMessage(job, 'running'));
  const succeeded = applyScanWorkerMessage(running, workerMessage(job, 'succeeded'));
  assert.equal(running.state, 'running');
  assert.equal(succeeded.state, 'succeeded');
  assert.equal(job.state, 'queued');

  const failed = transitionScanJob(job, 'failed', 'worker_timeout');
  assert.equal(failed.state, 'failed');
  assert.equal(failed.failureCode, 'worker_timeout');
  assert.throws(() => transitionScanJob(job, 'succeeded'), /Invalid scan job state transition/);
  assert.throws(() => transitionScanJob(job, 'failed', 'internal exception text'), /Invalid scan job failure code/);
  assert.throws(() => transitionScanJob(succeeded, 'running'), /Invalid scan job state transition/);
});

test('rejects mismatched and malformed untrusted worker messages', () => {
  const job = createScanJob({ sessionId, ownerId, source: 'upload' });
  assert.throws(() => applyScanWorkerMessage(job, {
    ...workerMessage(job, 'running'),
    command: 'run arbitrary code'
  }), /Invalid worker message schema/);
  assert.throws(() => applyScanWorkerMessage(job, {
    ...workerMessage(job, 'running'),
    hostPath: 'C:\\private'
  }), /Invalid worker message schema/);
  assert.throws(() => applyScanWorkerMessage(job, {
    ...workerMessage(job, 'running'),
    result: { report: 'unvalidated' }
  }), /Invalid worker message schema/);
  assert.throws(() => applyScanWorkerMessage(job, {
    ...workerMessage(job, 'running'),
    jobId: '00000000-0000-4000-8000-000000000000'
  }), /Worker message job mismatch/);
  assert.throws(() => applyScanWorkerMessage(job, {
    ...workerMessage(job, 'failed'),
    failureCode: 'secret error detail'
  }), /Invalid worker message fields/);
});

test('checks job ownership against the session capability identifier', () => {
  const job = createScanJob({ sessionId, ownerId, source: 'upload' });
  assert.equal(scanJobBelongsToSession(job, sessionId), true);
  assert.equal(scanJobBelongsToSession(job, '95d07d30-29bc-4f4e-a120-05f3479f851d'), false);
  assert.equal(scanJobBelongsToOwner(job, ownerId), true);
  assert.equal(scanJobBelongsToOwner(job, '67890'), false);
  assert.throws(() => scanJobBelongsToSession({ ...job, command: 'run' }, sessionId), /Invalid scan job schema/);
});

test('reports the isolated worker unavailable and never silently dispatches', async () => {
  const job = createScanJob({ sessionId, ownerId, source: 'upload' });
  assert.deepEqual(scanWorker.getStatus(), {
    state: 'unavailable',
    reason: 'isolated_worker_not_configured'
  });
  assert.equal(scanWorker.isAvailable(), false);
  await assert.rejects(scanWorker.submit(job), { code: 'SCAN_WORKER_UNAVAILABLE' });
  await assert.rejects(scanWorker.cancel(job), { code: 'SCAN_WORKER_UNAVAILABLE' });
});
