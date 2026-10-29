import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import DockerOrchestrator, { DOCKER_LIMITS } from './dockerOrchestrator.js';

const createIo = () => ({
  sockets: { adapter: { rooms: new Map() } },
  to() { return { emit() {} }; },
  emit() {}
});

const createOrchestrator = (io, options = {}) => new DockerOrchestrator(io, {
  executionMode: 'trusted-local',
  ...options
});

const createDocker = (overrides = {}) => {
  const calls = {
    buildOptions: [],
    createOptions: [],
    containers: new Map(),
    removedImages: []
  };
  const containerDefaults = {
    id: 'container-default',
    async start() {},
    async inspect() { return { State: { Running: true } }; },
    async logs() { return new PassThrough(); },
    async stats() { return new PassThrough(); },
    async stop() { calls.stopCount = (calls.stopCount || 0) + 1; },
    async remove() { calls.removeCount = (calls.removeCount || 0) + 1; }
  };
  const docker = {
    async version() { return { Version: 'mock' }; },
    ping(callback) { callback(null); },
    buildImage(_context, options) {
      calls.buildOptions.push(options);
      return Promise.resolve(new PassThrough());
    },
    modem: {
      followProgress(_stream, finished, progress) {
        progress({ aux: { ID: 'sha256:built-image' } });
        queueMicrotask(() => finished(null, []));
      }
    },
    getImage(imageRef) {
      return {
        async inspect() {
          return {
            Id: imageRef.startsWith('sha256:') ? imageRef : 'sha256:built-image',
            Config: { User: '' }
          };
        },
        async tag() {},
        async remove() { calls.removedImages.push(imageRef); }
      };
    },
    async createContainer(options) {
      calls.createOptions.push(options);
      const container = {
        ...containerDefaults,
        id: `container-${calls.createOptions.length}`,
        ...overrides.container
      };
      calls.containers.set(container.id, container);
      return container;
    },
    getContainer(id) {
      const container = calls.containers.get(id);
      if (!container) throw new Error(`Unknown mock container ${id}`);
      return container;
    },
    ...overrides.docker
  };
  return { docker, calls };
};

const makeBuildContext = (t) => {
  const context = fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-docker-test-'));
  const dockerfilePath = path.join(context, 'Dockerfile');
  fs.writeFileSync(dockerfilePath, 'FROM scratch\n');
  t.after(() => fs.rmSync(context, { recursive: true, force: true }));
  return { context, dockerfilePath };
};

test('build timeout aborts Dockerode build request and cleans tracked image refs', async (t) => {
  const { context, dockerfilePath } = makeBuildContext(t);
  const buildStream = new PassThrough();
  const { docker, calls } = createDocker({
    docker: {
      buildImage(_context, options) {
        calls.buildOptions.push(options);
        return Promise.resolve(buildStream);
      },
      modem: {
        followProgress(_stream, _finished, progress) {
          progress({ aux: { ID: 'sha256:partial-image' } });
        }
      }
    }
  });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    buildTimeoutMs: 15,
    logger: { error() {}, warn() {} }
  });

  await assert.rejects(
    orchestrator.buildImage(context, 'test-timeout', 'timeout-session', dockerfilePath),
    (error) => error.code === 'BUILD_TIMEOUT'
  );
  assert.equal(calls.buildOptions[0].abortSignal.aborted, true);
  assert.equal(buildStream.destroyed, true);
  assert.equal(calls.buildOptions[0].networkmode, 'none');
  assert.equal('authconfig' in calls.buildOptions[0], false);
  assert.equal('buildargs' in calls.buildOptions[0], false);
  assert.equal('Env' in calls.buildOptions[0], false);
  assert.equal(calls.buildOptions[0].memory, DOCKER_LIMITS.buildMemoryBytes);
  assert.deepEqual(calls.removedImages.sort(), ['sha256:partial-image', 'test-timeout']);
  assert.equal(orchestrator.buildControllers.has('timeout-session'), false);
});

test('Docker connectivity check has a bounded wait', async (t) => {
  const { context, dockerfilePath } = makeBuildContext(t);
  const { docker, calls } = createDocker({ docker: { ping() {} } });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    connectivityTimeoutMs: 15,
    logger: { error() {}, warn() {} }
  });
  const startedAt = Date.now();

  await assert.rejects(
    orchestrator.buildImage(context, 'test-ping-timeout', 'ping-timeout-session', dockerfilePath),
    (error) => error.code === 'DOCKER_CONNECTIVITY_FAILED'
  );
  assert.ok(Date.now() - startedAt < 500);
  await orchestrator.cleanup('ping-timeout-session');
  assert.deepEqual(calls.removedImages, ['test-ping-timeout']);
});

test('explicit session cancellation aborts the active Docker build request', async (t) => {
  const { context, dockerfilePath } = makeBuildContext(t);
  const { docker, calls } = createDocker({
    docker: {
      buildImage(_context, options) {
        calls.buildOptions.push(options);
        return new Promise((_resolve, reject) => {
          options.abortSignal.addEventListener(
            'abort',
            () => reject(options.abortSignal.reason),
            { once: true }
          );
        });
      }
    }
  });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    logger: { error() {}, warn() {} }
  });
  const build = orchestrator.buildImage(
    context,
    'test-cancel',
    'cancel-session',
    dockerfilePath
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.buildOptions.length, 1);
  const cancellation = orchestrator.cancelSession('cancel-session');

  await assert.rejects(build, (error) => error.code === 'ABORT_ERR');
  await cancellation;
  assert.equal(calls.buildOptions[0].abortSignal.aborted, true);
  assert.deepEqual(calls.removedImages, ['test-cancel']);
});

test('runtime uses hard CPU, memory, process, network, and privilege boundaries', async () => {
  const { docker, calls } = createDocker();
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    runtimeTimeoutMs: 10000,
    logger: { error() {}, warn() {} }
  });

  await orchestrator.runContainer('runtime-image', 'runtime-session');
  const options = calls.createOptions[0];
  assert.equal(options.User, '65532:65532');
  assert.equal('Env' in options, false);
  assert.equal(options.HostConfig.Memory, 512 * 1024 * 1024);
  assert.equal(options.HostConfig.MemorySwap, 512 * 1024 * 1024);
  assert.equal(options.HostConfig.CpuPeriod, 100000);
  assert.equal(options.HostConfig.CpuQuota, 50000);
  assert.equal(options.HostConfig.PidsLimit, 128);
  assert.equal(options.HostConfig.NetworkMode, 'none');
  assert.deepEqual(options.HostConfig.CapDrop, ['ALL']);
  assert.deepEqual(options.HostConfig.SecurityOpt, ['no-new-privileges:true']);
  assert.equal(options.HostConfig.Tmpfs['/tmp'].includes('size=67108864'), true);
  assert.deepEqual(options.HostConfig.LogConfig, {
    Type: 'local',
    Config: { 'max-size': '10m', 'max-file': '1' }
  });
  assert.equal('Binds' in options.HostConfig, false);
  await orchestrator.cleanup('runtime-session');
});

test('execution is disabled by default and rejects build and runtime work before Docker calls', async () => {
  const { docker, calls } = createDocker();
  const orchestrator = new DockerOrchestrator(createIo(), {
    docker,
    executionMode: 'disabled',
    logger: { error() {}, warn() {} }
  });
  assert.equal(orchestrator.isExecutionEnabled(), false);
  await assert.rejects(
    orchestrator.runContainer('image', 'disabled-runtime'),
    (error) => error.code === 'EXECUTION_DISABLED'
  );
  assert.throws(
    () => orchestrator.buildImage('.', 'image', 'disabled-build', 'Dockerfile'),
    (error) => error.code === 'EXECUTION_DISABLED'
  );
  assert.equal(calls.createOptions.length, 0);
  assert.equal(calls.buildOptions.length, 0);
});

test('build network mode is constrained and passed separately from runtime networking', async (t) => {
  const { context, dockerfilePath } = makeBuildContext(t);
  const { docker, calls } = createDocker();
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    buildNetwork: 'default',
    containerNetwork: 'none',
    logger: { error() {}, warn() {} }
  });
  await orchestrator.buildImage(context, 'network-image', 'network-session', dockerfilePath);
  assert.equal(calls.buildOptions[0].networkmode, 'default');
  await orchestrator.runContainer('network-image', 'network-session');
  assert.equal(calls.createOptions[0].HostConfig.NetworkMode, 'none');
  await orchestrator.cleanup('network-session');
});

test('orchestrator rejects unsupported build network modes', () => {
  assert.throws(() => createOrchestrator(createIo(), {
    docker: {},
    buildNetwork: 'host'
  }), /LUMINICENT_BUILD_NETWORK must be/);
});

test('runtime deadline stops and removes the running container', async () => {
  const { docker, calls } = createDocker();
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    runtimeTimeoutMs: 10,
    logger: { error() {}, warn() {} }
  });

  await orchestrator.runContainer('runtime-image', 'deadline-session');
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(calls.stopCount, 1);
  assert.equal(calls.removeCount, 1);
  assert.equal(orchestrator.containers.has('deadline-session'), false);
  assert.equal(orchestrator.runtimeTimers.has('deadline-session'), false);
});

test('runtime deadline aborts a pending container start and removes the container', async () => {
  const { docker, calls } = createDocker({
    container: {
      start({ abortSignal }) {
        return new Promise((_resolve, reject) => {
          abortSignal.addEventListener('abort', () => reject(abortSignal.reason), {
            once: true
          });
        });
      }
    }
  });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    runtimeTimeoutMs: 10,
    logger: { error() {}, warn() {} }
  });

  await assert.rejects(
    orchestrator.runContainer('runtime-image', 'startup-deadline-session'),
    (error) => error.code === 'RUNTIME_TIMEOUT'
  );
  assert.equal(calls.stopCount, 1);
  assert.equal(calls.removeCount, 1);
});

test('partial container startup failure removes its container and image', async () => {
  const { docker, calls } = createDocker({
    container: { async start() { throw new Error('mock startup failure'); } }
  });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    logger: { error() {}, warn() {} }
  });

  await assert.rejects(
    orchestrator.runContainer('startup-image', 'startup-session'),
    /mock startup failure/
  );
  assert.equal(calls.stopCount, 1);
  assert.equal(calls.removeCount, 1);
  assert.deepEqual(calls.removedImages, ['startup-image']);
  assert.equal(orchestrator.containers.has('startup-session'), false);
});

test('cleanup reports failures while attempting remaining resources', async () => {
  const logEntries = [];
  const { docker, calls } = createDocker({
    container: {
      async stop() { throw Object.assign(new Error('stop error'), { code: 'STOP_FAILED' }); }
    }
  });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    logger: { error: (...args) => logEntries.push(args), warn() {} }
  });

  await orchestrator.runContainer('cleanup-image', 'cleanup-session');
  await assert.rejects(
    orchestrator.cleanup('cleanup-session'),
    (error) => error instanceof AggregateError && error.errors.length === 1
  );
  assert.equal(calls.removeCount, 1);
  assert.deepEqual(calls.removedImages, ['cleanup-image']);
  assert.equal(logEntries.some(([message]) => message === 'Docker cleanup failed'), true);
  assert.equal(orchestrator.containers.has('cleanup-session'), false);
});

test('concurrent sessions clean only their own container and image', async () => {
  const { docker, calls } = createDocker();
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    logger: { error() {}, warn() {} }
  });
  await Promise.all([
    orchestrator.runContainer('image-one', 'session-one'),
    orchestrator.runContainer('image-two', 'session-two')
  ]);

  await Promise.all([
    orchestrator.cleanup('session-one'),
    orchestrator.cleanup('session-two')
  ]);
  assert.equal(calls.stopCount, 2);
  assert.equal(calls.removeCount, 2);
  assert.deepEqual(calls.removedImages.sort(), ['image-one', 'image-two']);
  assert.equal(orchestrator.containers.size, 0);
});

test('repeated and concurrent cleanup share one operation and remain idempotent', async () => {
  let releaseStop;
  const stopGate = new Promise((resolve) => { releaseStop = resolve; });
  const { docker, calls } = createDocker({
    container: {
      async stop() {
        calls.stopCount = (calls.stopCount || 0) + 1;
        await stopGate;
      }
    }
  });
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    logger: { error() {}, warn() {} }
  });
  await orchestrator.runContainer('idempotent-image', 'idempotent-session');

  const firstCleanup = orchestrator.cleanup('idempotent-session');
  const concurrentCleanup = orchestrator.cleanup('idempotent-session');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.stopCount, 1);
  releaseStop();
  await Promise.all([firstCleanup, concurrentCleanup]);
  await orchestrator.cleanup('idempotent-session');

  assert.equal(calls.stopCount, 1);
  assert.equal(calls.removeCount, 1);
  assert.deepEqual(calls.removedImages, ['idempotent-image']);
  assert.equal(orchestrator.getSessionInfo('idempotent-session'), null);
});

test('cleanupAll removes idle session records and tracked runtime resources', async () => {
  const { docker, calls } = createDocker();
  const orchestrator = createOrchestrator(createIo(), {
    docker,
    logger: { error() {}, warn() {} }
  });
  orchestrator.createSession('idle-shutdown-session');
  await orchestrator.runContainer('shutdown-image', 'runtime-shutdown-session');

  await orchestrator.cleanupAll();

  assert.equal(orchestrator.getSessionInfo('idle-shutdown-session'), null);
  assert.equal(orchestrator.getSessionInfo('runtime-shutdown-session'), null);
  assert.equal(calls.stopCount, 1);
  assert.equal(calls.removeCount, 1);
  assert.deepEqual(calls.removedImages, ['shutdown-image']);
  assert.equal(orchestrator.sessions.size, 0);
});

test('discardSessionRecord is idempotent for a session without orchestration resources', () => {
  const orchestrator = createOrchestrator(createIo(), {
    docker: {},
    logger: { error() {}, warn() {} }
  });
  orchestrator.createSession('pre-orchestration-session');
  orchestrator.logBytes.set('pre-orchestration-session', 123);

  assert.doesNotThrow(() => orchestrator.discardSessionRecord('pre-orchestration-session'));
  assert.doesNotThrow(() => orchestrator.discardSessionRecord('pre-orchestration-session'));
  assert.equal(orchestrator.getSessionInfo('pre-orchestration-session'), null);
  assert.equal(orchestrator.logBytes.has('pre-orchestration-session'), false);
});

test('discardSessionRecord refuses to remove a session with tracked resources', () => {
  const orchestrator = createOrchestrator(createIo(), {
    docker: {},
    logger: { error() {}, warn() {} }
  });
  orchestrator.createSession('active-orchestration-session');
  orchestrator.imageRefs.set('active-orchestration-session', new Set(['active-image']));

  assert.throws(
    () => orchestrator.discardSessionRecord('active-orchestration-session'),
    (error) => error.code === 'SESSION_RESOURCES_ACTIVE'
  );
  assert.notEqual(orchestrator.getSessionInfo('active-orchestration-session'), null);
});

test('retained session logs are bounded by entry count and chunk size', () => {
  const orchestrator = createOrchestrator(createIo(), {
    docker: {},
    logger: { error() {}, warn() {} }
  });
  for (let index = 0; index < DOCKER_LIMITS.maxLogEntries + 1; index += 1) {
    orchestrator.emitTerminalOutput('log-session', 'runtime', 'x'.repeat(20000));
  }
  const logs = orchestrator.getSessionInfo('log-session').logs;
  assert.ok(logs.length <= DOCKER_LIMITS.maxLogEntries);
  assert.ok(
    logs.reduce((total, entry) => total + Buffer.byteLength(entry.message), 0) <=
      DOCKER_LIMITS.maxLogBytes
  );
  assert.ok(logs[0].message.length <= DOCKER_LIMITS.maxLogChunkBytes + 12);
});
