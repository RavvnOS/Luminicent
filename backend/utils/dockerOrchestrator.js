import Docker from 'dockerode'
import fs from 'fs'
import path from 'path'
import tar from "tar-fs";

export const getDockerInstance = () => {
  if (process.env.DOCKER_HOST) {
    return new Docker();
  }
  if (process.platform === 'win32') {
    if (fs.existsSync('//./pipe/dockerDesktopLinuxEngine')) {
      return new Docker({ socketPath: '//./pipe/dockerDesktopLinuxEngine' });
    }
    return new Docker({ socketPath: '//./pipe/docker_engine' });
  }
  return new Docker({ socketPath: '/var/run/docker.sock' });
};

const docker = getDockerInstance();

export const DOCKER_LIMITS = Object.freeze({
  memoryBytes: 512 * 1024 * 1024,
  memorySwapBytes: 512 * 1024 * 1024,
  cpuPeriod: 100000,
  cpuQuota: 50000,
  pids: 128,
  tmpfsBytes: 64 * 1024 * 1024,
  buildMemoryBytes: 1024 * 1024 * 1024,
  buildMemorySwapBytes: 1024 * 1024 * 1024,
  buildCpuPeriod: 100000,
  buildCpuQuota: 100000,
  connectivityTimeoutMs: 10000,
  buildTimeoutMs: 5 * 60 * 1000,
  runtimeTimeoutMs: 5 * 60 * 1000,
  maxLogChunkBytes: 16 * 1024,
  maxLogEntries: 200,
  maxLogBytes: 1024 * 1024,
  maxStatsBufferBytes: 64 * 1024
});

const isMissingResource = (error) =>
  error?.statusCode === 404 || error?.json?.statusCode === 404;

const getAbortReason = (signal) => signal?.reason || Object.assign(
  new Error('Operation cancelled'),
  { code: 'ABORT_ERR' }
);

const throwIfAborted = (signal) => {
  if (signal?.aborted) throw getAbortReason(signal);
};

const raceWithSignal = (operation, signal) => {
  if (!signal) return operation;
  throwIfAborted(signal);

  return new Promise((resolve, reject) => {
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const onAbort = () => {
      cleanup();
      reject(getAbortReason(signal));
    };

    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(operation).then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      }
    );
  });
};

class DockerOrchestrator {
  constructor(io, options = {}) {
    this.io = io
    this.docker = options.docker || docker
    this.logger = options.logger || console
    this.buildTimeoutMs = options.buildTimeoutMs ?? DOCKER_LIMITS.buildTimeoutMs
    this.runtimeTimeoutMs = options.runtimeTimeoutMs ?? DOCKER_LIMITS.runtimeTimeoutMs
    this.connectivityTimeoutMs = options.connectivityTimeoutMs ?? DOCKER_LIMITS.connectivityTimeoutMs
    this.containerNetwork = options.containerNetwork || process.env.LUMINICENT_CONTAINER_NETWORK || 'none'
    this.executionMode = options.executionMode || process.env.LUMINICENT_EXECUTION_MODE || 'disabled'
    this.buildNetwork = options.buildNetwork || process.env.LUMINICENT_BUILD_NETWORK || 'none'
    if (!['disabled', 'trusted-local'].includes(this.executionMode)) {
      throw new TypeError('LUMINICENT_EXECUTION_MODE must be "disabled" or "trusted-local"')
    }
    if (!['none', 'default'].includes(this.buildNetwork)) {
      throw new TypeError('LUMINICENT_BUILD_NETWORK must be "none" or "default"')
    }
    if (this.buildNetwork === 'default' && this.executionMode !== 'trusted-local') {
      throw new TypeError('LUMINICENT_BUILD_NETWORK=default requires trusted-local execution mode')
    }
    if (!['none', 'bridge'].includes(this.containerNetwork)) {
      throw new TypeError('LUMINICENT_CONTAINER_NETWORK must be "none" or "bridge"')
    }
    this.containers = new Map()
    this.containerRefs = new Map()
    this.containerCreationOperations = new Map()
    this.sessions = new Map()
    this.logBytes = new Map()
    this.statsStreams = new Map()
    this.logStreams = new Map()
    this.imageRefs = new Map()
    this.buildControllers = new Map()
    this.buildOperations = new Map()
    this.pendingCancellations = new Map()
    this.runtimeTimers = new Map()
    this.runtimeControllers = new Map()
    this.cleanupOperations = new Map()
  }

  emit(sessionId, event, payload) {
    if (!sessionId) return
    this.io.to(sessionId).emit(event, payload)
  }

  emitStatus(sessionId, data = {}) {
    const payload = {
      sessionId,
      timestamp: Date.now(),
      type: data.type || 'info',
      stage: data.stage || 'info',
      percent: data.percent,
      status: data.status,
      message: data.message,
      error: data.error
    }

    if (!sessionId) return
    this.io.to(sessionId).emit('status', payload)
  }

  emitTerminalOutput(sessionId, type, message) {
    const fullMessage = typeof message === 'string'
      ? message
      : message?.message || message?.data || JSON.stringify(message || '')

    if (!fullMessage) return
    const remainingBytes = DOCKER_LIMITS.maxLogBytes -
      (this.logBytes.get(sessionId) || 0)
    if (remainingBytes <= 0) return
    const encodedMessage = Buffer.from(fullMessage)
    const allowedBytes = Math.min(DOCKER_LIMITS.maxLogChunkBytes, remainingBytes)
    const truncated = encodedMessage.length > allowedBytes
    const marker = Buffer.from(' [truncated]')
    const appendMarker = truncated && allowedBytes >= marker.length
    const contentLimit = appendMarker ? allowedBytes - marker.length : allowedBytes
    let messageContent = encodedMessage.subarray(0, contentLimit).toString('utf-8')
    while (Buffer.byteLength(messageContent) > contentLimit) {
      messageContent = messageContent.slice(0, -1)
    }
    const normalizedMessage = truncated
      ? `${messageContent}${appendMarker ? marker.toString('utf-8') : ''}`
      : messageContent
    this.logBytes.set(
      sessionId,
      (this.logBytes.get(sessionId) || 0) + Buffer.byteLength(normalizedMessage)
    )

    const payload = {
      sessionId,
      type,
      message: normalizedMessage,
      timestamp: Date.now()
    }

    this.emit(sessionId, 'terminal_output', payload)

    if (type === 'build') {
      this.emit(sessionId, 'build_log', {
        sessionId,
        data: normalizedMessage
      })
    }

    if (type === 'runtime') {
      this.emit(sessionId, 'runtime_log', {
        sessionId,
        data: normalizedMessage
      })
    }

    this.updateSession(sessionId, {
      logs: [{ type, message: normalizedMessage, timestamp: Date.now() }]
    })
  }

  createSession(sessionId, initial = {}) {
    const record = {
      sessionId,
      status: 'IDLE',
      startedAt: Date.now(),
      logs: [],
      metrics: {},
      ...initial
    }
    this.sessions.set(sessionId, record)
    return record
  }

  updateSession(sessionId, patch) {
    const session = this.sessions.get(sessionId) || this.createSession(sessionId)
    const updated = {
      ...session,
      ...patch,
      updatedAt: Date.now()
    }
    if (patch.logs) {
      updated.logs = [...(session.logs || []), ...patch.logs]
        .slice(-DOCKER_LIMITS.maxLogEntries)
    }
    this.sessions.set(sessionId, updated)
    return updated
  }

  getSessionInfo(sessionId) {
    return this.sessions.get(sessionId) || null
  }

  discardSessionRecord(sessionId) {
    if (this.containers.has(sessionId) || this.containerRefs.has(sessionId) ||
        this.containerCreationOperations.has(sessionId) || this.imageRefs.has(sessionId) ||
        this.buildControllers.has(sessionId) || this.buildOperations.has(sessionId) ||
        this.pendingCancellations.has(sessionId) || this.runtimeControllers.has(sessionId) ||
        this.runtimeTimers.has(sessionId) || this.logStreams.has(sessionId) ||
        this.statsStreams.has(sessionId) || this.cleanupOperations.has(sessionId)) {
      const error = new Error('Cannot discard a session while orchestration resources are active')
      error.code = 'SESSION_RESOURCES_ACTIVE'
      throw error
    }
    this.sessions.delete(sessionId)
    this.logBytes.delete(sessionId)
  }

  getDeploymentHistory() {
    return Array.from(this.sessions.values()).sort((a, b) => b.startedAt - a.startedAt)
  }

  buildImage(buildContext, imageName, sessionId, dockerfilePath, options = {}) {
    this.assertExecutionEnabled()
    const operation = this.performBuildImage(
      buildContext,
      imageName,
      sessionId,
      dockerfilePath,
      options
    )
    this.buildOperations.set(sessionId, operation)
    void operation.finally(() => {
      if (this.buildOperations.get(sessionId) === operation) {
        this.buildOperations.delete(sessionId)
      }
    }).catch(() => {})
    return operation
  }

  async performBuildImage(buildContext, imageName, sessionId, dockerfilePath, options = {}) {
    this.updateSession(sessionId, {
      imageName,
      status: 'STARTING_BUILD',
      buildStart: Date.now()
    })
    this.trackImage(sessionId, imageName)
    this.emitStatus(sessionId, {
      status: 'STARTING_BUILD',
      stage: 'build',
      type: 'info',
      percent: 10,
      message: `Building image: ${imageName}`
    });
    const dockerClient = this.docker
    const externalSignal = options.signal
    throwIfAborted(externalSignal)

    // Validate build context exists
    if (!buildContext || !fs.existsSync(buildContext)) {
      const errMsg = `Build context not found: ${buildContext}`
      this.emitStatus(sessionId, {
        status: 'BUILD_FAILED',
        stage: 'build',
        type: 'error',
        error: errMsg,
        message: errMsg
      })
      throw new Error(errMsg)
    }

    if (!dockerfilePath || !fs.existsSync(dockerfilePath)) {
      const errMsg = `Dockerfile not found in build context: ${dockerfilePath}`
      this.emitStatus(sessionId, {
        status: 'BUILD_FAILED',
        stage: 'build',
        type: 'error',
        error: errMsg,
        message: errMsg
      })
      throw new Error(errMsg)
    }

    // Check Docker daemon availability
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(Object.assign(new Error('Docker connectivity check timed out'), {
            code: 'DOCKER_PING_TIMEOUT'
          })),
          this.connectivityTimeoutMs
        )
        dockerClient.ping((err) => {
          clearTimeout(timer)
          if (err) reject(err)
          else resolve()
        })
      })
    } catch (err) {
      this.logger.warn('Docker connectivity check failed', {
        code: err.code || err.statusCode || err.name || 'UNKNOWN'
      })
      const errMsg = `Docker Desktop is not running or initializing. Please start Docker Desktop on your computer.`
      this.emitStatus(sessionId, {
        status: 'BUILD_FAILED',
        stage: 'build',
        type: 'error',
        error: errMsg,
        message: errMsg
      })
      throw Object.assign(new Error(errMsg), {
        code: 'DOCKER_CONNECTIVITY_FAILED',
        cause: err
      })
    }

    const dockerfileRelative = path.relative(buildContext, dockerfilePath).replace(/\\/g, '/')
    const tarStream = tar.pack(buildContext);
    const controller = new AbortController()
    const abortFromRequest = () => controller.abort(getAbortReason(externalSignal))
    if (externalSignal) {
      externalSignal.addEventListener('abort', abortFromRequest, { once: true })
    }
    let stream
    let builtImageId = null;
    let timeoutError
    const abortBuildStreams = () => {
      tarStream.destroy()
      stream?.destroy()
    }
    controller.signal.addEventListener('abort', abortBuildStreams, { once: true })
    this.buildControllers.set(sessionId, controller)
    if (this.pendingCancellations.has(sessionId)) {
      controller.abort(this.pendingCancellations.get(sessionId))
      this.pendingCancellations.delete(sessionId)
    }

    const timeout = setTimeout(() => {
      timeoutError = Object.assign(
        new Error(`Docker build timed out after ${this.buildTimeoutMs}ms`),
        { code: 'BUILD_TIMEOUT' }
      )
      controller.abort(timeoutError)
    }, this.buildTimeoutMs)
    timeout.unref?.()

    try {
      throwIfAborted(controller.signal)
      stream = await raceWithSignal(dockerClient.buildImage(tarStream, {
        t: imageName,
        dockerfile: dockerfileRelative,
        abortSignal: controller.signal,
        memory: DOCKER_LIMITS.buildMemoryBytes,
        memswap: DOCKER_LIMITS.buildMemorySwapBytes,
        cpuquota: DOCKER_LIMITS.buildCpuQuota,
        cpuperiod: DOCKER_LIMITS.buildCpuPeriod,
        networkmode: this.buildNetwork
      }), controller.signal)
      throwIfAborted(controller.signal)

      await raceWithSignal(new Promise((resolve, reject) => {
        dockerClient.modem.followProgress(
          stream,
          (error) => error ? reject(error) : resolve(),
          (event) => {
            if (!event || controller.signal.aborted) return
            if (event.aux?.ID) {
              builtImageId = event.aux.ID
              this.trackImage(sessionId, builtImageId)
            }

            const message = event.stream
              ? event.stream.toString().trim()
              : event.status
                ? event.status.toString()
                : JSON.stringify(event)
            if (message) this.emitTerminalOutput(sessionId, 'build', message)
          }
        )
      }), controller.signal)

      this.updateSession(sessionId, {
        status: 'BUILD_IMAGE',
        buildEnd: Date.now()
      })
      this.emitStatus(sessionId, {
        status: 'BUILD_IMAGE',
        stage: 'build',
        type: 'success',
        percent: 50,
        message: 'Docker image built successfully'
      })

      let image = dockerClient.getImage(imageName)
      let inspect
      try {
        inspect = await image.inspect()
      } catch (inspectError) {
        if (!builtImageId) throw inspectError
        image = dockerClient.getImage(builtImageId)
        inspect = await image.inspect()
        await image.tag({ repo: imageName, tag: 'latest' })
      }
      this.trackImage(sessionId, inspect.Id)
      return imageName
    } catch (error) {
      const failure = timeoutError || (controller.signal.aborted
        ? getAbortReason(controller.signal)
        : error)
      this.emitStatus(sessionId, {
        status: 'BUILD_FAILED',
        stage: 'build',
        type: 'error',
        error: failure.message,
        message: 'Docker build failed or was cancelled'
      })
      try {
        await this.cleanup(sessionId)
      } catch (cleanupError) {
        this.logCleanupError(sessionId, 'build-failure', cleanupError)
        failure.cleanupError = cleanupError
      }
      throw failure
    } finally {
      clearTimeout(timeout)
      externalSignal?.removeEventListener('abort', abortFromRequest)
      controller.signal.removeEventListener('abort', abortBuildStreams)
      if (this.buildControllers.get(sessionId) === controller) {
        this.buildControllers.delete(sessionId)
      }
      if (!tarStream.destroyed) tarStream.destroy()
    }
  }

  trackImage(sessionId, imageRef) {
    if (!imageRef) return
    const refs = this.imageRefs.get(sessionId) || new Set()
    refs.add(imageRef)
    this.imageRefs.set(sessionId, refs)
  }

  async runContainer(imageName, sessionId, options = {}) {
    this.assertExecutionEnabled()
    const dockerClient = this.docker
    this.trackImage(sessionId, imageName)
    let removeRequestAbortListener = () => {}
    try {
      throwIfAborted(options.signal)
      let imageRef = imageName
      let configuredUser
      try {
        const image = dockerClient.getImage(imageName)
        const imageInspect = await image.inspect()
        configuredUser = imageInspect.Config?.User
      } catch (imgErr) {
        if (isMissingResource(imgErr)) {
          imageRef = null
        } else {
          throw imgErr
        }
      }

      throwIfAborted(options.signal)
      this.updateSession(sessionId, {
        status: 'RUN_CONTAINER',
        containerStart: Date.now()
      })
      this.emitStatus(sessionId, {
        status: 'RUN_CONTAINER',
        stage: 'container',
        type: 'info',
        percent: 60,
        message: 'Starting container...'
      })
      const containerName = `luminicent-${sessionId}`
      const runtimeController = new AbortController()
      if (options.signal) {
        const abortRuntimeFromRequest = () => {
          runtimeController.abort(getAbortReason(options.signal))
        }
        options.signal.addEventListener('abort', abortRuntimeFromRequest, { once: true })
        removeRequestAbortListener = () => {
          options.signal.removeEventListener('abort', abortRuntimeFromRequest)
        }
        if (options.signal.aborted) abortRuntimeFromRequest()
      }
      this.runtimeControllers.set(sessionId, runtimeController)
      this.containerRefs.set(sessionId, containerName)
      const runtimeTimer = setTimeout(() => {
        const timeoutError = Object.assign(
          new Error(`Runtime exceeded ${this.runtimeTimeoutMs}ms deadline`),
          { code: 'RUNTIME_TIMEOUT' }
        )
        runtimeController.abort(timeoutError)
        this.emitStatus(sessionId, {
          status: 'RUNTIME_TIMEOUT',
          stage: 'container',
          type: 'error',
          message: timeoutError.message
        })
        void this.cleanup(sessionId).catch((error) => {
          this.logCleanupError(sessionId, 'runtime-deadline', error)
        })
      }, this.runtimeTimeoutMs)
      runtimeTimer.unref?.()
      this.runtimeTimers.set(sessionId, runtimeTimer)
      const createOptions = {
        name: containerName,
        abortSignal: runtimeController.signal,
        Image: imageRef || imageName,
        Hostname: 'devops-simulator',
        Tty: true,
        AttachStdin: false,
        AttachStdout: true,
        AttachStderr: true,
        OpenStdin: false,
        User: configuredUser &&
          !['0', 'root'].includes(configuredUser.split(':', 1)[0])
          ? configuredUser
          : '65532:65532',
        HostConfig: {
          Memory: DOCKER_LIMITS.memoryBytes,
          MemorySwap: DOCKER_LIMITS.memorySwapBytes,
          CpuPeriod: DOCKER_LIMITS.cpuPeriod,
          CpuQuota: DOCKER_LIMITS.cpuQuota,
          PidsLimit: DOCKER_LIMITS.pids,
          AutoRemove: false,
          NetworkMode: this.containerNetwork,
          CapDrop: ['ALL'],
          SecurityOpt: ['no-new-privileges:true'],
          Tmpfs: {
            '/tmp': `rw,noexec,nosuid,size=${DOCKER_LIMITS.tmpfsBytes}`
          },
          LogConfig: {
            Type: 'local',
            Config: { 'max-size': '10m', 'max-file': '1' }
          }
        }
      }

      const creationOperation = dockerClient.createContainer(createOptions).then((container) => {
        this.containers.set(sessionId, container.id)
        this.containerRefs.delete(sessionId)
        this.updateSession(sessionId, {
          containerId: container.id,
          status: 'CONTAINER_STARTING'
        })
        return container
      })
      this.containerCreationOperations.set(sessionId, creationOperation)
      let container
      try {
        container = await creationOperation
      } finally {
        if (this.containerCreationOperations.get(sessionId) === creationOperation) {
          this.containerCreationOperations.delete(sessionId)
        }
      }

      throwIfAborted(options.signal)
      await container.start({ abortSignal: runtimeController.signal });
      throwIfAborted(options.signal)

      const inspect = await container.inspect();
      throwIfAborted(options.signal)

      if (!inspect.State.Running) {
          const logs = await container.logs({
            stdout: true,
            stderr: true
          });
          this.emitTerminalOutput(sessionId, 'runtime', logs.toString('utf-8'))
      }

      this.emitStatus(sessionId, {
        status: 'CONTAINER_RUNNING',
        stage: 'container',
        type: 'success',
        percent: 75,
        message: `Container started: ${container.id.substring(0, 12)}`
      })
      this.updateSession(sessionId, {
        status: 'CONTAINER_RUNNING'
      })

      void this.monitorContainerStats(container, sessionId)
      return container
    } catch (error) {
      this.emitStatus(sessionId, {
        status: 'ERROR',
        stage: 'container',
        type: 'error',
        error: error.message,
        message: error.message
      })
      this.updateSession(sessionId, {
        status: 'ERROR',
        error: error.message
      })
      try {
        await this.cleanup(sessionId)
      } catch (cleanupError) {
        this.logCleanupError(sessionId, 'container-startup', cleanupError)
        error.cleanupError = cleanupError
      }
      throw error
    } finally {
      removeRequestAbortListener()
    }
  }

  async streamLogs(container, sessionId, options = {}) {
    try {
      this.emitStatus(sessionId, {
        status: 'RUNTIME_LOG',
        stage: 'container',
        type: 'info',
        percent: 80,
        message: 'Streaming container logs...'
      })
      this.updateSession(sessionId, {
        status: 'RUNTIME_LOG'
      })

      const stream = await container.logs({
        follow: true,
        stdout: true,
        stderr: true,
        tail: 100
      })
      this.logStreams.set(sessionId, stream)
      if (options.signal) {
        const closeOnAbort = () => stream.destroy()
        if (options.signal.aborted) closeOnAbort()
        else options.signal.addEventListener('abort', closeOnAbort, { once: true })
        stream.once('close', () => options.signal.removeEventListener('abort', closeOnAbort))
      }

      stream.on('data', (chunk) => {
        const message = chunk.subarray(0, DOCKER_LIMITS.maxLogChunkBytes).toString('utf-8')
        if (message.trim()) {
          this.emitTerminalOutput(sessionId, 'runtime', message)
        }
      })

      stream.on('error', (error) => {
        this.emitStatus(sessionId, {
          status: 'ERROR',
          stage: 'container',
          type: 'error',
          error: error.message,
          message: 'Error streaming container logs'
        })
      })

      stream.on('end', () => {
        this.logStreams.delete(sessionId)
        this.emitStatus(sessionId, {
          status: 'FINISHED',
          stage: 'container',
          type: 'success',
          percent: 100,
          message: 'Log stream ended.'
        })
      })
      stream.on('close', () => this.logStreams.delete(sessionId))

      return stream
    } catch (error) {
      this.emit(sessionId, 'status', {
        sessionId,
        status: 'ERROR',
        error: error.message
      })
      throw error
    }
  }

  async monitorContainerStats(container, sessionId) {
    try {
      const statsStream = await container.stats({ stream: true })
      this.statsStreams.set(sessionId, statsStream)
      let buffer = ''
      let lastCpu = 0
      let lastSystem = 0

      statsStream.on('data', (chunk) => {
        buffer += chunk.toString('utf-8')
        if (Buffer.byteLength(buffer) > DOCKER_LIMITS.maxStatsBufferBytes) {
          buffer = buffer.slice(-DOCKER_LIMITS.maxStatsBufferBytes)
        }
        const parts = buffer.split(/\r?\n/)
        buffer = parts.pop() || ''

        for (const part of parts) {
          if (!part.trim()) continue
          try {
            const stats = JSON.parse(part)
            const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - lastCpu
            const systemDelta = stats.cpu_stats.system_cpu_usage - lastSystem
            const onlineCpus = stats.cpu_stats.online_cpus || stats.cpu_stats.cpu_usage.percpu_usage?.length || 1
            const cpuUsage = systemDelta > 0 ? Number(((cpuDelta / systemDelta) * onlineCpus * 100).toFixed(2)) : 0
            lastCpu = stats.cpu_stats.cpu_usage.total_usage || lastCpu
            lastSystem = stats.cpu_stats.system_cpu_usage || lastSystem
            const memoryUsage = stats.memory_stats.usage || 0
            const memoryLimit = stats.memory_stats.limit || 0
            const memoryPercent = memoryLimit ? Number(((memoryUsage / memoryLimit) * 100).toFixed(2)) : 0
            const networkRx = Object.values(stats.networks || {}).reduce((sum, net) => sum + (net.rx_bytes || 0), 0)
            const networkTx = Object.values(stats.networks || {}).reduce((sum, net) => sum + (net.tx_bytes || 0), 0)

            const metrics = {
              cpuUsage,
              memoryUsage,
              memoryLimit,
              memoryPercent,
              networkRx,
              networkTx
            }

            this.emit(sessionId, 'CONTAINER_METRICS', {
              sessionId,
              metrics
            })
            this.emit(sessionId, 'docker_stats', {
              sessionId,
              metrics
            })
            this.updateSession(sessionId, { metrics })
          } catch (err) {
            this.logger.warn('Invalid Docker stats payload', {
              sessionId,
              code: err.code || err.name || 'UNKNOWN'
            })
          }
        }
      })

      statsStream.on('end', () => {
        this.statsStreams.delete(sessionId)
      })

      statsStream.on('error', () => {
        this.statsStreams.delete(sessionId)
      })
    } catch (error) {
      this.logger.warn('Unable to monitor container stats', {
        sessionId,
        code: error.code || error.name || 'UNKNOWN'
      })
    }
  }

  logCleanupError(sessionId, resource, error) {
    this.logger.error('Docker cleanup failed', {
      sessionId,
      resource,
      code: error.code || error.statusCode || error.name || 'UNKNOWN'
    })
  }

  isExecutionEnabled() {
    return this.executionMode === 'trusted-local'
  }

  assertExecutionEnabled() {
    if (!this.isExecutionEnabled()) {
      throw Object.assign(
        new Error('Project execution is disabled; explicitly configure trusted-local mode on a local-only deployment'),
        { code: 'EXECUTION_DISABLED' }
      )
    }
  }

  cancelSession(sessionId, reason = Object.assign(
    new Error('Session cancelled'),
    { code: 'ABORT_ERR' }
  )) {
    const operation = this.buildOperations.get(sessionId)
    const controller = this.buildControllers.get(sessionId)
    if (controller) controller.abort(reason)
    else if (operation) this.pendingCancellations.set(sessionId, reason)
    return (async () => {
      if (operation) {
        try {
          await operation
        } catch {
          // The operation error is reported to its caller; cleanup remains required.
        }
      }
      await this.cleanup(sessionId)
    })()
  }

  cleanup(sessionId) {
    if (!this.sessions.has(sessionId) && !this.containers.has(sessionId) &&
        !this.containerRefs.has(sessionId) && !this.imageRefs.has(sessionId) &&
        !this.buildOperations.has(sessionId) && !this.containerCreationOperations.has(sessionId)) {
      return Promise.resolve()
    }
    const current = this.cleanupOperations.get(sessionId)
    if (current) return current

    const operation = this.performCleanup(sessionId)
    this.cleanupOperations.set(sessionId, operation)
    void operation.finally(() => {
      if (this.cleanupOperations.get(sessionId) === operation) {
        this.cleanupOperations.delete(sessionId)
      }
    }).catch(() => {})
    return operation
  }

  async performCleanup(sessionId) {
    const errors = []
    this.runtimeControllers.get(sessionId)?.abort(
      Object.assign(new Error('Container cleanup requested'), { code: 'ABORT_ERR' })
    )
    this.runtimeControllers.delete(sessionId)
    clearTimeout(this.runtimeTimers.get(sessionId))
    this.runtimeTimers.delete(sessionId)
    for (const streamMap of [this.logStreams, this.statsStreams]) {
      const stream = streamMap.get(sessionId)
      stream?.destroy()
      streamMap.delete(sessionId)
    }
    const creationOperation = this.containerCreationOperations.get(sessionId)
    if (creationOperation) {
      await Promise.allSettled([creationOperation])
    }

    this.emit(sessionId, 'status', {
      sessionId,
      status: 'CLEANUP',
      message: 'Cleaning up session resources...'
    })

    const containerRef = this.containers.get(sessionId) || this.containerRefs.get(sessionId)
    if (containerRef) {
      try {
        const container = this.docker.getContainer(containerRef)
        await container.stop({ t: 0 })
      } catch (error) {
        if (!isMissingResource(error) && error.statusCode !== 304) {
          errors.push(error)
          this.logCleanupError(sessionId, 'container-stop', error)
        }
      }

      try {
        await this.docker.getContainer(containerRef).remove({ force: true, v: true })
        this.containers.delete(sessionId)
        this.containerRefs.delete(sessionId)
      } catch (error) {
        if (isMissingResource(error)) {
          this.containers.delete(sessionId)
          this.containerRefs.delete(sessionId)
        }
        else {
          errors.push(error)
          this.logCleanupError(sessionId, 'container-remove', error)
        }
      }
    }

    const refs = this.imageRefs.get(sessionId) || new Set()
    for (const imageRef of refs) {
      try {
        await this.docker.getImage(imageRef).remove({ force: true, noprune: true })
        refs.delete(imageRef)
      } catch (error) {
        if (isMissingResource(error)) refs.delete(imageRef)
        else {
          errors.push(error)
          this.logCleanupError(sessionId, 'image-remove', error)
        }
      }
    }
    if (refs.size === 0) this.imageRefs.delete(sessionId)

    if (errors.length > 0) {
      const failure = new AggregateError(errors, 'Session cleanup was incomplete')
      this.updateSession(sessionId, {
        status: 'CLEANUP_ERROR',
        error: failure.message
      })
      this.emit(sessionId, 'status', {
        sessionId,
        status: 'CLEANUP_ERROR',
        error: failure.message
      })
      throw failure
    }

    this.updateSession(sessionId, {
      status: 'FINISHED',
      endedAt: Date.now(),
      durationMs: Date.now() - (this.sessions.get(sessionId)?.startedAt || Date.now())
    })
    this.emit(sessionId, 'status', {
      sessionId,
      status: 'FINISHED',
      message: 'Simulation completed and cleaned up'
    })
    this.sessions.delete(sessionId)
    this.logBytes.delete(sessionId)
  }

  async cleanupAll() {
    const shutdownReason = Object.assign(
      new Error('Backend is shutting down'),
      { code: 'ABORT_ERR' }
    )
    const builds = Array.from(this.buildOperations.entries())
    for (const [sessionId] of builds) {
      const controller = this.buildControllers.get(sessionId)
      if (controller) controller.abort(shutdownReason)
      else this.pendingCancellations.set(sessionId, shutdownReason)
    }
    await Promise.allSettled(builds.map(([, operation]) => operation))

    const sessionIds = new Set([
      ...this.sessions.keys(),
      ...this.containers.keys(),
      ...this.containerRefs.keys(),
      ...this.imageRefs.keys(),
      ...this.runtimeControllers.keys(),
      ...this.runtimeTimers.keys(),
      ...this.logStreams.keys(),
      ...this.statsStreams.keys(),
      ...this.containerCreationOperations.keys()
    ])
    const results = await Promise.allSettled(
      Array.from(sessionIds, (sessionId) => this.cleanup(sessionId))
    )
    const errors = results
      .filter((result) => result.status === 'rejected')
      .map((result) => result.reason)
    if (errors.length > 0) {
      throw new AggregateError(errors, 'One or more Docker sessions could not be cleaned')
    }
  }
}

export default DockerOrchestrator;
