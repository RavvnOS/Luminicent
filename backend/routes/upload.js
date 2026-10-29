import express from 'express';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import { createWriteStream } from 'node:fs';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import yauzl from 'yauzl';
import {
  createApiTokenMiddleware,
  getAuthenticatedUserId
} from '../utils/accessControl.js';
import { scanWorker } from '../utils/scanWorker.js';

export const UPLOAD_LIMITS = Object.freeze({
  compressedBytes: 100 * 1024 * 1024,
  expandedBytes: 1024 * 1024 * 1024,
  entries: 10_000,
  fileBytes: 100 * 1024 * 1024,
  pathDepth: 32
});

class ArchiveError extends Error {
  constructor(message = 'Invalid or unsupported ZIP archive') {
    super(message);
    this.code = 'INVALID_ARCHIVE';
  }
}

class ResourceLimitError extends Error {
  constructor() {
    super('Archive exceeds resource limits');
    this.code = 'RESOURCE_LIMIT';
  }
}

const isStrictChild = (root, candidate) => {
  const relativePath = path.relative(root, candidate);
  return relativePath !== '' && relativePath !== '..' &&
    !relativePath.startsWith(`..${path.sep}`) && !path.isAbsolute(relativePath);
};

const openZipArchive = (archivePath) => new Promise((resolve, reject) => {
  yauzl.open(archivePath, {
    lazyEntries: true,
    decodeStrings: true,
    validateEntrySizes: false
  }, (error, zip) => {
    if (error) {
      reject(new ArchiveError());
      return;
    }
    resolve(zip);
  });
});

const validateEntry = (entry, destination, limits, paths, ancestors) => {
  const rawName = entry.fileName;
  if (typeof rawName !== 'string' || rawName.includes('\0')) {
    throw new ArchiveError();
  }

  const entryName = rawName.replace(/\\/g, '/');
  if (!entryName || entryName.startsWith('/') || path.posix.isAbsolute(entryName) ||
      /^[a-zA-Z]:/.test(entryName) || entryName.startsWith('//')) {
    throw new ArchiveError();
  }

  const rawComponents = entryName.split('/');
  if (rawComponents.some((component) => component === '..' || component === '.')) {
    throw new ArchiveError();
  }

  const unixMode = (entry.externalFileAttributes >>> 16) & 0xFFFF;
  const unixType = unixMode & 0xF000;
  if (unixType !== 0 && unixType !== 0x8000 && unixType !== 0x4000) {
    throw new ArchiveError();
  }

  const directoryFromName = entryName.endsWith('/');
  if ((unixType === 0x8000 && directoryFromName) ||
      (entry.generalPurposeBitFlag & 1) !== 0) {
    throw new ArchiveError();
  }

  const normalizedName = path.posix.normalize(entryName);
  const normalizedPath = normalizedName.replace(/\/$/, '');
  const components = normalizedPath.split('/');
  if (!normalizedPath || components.length > limits.pathDepth ||
      normalizedPath === '..' || normalizedPath.startsWith('../')) {
    throw new ResourceLimitError();
  }

  const outputPath = path.resolve(destination, ...components);
  if (!isStrictChild(destination, outputPath)) {
    throw new ArchiveError();
  }

  const isDirectory = unixType === 0x4000 || directoryFromName;
  const key = normalizedPath.toLowerCase();
  if (paths.has(key)) {
    throw new ArchiveError();
  }

  const parentParts = components.slice(0, -1);
  for (let index = 1; index <= parentParts.length; index += 1) {
    if (paths.get(parentParts.slice(0, index).join('/').toLowerCase()) === 'file') {
      throw new ArchiveError();
    }
  }
  if (!isDirectory && ancestors.has(key)) {
    throw new ArchiveError();
  }

  paths.set(key, isDirectory ? 'directory' : 'file');
  for (let index = 1; index < components.length; index += 1) {
    ancestors.add(components.slice(0, index).join('/').toLowerCase());
  }
  return { outputPath, isDirectory, key };
};

const readArchiveEntries = async (archivePath, destination, limits) => {
  const zip = await openZipArchive(archivePath);
  try {
    return await new Promise((resolve, reject) => {
      const entries = [];
      const paths = new Map();
      const ancestors = new Set();
      let declaredExpandedBytes = 0;
      zip.on('error', () => reject(new ArchiveError()));
      zip.on('entry', (entry) => {
        try {
          if (entries.length >= limits.entries) {
            throw new ResourceLimitError();
          }
          const descriptor = validateEntry(entry, destination, limits, paths, ancestors);
          if (!descriptor.isDirectory) {
            if (!Number.isSafeInteger(entry.uncompressedSize) || entry.uncompressedSize < 0 ||
                entry.uncompressedSize > limits.fileBytes) {
              throw new ResourceLimitError();
            }
            declaredExpandedBytes += entry.uncompressedSize;
            if (declaredExpandedBytes > limits.expandedBytes) {
              throw new ResourceLimitError();
            }
          } else if (entry.uncompressedSize !== 0) {
            throw new ArchiveError();
          }
          entries.push({ entry, ...descriptor, uncompressedSize: entry.uncompressedSize });
          zip.readEntry();
        } catch (error) {
          zip.close();
          reject(error);
        }
      });
      zip.on('end', () => resolve(entries));
      zip.readEntry();
    });
  } finally {
    zip.close();
  }
};

export const extractArchiveSafely = async (archivePath, destination, limits, assertSafe) => {
  const expectedEntries = await readArchiveEntries(archivePath, destination, limits);
  const zip = await openZipArchive(archivePath);
  let actualEntries = 0;
  let expandedBytes = 0;
  let fileCount = 0;

  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const paths = new Map();
      const ancestors = new Set();
      const fail = (error) => {
        if (settled) return;
        settled = true;
        zip.close();
        reject(error);
      };

      zip.on('error', () => fail(new ArchiveError()));
      zip.on('end', () => {
        if (actualEntries !== expectedEntries.length) {
          fail(new ArchiveError());
          return;
        }
        settled = true;
        resolve();
      });
      zip.on('entry', (entry) => {
        if (settled) return;
        try {
          if (actualEntries >= limits.entries || actualEntries >= expectedEntries.length) {
            throw new ResourceLimitError();
          }
          const descriptor = validateEntry(entry, destination, limits, paths, ancestors);
          const expected = expectedEntries[actualEntries];
          if (descriptor.key !== expected.key ||
              descriptor.isDirectory !== expected.isDirectory ||
              entry.uncompressedSize !== expected.uncompressedSize) {
            throw new ArchiveError();
          }
          actualEntries += 1;
          assertSafe();

          if (descriptor.isDirectory) {
            fs.mkdirSync(descriptor.outputPath, { recursive: true, mode: 0o700 });
            zip.readEntry();
            return;
          }

          fileCount += 1;
          if (fileCount > limits.entries) {
            throw new ResourceLimitError();
          }
          fs.mkdirSync(path.dirname(descriptor.outputPath), { recursive: true, mode: 0o700 });
          zip.openReadStream(entry, (error, input) => {
            if (error) {
              fail(new ArchiveError());
              return;
            }

            let fileBytes = 0;
            let outputError;
            const meter = new Transform({
              transform(chunk, _encoding, callback) {
                assertSafe();
                fileBytes += chunk.length;
                expandedBytes += chunk.length;
                if (fileBytes > limits.fileBytes || expandedBytes > limits.expandedBytes) {
                  callback(new ResourceLimitError());
                  return;
                }
                callback(null, chunk);
              }
            });
            const output = createWriteStream(descriptor.outputPath, {
              flags: 'wx',
              mode: 0o600
            });
            output.on('error', (writeError) => { outputError = writeError; });

            pipeline(input, meter, output).then(() => {
              if (settled) return;
              if (fileBytes !== entry.uncompressedSize) {
                fail(new ArchiveError());
                return;
              }
              zip.readEntry();
            }).catch((streamError) => {
              fail(
                streamError.code === 'RESOURCE_LIMIT'
                  ? streamError
                  : (outputError || new ArchiveError())
              );
            });
          });
        } catch (error) {
          fail(error);
        }
      });
      zip.readEntry();
    });
  } finally {
    zip.close();
  }
};

const createWorkspace = (root) => {
  const rootPath = fs.realpathSync(root);
  const createdPath = fs.mkdtempSync(path.join(rootPath, 'luminicent-'));
  let canonicalPath;
  try {
    canonicalPath = fs.realpathSync(createdPath);
    if (!isStrictChild(rootPath, canonicalPath)) {
      throw new Error('Temporary workspace is outside the upload root');
    }
  } catch (error) {
    try {
      const stat = fs.lstatSync(createdPath);
      if (fs.realpathSync(root) === rootPath && stat.isDirectory() &&
          !stat.isSymbolicLink() && fs.realpathSync(createdPath) === createdPath &&
          isStrictChild(rootPath, createdPath)) {
        fs.rmSync(createdPath, { recursive: true, force: false });
      }
    } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') {
        throw new AggregateError([error, cleanupError], 'Upload workspace initialization failed');
      }
    }
    throw error;
  }

  let cleaned = false;
  return {
    path: canonicalPath,
    assertSafe: () => {
      if (cleaned || fs.realpathSync(root) !== rootPath ||
          fs.realpathSync(createdPath) !== canonicalPath ||
          !isStrictChild(rootPath, canonicalPath)) {
        throw new Error('Temporary workspace is no longer within the upload root');
      }
    },
    cleanup: () => {
      if (cleaned) return;
      const currentRoot = fs.realpathSync(root);
      if (currentRoot !== rootPath) {
        throw new Error('Upload root changed before cleanup');
      }

      let stat;
      try {
        stat = fs.lstatSync(createdPath);
      } catch (error) {
        if (error.code === 'ENOENT') {
          cleaned = true;
          return;
        }
        throw error;
      }

      if (!stat.isDirectory() || stat.isSymbolicLink() ||
          fs.realpathSync(createdPath) !== canonicalPath ||
          !isStrictChild(rootPath, canonicalPath)) {
        throw new Error('Temporary workspace failed cleanup containment checks');
      }

      fs.rmSync(createdPath, { recursive: true, force: false });
      cleaned = true;
    }
  };
};

const cleanupUpload = (uploadPath, root) => {
  if (!uploadPath) return;

  const rootPath = fs.realpathSync(root);
  const absolutePath = path.resolve(uploadPath);
  if (!isStrictChild(rootPath, absolutePath)) {
    throw new Error('Uploaded file is outside the upload root');
  }

  let stat;
  try {
    stat = fs.lstatSync(absolutePath);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }

  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('Uploaded file failed cleanup checks');
  }
  fs.rmSync(absolutePath, { force: false });
};

const writeError = (res, status, message) => {
  if (!res.headersSent && !res.destroyed) {
    res.status(status).json({ error: message });
  }
};

export const createUploadRouter = ({
  uploadsRoot = path.resolve(process.env.LUMINICENT_UPLOADS_DIR || 'uploads'),
  archiveLimits = UPLOAD_LIMITS,
  logger = console,
  sessionRegistry = null,
  apiTokenMiddleware = createApiTokenMiddleware()
} = {}) => {
  const limits = { ...UPLOAD_LIMITS, ...archiveLimits };
  for (const limit of Object.values(limits)) {
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new TypeError('Archive limits must be positive safe integers');
    }
  }

  fs.mkdirSync(uploadsRoot, { recursive: true, mode: 0o700 });
  const canonicalUploadRoot = fs.realpathSync(uploadsRoot);
  const router = express.Router();
  const getSessionRegistry = (req) => req.sessionRegistry || sessionRegistry;
  router.post('/sessions', apiTokenMiddleware, express.json({ limit: '4kb' }), async (req, res) => {
    const body = req.body;
    if (body !== undefined && (!body || typeof body !== 'object'
      || Array.isArray(body) || Object.keys(body).length > 0)) {
      writeError(res, 400, 'Invalid session request');
      return;
    }
    const ownerId = getAuthenticatedUserId(req);
    if (!ownerId) {
      writeError(res, 401, 'Authenticated user session required');
      return;
    }
    if (!getSessionRegistry(req)) {
      writeError(res, 503, 'Persistent scan storage is unavailable');
      return;
    }
    try {
      res.set('Cache-Control', 'no-store');
      res.status(201).json(await getSessionRegistry(req).create(ownerId));
    } catch (error) {
      const status = error.code === 'SESSION_CAPACITY' ? 429 :
        error.code === 'PERSISTENCE_UNAVAILABLE' ? 503 : 500;
      logger.warn('Session creation failed', {
        code: error.code || error.name || 'UNKNOWN'
      });
      const message = status === 429
        ? error.message
        : status === 503
          ? 'Persistent scan storage is unavailable'
          : 'Unable to create session';
      writeError(res, status, message);
    }
  });
  const upload = multer({
    dest: canonicalUploadRoot,
    limits: { fileSize: limits.compressedBytes, fields: 0 },
    fileFilter: (req, file, callback) => {
      if (file.mimetype === 'application/zip' || file.originalname.toLowerCase().endsWith('.zip')) {
        callback(null, true);
      } else {
        callback(new Error('Invalid upload'));
      }
    }
  });

  router.post('/upload', apiTokenMiddleware, async (req, res, next) => {
    const ownerId = getAuthenticatedUserId(req);
    if (!ownerId) {
      writeError(res, 401, 'Authenticated user session required');
      return;
    }
    const sessionId = req.get('x-luminicent-session-id');
    const sessionToken = req.get('x-luminicent-session-token');
    try {
      if (!getSessionRegistry(req) ||
          !await getSessionRegistry(req).verify(sessionId, sessionToken, ownerId)) {
        writeError(res, 404, 'Scan not found');
        return;
      }
    } catch (error) {
      if (error.code === 'PERSISTENCE_UNAVAILABLE') {
        writeError(res, 503, 'Persistent scan storage is unavailable');
        return;
      }
      next(error);
      return;
    }
    req.luminicentOwnerId = ownerId;
    req.luminicentSessionId = sessionId;
    req.luminicentSessionToken = sessionToken;
    next();
  }, async (req, res, next) => {
    if (req.orchestrator?.isExecutionEnabled?.() === true) {
      next();
      return;
    }
    try {
      await getSessionRegistry(req).delete(
        req.luminicentSessionId,
        req.luminicentSessionToken,
        req.luminicentOwnerId
      );
    } catch (error) {
      if (error.code === 'PERSISTENCE_UNAVAILABLE') {
        writeError(res, 503, 'Persistent scan storage is unavailable');
        return;
      }
      next(error);
      return;
    }
    writeError(
      res,
      503,
      'Project execution is disabled; isolated scan worker is unavailable'
    );
  }, (req, res, next) => {
    upload.single('file')(req, res, (error) => {
      if (!error) {
        next();
        return;
      }

      const tooLarge = error.code === 'LIMIT_FILE_SIZE';
      logger.warn('Upload rejected', { code: tooLarge ? error.code : 'INVALID_UPLOAD' });
      writeError(
        res,
        tooLarge ? 413 : 400,
        tooLarge ? 'Upload exceeds the configured compressed upload limit' : 'Invalid upload'
      );
    });
  }, async (req, res) => {
    if (!req.file) {
      writeError(res, 400, 'No file uploaded');
      return;
    }

    const sessionId = req.luminicentSessionId;
    const sessionToken = req.luminicentSessionToken;
    const ownerId = req.luminicentOwnerId;
    const uploadPath = req.file.path;
    const orchestrator = req.orchestrator;
    let workspace;
    let operationError;
    let errorMessage = 'Upload processing failed';
    let errorStatus = 500;
    let stage = 'request';
    const requestController = new AbortController();
    const abortRequest = () => {
      if (requestController.signal.aborted) return;
      const error = Object.assign(new Error('Upload request was cancelled'), {
        code: 'ABORT_ERR'
      });
      requestController.abort(error);
    };
    const abortIfDisconnected = () => {
      if (!res.writableEnded) abortRequest();
    };
    req.once('aborted', abortRequest);
    res.once('close', abortIfDisconnected);

    try {
      if (!orchestrator) {
        throw new Error('Orchestrator unavailable');
      }

      stage = 'workspace';
      workspace = createWorkspace(canonicalUploadRoot);
      workspace.assertSafe();
      stage = 'extract';
      orchestrator.emitStatus(sessionId, {
        status: 'EXTRACTING',
        stage: 'extract',
        type: 'info',
        percent: 10,
        message: 'Extracting application package...'
      });

      try {
        await extractArchiveSafely(
          uploadPath,
          workspace.path,
          limits,
          () => {
            if (requestController.signal.aborted) {
              throw requestController.signal.reason;
            }
            workspace.assertSafe();
          }
        );
      } catch (error) {
        if (error.code === 'RESOURCE_LIMIT') {
          errorMessage = 'Archive exceeds resource limits';
          errorStatus = 413;
        } else if (error.code === 'INVALID_ARCHIVE') {
          errorMessage = 'Invalid or unsupported ZIP archive';
          errorStatus = 400;
        }
        throw error;
      }

      workspace.assertSafe();
      stage = 'worker';
      errorMessage = 'Isolated scan worker is unavailable; project scans are disabled';
      errorStatus = 503;
      const workerStatus = scanWorker.getStatus();
      throw Object.assign(new Error(workerStatus.reason), {
        code: 'SCAN_WORKER_UNAVAILABLE'
      });
    } catch (error) {
      operationError = error;
      if (error.code === 'RESOURCE_LIMIT') {
        errorMessage = 'Archive exceeds resource limits';
        errorStatus = 413;
      } else if (error.code === 'INVALID_ARCHIVE') {
        errorMessage = 'Invalid or unsupported ZIP archive';
        errorStatus = 400;
      }
      logger.error('Upload processing failed', {
        sessionId,
        stage,
        code: error.code || error.name || 'UNKNOWN'
      });

    } finally {
      req.removeListener('aborted', abortRequest);
      res.removeListener('close', abortIfDisconnected);
      for (const [label, cleanup] of [
        ['extraction workspace', () => workspace?.cleanup()],
        ['uploaded archive', () => cleanupUpload(uploadPath, canonicalUploadRoot)]
      ]) {
        try {
          cleanup();
        } catch (cleanupError) {
          logger.error(`Upload ${label} cleanup failed`, {
            sessionId,
            code: cleanupError.code || cleanupError.name || 'UNKNOWN'
          });
          if (!operationError) {
            operationError = cleanupError;
            errorMessage = 'Upload processing failed';
          }
        }
      }
    }

    if (operationError) {
      try {
        await getSessionRegistry(req).delete(sessionId, sessionToken, ownerId);
      } catch (error) {
        logger.error('Upload capability cleanup failed', {
          sessionId,
          code: error.code || error.name || 'UNKNOWN'
        });
      }
      try {
        orchestrator?.emitStatus(sessionId, {
          status: 'ERROR',
          stage: 'error',
          type: 'error',
          message: errorMessage,
          error: errorMessage
        });
      } catch (emitError) {
        logger.warn('Unable to emit upload failure status', {
          sessionId,
          code: emitError.code || emitError.name || 'UNKNOWN'
        });
      }
      writeError(res, errorStatus, errorMessage);
      return;
    }

    try {
      await getSessionRegistry(req).delete(sessionId, sessionToken, ownerId);
    } catch (error) {
      logger.error('Upload capability cleanup failed', {
        sessionId,
        code: error.code || error.name || 'UNKNOWN'
      });
    }
    writeError(res, 503, 'Isolated scan worker is unavailable; project scans are disabled');
  });

  router.post('/cleanup', apiTokenMiddleware, express.json(), async (req, res) => {
    const ownerId = getAuthenticatedUserId(req);
    if (!ownerId) {
      return res.status(401).json({ error: 'Authenticated user session required' });
    }
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some((key) => !['sessionId', 'sessionToken'].includes(key))) {
      return res.status(400).json({ error: 'Invalid cleanup request' });
    }
    const { sessionId, sessionToken } = body;
    if (!sessionId) {
      return res.status(400).json({ error: 'sessionId is required' });
    }
    try {
      if (!getSessionRegistry(req) ||
          !await getSessionRegistry(req).verify(sessionId, sessionToken, ownerId)) {
        return res.status(404).json({ error: 'Scan not found' });
      }
    } catch (error) {
      if (error.code === 'PERSISTENCE_UNAVAILABLE') {
        return res.status(503).json({ error: 'Persistent scan storage is unavailable' });
      }
      return next(error);
    }

    try {
      await req.orchestrator.cleanup(sessionId);
      await getSessionRegistry(req).delete(sessionId, sessionToken, ownerId);
      res.json({ success: true, sessionId, message: 'Simulation stopped' });
    } catch (error) {
      logger.error('Cleanup request failed', {
        code: error.code || error.name || 'UNKNOWN'
      });
      const unavailable = error.code === 'PERSISTENCE_UNAVAILABLE';
      res.status(unavailable ? 503 : 500).json({
        error: unavailable ? 'Persistent scan storage is unavailable' : 'Cleanup failed'
      });
    }
  });

  return router;
};

const router = createUploadRouter();
export default router;
