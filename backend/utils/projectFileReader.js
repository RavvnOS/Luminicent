import fs from 'node:fs';
import path from 'node:path';

const SOURCE_EXTENSIONS = new Set([
  '.c', '.cc', '.cpp', '.cs', '.css', '.dart', '.go', '.h', '.hpp', '.html',
  '.java', '.js', '.jsx', '.mjs', '.cjs', '.key', '.kt', '.map', '.mts', '.cts',
  '.pem', '.php', '.py', '.pyi', '.rb', '.rs', '.scala', '.sh', '.sql', '.svg',
  '.svelte', '.swift', '.ts', '.tsx', '.vue'
]);
const DOCUMENT_EXTENSIONS = new Set(['.adoc', '.md', '.rst', '.txt']);
const CONFIG_EXTENSIONS = new Set([
  '.cfg', '.conf', '.config', '.env', '.gradle', '.hcl', '.ini', '.json',
  '.properties', '.tf', '.toml', '.xml', '.yaml', '.yml'
]);
const BINARY_EXTENSIONS = new Set([
  '.7z', '.bmp', '.class', '.dll', '.exe', '.gif', '.gz', '.ico', '.jar',
  '.jpeg', '.jpg', '.mp3', '.mp4', '.pdf', '.png', '.pyc', '.so', '.tar',
  '.tif', '.tiff', '.wasm', '.webp', '.woff', '.woff2', '.zip'
]);
const TEXT_BASENAMES = new Set([
  '.dockerignore', '.gitignore', '.npmrc', '.pypirc', '.netrc', 'dockerfile',
  'gemfile', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa', 'license', 'makefile',
  'notice', 'procfile', 'pipfile', 'pipfile.lock', 'poetry.lock'
]);
const IGNORED_BASENAMES = new Set(['.ds_store', 'desktop.ini', 'thumbs.db']);
const CONFIGURATION_BASENAMES = new Set([
  '.dockerignore', '.env', '.npmrc', '.pypirc', '.netrc', 'dockerfile'
]);

const isContainedPath = (rootPath, candidatePath) => {
  const relativePath = path.relative(rootPath, candidatePath);
  return relativePath === '' ||
    (relativePath !== '..' && !relativePath.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relativePath));
};

export class ProjectFileReadError extends Error {
  constructor(code, message, cause) {
    super(message, { cause });
    this.name = 'ProjectFileReadError';
    this.code = code;
    this.relativePath = null;
  }
}

export const classifyProjectFile = (fileName) => {
  const lowerName = path.basename(fileName).toLowerCase();
  const extension = path.extname(lowerName);

  if (IGNORED_BASENAMES.has(lowerName)) return 'ignored';
  if (BINARY_EXTENSIONS.has(extension)) return 'binary';
  if (TEXT_BASENAMES.has(lowerName) || lowerName === '.env' || lowerName.startsWith('.env.')) {
    return 'configuration';
  }
  if (SOURCE_EXTENSIONS.has(extension)) return 'source';
  if (DOCUMENT_EXTENSIONS.has(extension)) return 'document';
  if (CONFIG_EXTENSIONS.has(extension)) return 'configuration';
  return 'unsupported';
};

export const isProjectConfigurationFile = (fileName) =>
  CONFIG_EXTENSIONS.has(path.extname(path.basename(fileName).toLowerCase())) ||
  CONFIGURATION_BASENAMES.has(path.basename(fileName).toLowerCase());

export const readProjectFile = (
  fileSystem,
  filePath,
  { maxBytes, rootPath } = {}
) => {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError('A non-negative safe maxBytes limit is required');
  }

  let descriptor;
  const resolvedRoot = rootPath ? path.resolve(rootPath) : null;
  const relativePath = resolvedRoot
    ? path.relative(resolvedRoot, path.resolve(filePath)).replace(/\\/g, '/')
    : path.basename(filePath);
  const safeRelativePath = relativePath && relativePath !== '..' &&
    !relativePath.startsWith('../') && !path.isAbsolute(relativePath)
    ? relativePath
    : null;
  const raise = (code, message, cause) => {
    const error = new ProjectFileReadError(code, message, cause);
    error.relativePath = safeRelativePath;
    throw error;
  };
  try {
    if (rootPath) {
      const canonicalRoot = fileSystem.realpathSync(rootPath);
      const canonicalFile = fileSystem.realpathSync(filePath);
      if (canonicalFile === canonicalRoot || !isContainedPath(canonicalRoot, canonicalFile)) {
        raise(
          'PROJECT_FILE_OUTSIDE_ROOT',
          'Project file is outside the analysis root'
        );
      }
    }

    descriptor = fileSystem.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
    );
    const metadata = fileSystem.fstatSync(descriptor);
    if (!metadata.isFile()) {
      raise(
        'PROJECT_FILE_NOT_REGULAR',
        'Project entry is not a regular file'
      );
    }
    if (metadata.size > maxBytes) {
      raise(
        'PROJECT_FILE_TOO_LARGE',
        'Project file exceeds its configured read limit'
      );
    }

    const chunks = [];
    const buffer = Buffer.alloc(64 * 1024);
    let byteLength = 0;
    while (true) {
      const bytesRead = fileSystem.readSync(
        descriptor,
        buffer,
        0,
        Math.min(buffer.length, maxBytes - byteLength + 1),
        null
      );
      if (bytesRead === 0) break;
      byteLength += bytesRead;
      if (byteLength > maxBytes) {
        raise(
          'PROJECT_FILE_TOO_LARGE',
          'Project file exceeds its configured read limit'
        );
      }
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }

    const bytes = Buffer.concat(chunks, byteLength);
    if ((bytes.length >= 2 &&
        ((bytes[0] === 0xFF && bytes[1] === 0xFE) ||
          (bytes[0] === 0xFE && bytes[1] === 0xFF)))) {
      raise(
        'PROJECT_FILE_UNSUPPORTED_ENCODING',
        'UTF-16 project files are not supported; UTF-8 is required'
      );
    }
    if (bytes.some((byte) =>
      byte === 0 ||
      (byte < 0x20 && byte !== 0x09 && byte !== 0x0A && byte !== 0x0D) ||
      byte === 0x7F
    )) {
      raise(
        'PROJECT_FILE_BINARY',
        'Binary control bytes are not supported as text input'
      );
    }

    let content;
    try {
      content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
    } catch (error) {
      raise(
        'PROJECT_FILE_INVALID_UTF8',
        'Project file is not valid UTF-8',
        error
      );
    }

    return {
      status: 'decoded',
      fileType: classifyProjectFile(filePath),
      content,
      byteLength,
      hadUtf8Bom: bytes.length >= 3 &&
        bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF
    };
  } catch (error) {
    if (error instanceof ProjectFileReadError) {
      error.relativePath ||= safeRelativePath;
      throw error;
    }
    const wrapped = new ProjectFileReadError(
      'PROJECT_FILE_UNREADABLE',
      'Project file could not be read',
      error
    );
    wrapped.relativePath = safeRelativePath;
    throw wrapped;
  } finally {
    if (descriptor !== undefined) fileSystem.closeSync(descriptor);
  }
};
