import fs from 'node:fs';
import path from 'node:path';
import {
  isSupportedJsTsFile,
  isTypeScriptFile,
  isJsxFile,
  JS_TS_EXTENSIONS
} from '../parser.js';
import { NODE_BUILTIN_MODULES } from './callGraph.js';
import { BoundedAstCache } from './boundedAstCache.js';
import { ProjectBudgetManager } from './projectBudgetManager.js';
import { readProjectFile } from '../../projectFileReader.js';

export const PROJECT_REGISTRY_LIMITS = Object.freeze({
  maxProjectFiles: 250,
  maxModuleGraphEdges: 1000,
  maxImportResolutions: 500
});

export const RESOLUTION_EXTENSIONS = Object.freeze([
  '',
  '.js',
  '.ts',
  '.jsx',
  '.tsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts'
]);

export const DIRECTORY_INDEX_FILES = Object.freeze([
  'index.js',
  'index.ts',
  'index.jsx',
  'index.tsx',
  'index.mjs',
  'index.cjs',
  'index.mts',
  'index.cts'
]);

const IGNORED_DIRECTORY_NAMES = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  'coverage',
  '.cache'
]);

/**
 * Normalizes a relative path to standard POSIX format, removing leading ./ and redundant slashes.
 */
export function normalizePosixPath(filePath) {
  if (!filePath || typeof filePath !== 'string') return '';
  let normalized = filePath.replace(/\\/g, '/');
  if (normalized.startsWith('./')) {
    normalized = normalized.slice(2);
  }
  return path.posix.normalize(normalized);
}

/**
 * Represents a single indexed source module within a project.
 */
export class ModuleRecord {
  constructor({
    relativePath,
    absolutePath,
    extension = '',
    isTypeScript = false,
    isJsx = false,
    sizeBytes = 0,
    sourceCode = null
  }) {
    this.relativePath = relativePath;
    this.absolutePath = absolutePath;
    this.extension = extension;
    this.isTypeScript = isTypeScript;
    this.isJsx = isJsx;
    this.sizeBytes = sizeBytes;
    this.sourceCode = sourceCode;
  }
}

/**
 * Project-wide module registry providing deterministic file indexing,
 * static CommonJS / ESM resolution, directory index resolution, and bounded AST caching.
 */
export class ProjectModuleRegistry {
  constructor(scanRoot = '.', options = {}) {
    this.scanRoot = path.resolve(scanRoot);
    this.options = options;
    this.budgetManager = options.budgetManager || new ProjectBudgetManager({
      limits: options.budgetLimits || {
        maxProjectFiles: options.maxProjectFiles,
        maxModuleGraphEdges: options.maxModuleGraphEdges,
        maxImportResolutions: options.maxImportResolutions,
        maxAstCacheEntries: options.maxAstCacheEntries,
        maxAstReparses: options.maxAstReparses,
        maxAnalysisDurationMs: options.maxAnalysisDurationMs
      },
      now: options.now,
      clock: options.clock
    });
    this.limits = Object.freeze({
      maxProjectFiles: this.budgetManager.getLimit('maxProjectFiles'),
      maxModuleGraphEdges: this.budgetManager.getLimit('maxModuleGraphEdges'),
      maxImportResolutions: this.budgetManager.getLimit('maxImportResolutions')
    });

    this.modules = new Map(); // normalized relative POSIX path -> ModuleRecord
    this.graphEdges = new Set(); // "fromRel -> toRel"
    this.importResolutionsCount = 0;
    this.limitations = options.limitations || [];
    this.isPartial = false;
    this.astCache = options.astCache || new BoundedAstCache({
      limitations: this.limitations,
      budgetManager: this.budgetManager,
      maxCachedAsts: this.budgetManager.getLimit('maxAstCacheEntries'),
      maxAstReparses: this.budgetManager.getLimit('maxAstReparses')
    });
    if (options.astCache) this.astCache.attachBudgetManager?.(this.budgetManager);

    // Optional initial in-memory module mapping (useful for fast unit testing)
    if (options.modules) {
      this.indexInMemoryModules(options.modules);
    }
  }

  /**
   * Indexes in-memory mock modules deterministically.
   *
   * @param {Object} modules - Object mapping relative paths to source strings
   */
  indexInMemoryModules(modules) {
    if (!modules || typeof modules !== 'object') return;
    const sortedKeys = Object.keys(modules).sort((a, b) => a.localeCompare(b));

    for (const key of sortedKeys) {
      const posixRel = normalizePosixPath(key);
      if (posixRel.startsWith('..') || path.isAbsolute(posixRel)) {
        if (!this.limitations.includes('module_path_outside_scan_root')) {
          this.limitations.push('module_path_outside_scan_root');
        }
        continue;
      }

      const fileBudget = this.budgetManager.consumeOnce('maxProjectFiles', posixRel);
      if (!fileBudget.allowed) {
        this._recordBudgetFailure(fileBudget);
        this.isPartial = true;
        break;
      }

      const code = modules[key];
      const ext = path.extname(posixRel).toLowerCase();
      const absPath = path.resolve(this.scanRoot, posixRel);

      this.modules.set(posixRel, new ModuleRecord({
        relativePath: posixRel,
        absolutePath: absPath,
        extension: ext,
        isTypeScript: isTypeScriptFile(posixRel),
        isJsx: isJsxFile(posixRel),
        sizeBytes: typeof code === 'string' ? Buffer.byteLength(code, 'utf8') : 0,
        sourceCode: typeof code === 'string' ? code : null
      }));
    }
  }

  /**
   * Recursively scans the filesystem under scanRoot, collecting eligible JS/TS files.
   * Discovered files are sorted alphabetically to guarantee 100% deterministic indexing.
   */
  indexProject() {
    if (this.options.modules) return; // In-memory modules already indexed

    const collected = [];

    const walkDir = (dirPath, depth = 0) => {
      if (depth > 32) return;
      let entries = [];
      try {
        entries = fs.readdirSync(dirPath, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory()) {
          if (!IGNORED_DIRECTORY_NAMES.has(entry.name)) {
            walkDir(fullPath, depth + 1);
          }
          continue;
        }

        if (entry.isFile() && isSupportedJsTsFile(entry.name)) {
          // Verify scan root boundary
          const relPath = path.relative(this.scanRoot, fullPath);
          if (relPath.startsWith('..') || path.isAbsolute(relPath)) {
            continue; // Ignore files that escape scan root via links
          }

          const posixRel = normalizePosixPath(relPath);
          collected.push({
            posixRel,
            fullPath
          });
        }
      }
    };

    walkDir(this.scanRoot);

    // Sort alphabetically by relative path to guarantee determinism
    collected.sort((a, b) => a.posixRel.localeCompare(b.posixRel));

    for (const item of collected) {
      const fileBudget = this.budgetManager.consumeOnce('maxProjectFiles', item.posixRel);
      if (!fileBudget.allowed) {
        this._recordBudgetFailure(fileBudget);
        this.isPartial = true;
        break;
      }

      let sizeBytes = 0;
      try {
        sizeBytes = fs.statSync(item.fullPath).size;
      } catch {}

      this.modules.set(item.posixRel, new ModuleRecord({
        relativePath: item.posixRel,
        absolutePath: item.fullPath,
        extension: path.extname(item.posixRel).toLowerCase(),
        isTypeScript: isTypeScriptFile(item.posixRel),
        isJsx: isJsxFile(item.posixRel),
        sizeBytes,
        sourceCode: null
      }));
    }
  }

  /**
   * Resolves an imported module specifier relative to a source file.
   * Handles relative files, extensions, directory indexes, built-ins, and external packages.
   *
   * @param {string} specifier - Module specifier from require() or import
   * @param {string} fromRelativePath - Relative path of importing module
   * @param {Object} options - Resolution options
   * @returns {Object|null} Resolution descriptor or null if unresolvable
   */
  resolveModule(specifier, fromRelativePath = '', options = {}) {
    const importBudget = this.budgetManager.consume('maxImportResolutions');
    this.importResolutionsCount = this.budgetManager.getStats().counters.maxImportResolutions;
    if (!importBudget.allowed) {
      this._recordBudgetFailure(importBudget, options);
      this.isPartial = true;
      return null;
    }

    if (!specifier || typeof specifier !== 'string') {
      const lim = 'unresolved_dynamic_import';
      if (!this.limitations.includes(lim)) {
        this.limitations.push(lim);
      }
      if (options.limitations && !options.limitations.includes(lim)) {
        options.limitations.push(lim);
      }
      return null;
    }

    // 1. Node.js built-in modules
    if (specifier.startsWith('node:') || NODE_BUILTIN_MODULES.has(specifier)) {
      return {
        resolved: false,
        isExternal: true,
        isBuiltin: true,
        specifier,
        relativePath: null
      };
    }

    // 2. Third-party packages (not relative, not absolute)
    if (!specifier.startsWith('./') && !specifier.startsWith('../') && !path.isAbsolute(specifier)) {
      return {
        resolved: false,
        isExternal: true,
        isThirdParty: true,
        specifier,
        relativePath: null
      };
    }

    // 3. Reject absolute paths that attempt external root escape
    if (path.isAbsolute(specifier)) {
      const rel = path.relative(this.scanRoot, specifier);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        const lim = 'module_path_outside_scan_root';
        if (!this.limitations.includes(lim)) {
          this.limitations.push(lim);
        }
        if (options.limitations && !options.limitations.includes(lim)) {
          options.limitations.push(lim);
        }
        return null;
      }
    }

    // 4. Resolve relative paths within scan root
    const normalizedFrom = fromRelativePath ? normalizePosixPath(fromRelativePath) : '';
    const fromDir = normalizedFrom ? path.posix.dirname(normalizedFrom) : '.';
    const targetCandidate = path.posix.normalize(path.posix.join(fromDir, specifier));

    // Guard against directory traversal escaping scan root
    if (targetCandidate.startsWith('..') || path.posix.isAbsolute(targetCandidate)) {
      const lim = 'module_path_outside_scan_root';
      if (!this.limitations.includes(lim)) {
        this.limitations.push(lim);
      }
      if (options.limitations && !options.limitations.includes(lim)) {
        options.limitations.push(lim);
      }
      return null;
    }

    let resolvedRel = null;
    let isBarrel = false;

    // A. Check exact match or candidate extensions
    for (const ext of RESOLUTION_EXTENSIONS) {
      const candidateKey = targetCandidate + ext;
      if (this.modules.has(candidateKey)) {
        resolvedRel = candidateKey;
        break;
      }
    }

    // B. Check directory index files (barrel files)
    if (!resolvedRel) {
      for (const idx of DIRECTORY_INDEX_FILES) {
        const candidateKey = path.posix.join(targetCandidate, idx);
        if (this.modules.has(candidateKey)) {
          resolvedRel = candidateKey;
          isBarrel = true;
          break;
        }
      }
    }

    // C. Disk fallback lookup for live files created during test or dynamic setups
    if (!resolvedRel && !this.options.modules) {
      const absBaseDir = normalizedFrom
        ? path.dirname(path.resolve(this.scanRoot, normalizedFrom))
        : this.scanRoot;

      for (const ext of RESOLUTION_EXTENSIONS) {
        const testPath = path.resolve(absBaseDir, specifier + ext);
        const relFromRoot = path.relative(this.scanRoot, testPath);
        if (!relFromRoot.startsWith('..') && !path.isAbsolute(relFromRoot)) {
          if (fs.existsSync(testPath) && fs.statSync(testPath).isFile()) {
            resolvedRel = normalizePosixPath(relFromRoot);
            if (!this.modules.has(resolvedRel)) {
              if (!this._registerResolvedModule(resolvedRel, testPath)) {
                resolvedRel = null;
                break;
              }
            }
            break;
          }
        }
      }

      // Check index files on disk
      if (!resolvedRel) {
        for (const idx of DIRECTORY_INDEX_FILES) {
          const testPath = path.resolve(absBaseDir, path.join(specifier, idx));
          const relFromRoot = path.relative(this.scanRoot, testPath);
          if (!relFromRoot.startsWith('..') && !path.isAbsolute(relFromRoot)) {
            if (fs.existsSync(testPath) && fs.statSync(testPath).isFile()) {
              resolvedRel = normalizePosixPath(relFromRoot);
              isBarrel = true;
              if (!this.modules.has(resolvedRel)) {
                if (!this._registerResolvedModule(resolvedRel, testPath)) {
                  resolvedRel = null;
                  break;
                }
              }
              break;
            }
          }
        }
      }
    }

    if (!resolvedRel) {
      const lim = 'unresolved_imported_module';
      if (!this.limitations.includes(lim)) {
        this.limitations.push(lim);
      }
      if (options.limitations && !options.limitations.includes(lim)) {
        options.limitations.push(lim);
      }
      return null;
    }

    // Track module graph edge
    const edgeKey = `${normalizedFrom || 'root'} -> ${resolvedRel}`;
    if (!this.graphEdges.has(edgeKey)) {
      const edgeBudget = this.budgetManager.consumeOnce('maxModuleGraphEdges', edgeKey);
      if (!edgeBudget.allowed) {
        this._recordBudgetFailure(edgeBudget, options);
        this.isPartial = true;
        return null;
      } else {
        this.graphEdges.add(edgeKey);
      }
    }

    const record = this.modules.get(resolvedRel);
    return {
      resolved: true,
      isExternal: false,
      isBarrel,
      relativePath: resolvedRel,
      absolutePath: record?.absolutePath || path.resolve(this.scanRoot, resolvedRel),
      moduleRecord: record
    };
  }

  /**
   * Retrieves an indexed module record by normalized relative path.
   */
  getModule(relativePath) {
    if (!relativePath) return null;
    const posixRel = normalizePosixPath(relativePath);
    return this.modules.get(posixRel) || null;
  }

  /**
   * Retrieves or parses the AST for an indexed module using the bounded AST cache.
   *
   * @param {string} relativePath - Relative module path
   * @param {Object} options - Parser options
   * @returns {Object} Parse result
   */
  getAst(relativePath, options = {}) {
    const posixRel = normalizePosixPath(relativePath);
    const record = this.modules.get(posixRel);
    if (!record) {
      return {
        ast: null,
        parseStatus: 'failed',
        errors: [{ code: 'MODULE_NOT_FOUND', message: `Module ${posixRel} not found in registry` }],
        isPartial: true,
        recoveredErrors: []
      };
    }

    let code = record.sourceCode;
    if (typeof code !== 'string') {
      try {
        code = readProjectFile(fs, record.absolutePath, {
          maxBytes: this.options.maxSourceBytes || 10 * 1024 * 1024,
          rootPath: this.scanRoot
        }).content;
      } catch (err) {
        return {
          ast: null,
          parseStatus: 'failed',
          errors: [{ code: err.code || 'FILE_READ_ERROR', message: 'Could not read the indexed project module' }],
          isPartial: true,
          recoveredErrors: []
        };
      }
    }

    return this.astCache.getOrParse(code, record.absolutePath, {
      ...options,
      relativePath: posixRel,
      limitations: this.limitations
    });
  }

  _recordBudgetFailure(result, options = {}) {
    const limitation = result?.code;
    if (!limitation) return;
    if (!this.limitations.includes(limitation)) this.limitations.push(limitation);
    if (options.limitations && !options.limitations.includes(limitation)) {
      options.limitations.push(limitation);
    }
    this.isPartial = true;
  }

  _registerResolvedModule(relativePath, absolutePath) {
    const fileBudget = this.budgetManager.consumeOnce('maxProjectFiles', relativePath);
    if (!fileBudget.allowed) {
      this._recordBudgetFailure(fileBudget);
      return false;
    }
    let sizeBytes = 0;
    try {
      sizeBytes = fs.statSync(absolutePath).size;
    } catch {
      if (!this.limitations.includes('module_file_stat_error')) {
        this.limitations.push('module_file_stat_error');
      }
      this.isPartial = true;
      return false;
    }
    this.modules.set(relativePath, new ModuleRecord({
      relativePath,
      absolutePath,
      extension: path.extname(relativePath).toLowerCase(),
      isTypeScript: isTypeScriptFile(relativePath),
      isJsx: isJsxFile(relativePath),
      sizeBytes,
      sourceCode: null
    }));
    return true;
  }

  /**
   * Returns current registry statistics and resource consumption metrics.
   */
  getStats() {
    return {
      modulesCount: this.modules.size,
      maxProjectFiles: this.limits.maxProjectFiles,
      graphEdgesCount: this.budgetManager.getStats().counters.maxModuleGraphEdges,
      localGraphEdgesCount: this.graphEdges.size,
      maxModuleGraphEdges: this.limits.maxModuleGraphEdges,
      importResolutionsCount: this.importResolutionsCount,
      maxImportResolutions: this.limits.maxImportResolutions,
      isPartial: this.isPartial || this.limitations.length > 0,
      limitations: [...this.limitations],
      astCacheStats: this.astCache.getStats(),
      budgetStats: this.budgetManager.getStats()
    };
  }
}
