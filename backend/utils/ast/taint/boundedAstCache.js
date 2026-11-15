import { createHash } from 'node:crypto';
import { parseSource, PARSER_LIMITS } from '../parser.js';
import { PROJECT_BUDGET_LIMITATION_CODES } from './projectBudgetManager.js';

export const AST_CACHE_LIMITS = Object.freeze({
  maxCachedAsts: 250,
  maxAstReparses: 50
});

let nextCacheId = 1;

/**
 * Normalizes a cache key into a standard POSIX relative identifier.
 *
 * @param {string} key - File path or module identifier
 * @returns {string} Normalized key
 */
export function normalizeCacheKey(key) {
  if (!key || typeof key !== 'string') return 'source.js';
  let normalized = key.replace(/\\/g, '/');
  if (normalized.startsWith('./')) {
    normalized = normalized.slice(2);
  }
  return normalized;
}

/**
 * Bounded, deterministic LRU cache for parsed Babel ASTs.
 * Enforces a strict 250-AST capacity ceiling and a 50-reparse budget.
 */
export class BoundedAstCache {
  constructor(options = {}) {
    this.maxCachedAsts = Number.isInteger(options.maxCachedAsts) && options.maxCachedAsts > 0
      ? options.maxCachedAsts
      : AST_CACHE_LIMITS.maxCachedAsts;

    this.maxAstReparses = Number.isInteger(options.maxAstReparses) && options.maxAstReparses >= 0
      ? options.maxAstReparses
      : AST_CACHE_LIMITS.maxAstReparses;

    this.cache = new Map(); // key -> { ast, parseStatus, errors, isPartial, recoveredErrors, fingerprint, key }
    this.evictionHistory = new Set(); // keys that were evicted due to LRU capacity
    this.limitations = options.limitations || [];
    this.budgetManager = options.budgetManager || null;
    this.cacheId = nextCacheId++;
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      reparses: 0,
      parseErrors: 0
    };
  }

  /**
   * Computes a deterministic SHA-256 fingerprint for source code.
   *
   * @param {string} code - Raw source code
   * @returns {string} 16-hex-character content fingerprint
   */
  computeFingerprint(code) {
    if (typeof code !== 'string') return '';
    return createHash('sha256').update(code, 'utf8').digest('hex').slice(0, 16);
  }

  /**
   * Retrieves an AST from cache, updating its LRU position if found.
   * Invalidates and returns null if the content fingerprint does not match.
   *
   * @param {string} key - Cache key (usually normalized relative module path)
   * @param {string|null} fingerprint - Optional expected content fingerprint
   * @returns {Object|null} Cached parse result or null
   */
  get(key, fingerprint = null) {
    if (!key || typeof key !== 'string') return null;
    const normalizedKey = normalizeCacheKey(key);

    if (this.cache.has(normalizedKey)) {
      const entry = this.cache.get(normalizedKey);

      // Invalidate if source content has changed
      if (fingerprint && entry.fingerprint && entry.fingerprint !== fingerprint) {
        this._releaseEntry(normalizedKey);
        this.cache.delete(normalizedKey);
        this.evictionHistory.delete(normalizedKey);
        this.stats.misses++;
        return null;
      }

      // Move key to MRU (most recently used) position in Map
      this.cache.delete(normalizedKey);
      this.cache.set(normalizedKey, entry);
      this.stats.hits++;
      return entry;
    }

    this.stats.misses++;
    return null;
  }

  /**
   * Stores a parse result in the cache, evicting the least recently used entry if full.
   *
   * @param {string} key - Cache key
   * @param {Object} parseResult - Result from parseSource
   * @param {string} fingerprint - Content fingerprint
   */
  set(key, parseResult, fingerprint = '') {
    if (!key || typeof key !== 'string' || !parseResult?.ast || parseResult.parseStatus === 'failed') return false;
    const normalizedKey = normalizeCacheKey(key);

    // If key already exists, delete it first to place it at MRU.
    if (this.cache.has(normalizedKey)) {
      this._releaseEntry(normalizedKey);
      this.cache.delete(normalizedKey);
    } else if (this.cache.size >= this.maxCachedAsts) {
      // Evict LRU (first key in insertion order)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this._releaseEntry(oldestKey);
        this.cache.delete(oldestKey);
        this.evictionHistory.add(oldestKey);
        this.stats.evictions++;
      }
    }

    const budgetKey = `${this.cacheId}:${normalizedKey}`;
    if (this.budgetManager) {
      const acquired = this.budgetManager.acquire('maxAstCacheEntries', budgetKey);
      if (!acquired.allowed) {
        this._recordLimitation(acquired.code);
        return false;
      }
    }

    this.cache.set(normalizedKey, {
      ast: parseResult.ast || null,
      parseStatus: parseResult.parseStatus || (parseResult.ast ? 'success' : 'failed'),
      errors: parseResult.errors || [],
      isPartial: Boolean(parseResult.isPartial),
      recoveredErrors: parseResult.recoveredErrors || [],
      fingerprint,
      key: normalizedKey
    });
    return true;
  }

  attachBudgetManager(budgetManager) {
    if (!budgetManager || this.budgetManager === budgetManager) return;
    if (this.budgetManager) {
      for (const key of this.cache.keys()) this._releaseEntry(key);
    }
    this.budgetManager = budgetManager;
    for (const key of this.cache.keys()) {
      const result = budgetManager.acquire('maxAstCacheEntries', `${this.cacheId}:${key}`);
      if (!result.allowed) {
        this._recordLimitation(result.code);
        this.cache.delete(key);
        this.evictionHistory.add(key);
        this.stats.evictions++;
      }
    }
  }

  _releaseEntry(key) {
    if (this.budgetManager) {
      this.budgetManager.release('maxAstCacheEntries', `${this.cacheId}:${key}`);
    }
  }

  _recordLimitation(code) {
    if (!code) return;
    if (!this.limitations.includes(code)) this.limitations.push(code);
  }

  _skippedResult(code, message, key) {
    this._recordLimitation(code);
    const errorCode = code === PROJECT_BUDGET_LIMITATION_CODES.maxAstReparses
      ? 'CACHE_REPARSE_LIMIT_EXCEEDED'
      : code.toUpperCase();
    return {
      ast: null,
      parseStatus: 'skipped',
      errors: [{ code: errorCode, message: `${message} for module ${key}` }],
      isPartial: true,
      recoveredErrors: []
    };
  }

  /**
   * Retrieves an AST from cache or parses the source code if absent.
   * Enforces the maximum reparse budget if an evicted file must be parsed again.
   *
   * @param {string} code - Source code
   * @param {string} filePath - File path for parser error reporting
   * @param {Object} options - Parser and cache options
   * @returns {Object} Parse result
   */
  getOrParse(code, filePath, options = {}) {
    const rawKey = options.cacheKey || options.relativePath || filePath || 'source.js';
    const key = normalizeCacheKey(rawKey);
    const fingerprint = this.computeFingerprint(code);

    if (this.budgetManager) {
      const duration = this.budgetManager.check('maxAnalysisDurationMs');
      if (!duration.allowed) {
        this._recordLimitation(duration.code);
        if (options.limitations && !options.limitations.includes(duration.code)) {
          options.limitations.push(duration.code);
        }
        return this._skippedResult(
          duration.code,
          `Project analysis duration limit of ${duration.limit} ms exceeded`,
          key
        );
      }
    }

    const cached = this.get(key, fingerprint);
    if (cached) {
      return cached;
    }

    // Check if key was previously evicted
    if (this.evictionHistory.has(key)) {
      if (this.budgetManager) {
        const consumed = this.budgetManager.consume('maxAstReparses');
        if (!consumed.allowed) {
          this._recordLimitation(consumed.code);
          if (options.limitations && !options.limitations.includes(consumed.code)) {
            options.limitations.push(consumed.code);
          }
          return this._skippedResult(
            consumed.code,
            `AST cache eviction reparse budget of ${consumed.limit} reparses exceeded`,
            key
          );
        }
        this.stats.reparses++;
      } else {
        if (this.stats.reparses >= this.maxAstReparses) {
          const limitation = PROJECT_BUDGET_LIMITATION_CODES.maxAstReparses;
          this._recordLimitation(limitation);
          if (options.limitations && !options.limitations.includes(limitation)) {
            options.limitations.push(limitation);
          }
          return this._skippedResult(
            limitation,
            `AST cache eviction reparse budget of ${this.maxAstReparses} reparses exceeded`,
            key
          );
        }
        this.stats.reparses++;
      }
      this.evictionHistory.delete(key);
    }

    // Parse source safely
    const parseResult = parseSource(code, {
      filePath,
      maxSourceBytes: options.maxSourceBytes || PARSER_LIMITS.maxSourceBytes,
      errorRecovery: options.errorRecovery !== false
    });

    if (parseResult.parseStatus === 'failed' || !parseResult.ast) {
      this.stats.parseErrors++;
      // Parse failures do not leave or create invalid or stale cache entries
      this.cache.delete(key);
      return parseResult;
    }

    if (!this.set(key, parseResult, fingerprint) && this.budgetManager) {
      const code = PROJECT_BUDGET_LIMITATION_CODES.maxAstCacheEntries;
      this._recordLimitation(code);
      if (options.limitations && !options.limitations.includes(code)) {
        options.limitations.push(code);
      }
      return { ...parseResult, isPartial: true };
    }
    return parseResult;
  }

  has(key) {
    if (!key || typeof key !== 'string') return false;
    return this.cache.has(normalizeCacheKey(key));
  }

  invalidate(key) {
    if (!key || typeof key !== 'string') return;
    const normalizedKey = normalizeCacheKey(key);
    this._releaseEntry(normalizedKey);
    this.cache.delete(normalizedKey);
    this.evictionHistory.delete(normalizedKey);
  }

  clear() {
    for (const key of this.cache.keys()) this._releaseEntry(key);
    this.cache.clear();
    this.evictionHistory.clear();
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      reparses: 0,
      parseErrors: 0
    };
  }

  getStats() {
    const projectCounters = this.budgetManager?.getStats().counters;
    return {
      ...this.stats,
      reparses: projectCounters?.maxAstReparses ?? this.stats.reparses,
      localReparses: this.stats.reparses,
      size: this.cache.size,
      projectSize: projectCounters?.maxAstCacheEntries ?? this.cache.size,
      capacity: this.maxCachedAsts,
      maxReparses: this.budgetManager?.getLimit('maxAstReparses') ?? this.maxAstReparses,
      isReparseBudgetExceeded: this.budgetManager
        ? projectCounters.maxAstReparses >= this.budgetManager.getLimit('maxAstReparses')
        : this.stats.reparses >= this.maxAstReparses,
      limitations: [...this.limitations]
    };
  }
}
