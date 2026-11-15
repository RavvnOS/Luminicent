export const PROJECT_BUDGET_LIMITS = Object.freeze({
  maxProjectFiles: 250,
  maxModuleGraphEdges: 1_000,
  maxImportResolutions: 500,
  maxAstCacheEntries: 250,
  maxAstReparses: 50,
  maxCallDepth: 5,
  maxTotalInvocations: 200,
  maxCallSitesPerFunction: 50,
  maxTaintOperations: 10_000,
  maxAnalysisDurationMs: 15_000
});

export const PROJECT_BUDGET_LIMITATION_CODES = Object.freeze({
  maxProjectFiles: 'project_file_limit_exceeded',
  maxModuleGraphEdges: 'module_graph_edge_limit_exceeded',
  maxImportResolutions: 'import_resolution_limit_exceeded',
  maxAstCacheEntries: 'ast_cache_entry_limit_exceeded',
  maxAstReparses: 'ast_cache_eviction_budget_exceeded',
  maxCallDepth: 'call_graph_depth_limit_exceeded',
  maxTotalInvocations: 'call_graph_invocation_limit_exceeded',
  maxCallSitesPerFunction: 'call_graph_call_site_limit_exceeded',
  maxTaintOperations: 'taint_operation_limit_exceeded',
  maxAnalysisDurationMs: 'analysis_duration_limit_exceeded'
});

const DEPTH_RESOURCE = 'maxCallDepth';
const DURATION_RESOURCE = 'maxAnalysisDurationMs';

export class ProjectBudgetManager {
  constructor(options = {}) {
    const overrides = options.limits || options;
    this.limits = Object.freeze(Object.fromEntries(
      Object.entries(PROJECT_BUDGET_LIMITS).map(([resource, defaultLimit]) => {
        const configured = overrides[resource];
        return [resource, Number.isFinite(configured) && configured >= 0 ? configured : defaultLimit];
      })
    ));
    this.now = typeof options.now === 'function'
      ? options.now
      : typeof options.clock === 'function'
        ? options.clock
        : () => Date.now();
    this.startedAt = this.now();
    this.counters = new Map(Object.keys(this.limits).map((resource) => [resource, 0]));
    this.scopeCounters = new Map();
    this.onceKeys = new Map();
    this.activeKeys = new Map();
    this.limitationRecords = new Map();
  }

  getLimit(resource) {
    return Object.prototype.hasOwnProperty.call(this.limits, resource) ? this.limits[resource] : null;
  }

  getElapsedMs() {
    return Math.max(0, this.now() - this.startedAt);
  }

  check(resource, amount = 1, options = {}) {
    const limit = this.getLimit(resource);
    if (limit === null || !Number.isFinite(amount) || amount < 0) {
      return this._result(false, resource, limit, this.counters.get(resource) || 0, 'invalid_budget_request');
    }

    if (resource !== DURATION_RESOURCE && this.getElapsedMs() >= this.getLimit(DURATION_RESOURCE)) {
      return this._exhausted(DURATION_RESOURCE, this.getElapsedMs(), options);
    }

    if (resource === DURATION_RESOURCE) {
      const elapsed = this.getElapsedMs();
      if (elapsed >= limit) {
        return this._exhausted(resource, elapsed, options);
      }
      return this._result(true, resource, limit, elapsed);
    }

    const used = resource === DEPTH_RESOURCE
      ? 0
      : options.scope
        ? (this.scopeCounters.get(resource)?.get(options.scope) || 0)
        : (this.counters.get(resource) || 0);
    const requested = resource === DEPTH_RESOURCE ? amount : used + amount;
    if (requested > limit) {
      return this._exhausted(resource, used, options);
    }
    return this._result(true, resource, limit, used);
  }

  consume(resource, amount = 1, options = {}) {
    if (resource !== DURATION_RESOURCE && this.getElapsedMs() >= this.getLimit(DURATION_RESOURCE)) {
      return this._exhausted(DURATION_RESOURCE, this.getElapsedMs(), options);
    }
    const keySet = options.key === undefined ? null : this._keySet(this.onceKeys, resource);
    const key = options.scope && options.key !== undefined
      ? `${options.scope}\u0000${options.key}`
      : options.key;
    if (keySet?.has(key)) {
      return this._result(true, resource, this.getLimit(resource), this.counters.get(resource) || 0, null, true);
    }

    const check = this.check(resource, amount, options);
    if (!check.allowed) return check;
    if (resource !== DEPTH_RESOURCE && resource !== DURATION_RESOURCE) {
      if (options.scope) {
        let scopes = this.scopeCounters.get(resource);
        if (!scopes) {
          scopes = new Map();
          this.scopeCounters.set(resource, scopes);
        }
        scopes.set(options.scope, (scopes.get(options.scope) || 0) + amount);
      } else {
        this.counters.set(resource, (this.counters.get(resource) || 0) + amount);
      }
      if (keySet) keySet.add(key);
    }
    return this._result(true, resource, this.getLimit(resource), this.counters.get(resource) || 0);
  }

  consumeOnce(resource, key, amount = 1, options = {}) {
    if (key === undefined || key === null) {
      return this._result(false, resource, this.getLimit(resource), this.counters.get(resource) || 0, 'invalid_budget_request');
    }
    return this.consume(resource, amount, { ...options, key });
  }

  acquire(resource, key, options = {}) {
    if (key === undefined || key === null) {
      return this._result(false, resource, this.getLimit(resource), this.counters.get(resource) || 0, 'invalid_budget_request');
    }
    if (resource !== DURATION_RESOURCE && this.getElapsedMs() >= this.getLimit(DURATION_RESOURCE)) {
      return this._exhausted(DURATION_RESOURCE, this.getElapsedMs(), options);
    }
    const active = this._keySet(this.activeKeys, resource);
    if (active.has(key)) {
      return this._result(true, resource, this.getLimit(resource), this.counters.get(resource) || 0, null, true);
    }
    const result = this.check(resource, 1, options);
    if (!result.allowed) return result;
    active.add(key);
    this.counters.set(resource, (this.counters.get(resource) || 0) + 1);
    return this._result(true, resource, this.getLimit(resource), this.counters.get(resource));
  }

  release(resource, key) {
    const active = this.activeKeys.get(resource);
    if (!active || !active.has(key)) return false;
    active.delete(key);
    this.counters.set(resource, Math.max(0, (this.counters.get(resource) || 0) - 1));
    return true;
  }

  _keySet(map, resource) {
    let keys = map.get(resource);
    if (!keys) {
      keys = new Set();
      map.set(resource, keys);
    }
    return keys;
  }

  _exhausted(resource, used, options = {}) {
    const code = PROJECT_BUDGET_LIMITATION_CODES[resource];
    const limit = this.getLimit(resource);
    if (!this.limitationRecords.has(code)) {
      this.limitationRecords.set(code, {
        code,
        resource,
        limit,
        used,
        coverage: options.coverage || 'partial'
      });
    }
    return this._result(false, resource, limit, used, code);
  }

  _result(allowed, resource, limit, used, code = null, duplicate = false) {
    return {
      allowed,
      resource,
      limit,
      used,
      code,
      duplicate,
      coverage: allowed ? 'complete' : (this.limitationRecords.get(code)?.coverage || 'partial')
    };
  }

  getLimitationCodes() {
    return [...this.limitationRecords.keys()];
  }

  getLimitations() {
    return [...this.limitationRecords.values()].map((item) => ({ ...item }));
  }

  getStats() {
    const counters = Object.fromEntries(this.counters);
    return {
      limits: { ...this.limits },
      counters,
      scopedCounters: Object.fromEntries(
        [...this.scopeCounters].map(([resource, scopes]) => [resource, Object.fromEntries(scopes)])
      ),
      elapsedMs: this.getElapsedMs(),
      limitations: this.getLimitations()
    };
  }
}
