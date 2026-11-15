/**
 * Resource limits for taint propagation to guard against pathological processing.
 */
export const TAINT_STATE_LIMITS = Object.freeze({
  maxSteps: 50,
  maxTrackedVariables: 200
});

/**
 * Represents a single taint record tracking origin, current expression, and propagation steps.
 */
export class TaintRecord {
  /**
   * @param {Object} source - Original source descriptor { expression, path, line, column, file }
   * @param {string} currentExpr - Current representation of the tainted expression
   * @param {Array<Object>} steps - History of propagation steps [{ from, to, expression, line, column }]
   * @param {Object} [sanitization] - Sanitization status { sanitized: boolean, details: Object }
   */
  constructor(source, currentExpr, steps = [], sanitization = { sanitized: false, details: null }) {
    this.source = source;
    this.currentExpr = currentExpr || source.expression;
    this.steps = [...steps];
    this.sanitization = sanitization;
  }

  /**
   * Clones this record with an appended propagation step.
   *
   * @param {string} to - Destination variable or expression name
   * @param {Object} loc - Location { line, column }
   * @param {string} exprText - Expression text
   * @returns {TaintRecord} New record with updated step
   */
  withStep(to, loc = {}, exprText = '') {
    const nextSteps = [...this.steps];
    if (nextSteps.length < TAINT_STATE_LIMITS.maxSteps) {
      nextSteps.push({
        from: this.currentExpr,
        to,
        expression: exprText || to,
        line: loc.line,
        column: loc.column,
        ...(loc.file ? { file: loc.file } : {}),
        ...(loc.fromModule ? { fromModule: loc.fromModule } : {}),
        ...(loc.toModule ? { toModule: loc.toModule } : {}),
        ...(loc.importExport ? { importExport: loc.importExport } : {})
      });
    }
    return new TaintRecord(this.source, to, nextSteps, this.sanitization);
  }

  /**
   * Returns a copy marked with sanitization metadata.
   */
  withSanitization(sanitizationDetails) {
    return new TaintRecord(this.source, this.currentExpr, this.steps, {
      sanitized: true,
      context: sanitizationDetails?.context || 'all',
      details: sanitizationDetails
    });
  }
}

/**
 * Lexically-scoped taint environment supporting shadowing and nested blocks.
 */
export class TaintScope {
  /**
   * @param {TaintScope|null} parent - Parent lexical scope
   * @param {string} scopeName - Descriptive name for debugging/tracing
   */
  constructor(parent = null, scopeName = 'block') {
    this.parent = parent;
    this.scopeName = scopeName;
    this.bindings = new Map(); // identifier -> TaintRecord | null (null means explicitly clean/shadowed)
    this.propertyBindings = new Map(); // "obj.prop" -> TaintRecord
    this.optionsBindings = new Map(); // identifier -> Object descriptor { shell: boolean, ... }
    this.aliasSets = []; // Array of Set<string>
  }

  /**
   * Tracks an alias relationship between two identifiers pointing to the same object.
   */
  addAlias(obj1, obj2) {
    if (!obj1 || !obj2 || obj1 === obj2) return;
    let set = this.aliasSets.find((s) => s.has(obj1) || s.has(obj2));
    if (!set) {
      set = new Set([obj1, obj2]);
      this.aliasSets.push(set);
    } else {
      set.add(obj1);
      set.add(obj2);
    }
  }

  /**
   * Resolves all known aliases for an identifier across lexical scopes.
   */
  getAliases(obj) {
    if (!obj) return [];
    const directSet = this.aliasSets.find((s) => s.has(obj));
    const set = directSet ? Array.from(directSet).filter((x) => x !== obj) : [];
    if (this.parent) {
      return [...new Set([...set, ...this.parent.getAliases(obj)])];
    }
    return set;
  }

  /**
   * Tracks an options configuration object associated with an identifier.
   */
  setOption(name, optionsObj) {
    if (!name) return;
    this.optionsBindings.set(name, optionsObj);
  }

  /**
   * Resolves tracked options for an identifier, traversing up lexical scope.
   */
  getOption(name) {
    if (!name) return null;
    if (this.optionsBindings.has(name)) {
      return this.optionsBindings.get(name);
    }
    if (this.parent) {
      return this.parent.getOption(name);
    }
    return null;
  }

  /**
   * Updates or mutates a property on a tracked options object.
   * If the binding exists in a parent scope, creates a shadowed copy in this scope.
   */
  setOptionProperty(name, propName, value) {
    if (!name || !propName) return;
    let existing = this.getOption(name);
    if (existing) {
      existing[propName] = value;
    } else {
      existing = { [propName]: value };
      this.optionsBindings.set(name, existing);
    }
  }

  /**
   * Creates a nested child scope.
   */
  createChildScope(name = 'child_block') {
    return new TaintScope(this, name);
  }

  /**
   * Marks a variable as tainted in this scope.
   */
  setTainted(name, record) {
    if (!name || this.bindings.size >= TAINT_STATE_LIMITS.maxTrackedVariables) return;
    this.bindings.set(name, record);
  }

  /**
   * Marks a variable as clean in this scope (shadowing or clearing taint).
   * Also clears any tracked property bindings on this container variable.
   */
  setClean(name, options = {}) {
    if (!name) return;
    this.bindings.set(name, null);
    this.aliasSets = this.aliasSets.map((s) => {
      s.delete(name);
      return s;
    }).filter((s) => s.size > 1);

    for (const key of Array.from(this.propertyBindings.keys())) {
      if (key.startsWith(`${name}.`)) {
        this.propertyBindings.delete(key);
      }
    }
    if (options.clearParentProperties !== false && this.parent) {
      for (const key of Array.from(this.parent.propertyBindings.keys())) {
        if (key.startsWith(`${name}.`)) {
          this.parent.propertyBindings.delete(key);
        }
      }
    }
  }

  /**
   * Explicitly clears taint on a single property of a container and propagates to aliases.
   */
  clearPropertyTaint(objectName, propName, propagateAliases = true) {
    if (!objectName || !propName) return;
    const key = `${objectName}.${propName}`;
    this.propertyBindings.delete(key);
    if (this.parent) {
      this.parent.clearPropertyTaint(objectName, propName, false);
    }
    if (propagateAliases) {
      for (const alias of this.getAliases(objectName)) {
        this.clearPropertyTaint(alias, propName, false);
      }
    }
  }

  /**
   * Copies all property taint bindings from a source object to an alias target object.
   */
  copyProperties(sourceObj, targetObj) {
    if (!sourceObj || !targetObj || sourceObj === targetObj) return;
    this.addAlias(sourceObj, targetObj);
    const prefix = `${sourceObj}.`;
    for (const [key, record] of this.propertyBindings.entries()) {
      if (key.startsWith(prefix)) {
        const subProp = key.slice(prefix.length);
        this.setPropertyTainted(targetObj, subProp, record, false);
      }
    }
    if (this.parent) {
      this.parent.copyProperties(sourceObj, targetObj);
      for (const [key, record] of this.parent.propertyBindings.entries()) {
        if (key.startsWith(prefix)) {
          this.setPropertyTainted(targetObj, key.slice(prefix.length), record, false);
        }
      }
    }
  }

  /**
   * Marks a property on a container (object/array) as tainted and propagates to aliases.
   * e.g. setPropertyTainted('data', 'name', record)
   */
  setPropertyTainted(objectName, propName, record, propagateAliases = true) {
    if (!objectName || !propName) return;
    const key = `${objectName}.${propName}`;
    if (this.propertyBindings.size < TAINT_STATE_LIMITS.maxTrackedVariables) {
      this.propertyBindings.set(key, record);
    }
    if (propagateAliases) {
      for (const alias of this.getAliases(objectName)) {
        this.setPropertyTainted(alias, propName, record, false);
      }
    }
  }

  /**
   * Checks whether a variable name or member path is tainted.
   *
   * @param {string} identifier - Variable name, e.g. "userInput"
   * @param {string|null} [subProperty=null] - Optional property name, e.g. "name"
   * @returns {TaintRecord|null} The TaintRecord if tainted, or null
   */
  lookup(identifier, subProperty = null) {
    if (!identifier) return null;

    // Check property-specific taint if subProperty is provided
    if (subProperty) {
      const propKey = `${identifier}.${subProperty}`;
      if (this.propertyBindings.has(propKey)) {
        return this.propertyBindings.get(propKey);
      }
      if (this.bindings.has(identifier)) return null;
      if (this.parent) {
        return this.parent.lookup(identifier, subProperty);
      }
      return null;
    }

    // Check variable binding in current scope
    if (this.bindings.has(identifier)) {
      const record = this.bindings.get(identifier);
      if (record === null) {
        // Variable is explicitly clean or shadowed with safe value in this scope
        return null;
      }
      return record;
    }

    // If subProperty is not specified, check if any property on this container is tainted
    for (const [key, record] of this.propertyBindings.entries()) {
      if (key.startsWith(`${identifier}.`)) {
        return record;
      }
    }

    // Traverse to parent scope
    if (this.parent) {
      return this.parent.lookup(identifier, subProperty);
    }

    return null;
  }

  /**
   * Checks if an entire object or any of its properties are tainted.
   */
  lookupAnyProperty(objectName) {
    if (!objectName) return null;
    const direct = this.lookup(objectName);
    if (direct) return direct;

    const prefix = `${objectName}.`;
    for (const [key, record] of this.propertyBindings.entries()) {
      if (key.startsWith(prefix) && record) {
        return record;
      }
    }

    if (this.parent) {
      return this.parent.lookupAnyProperty(objectName);
    }

    return null;
  }
}
