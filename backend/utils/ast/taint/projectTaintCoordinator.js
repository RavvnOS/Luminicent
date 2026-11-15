import fs from 'node:fs';
import { walkAST } from '../traversal.js';
import { ProjectBudgetManager } from './projectBudgetManager.js';
import { ProjectModuleRegistry, normalizePosixPath } from './projectRegistry.js';
import { ProjectSymbolRegistry } from './projectSymbolRegistry.js';
import { buildFunctionRegistry } from './callGraph.js';
import { discoverFrameworkEntryPoints } from './frameworkEntryPointDiscoverer.js';
import { analyzeAstTaint } from './taintAnalyzer.js';
import { readProjectFile } from '../../projectFileReader.js';
import { createSinkIdentity } from '../../findingIdentity.js';

function addUnique(values, value) {
  if (value && !values.includes(value)) values.push(value);
}

export function locationKey(finding) {
  return createSinkIdentity(finding);
}

function traceKey(trace) {
  return JSON.stringify({
    source: trace?.source,
    steps: trace?.steps,
    sink: trace?.sink
  });
}

function redactTraceValue(value) {
  if (typeof value === 'string') {
    return value
      .replace(/(['"`])(?:\\.|(?!\1)[^\\])*?\1/g, '<literal>')
      .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{16,}\b|\bsk_live_[A-Za-z0-9]{16,}\b|\bAIza[0-9A-Za-z_-]{35}\b/g, '<redacted>')
      .replace(/:\/\/([^:/\s]+):([^@/\s]+)@/g, '://$1:<redacted>@')
      .replace(/\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;}]+/gi, '$1=<redacted>');
  }
  if (Array.isArray(value)) return value.map(redactTraceValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactTraceValue(item)]));
}

function mergeFinding(findingsByKey, finding) {
  const key = locationKey(finding);
  if (!key) {
    finding.sinkIdentityStatus = 'unresolved';
    findingsByKey.set(Symbol(`unresolved-${findingsByKey.size}`), finding);
    return;
  }
  finding.sinkIdentity = key;
  finding.sinkIdentityStatus = 'resolved';
  const existing = findingsByKey.get(key);
  if (!existing) {
    findingsByKey.set(key, finding);
    return;
  }
  if (!finding.taintTrace) return;
  const traces = existing.taintTrace?.alternatePaths || [];
  const candidate = traceKey(finding.taintTrace);
  if (traceKey(existing.taintTrace) !== candidate &&
      !traces.some((trace) => traceKey(trace) === candidate)) {
    traces.push(finding.taintTrace);
    traces.sort((left, right) => traceKey(left).localeCompare(traceKey(right)));
    existing.taintTrace.alternatePaths = traces;
  }
}

export class ProjectTaintCoordinator {
  constructor(scanRoot = '.', options = {}) {
    this.scanRoot = scanRoot;
    this.limitations = options.limitations || options.projectRegistry?.limitations || [];
    this.projectRegistry = options.projectRegistry || null;
    this.budgetManager = options.budgetManager ||
      this.projectRegistry?.budgetManager ||
      new ProjectBudgetManager({
        limits: options.budgetLimits,
        now: options.now,
        clock: options.clock
      });

    if (this.projectRegistry && this.projectRegistry.budgetManager !== this.budgetManager) {
      throw new TypeError('ProjectTaintCoordinator must share the ProjectModuleRegistry budget manager');
    }

    this.projectRegistry ||= new ProjectModuleRegistry(scanRoot, {
      modules: options.modules,
      limitations: this.limitations,
      budgetManager: this.budgetManager,
      astCache: options.astCache,
      maxSourceBytes: options.maxSourceBytes
    });
    this.symbolRegistry = options.symbolRegistry ||
      new ProjectSymbolRegistry(this.projectRegistry, {
        budgetManager: this.budgetManager,
        limitations: this.limitations
      });
    if (this.symbolRegistry.budgetManager !== this.budgetManager) {
      throw new TypeError('ProjectTaintCoordinator must share the ProjectSymbolRegistry budget manager');
    }

    this.functionRegistries = new Map();
    this.functionDescriptorsBySymbolId = new Map();
    this.frameworkEntryPoints = new Map();
    this.globalState = {
      totalInvocations: 0,
      limitsExceeded: false,
      budgetExhausted: false,
      limitations: [],
      evaluatedCallSites: new Set()
    };
    this.isBuilt = false;
    this.result = null;
  }

  build() {
    if (this.isBuilt) return this;

    this.projectRegistry.indexProject();
    this.symbolRegistry.build();
    const modulePaths = [...this.projectRegistry.modules.keys()]
      .map(normalizePosixPath)
      .sort((left, right) => left.localeCompare(right));

    for (const relativePath of modulePaths) {
      const record = this.projectRegistry.getModule(relativePath);
      const parsed = this.projectRegistry.getAst(relativePath, {
        limitations: this.limitations
      });
      if (!parsed?.ast) {
        addUnique(this.limitations, 'unresolved_project_module_ast');
        continue;
      }

      let code = record?.sourceCode;
      if (typeof code !== 'string') {
        try {
          code = readProjectFile(fs, record.absolutePath, {
            maxBytes: 10 * 1024 * 1024,
            rootPath: this.projectRegistry.scanRoot
          }).content;
        } catch {
          addUnique(this.limitations, 'project_module_source_unavailable');
          continue;
        }
      }

      const registry = buildFunctionRegistry(parsed.ast, {
        code,
        filePath: relativePath,
        relativePath,
        scanRoot: this.projectRegistry.scanRoot,
        projectRoot: this.projectRegistry.scanRoot,
        budgetManager: this.budgetManager,
        limitations: this.limitations,
        disableFilesystemResolution: true
      });
      this.functionRegistries.set(relativePath, registry);
    }

    this._wireResolvedImports();
    this._wireResolvedExports();
    this._collectUnsupportedRelationships();
    const discovery = discoverFrameworkEntryPoints({
      projectRegistry: this.projectRegistry,
      symbolRegistry: this.symbolRegistry,
      functionRegistries: this.functionRegistries,
      functionDescriptorsBySymbolId: this.functionDescriptorsBySymbolId,
      budgetManager: this.budgetManager,
      limitations: this.limitations
    });
    this.frameworkEntryPoints = discovery.entriesByModule;
    if (discovery.stoppedForDuration) {
      this.globalState.budgetExhausted = true;
      this.globalState.limitsExceeded = true;
    }
    this.isBuilt = true;
    return this;
  }

  _wireResolvedImports() {
    for (const [modulePath, registry] of this.functionRegistries) {
      for (const [localName, imported] of registry.imports) {
        const relation = this.symbolRegistry.getImport(modulePath, localName);
        if (!relation || relation.resolutionStatus !== 'resolved' || !relation.targetModulePath) continue;
        const targetRegistry = this.functionRegistries.get(relation.targetModulePath);
        if (targetRegistry) registry.moduleCache.set(imported.sourceModule, targetRegistry);
      }
    }
  }

  _wireResolvedExports() {
    const descriptorsBySymbolId = new Map();
    for (const [modulePath, registry] of this.functionRegistries) {
      const symbolsByNode = new Map(
        this.symbolRegistry.getSymbols(modulePath).map((symbol) => [symbol.node, symbol])
      );
      const descriptors = new Set([
        ...registry.functions.values(),
        ...registry.exports.values()
      ]);
      const descriptorByNode = new Map();
      for (const descriptor of descriptors) {
        if (descriptor?.node) descriptorByNode.set(descriptor.node, descriptor);
      }

      for (const [node, symbol] of symbolsByNode) {
        const descriptor = descriptorByNode.get(node);
        if (descriptor) descriptorsBySymbolId.set(symbol.id, descriptor);
      }
    }

    for (const [modulePath, registry] of this.functionRegistries) {
      for (const exported of this.symbolRegistry.getExports(modulePath)) {
        if (exported.status !== 'resolved' || !exported.symbol) continue;
        const descriptor = descriptorsBySymbolId.get(exported.symbol.id);
        if (!descriptor) continue;
        descriptor.projectSymbolId = exported.symbol.id;
        descriptor.reExportChain = (exported.reExportChain || []).map((item) => ({ ...item }));
        registry.registerExport(exported.exportedName, descriptor);
      }
    }
    this.functionDescriptorsBySymbolId = descriptorsBySymbolId;
  }

  _collectUnsupportedRelationships() {
    const graph = new Map();
    for (const edge of this.projectRegistry.graphEdges) {
      const separator = edge.indexOf(' -> ');
      if (separator < 0) continue;
      const from = edge.slice(0, separator);
      const to = edge.slice(separator + 4);
      if (from === 'root') continue;
      if (!graph.has(from)) graph.set(from, new Set());
      graph.get(from).add(to);
    }
    const active = new Set();
    const complete = new Set();
    const visit = (modulePath) => {
      if (active.has(modulePath)) {
        addUnique(this.limitations, 'circular_module_import_detected');
        return;
      }
      if (complete.has(modulePath)) return;
      active.add(modulePath);
      for (const target of graph.get(modulePath) || []) visit(target);
      active.delete(modulePath);
      complete.add(modulePath);
    };
    for (const modulePath of [...graph.keys()].sort((left, right) => left.localeCompare(right))) {
      visit(modulePath);
    }

    for (const [modulePath, registry] of this.functionRegistries) {
      const parsed = this.projectRegistry.getAst(modulePath);
      if (!parsed?.ast) continue;
      const namespaceLocals = new Set(
        [...registry.imports]
          .filter(([localName]) => this.symbolRegistry.getImport(modulePath, localName)?.isNamespace)
          .map(([localName]) => localName)
      );
      walkAST(parsed.ast, {
        ImportExpression: () => addUnique(this.limitations, 'unsupported_dynamic_import'),
        CallExpression: (node) => {
          if (node.callee?.type === 'Import') {
            addUnique(this.limitations, 'unsupported_dynamic_import');
          }
          if (
            node.callee?.type === 'MemberExpression' &&
            node.callee.computed &&
            node.callee.property?.type !== 'StringLiteral' &&
            node.callee.property?.type !== 'NumericLiteral' &&
            node.callee.object?.type === 'Identifier' &&
            namespaceLocals.has(node.callee.object.name)
          ) {
            addUnique(this.limitations, 'unsupported_computed_dispatch');
          }
        }
      });
    }
    for (const limitation of this.symbolRegistry.limitations) {
      addUnique(this.limitations, limitation);
    }
  }

  analyze() {
    if (this.result) return this.result;
    this.build();

    const findingsByKey = new Map();
    const paths = [...this.functionRegistries.keys()].sort((left, right) => left.localeCompare(right));
    for (const relativePath of paths) {
      if (this.globalState.budgetExhausted) break;
      const durationBudget = this.budgetManager.check('maxAnalysisDurationMs');
      if (!durationBudget.allowed) {
        this.globalState.budgetExhausted = true;
        this.globalState.limitsExceeded = true;
        addUnique(this.limitations, durationBudget.code);
        break;
      }
      const parsed = this.projectRegistry.getAst(relativePath, {
        limitations: this.limitations
      });
      if (!parsed?.ast) continue;
      const record = this.projectRegistry.getModule(relativePath);
      const registry = this.functionRegistries.get(relativePath);
      const result = analyzeAstTaint(parsed.ast, {
        code: record?.sourceCode || registry?.options?.code || '',
        filePath: relativePath,
        relativePath,
        functionRegistry: registry,
        projectSymbolRegistry: this.symbolRegistry,
        budgetManager: this.budgetManager,
        requireVerifiedFrameworkRequestSources: true,
        globalState: this.globalState,
        moduleChain: [relativePath],
        frameworkEntryPointSeeds: this.frameworkEntryPoints.get(relativePath) || new Map()
      });
      for (const limitation of result.limitations || []) addUnique(this.limitations, limitation);
      for (const finding of result.findings || []) {
        if (finding.taintTrace) finding.taintTrace = redactTraceValue(finding.taintTrace);
        if (typeof finding.evidence === 'string') finding.evidence = redactTraceValue(finding.evidence);
        const crossesModules = finding.taintTrace?.steps?.some((step) =>
          step.fromModule && step.toModule && step.fromModule !== step.toModule
        );
        if (crossesModules) {
          finding.origin = 'project_cross_file_taint_analysis';
          finding.detectionMethod = 'project_cross_file_taint_analysis';
        }
        mergeFinding(findingsByKey, finding);
      }
    }

    for (const limitation of this.budgetManager.getLimitationCodes()) addUnique(this.limitations, limitation);
    this.result = {
      findings: [...findingsByKey.values()].sort((left, right) =>
        left.file.localeCompare(right.file) ||
        left.line - right.line ||
        String(left.ruleId).localeCompare(String(right.ruleId)) ||
        (left.sourceSpan?.start ?? Number.MAX_SAFE_INTEGER) -
          (right.sourceSpan?.start ?? Number.MAX_SAFE_INTEGER) ||
        (left.sourceSpan?.end ?? Number.MAX_SAFE_INTEGER) -
          (right.sourceSpan?.end ?? Number.MAX_SAFE_INTEGER) ||
        JSON.stringify(left).localeCompare(JSON.stringify(right))
      ),
      coverageStatus: this.limitations.length || this.globalState.limitsExceeded
        ? 'partial'
        : 'completed',
      limitations: [...this.limitations].sort((left, right) => left.localeCompare(right)),
      budgetStats: this.budgetManager.getStats(),
      moduleStats: this.projectRegistry.getStats(),
      symbolStats: this.symbolRegistry.getStats(),
      functionRegistryCount: this.functionRegistries.size
    };
    return this.result;
  }
}
