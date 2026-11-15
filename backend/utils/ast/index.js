export { parseSource, isSupportedJsTsFile, isTypeScriptFile, isJsxFile, PARSER_LIMITS } from './parser.js';
export { walkAST, getNodeLocation, isCallTo, isNewExpression, isDynamicStringExpression } from './traversal.js';
export {
  detectDynamicExecution,
  detectCommandExecution,
  detectSqlInjection,
  detectUnsafeDeserialization
} from './recognizers.js';
export { analyzeAstSource } from './analyzer.js';
export { analyzeAstTaint } from './taint/taintAnalyzer.js';
export { inspectTaintSource, inspectDestructuredSources } from './taint/taintSources.js';
export { inspectSecuritySink } from './taint/taintSinks.js';
export {
  evaluateSanitizer,
  SINK_CONTEXTS,
  BOOLEAN_VALIDATORS,
  NUMERIC_CONVERSIONS,
  SQL_SPECIFIC_SANITIZERS,
  HTML_ONLY_SANITIZERS
} from './taint/taintSanitizers.js';
export { TaintScope, TaintRecord, TAINT_STATE_LIMITS } from './taint/taintState.js';
export {
  CALL_GRAPH_LIMITS,
  FunctionDescriptor,
  FunctionRegistry,
  buildFunctionRegistry,
  extractParamNames,
  findReturnStatements
} from './taint/callGraph.js';
export {
  BoundedAstCache,
  AST_CACHE_LIMITS,
  normalizeCacheKey
} from './taint/boundedAstCache.js';
export {
  ProjectModuleRegistry,
  PROJECT_REGISTRY_LIMITS,
  normalizePosixPath
} from './taint/projectRegistry.js';
export {
  ProjectBudgetManager,
  PROJECT_BUDGET_LIMITS,
  PROJECT_BUDGET_LIMITATION_CODES
} from './taint/projectBudgetManager.js';
export { ProjectSymbolRegistry } from './taint/projectSymbolRegistry.js';
export { ProjectTaintCoordinator } from './taint/projectTaintCoordinator.js';
export {
  FRAMEWORK_ROUTE_METHODS,
  discoverFrameworkEntryPoints
} from './taint/frameworkEntryPointDiscoverer.js';
