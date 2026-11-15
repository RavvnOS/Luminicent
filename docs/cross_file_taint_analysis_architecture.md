# Luminicent Architecture Specification — Phase 5.4 Cross-File Taint Analysis Engine

**Document Status**: Approved Final Design Specification (Phase 5.4.0.1)
**Safety Invariant**: Pure Static Analysis Only (`LUMINICENT_EXECUTION_MODE=disabled`). No code execution, no dependency installation, no container deployment.

---

## 1. Overview and Problem Statement

Phase 5.3 and Phase 5.3.1 delivered an inter-procedural taint analysis engine that verified call-graph resolution, return-path correctness, object aliasing, and contextual sanitization within individual compilation units. However, whole-project static analysis currently runs file-by-file in isolation, presenting critical gaps:
1. **Broken Inter-Module Traces**: Tainted data originating in an API route (File A) passed through an imported utility (File B) to a database or process sink (File C) is not traced if intermediate functions do not return the data back to File A.
2. **Scan-Root Confinement Bug**: When resolving relative imports (`require('../utils')`), `scanRoot` in `callGraph.js` defaulted to the importing file's directory (`baseDir`), incorrectly flagging valid relative imports as directory traversal attempts (`module_path_outside_scan_root`).
3. **Missing Barrel File & Re-Export Resolution**: Directory imports (`require('./models')`) and re-export statements (`export * from ...`, `export { x } from ...`) fail resolution.
4. **Independent Budget Multiplication**: Resource limits were evaluated independently per file rather than tracking a unified project-wide analysis budget.

Phase 5.4 introduces a bounded, project-wide taint analysis architecture that links recognized request sources to security sinks across file and module boundaries.

---

## 2. Refined Project-Wide Architecture

```mermaid
flowchart TD
    subgraph Indexing["Phase 1: Project Indexing & Caching"]
        Files["Project JS/TS Source Files"] --> PMR["ProjectModuleRegistry"]
        PMR --> BAC["BoundedAstCache (Max 250 ASTs, LRU)"]
        BAC --> PBM["ProjectBudgetManager (Shared Unified Budget)"]
    end

    subgraph SymbolGraph["Phase 2: Dependency Graph & Symbol Resolution"]
        PMR --> MDG["ModuleDependencyGraph"]
        MDG -->|Cycle Detection| MDG
        MDG -->|Barrel (index.js/ts) Resolution| PSR["ProjectSymbolRegistry"]
        MDG -->|Re-export Resolution: export * / export {x}| PSR
    end

    subgraph EntryPoints["Phase 3: Entry-Point & Framework Discovery"]
        PSR --> FED["FrameworkEntryPointDiscoverer"]
        FED -->|Express router.get/post / app.use| EP["Registered Route Handlers"]
        FED -->|Unknown / Dynamic Routes| LIM["Record Limitation: dynamic_route_registration"]
        EP --> CFTC["CrossFileTaintCoordinator"]
    end

    subgraph Propagation["Phase 4: Cross-File Taint Propagation"]
        CFTC --> CSContext["CrossFileTaintContext (Call-Site Isolated)"]
        CSContext -->|Step Tracking| Sinks["Security Sinks (SQL, Command, Deserialization)"]
        Sinks -->|Context-Sensitive Sanitizer Evaluation| SanCheck{"Sanitizer Context Check"}
        SanCheck -->|SQL / Shell: Numeric Coercion| Cleansed["Taint Removed"]
        SanCheck -->|CWE-88 Arg / CWE-114 Exec: Numeric Coercion| Retained["Taint Retained!"]
        SanCheck -->|Boolean Validator / Incompatible Sanitizer| Retained
    end

    subgraph Reporting["Phase 5: Synthesis & Reporting"]
        Retained --> Dedup["Deduplication & Recognizer Enrichment"]
        Dedup --> RiskEng["Risk Prioritization Engine (K=30)"]
        RiskEng --> Report["Unified Report Schema v2.0.0"]
        PBM -->|Budget Exhausted / Limitations| PartCov["Coverage: Partial"]
        PartCov --> Report
    end
```

---

## 3. Corrected Cross-Module Sanitizer Semantics

Phase 5.4 strictly preserves the sanitizer and sink semantics established in Phase 5.2.3 and Phase 5.2.4 across module boundaries:

### Context-Specific Rule Matrix

| Sanitizer / Transformation | SQL Sink (`LUM-INJ-001`) | Shell Command Sink (`LUM-INJ-002`, `isShellDirect` or `hasShell: true`) | Non-Shell Command Argument (`LUM-INJ-002`, `CWE-88`) | Process Executable Path (`LUM-INJ-002`, `CWE-114`) |
|---|:---:|:---:|:---:|:---:|
| **Numeric Transformations** (`parseInt`, `parseFloat`, `Number`, `+x`, `x|0`) | **Cleansed** (Safe scalar) | **Cleansed** (Safe scalar, no metacharacters) | **RETAINED** (Numeric arguments can alter process flags/ports) | **RETAINED** (Executable path cannot be selected by numeric ID safely) |
| **Boolean Validators** (`validator.isInt`, `validator.isNumeric`) | **RETAINED** (Returns boolean; does not cleanse input) | **RETAINED** (Returns boolean; does not cleanse input) | **RETAINED** | **RETAINED** |
| **SQL Database Escaping** (`mysql.escape`, `db.escape`) | **Cleansed** (Context-appropriate) | **RETAINED** (Incompatible: quotes do not escape shell) | **RETAINED** | **RETAINED** |
| **HTML Sanitizers** (`DOMPurify`, `escapeHtml`, `he.encode`) | **RETAINED** (Incompatible with SQL) | **RETAINED** (Incompatible with Shell) | **RETAINED** | **RETAINED** |

### Cross-Module Propagation Invariant
When a variable transformed by `parseInt` in `helpers/sanitizer.js` is imported into `controllers/task.js` and passed to a sink in `services/runner.js`:
- If `services/runner.js` executes `db.query(...)` or `child_process.exec(...)`, the finding is suppressed.
- If `services/runner.js` executes `child_process.spawn("utility", [transformedVar])`, a finding for **CWE-88 (Argument Injection)** is emitted.
- If `services/runner.js` executes `child_process.spawn(transformedVar, [])`, a finding for **CWE-114 (Process Control)** is emitted.

---

## 4. Framework Entry-Point and Callback Discovery

### Static Express Pattern Recognition
`frameworkEntryPointDiscoverer.js` runs inside the existing project coordinator and only seeds the existing taint engine. It does not execute, import, or load scanned code.

1. **Verified router registrations**:
   - Supported methods are `get`, `post`, `put`, `delete`, `patch`, `options`, `head`, `all`, and `use`.
   - A receiver is recognized only when it is statically created from the `express` package (for example `const app = express()` or `const router = express.Router()`), including supported default, namespace, named `Router`, and CommonJS factory bindings. Factory bindings must be unique and not reassigned; router bindings that are reassigned, mutated, or passed to an opaque call are rejected.
   - Statically chained registrations such as `router.route('/path').post(handler)` are supported for the route verbs.
   - Statically aliased routers are supported. Imported router objects whose Express identity is not resolved, shadowed factory names, and arbitrary objects with a method named `get` or `use` are not treated as routers; route-shaped calls with uncertain identity degrade coverage. Other frameworks are not assigned framework coverage.
2. **Handler resolution**:
   - Inline callbacks and locally indexed functions can be seeded directly.
   - Named, default, namespace, aliased, and CommonJS imported controller references resolve through `ProjectSymbolRegistry` to a unique indexed function descriptor; re-export identity is preserved.
   - `use` handles statically understood middleware argument lists with or without a literal path. Static arrays of handlers are traversed. Spread arguments, unresolved local symbols, ambiguous imports, external handlers, and dynamic route shapes are reported as limitations instead of guessed.
3. **Request taint seeding**:
   - In project-wide analysis, request-shaped expressions and parameter names alone do not create HTTP taint. The first handler parameter is treated as the request parameter only after an explicit verified route registration; only its supported request properties are seeded.
   - Direct request objects seed `query`, `params`, `body`, `headers`, `cookies`, and `signedCookies`. Object destructuring seeds statically named properties, including nested patterns such as `({ body: { command } })`.
   - Route-registration relationships are retained as a trace step with the existing imported symbol/re-export metadata. Source locations, sink roles, existing sanitizer rules, classifications, and redaction remain owned by the taint engine.
4. **Conservative limitations**:
   - Dynamic methods/paths, unresolved or ambiguous project handlers, unsupported request parameter patterns, and discovery traversal/time exhaustion use stable limitation codes and make coverage partial.
   - Dynamic imports and other existing coordinator limitations continue to apply. External packages are not traversed. A function is never inferred as a handler because of its name or parameter names alone.

### Milestone Scoping Decision
- **Phase 5.4 Core**: Direct cross-file call expansion and helper chains.
- **Phase 5.4.5 complete**: Statically verified Express route and middleware registrations seed request taint through the existing project-wide coordinator. Discovery remains limited to verified static Express patterns; it does not infer framework coverage for other frameworks or arbitrary objects.
- **Phase 5.4.5.1 hardening**: Project-wide HTTP request taint requires a statically verified route registration. Shadowed, reassigned, mutated, imported-but-unresolved, and custom router identities fail closed and degrade coverage when a route-shaped call is detected.

---

## 5. Unified Project-Wide Resource Budget

Instead of independent per-file limit counters, Phase 5.4 introduces a single shared `ProjectBudgetManager` that flows through all module traversals:

### Shared Budget Boundaries (Preserving Phase 5.3 Invariants)

| Parameter | Limit | Scope | Violation Action |
|---|---:|---|---|
| **`maxCallDepth`** | **5 hops** | Call stack depth across all files | Aborts branch; records `call_graph_depth_limit_exceeded` |
| **`maxTotalInvocations`** | **200 calls** | Cumulative across entire project scan | Aborts expansion; records `max_call_invocations_exceeded` |
| **`maxCallSitesPerFunction`** | **50 sites** | Per function descriptor | Aborts excess sites; records `max_call_sites_per_function_exceeded` |
| **`maxProjectFiles`** | **250 files** | Project-wide eligible files | Aborts indexing; records `project_file_limit_exceeded` |
| **`maxModuleGraphEdges`** | **1,000 edges** | Total import/export relationships | Aborts graph build; records `module_graph_edge_limit_exceeded` |
| **`maxImportResolutions`** | **500 attempts**| Total disk/cache resolutions | Aborts resolution; records `import_resolution_limit_exceeded` |
| **`maxTaintOperations`** | **10,000 ops** | Total variable/property updates | Aborts traversal; records `taint_operation_limit_exceeded` |
| **`maxAnalysisDurationMs`** | **15,000 ms** | Total wall-clock time for AST phase | Aborts scan; records `ast_analysis_timeout` |

### Practical Bounded-Cache Policy
Replacing imprecise byte-based heap measurements, memory is strictly managed via a bounded LRU AST cache:
1. **Cache Capacity**: Maximum **250 parsed ASTs** stored concurrently.
2. **LRU Eviction**: When capacity is reached, the least-recently-accessed module AST is pruned from memory.
3. **Reparse Budget**: An evicted module may be re-parsed from disk if subsequent call paths require it, up to a hard ceiling of **50 total reparses**.
4. **Coverage Degradation**: If the reparse budget (50) is exhausted, further resolution of evicted modules fails closed; the limitation `ast_cache_eviction_budget_exceeded` is recorded; scan coverage status becomes `partial`.

---

## 6. Regression Test Matrix

The following test suites must be implemented in future phases:

### Suite 1: Sanitizer Context Sensitivity Across Modules (`crossFileSanitizers.test.js`)
1. **SQL Numeric Coercion**: `parseInt` in File B suppresses SQL injection at `db.query` in File C.
2. **Shell Command Numeric Coercion**: `parseInt` in File B suppresses command injection at `child_process.exec` in File C.
3. **Non-Shell Argument Numeric Coercion (CWE-88)**: `parseInt` in File B **retains taint** when passed as an argument in `child_process.spawn("utility", [id])` in File C.
4. **Executable Path Numeric Coercion (CWE-114)**: `parseInt` in File B **retains taint** when passed as the executable in `child_process.spawn(id, [])` in File C.
5. **Boolean Validator Ineffectiveness**: `validator.isInt(input)` in File B without conditional branching **retains taint** at all sinks in File C.
6. **SQL Escaping Command Incompatibility**: `mysql.escape(input)` in File B **retains taint** when passed to `exec()` in File C.
7. **HTML Sanitizer Incompatibility**: `DOMPurify.sanitize(input)` in File B **retains taint** when passed to SQL or command sinks in File C.

### Suite 2: Framework Entry-Point & Registration (`frameworkEntryPoints.test.js`)
8. **Imported Route Controller**: `router.post('/task', controller.run)` seeds `req.body.cmd` inside `controllers/task.js` and traces to sink in `services/db.js`.
9. **Destructured Request Handler**: `router.get('/user', ({ query: { id } }, res) => ...)` seeds `id` as tainted input.
10. **Multiple Middleware Handlers**: Each statically resolved handler in `router.use(authMiddleware, controller)` is analyzed as a request entry point; mutation handoff between handlers is not modeled.
11. **Dynamic Route Registration Limitation**: Metaprogrammed route registration emits `dynamic_route_registration_detected` limitation and marks coverage `partial`.

### Suite 3: Unified Budget & Bounded Cache (`crossFileBudget.test.js`)
12. **Project-Wide Cumulative Invocations**: Multiple modules calling helpers cumulatively hit `maxTotalInvocations = 200`, setting scan coverage to `partial` with `max_call_invocations_exceeded`.
13. **Cross-File Call Depth Exceeded**: 6-module helper chain triggers `call_graph_depth_limit_exceeded` at hop 5.
14. **LRU Cache Eviction & Reparse Ceiling**: High-churn imports exceed 50 reparses, gracefully stopping with `ast_cache_eviction_budget_exceeded` and `partial` coverage.

---

## 7. Updated Implementation Roadmap

| Milestone | Deliverables | Modules Involved |
|---|---|---|
| **Phase 5.4.1** | **Project Module Registry, Bounded AST Cache & Path Fix**<br>- Implement `ProjectModuleRegistry` with scan-root relative paths.<br>- Fix `callGraph.js` directory traversal bug (`scanRoot` inheritance).<br>- Implement `BoundedAstCache` (LRU 250 ASTs, max 50 reparses).<br>- Implement barrel-file resolution (`./dir` $\to$ `./dir/index.js`, `./dir/index.ts`). | `backend/utils/ast/taint/projectRegistry.js` (new)<br>`backend/utils/ast/taint/boundedAstCache.js` (new)<br>`backend/utils/ast/taint/callGraph.js` |
| **Phase 5.4.2** | **Project Symbol Registry & Re-Export Support**<br>- Add support for `export * from './mod'` and `export { a, b } from './mod'`.<br>- Build cross-module symbol table linking imports to target function descriptors.<br>- Implement `ProjectBudgetManager` with unified limits (depth 5, invocations 200). | `backend/utils/ast/taint/projectSymbolRegistry.js` (new)<br>`backend/utils/ast/taint/projectBudgetManager.js` (new)<br>`backend/utils/ast/taint/callGraph.js` |
| **Phase 5.4.3** | **Cross-File Taint Coordinator & Trace Normalization**<br>- Implement `CrossFileTaintCoordinator`.<br>- Propagate taint across 3+ module chains (A $\to$ B $\to$ C).<br>- Enforce CWE-88 and CWE-114 taint retention for numeric transformations.<br>- Assemble schema v2.0.0 `taintTrace` with safe relative paths. | `backend/utils/ast/taint/crossFileTaintCoordinator.js` (new)<br>`backend/utils/ast/taint/taintAnalyzer.js` |
| **Phase 5.4.4** | **Production Analyzer Integration & Verification**<br>- Wire `CrossFileTaintCoordinator` into `productionAnalyzer.js`.<br>- Thread `scanRoot` and shared budget through project scans.<br>- Run full `scripts/test-safe.ps1`, Go CLI/UI tests, and AST regression suites. | `backend/utils/productionAnalyzer.js`<br>`scripts/test-safe.ps1` |
| **Phase 5.4.5 — Complete** | **Framework Entry-Point & Route Callback Discovery**<br>- Discover verified static Express registrations and resolve handlers through the project symbol registry.<br>- Seed request parameters through the existing taint engine and degrade coverage for unresolved or dynamic registrations. | `backend/utils/ast/taint/frameworkEntryPointDiscoverer.js` |

---

## 8. Remaining Limitations and Invariants

1. **Pure Static Analysis**: No code execution, runtime mocking, or dependency resolution outside the project root.
2. **Dynamic Imports**: Expressions like `import(variablePath)` or `require(dynamicExpr)` cannot be resolved statically and produce an `unresolved_dynamic_import` limitation.
3. **Risk Calibration & Schema Invariants**: Risk calibration constant $K = 30.0$ and Unified Report Schema `2.0.0` remain unchanged.
4. **No False Clean Coverage**: Any unresolvable module, exceeded resource budget, or dynamic routing pattern guarantees that the scan status is marked `partial`.
