import {
  getNodeLocation,
  getNodeEvidence,
  isCallTo,
  isNewExpression,
  isStringLiteral,
  getStringValue,
  isDynamicStringExpression,
  getMemberExpressionPath
} from './traversal.js';

/**
 * Recognizes dynamic execution patterns:
 * - Direct and indirect eval()
 * - Function constructor (new Function / Function)
 * - Node.js vm dynamic execution calls
 * - Timer APIs called with code strings
 */
export function detectDynamicExecution(node, sourceCode = '', context = {}) {
  const findings = [];
  const calleeProvenance = context.sinkProvenanceResolver?.resolveCall(node);

  // Direct or aliased global eval; locally implemented and shadowed bindings are excluded by provenance.
  if (node.type === 'CallExpression' && node.callee &&
      calleeProvenance?.status === 'global_builtin' &&
      calleeProvenance.api === 'eval') {
    const loc = getNodeLocation(node);
    findings.push({
      ruleId: 'LUM-DYN-001',
      checkId: 'dynamic_code_execution_pattern_search',
      category: 'dynamic_execution',
      severity: 'High',
      confidence: 'high',
      cwe: ['CWE-95'],
      title: 'Dynamic code execution via eval',
      description: 'The application invokes eval(), dynamically executing string input as JavaScript code. This pattern alone does not establish attacker control or exploitability.',
      remediation: 'Avoid eval(). Parse data with JSON.parse() or use safe data structures and explicit lookup dispatch tables instead of evaluating code.',
      severityRationale: "High: eval() executes arbitrary JavaScript expressions in the caller's execution scope; attacker control of input is not established.",
      evidence: 'eval() invocation (<redacted>)',
      line: loc.line,
      column: loc.column,
      origin: 'ast_analysis'
    });
  }

  // Function constructor: new Function(...) or Function(...)
  if (isNewExpression(node, 'Function') || (isCallTo(node, 'Function') && node.callee.name === 'Function')) {
    const loc = getNodeLocation(node);
    findings.push({
      ruleId: 'LUM-DYN-002',
      checkId: 'dynamic_code_execution_pattern_search',
      category: 'dynamic_execution',
      severity: 'High',
      confidence: 'high',
      cwe: ['CWE-95'],
      title: 'Dynamic code execution via Function constructor',
      description: 'The application constructs a dynamic function using new Function() or Function(), compiling string arguments as code. This pattern alone does not establish attacker control or exploitability.',
      remediation: 'Avoid dynamic function compilation. Use standard function declarations, arrow functions, or predefined handler maps instead.',
      severityRationale: 'High: the Function constructor compiles and executes arbitrary code strings; attacker control of input is not established.',
      evidence: 'Function constructor invocation (<redacted>)',
      line: loc.line,
      column: loc.column,
      origin: 'ast_analysis'
    });
  }

  // Node.js vm dynamic execution calls: vm.runInContext, vm.runInNewContext, vm.runInThisContext, vm.compileFunction, vm.Script
  if ((node.type === 'CallExpression' || node.type === 'NewExpression') && node.callee) {
    const calleePath = getMemberExpressionPath(node.callee);
    if (calleePath && /^(?:(?:node:)?vm\.)?(?:runInContext|runInNewContext|runInThisContext|compileFunction|Script)$/.test(calleePath)) {
      const loc = getNodeLocation(node);
      findings.push({
        ruleId: 'LUM-DYN-003',
        checkId: 'dynamic_code_execution_pattern_search',
        category: 'dynamic_execution',
        severity: 'High',
        confidence: 'high',
        cwe: ['CWE-94'],
        title: 'Dynamic code execution via Node.js vm',
        description: 'The application invokes a Node.js vm execution API. The vm module is not a security sandbox and executes dynamic code. This pattern alone does not establish attacker control or exploitability.',
        remediation: 'Avoid executing dynamic code in Node.js vm. Use isolated subprocesses or dedicated sandboxing engines with hard OS-level process boundaries if code evaluation is required.',
        severityRationale: 'High: Node.js vm dynamic execution APIs compile and run arbitrary code; the vm module is not a security sandbox.',
        evidence: 'vm dynamic execution call (<redacted>)',
        line: loc.line,
        column: loc.column,
        origin: 'ast_analysis'
      });
    }
  }

  // Timer string code execution: setTimeout("...", ms), setInterval("...", ms), setImmediate("...")
  if (isCallTo(node, /^(?:setTimeout|setInterval|setImmediate)$/)) {
    const args = node.arguments || [];
    if (args.length > 0) {
      const firstArg = args[0];
      const isFunction = firstArg.type === 'FunctionExpression' ||
                         firstArg.type === 'ArrowFunctionExpression' ||
                         firstArg.type === 'Identifier'; // function reference
      const isString = isStringLiteral(firstArg) ||
                       isDynamicStringExpression(firstArg);

      if (isString && !isFunction) {
        const loc = getNodeLocation(node);
        findings.push({
          ruleId: 'LUM-DYN-004',
          checkId: 'dynamic_code_execution_pattern_search',
          category: 'dynamic_execution',
          severity: 'Medium',
          confidence: 'medium',
          cwe: ['CWE-95'],
          title: 'Implicit code execution via timer string argument',
          description: 'The application passes a string to a timer API (setTimeout, setInterval, or setImmediate), causing the string to be evaluated as code like eval(). This pattern alone does not establish attacker control or exploitability.',
          remediation: 'Pass a function or arrow function callback to timer APIs instead of a string argument.',
          severityRationale: 'Medium: passing a string to a timer API triggers implicit code evaluation; attacker control of input is not established.',
          evidence: 'Timer called with string code argument (<redacted>)',
          line: loc.line,
          column: loc.column,
          origin: 'ast_analysis'
        });
      }
    }
  }

  return findings;
}

/**
 * Recognizes command execution APIs:
 * - child_process.exec, execSync
 * - child_process.spawn, spawnSync (with or without shell option)
 * - child_process.execFile, execFileSync
 */
export function detectCommandExecution(node, sourceCode = '', context = {}) {
  const findings = [];

  if (node.type !== 'CallExpression' || !node.callee) return findings;
  if (context.sinkProvenanceResolver?.resolveCall(node).status === 'locally_defined') {
    return findings;
  }

  const calleePath = getMemberExpressionPath(node.callee);
  const isDirectCmd = node.callee.type === 'Identifier' &&
    /^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(node.callee.name);
  const isMemberCmd = calleePath &&
    /^(?:(?:node:)?child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(calleePath);

  if (!isDirectCmd && !isMemberCmd) return findings;

  const methodName = node.callee.name || calleePath.split('.').pop();
  const args = node.arguments || [];
  if (args.length === 0) return findings;

  // Inspect options object for shell: true
  let hasShellOption = false;
  for (const arg of args) {
    if (arg.type === 'ObjectExpression') {
      for (const prop of arg.properties || []) {
        if (prop.key && (prop.key.name === 'shell' || prop.key.value === 'shell')) {
          if (prop.value && prop.value.type === 'BooleanLiteral' && prop.value.value === true) {
            hasShellOption = true;
          } else if (prop.value && (isStringLiteral(prop.value) || prop.value.type === 'Identifier')) {
            hasShellOption = true; // shell: '/bin/bash' or custom shell
          }
        }
      }
    }
  }

  const firstArg = args[0];
  const secondArg = args[1];

  const isArgumentArray = (firstArg && firstArg.type === 'ArrayExpression') ||
                          (secondArg && secondArg.type === 'ArrayExpression');

  // Check if first arg or second arg has dynamic arguments
  const hasDynamicArrayElements = isArgumentArray && (
    (firstArg?.type === 'ArrayExpression' && firstArg.elements.some((el) => !isStringLiteral(el))) ||
    (secondArg?.type === 'ArrayExpression' && secondArg.elements.some((el) => !isStringLiteral(el)))
  );

  // If the command is a fixed static string and doesn't enable shell mode, do not flag
  if (isStringLiteral(firstArg) && !hasShellOption && !hasDynamicArrayElements) {
    return findings;
  }

  // Check if command argument or options has dynamic variable / interpolation
  const isDynamicCmd = isDynamicStringExpression(firstArg) ||
                       (firstArg && firstArg.type === 'Identifier') ||
                       (firstArg && firstArg.type === 'CallExpression') ||
                       (firstArg && firstArg.type === 'MemberExpression') ||
                       hasDynamicArrayElements;

  if (!isDynamicCmd && !hasShellOption) return findings;

  const saferArgumentArray = isArgumentArray && !hasShellOption && !/^(?:exec|execSync)$/i.test(methodName);
  const severity = saferArgumentArray ? 'Medium' : 'High';
  const confidence = saferArgumentArray ? 'low' : 'medium';
  const rationale = saferArgumentArray
    ? 'Medium: a user-input indicator appears in a process argument array; shell parsing is not evident, but argument semantics and input validation still matter.'
    : 'High: a user-input indicator appears in a shell-based command API; input control and exploitability are not established.';

  const loc = getNodeLocation(node);
  const evidence = saferArgumentArray
    ? 'User-input indicator passed in process arguments (<redacted>)'
    : 'User-input indicator passed to shell command construction (<redacted>)';

  findings.push({
    ruleId: 'LUM-INJ-002',
    checkId: 'os_command_injection_pattern_search',
    category: 'injection',
    severity,
    confidence,
    cwe: ['CWE-78'],
    title: 'Potentially unsafe command construction',
    description: 'A command execution API appears to receive a value associated with user input. This pattern alone does not establish attacker control or exploitability.',
    remediation: saferArgumentArray
      ? 'Prefer fixed executable and argument structure, validate values against an allowlist, and avoid shell mode.'
      : 'Avoid shell command strings; use an argument-array API with a fixed executable and validate each argument against an allowlist.',
    severityRationale: rationale,
    evidence,
    line: loc.line,
    column: loc.column,
    origin: 'ast_analysis'
  });

  return findings;
}

/**
 * Recognizes SQL injection indicators:
 * - Dynamic SQL concatenation (+)
 * - Dynamic template literals (`...${...}...`)
 * passed to database query execution calls (query, execute, raw).
 */
export function detectSqlInjection(node, sourceCode = '', context = {}) {
  const findings = [];

  if (node.type !== 'CallExpression' || !node.callee) return findings;
  if (context.sinkProvenanceResolver?.resolveCall(node).status === 'locally_defined') {
    return findings;
  }

  const calleePath = getMemberExpressionPath(node.callee);
  let isDbQueryCall = false;

  if (calleePath && /\.(?:query|execute|executemany|raw)$/i.test(calleePath)) {
    isDbQueryCall = true;
  } else if (node.callee.property) {
    const propName = node.callee.property.name || getStringValue(node.callee.property);
    if (/^(?:query|execute|executemany|raw)$/i.test(propName)) {
      isDbQueryCall = true;
    }
  }

  if (!isDbQueryCall) return findings;

  const args = node.arguments || [];
  if (args.length === 0) return findings;

  const queryArg = args[0];

  // Inspect query argument for dynamic construction
  let isDynamicSql = false;

  if (queryArg.type === 'BinaryExpression' && queryArg.operator === '+') {
    // Dynamic binary concatenation in query argument
    if (isDynamicStringExpression(queryArg)) {
      isDynamicSql = true;
    }
  } else if (queryArg.type === 'TemplateLiteral') {
    // Template literal with expressions
    if (queryArg.expressions && queryArg.expressions.length > 0) {
      isDynamicSql = true;
    }
  } else if (queryArg.type === 'Identifier') {
    // Identifier passed as query; if variable tracking reveals dynamic SQL
    if (context.dynamicSqlVariables && context.dynamicSqlVariables.has(queryArg.name)) {
      isDynamicSql = true;
    }
  }

  // Safe check: If query is a plain static string literal, it is safe
  if (isStringLiteral(queryArg)) {
    return findings; // Clean parameterized query with SQL string literal
  }

  if (isDynamicSql) {
    let loc = getNodeLocation(node);
    if (queryArg.type === 'Identifier' && context.dynamicSqlVariables && context.dynamicSqlVariables.has(queryArg.name)) {
      const varLoc = context.dynamicSqlVariables.get(queryArg.name);
      loc = { line: varLoc.line, column: varLoc.column };
    }

    findings.push({
      ruleId: 'LUM-INJ-001',
      checkId: 'sql_injection_pattern_search',
      category: 'injection',
      severity: 'High',
      confidence: 'medium',
      cwe: ['CWE-89'],
      title: 'Potentially unsafe dynamic SQL construction',
      description: 'A SQL statement appears to be dynamically constructed and passed to a database execution API. This pattern alone does not establish attacker control or exploitability.',
      remediation: 'Use a parameterized query with values supplied separately; avoid interpolating or concatenating values into SQL syntax.',
      severityRationale: 'High: dynamic SQL syntax reaches a database execution API; input control and exploitability are not established.',
      evidence: 'Dynamic SQL passed to a database API (<redacted>)',
      line: loc.line,
      column: loc.column,
      origin: 'ast_analysis'
    });
  }

  return findings;
}

/**
 * Recognizes unsafe JavaScript deserialization calls:
 * - serialize.unserialize(...)
 * - nodeSerialize.unserialize(...)
 * - direct unserialize(...)
 */
export function detectUnsafeDeserialization(node, sourceCode = '', context = {}) {
  const findings = [];

  if (node.type !== 'CallExpression' || !node.callee) return findings;

  const calleePath = getMemberExpressionPath(node.callee);
  const isUnserialize = (calleePath && /(?:nodeSerialize|serialize)\.unserialize$/i.test(calleePath)) ||
                        (node.callee.type === 'Identifier' && node.callee.name === 'unserialize');
  if (isUnserialize) {
    const loc = getNodeLocation(node);

    findings.push({
      ruleId: 'LUM-DES-005',
      checkId: 'unsafe_deserialization_pattern_search',
      category: 'deserialization',
      severity: 'High',
      confidence: 'high',
      cwe: ['CWE-502'],
      title: 'Unsafe JavaScript object deserialization',
      description: 'The application uses an unsafe deserialization function that can execute arbitrary code embedded in serialized payloads. This pattern alone does not establish attacker control or exploitability.',
      remediation: 'Use JSON.parse() with schema validation (such as Zod or Ajv) instead of object deserialization libraries that support code or function reconstruction.',
      severityRationale: 'High: node-serialize unserialize() can execute arbitrary functions embedded in serialized data; attacker control is not established.',
      evidence: 'node-serialize unserialize() deserialization (<redacted>)',
      line: loc.line,
      column: loc.column,
      origin: 'ast_analysis'
    });
  }

  return findings;
}
