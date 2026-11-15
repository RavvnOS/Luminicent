import {
  getNodeLocation,
  isStringLiteral,
  getStringValue,
  getMemberExpressionPath
} from '../traversal.js';
import {
  inspectTaintSource,
  inspectDestructuredSources,
  TAINT_PROPERTIES
} from './taintSources.js';
import { inspectSecuritySink, extractOptionsFromObjectNode } from './taintSinks.js';
import { evaluateSanitizer, isTaintSanitized } from './taintSanitizers.js';
import { TaintScope, TaintRecord, TAINT_STATE_LIMITS } from './taintState.js';
import { createSinkProvenanceResolver } from '../sinkProvenance.js';
import { createSinkIdentity } from '../../findingIdentity.js';
import {
  CALL_GRAPH_LIMITS,
  FunctionDescriptor,
  buildFunctionRegistry,
  extractParamNames
} from './callGraph.js';

export const TAINT_ANALYZER_LIMITS = Object.freeze({
  maxFunctionsPerFile: 100,
  maxNodesPerFunction: 5_000,
  maxFindingsPerFile: 100
});

function hasSameFindingIdentity(left, right) {
  return typeof left._dedupeKey === 'string' &&
    left._dedupeKey === right._dedupeKey;
}

function recordBudgetFailure(result, options = {}) {
  if (result?.allowed || !result?.code) return;
  const limitations = options.limitations;
  if (limitations && !limitations.includes(result.code)) limitations.push(result.code);
  if (options.globalState) {
    options.globalState.limitsExceeded = true;
    options.globalState.budgetExhausted = true;
  }
}

function callBoundaryMetadata(options, callExpr, targetFunc) {
  const fromModule = options.relativePath || options.filePath || null;
  const toModule = targetFunc?.relativePath || targetFunc?.filePath || targetFunc?.file || null;
  if (!fromModule || !toModule || fromModule === toModule) return {};

  const callee = callExpr?.callee;
  const localName = callee?.type === 'Identifier'
    ? callee.name
    : callee?.type === 'MemberExpression' && callee.object?.type === 'Identifier'
      ? callee.object.name
      : null;
  const imported = localName
    ? options.projectSymbolRegistry?.getImport(fromModule, localName)
    : null;
  const importedName = callee?.type === 'MemberExpression'
    ? (callee.property?.name || callee.property?.value || null)
    : imported?.importedName || null;

  return {
    fromModule,
    toModule,
    importExport: {
      sourceSpecifier: imported?.sourceSpecifier || null,
      localName,
      importedName,
      exportedName: imported?.isNamespace ? importedName : imported?.importedName || importedName,
      reExportChain: (imported?.reExportChain || targetFunc?.reExportChain || [])
        .map((item) => ({ ...item }))
    }
  };
}

/**
 * Evaluates the return value of a user-defined function for tainted data.
 */
export function evaluateFunctionReturnTaint(targetFunc, argTaints, sourceCode, sinkContext, options = {}) {
  if (!targetFunc) return null;
  sourceCode = targetFunc.sourceCode || sourceCode;
  const targetPath = targetFunc.relativePath || targetFunc.filePath || targetFunc.file;

  const callStack = options.callStack || new Set();
  if (callStack.has(targetFunc.id)) {
    return null;
  }
  const nextCallStack = new Set([...callStack, targetFunc.id]);
  const callDepth = (options.callDepth || 0) + 1;
  if (options.budgetManager) {
    const depthBudget = options.budgetManager.check('maxCallDepth', callDepth);
    if (!depthBudget.allowed) {
      recordBudgetFailure(depthBudget, options);
      return null;
    }
    const callExpr = options.callExpr;
    if (argTaints?.some(Boolean)) {
      const invocationKey = callExpr?.loc
        ? `${targetFunc.id}@${callExpr.loc.start?.line || 0}:${callExpr.loc.start?.column || 0}`
        : null;
      const invocationBudget = invocationKey
        ? options.budgetManager.consumeOnce('maxTotalInvocations', invocationKey)
        : options.budgetManager.consume('maxTotalInvocations');
      if (!invocationBudget.allowed) {
        recordBudgetFailure(invocationBudget, options);
        return null;
      }
    }
  }
  if (callDepth > CALL_GRAPH_LIMITS.maxCallDepth) {
    if (options.limitations && !options.limitations.includes('call_graph_depth_limit_exceeded')) {
      options.limitations.push('call_graph_depth_limit_exceeded');
    }
    return null;
  }

  const childOpts = {
    ...options,
    code: sourceCode,
    filePath: targetPath || options.filePath,
    relativePath: targetPath || options.relativePath,
    functionRegistry: targetFunc.moduleRegistry || options.functionRegistry,
    moduleChain: options.moduleChain
      ? [...options.moduleChain, targetFunc.filePath || targetFunc.file]
      : [options.filePath || 'source.js', targetFunc.filePath || targetFunc.file],
    callStack: nextCallStack,
    callDepth
  };

  // 1. Concise arrow expression body: (x) => expr
  if (targetFunc.isArrowExpression) {
    const calleeScope = new TaintScope(null, `${targetFunc.name}_concise_return`);
    targetFunc.paramNames.forEach((pName, idx) => {
      if (typeof pName === 'string' && argTaints[idx]) {
        calleeScope.setTainted(pName, argTaints[idx]);
      } else if (pName && pName.type === 'ObjectPattern' && argTaints[idx]) {
        for (const prop of pName.properties) {
          calleeScope.setTainted(prop, argTaints[idx]);
        }
      }
    });
    return evaluateExpressionTaint(targetFunc.body, calleeScope, sourceCode, sinkContext, childOpts);
  }

  // 2. Block body function with return statements
  if (!targetFunc.returnStatements || targetFunc.returnStatements.length === 0) {
    return null; // Void function or no return statements
  }

  const calleeScope = new TaintScope(null, `${targetFunc.name}_return_eval`);
  targetFunc.paramNames.forEach((pName, idx) => {
    const argNode = childOpts.callExpr?.arguments?.[idx];
    if (typeof pName === 'string') {
      if (argTaints[idx]) {
        calleeScope.setTainted(pName, argTaints[idx]);
      }
      if (childOpts.callerScope && argNode?.type === 'Identifier') {
        childOpts.callerScope.copyProperties(argNode.name, pName);
      }
    } else if (pName && pName.type === 'ObjectPattern' && argTaints[idx]) {
      for (const prop of pName.properties) {
        let propTaint = null;
        if (argNode?.type === 'ObjectExpression') {
          const matchedProp = (argNode.properties || []).find((p) => {
            const k = p.key?.name || getStringValue(p.key);
            return k === prop;
          });
          if (matchedProp) {
            propTaint = evaluateExpressionTaint(matchedProp.value, childOpts.callerScope || calleeScope, sourceCode, sinkContext, childOpts);
          }
        } else if (argNode?.type === 'Identifier' && childOpts.callerScope) {
          propTaint = childOpts.callerScope.lookup(argNode.name, prop);
        } else {
          propTaint = argTaints[idx];
        }
        if (propTaint) {
          calleeScope.setTainted(prop, propTaint);
        }
      }
    }
  });

  // Traverse statements in the function body to update local variables in calleeScope
  function walkBodyStatements(stmts, currentScope) {
    if (!Array.isArray(stmts)) return;
    for (const stmt of stmts) {
      if (!stmt) continue;
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations || []) {
          if (!decl || !decl.id || !decl.init) continue;
          if (decl.id.type === 'Identifier') {
            const varName = decl.id.name;
            const varTaint = evaluateExpressionTaint(decl.init, currentScope, sourceCode, sinkContext, childOpts);
            if (varTaint) {
              currentScope.setTainted(varName, varTaint);
            } else {
              currentScope.setClean(varName, { clearParentProperties: false });
            }
            if (decl.init.type === 'Identifier') {
              currentScope.copyProperties(decl.init.name, varName);
            }
          }
        }
      } else if (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'AssignmentExpression') {
        const assign = stmt.expression;
        if (assign.left.type === 'Identifier') {
          const varName = assign.left.name;
          const rightTaint = evaluateExpressionTaint(assign.right, currentScope, sourceCode, sinkContext, childOpts);
          if (rightTaint) {
            currentScope.setTainted(varName, rightTaint);
          } else if (assign.operator === '=') {
            currentScope.setClean(varName);
          }
          if (assign.right.type === 'Identifier') {
            currentScope.copyProperties(assign.right.name, varName);
          }
        } else if (assign.left.type === 'MemberExpression' && assign.left.object.type === 'Identifier') {
          const objName = assign.left.object.name;
          const propName = assign.left.property.type === 'Identifier' && !assign.left.computed
            ? assign.left.property.name
            : getStringValue(assign.left.property);
          if (propName) {
            const rightTaint = evaluateExpressionTaint(assign.right, currentScope, sourceCode, sinkContext, childOpts);
            if (rightTaint) {
              currentScope.setPropertyTainted(objName, propName, rightTaint);
            } else if (assign.operator === '=') {
              currentScope.clearPropertyTaint(objName, propName);
            }
          }
        }
      } else if (stmt.type === 'BlockStatement') {
        walkBodyStatements(stmt.body, currentScope);
      } else if (stmt.type === 'IfStatement') {
        if (stmt.consequent) {
          const body = stmt.consequent.type === 'BlockStatement' ? stmt.consequent.body : [stmt.consequent];
          walkBodyStatements(body, currentScope);
        }
        if (stmt.alternate) {
          const body = stmt.alternate.type === 'BlockStatement' ? stmt.alternate.body : [stmt.alternate];
          walkBodyStatements(body, currentScope);
        }
      }
    }
  }

  const statements = targetFunc.body && Array.isArray(targetFunc.body.body)
    ? targetFunc.body.body
    : [];
  walkBodyStatements(statements, calleeScope);

  // Evaluate return statements prioritizing unsanitized taint over sanitized taint
  let candidateTaint = null;
  for (const retStmt of targetFunc.returnStatements) {
    if (retStmt.argument) {
      const retTaint = evaluateExpressionTaint(retStmt.argument, calleeScope, sourceCode, sinkContext, childOpts);
      if (retTaint) {
        // If ANY reachable return statement returns unsanitized taint, prioritize it immediately
        if (!isTaintSanitized(retTaint, sinkContext)) {
          return retTaint;
        }
        if (!candidateTaint) {
          candidateTaint = retTaint;
        }
      }
    }
  }

  return candidateTaint;
}

/**
 * Evaluates whether an expression node in the current scope is tainted.
 * Recursively resolves binary operations, template literals, member expressions, and identifiers.
 *
 * @param {Object} expr - AST expression node
 * @param {TaintScope} scope - Current lexical scope
 * @param {string} sourceCode - Raw code snippet
 * @param {string} [sinkContext=null] - Optional sink context for sanitizer checking
 * @param {Object} [options={}] - Coordinator options for inter-procedural propagation
 * @returns {TaintRecord|null} TaintRecord if expression carries tainted data, or null
 */
export function evaluateExpressionTaint(expr, scope, sourceCode = '', sinkContext = null, options = {}) {
  if (!expr || !scope) return null;
  if (options.globalState?.budgetExhausted) return null;
  const currentModule = options.relativePath || options.filePath || 'source.js';
  if (options.budgetManager) {
    const operationBudget = options.budgetManager.consume('maxTaintOperations');
    if (!operationBudget.allowed) {
      recordBudgetFailure(operationBudget, options);
      return null;
    }
  }

  // 1. Direct taint source check, e.g. req.query.name
  const directSource = inspectTaintSource(expr, sourceCode);
  if (directSource) {
    if (!directSource.file && (options.relativePath || options.filePath)) {
      directSource.file = options.relativePath || options.filePath;
    }
    const inherited = scope.lookup(directSource.root, directSource.property) ||
      scope.lookup(directSource.root);
    if (options.requireVerifiedFrameworkRequestSources && !inherited) return null;
    const seed = options.frameworkEntryPointSeed;
    if (seed) {
      if (inherited) {
        const steps = [...inherited.steps];
        if (!steps.some((step) => step.frameworkEntryPoint)) {
          const routeStep = frameworkRegistrationStep(
            seed,
            seed.handlerModulePath || options.relativePath || options.filePath
          );
          if (routeStep) steps.push(routeStep);
        }
        steps.push({
          from: inherited.currentExpr,
          to: directSource.expression,
          expression: directSource.expression,
          line: directSource.line,
          column: directSource.column,
          file: options.relativePath || options.filePath
        });
        return new TaintRecord(
          inherited.source,
          directSource.expression,
          steps,
          inherited.sanitization
        );
      }
      const routeStep = frameworkRegistrationStep(
        seed,
        seed.handlerModulePath || options.relativePath || options.filePath
      );
      return new TaintRecord(directSource, directSource.expression, routeStep ? [routeStep] : []);
    }
    if (options.requireVerifiedFrameworkRequestSources) return inherited || null;
    return new TaintRecord(directSource, directSource.expression);
  }

  // 2. Identifier lookup in scope
  if (expr.type === 'Identifier') {
    return scope.lookup(expr.name);
  }

  // 3. MemberExpression lookup (e.g. data.name, values[0], data.user.cmd)
  if (expr.type === 'MemberExpression') {
    const fullPath = getMemberExpressionPath(expr);
    if (fullPath) {
      const parts = fullPath.split('.');
      if (parts.length > 1) {
        const rootObj = parts[0];
        const subProp = parts.slice(1).join('.');
        const propTaint = scope.lookup(rootObj, subProp);
        if (propTaint) return propTaint;
      }
    }

    // If the object part is an identifier, check property-specific taint
    if (expr.object.type === 'Identifier') {
      let propName = null;
      if (expr.property.type === 'Identifier' && !expr.computed) {
        propName = expr.property.name;
      } else if (expr.computed && (expr.property.type === 'StringLiteral' || expr.property.type === 'NumericLiteral' || expr.property.type === 'Literal')) {
        propName = String(expr.property.value);
      }

      if (propName) {
        return scope.lookup(expr.object.name, propName);
      }

      // Check if entire object is tainted (fallback when property could not be statically determined)
      const objTaint = scope.lookup(expr.object.name);
      if (objTaint) return objTaint;
    } else {
      // Nested member expression, e.g. a.b.c
      const innerTaint = evaluateExpressionTaint(expr.object, scope, sourceCode, sinkContext, options);
      if (innerTaint) return innerTaint;
    }
  }

  // 4. BinaryExpression (string concatenation with '+')
  if (expr.type === 'BinaryExpression') {
    if (expr.operator === '+') {
      const leftTaint = evaluateExpressionTaint(expr.left, scope, sourceCode, sinkContext, options);
      if (leftTaint && !isTaintSanitized(leftTaint, sinkContext)) {
        const loc = getNodeLocation(expr);
        return leftTaint.withStep(
          `(${leftTaint.currentExpr} + ...)`,
          loc,
          sourceCode.slice(expr.start || 0, expr.end || 0).trim()
        );
      }
      const rightTaint = evaluateExpressionTaint(expr.right, scope, sourceCode, sinkContext, options);
      if (rightTaint && !isTaintSanitized(rightTaint, sinkContext)) {
        const loc = getNodeLocation(expr);
        return rightTaint.withStep(
          `(... + ${rightTaint.currentExpr})`,
          loc,
          sourceCode.slice(expr.start || 0, expr.end || 0).trim()
        );
      }
    }
  }

  // 5. TemplateLiteral (e.g. `SELECT * FROM ${user}`)
  if (expr.type === 'TemplateLiteral') {
    for (const subExpr of expr.expressions || []) {
      const subTaint = evaluateExpressionTaint(subExpr, scope, sourceCode, sinkContext, options);
      if (subTaint && !isTaintSanitized(subTaint, sinkContext)) {
        const loc = getNodeLocation(expr);
        return subTaint.withStep(
          `\`... \${${subTaint.currentExpr}} ...\``,
          loc,
          sourceCode.slice(expr.start || 0, expr.end || 0).trim()
        );
      }
    }
  }

  // 6. ObjectExpression (e.g. { sql: query, text: ... })
  if (expr.type === 'ObjectExpression') {
    for (const prop of expr.properties || []) {
      if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
        const propTaint = evaluateExpressionTaint(prop.value, scope, sourceCode, sinkContext, options);
        if (propTaint && !isTaintSanitized(propTaint, sinkContext)) {
          const keyName = prop.key.type === 'Identifier' ? prop.key.name : getStringValue(prop.key);
          const loc = getNodeLocation(prop);
          return propTaint.withStep(
            `{ ... ${keyName}: ... }`,
            loc,
            sourceCode && prop.start !== undefined && prop.end !== undefined
              ? sourceCode.slice(prop.start, prop.end).trim()
              : `${keyName}: ${propTaint.currentExpr}`
          );
        }
      }
    }
  }

  // 7. ArrayExpression (e.g. [ 'git', userArg ])
  if (expr.type === 'ArrayExpression') {
    const elements = expr.elements || [];
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i];
      if (!el) continue;
      const elTaint = evaluateExpressionTaint(el, scope, sourceCode, sinkContext, options);
      if (elTaint && !isTaintSanitized(elTaint, sinkContext)) {
        const loc = getNodeLocation(el);
        return elTaint.withStep(
          `[${i}]: ${elTaint.currentExpr}`,
          loc,
          sourceCode && el.start !== undefined && el.end !== undefined
            ? sourceCode.slice(el.start, el.end).trim()
            : `element [${i}]`
        );
      }
    }
  }

  // 8. ConditionalExpression (ternary: condition ? a : b)
  if (expr.type === 'ConditionalExpression') {
    const consTaint = evaluateExpressionTaint(expr.consequent, scope, sourceCode, sinkContext, options);
    if (consTaint) return consTaint;
    const altTaint = evaluateExpressionTaint(expr.alternate, scope, sourceCode, sinkContext, options);
    if (altTaint) return altTaint;
  }

  // 7. LogicalExpression (a || b, a && b)
  if (expr.type === 'LogicalExpression') {
    const leftTaint = evaluateExpressionTaint(expr.left, scope, sourceCode, sinkContext, options);
    if (leftTaint) return leftTaint;
    const rightTaint = evaluateExpressionTaint(expr.right, scope, sourceCode, sinkContext, options);
    if (rightTaint) return rightTaint;
  }

  // 8. SequenceExpression ((a, b))
  if (expr.type === 'SequenceExpression') {
    const exprs = expr.expressions || [];
    if (exprs.length > 0) {
      return evaluateExpressionTaint(exprs[exprs.length - 1], scope, sourceCode, sinkContext, options);
    }
  }

  // 9. AwaitExpression (e.g. await helper(req.query.cmd))
  if (expr.type === 'AwaitExpression') {
    return evaluateExpressionTaint(expr.argument, scope, sourceCode, sinkContext, options);
  }

  // 10. CallExpression (check for sanitizers, user-defined function returns, or fallback argument propagation)
  if (expr.type === 'CallExpression') {
    // Check sanitizer for specific sink context if provided
    const sanitizerEval = evaluateSanitizer(expr, sinkContext, {
      functionRegistry: options.functionRegistry,
      scope
    });
    // Analyze a project-defined implementation instead of trusting its qualified name.
    let targetFunc = null;
    let calleeResolutionAttempted = false;
    if (sanitizerEval?.isSanitized && options.functionRegistry) {
      targetFunc = options.functionRegistry.resolveCallee(expr.callee, options);
      calleeResolutionAttempted = true;
    }
    if (sanitizerEval?.isSanitized && !targetFunc) {
      const firstArg = expr.arguments?.[0];
      const innerTaint = evaluateExpressionTaint(firstArg, scope, sourceCode, sinkContext, options);
      if (innerTaint) {
        return innerTaint.withSanitization(sanitizerEval);
      }
      return null;
    }

    // Promise .then() chaining expression: p.then(cb)
    if (
      expr.callee?.type === 'MemberExpression' &&
      (expr.callee.property?.name === 'then' || expr.callee.property?.value === 'then')
    ) {
      const objTaint = evaluateExpressionTaint(expr.callee.object, scope, sourceCode, sinkContext, options);
      if (objTaint) {
        const callback = expr.arguments?.[0];
        if (callback && (callback.type === 'FunctionExpression' || callback.type === 'ArrowFunctionExpression')) {
          const cbParams = extractParamNames(callback.params);
          const cbDesc = new FunctionDescriptor({
            id: `then_callback:${expr.loc?.start?.line || 1}`,
            name: 'then_callback',
            file: options.filePath || 'source.js',
            node: callback,
            params: callback.params || [],
            paramNames: cbParams,
            body: callback.body,
            isArrowExpression: callback.type === 'ArrowFunctionExpression' && callback.body.type !== 'BlockStatement',
            returnStatements: callback.body.type === 'BlockStatement' ? findReturnStatements(callback.body) : [],
            sourceCode
          });
          const cbRet = evaluateFunctionReturnTaint(cbDesc, [objTaint], sourceCode, sinkContext, {
            ...options,
            callerScope: scope,
            callExpr: expr
          });
          return cbRet || objTaint;
        }
        return objTaint;
      }
    }

    // Inter-procedural function return evaluation for user-defined functions
    if (options.functionRegistry) {
      if (!calleeResolutionAttempted) {
        targetFunc = options.functionRegistry.resolveCallee(expr.callee, options);
      }
      if (targetFunc) {
        const argTaints = (expr.arguments || []).map((arg) =>
          evaluateExpressionTaint(arg, scope, sourceCode, sinkContext, options)
        );
        const retTaint = evaluateFunctionReturnTaint(targetFunc, argTaints, sourceCode, sinkContext, {
          ...options,
          callerScope: scope,
          callExpr: expr
        });
        if (retTaint) {
          const loc = getNodeLocation(expr);
          const callSnippet = sourceCode && expr.start !== undefined && expr.end !== undefined
            ? sourceCode.slice(expr.start, expr.end).trim()
            : `${targetFunc.name}(...)`;
          const callMetadata = callBoundaryMetadata(options, expr, targetFunc);
          return retTaint.withStep(`${targetFunc.name}()`, {
            ...loc,
            file: currentModule,
            ...callMetadata
          }, callSnippet);
        }
        // Known user-defined function returned clean value
        return null;
      }
    }

    // Check if callee receiver object is tainted (e.g. str.replace(...), str.trim())
    if (expr.callee?.type === 'MemberExpression') {
      const receiverTaint = evaluateExpressionTaint(expr.callee.object, scope, sourceCode, sinkContext, options);
      if (receiverTaint && !isTaintSanitized(receiverTaint, sinkContext)) {
        const loc = getNodeLocation(expr);
        const calleeStr = getMemberExpressionPath(expr.callee) || 'method';
        const callSnippet = sourceCode && expr.start !== undefined && expr.end !== undefined
          ? sourceCode.slice(expr.start, expr.end).trim()
          : `${calleeStr}(...)`;
        return receiverTaint.withStep(`${calleeStr}()`, loc, callSnippet);
      }
    }

    // Fallback: Check if any argument is tainted for unknown / unresolved calls.
    // If an argument is tainted, the returned value of the call inherits taint unless it was an effective sanitizer.
    for (const arg of expr.arguments || []) {
      const argTaint = evaluateExpressionTaint(arg, scope, sourceCode, sinkContext, options);
      if (argTaint && !isTaintSanitized(argTaint, sinkContext)) {
        const loc = getNodeLocation(expr);
        const calleeStr = getMemberExpressionPath(expr.callee) || expr.callee?.name || 'call';
        const callSnippet = sourceCode && expr.start !== undefined && expr.end !== undefined
          ? sourceCode.slice(expr.start, expr.end).trim()
          : `${calleeStr}(...)`;
        return argTaint.withStep(`${calleeStr}(...)`, loc, callSnippet);
      }
    }
  }

  return null;
}

/**
 * Formats a clear, structured evidence string from a confirmed taint trace.
 */
function formatTaintEvidence(source, steps, sink) {
  const parts = [];
  parts.push(`Source: ${source.expression} (L${source.line})`);
  if (steps && steps.length > 0) {
    const stepNames = steps.map((s) => s.to).filter(Boolean);
    if (stepNames.length > 0) {
      parts.push(`Flow: ${stepNames.join(' -> ')}`);
    }
  }
  parts.push(`Sink: ${sink.expression} (L${sink.line}) (<redacted>)`);
  return parts.join(' | ');
}

function frameworkRegistrationStep(seed, targetModulePath) {
  if (!seed?.modulePath || !targetModulePath) return null;
  return {
    from: 'Express route registration',
    to: 'registered request handler',
    expression: `Express ${seed.method} route handler registration`,
    line: seed.line,
    column: seed.column,
    file: seed.modulePath,
    fromModule: seed.modulePath,
    toModule: targetModulePath,
    ...(seed.importExport ? { importExport: seed.importExport } : {}),
    frameworkEntryPoint: true,
    registrationMethod: seed.method
  };
}

function requestPatternSource(segments, node, modulePath, parameterName) {
  const location = getNodeLocation(node);
  const root = parameterName || 'request';
  const path = `${root}.${segments.join('.')}`;
  return {
    isSource: true,
    root,
    property: segments[0],
    path,
    segments: [root, ...segments],
    subProperty: segments.slice(1).join('.') || null,
    expression: path,
    line: location.line,
    column: location.column,
    file: modulePath
  };
}

function seedFrameworkRequestParameter(functionNode, seed, scope, modulePath, options) {
  const limitations = options.limitations || [];
  const consumeSeedOperation = () => {
    if (!options.budgetManager) return true;
    const operation = options.budgetManager.consume('maxTaintOperations');
    recordBudgetFailure(operation, options);
    return operation.allowed;
  };
  const parameter = functionNode.params?.[0];
  if (!parameter) {
    if (!limitations.includes('unsupported_framework_request_parameter')) {
      limitations.push('unsupported_framework_request_parameter');
    }
    return;
  }
  const routeStep = frameworkRegistrationStep(seed, modulePath);
  const sourceFor = (segments, node, parameterName) => {
    const source = requestPatternSource(segments, node, modulePath, parameterName);
    return new TaintRecord(source, source.expression, routeStep ? [routeStep] : []);
  };
  const parameterPattern = parameter.type === 'AssignmentPattern' ? parameter.left : parameter;

  if (parameterPattern.type === 'Identifier') {
    for (const property of TAINT_PROPERTIES) {
      if (!consumeSeedOperation()) return;
      const source = sourceFor([property], parameterPattern, parameterPattern.name);
      scope.setPropertyTainted(parameterPattern.name, property, source);
    }
    return;
  }

  if (parameterPattern.type !== 'ObjectPattern') {
    if (!limitations.includes('unsupported_framework_request_parameter')) {
      limitations.push('unsupported_framework_request_parameter');
    }
    return;
  }

  let seededBindings = 0;
  const walkPattern = (pattern, segments) => {
    if (!pattern) return;
    if (pattern.type === 'AssignmentPattern') {
      walkPattern(pattern.left, segments);
      return;
    }
    if (pattern.type === 'Identifier') {
      if (!segments.length || !TAINT_PROPERTIES.has(segments[0])) return;
      if (!consumeSeedOperation()) return;
      scope.setTainted(pattern.name, sourceFor(segments, pattern, null));
      seededBindings++;
      return;
    }
    if (pattern.type === 'RestElement') {
      if (segments.length && TAINT_PROPERTIES.has(segments[0]) &&
          pattern.argument?.type === 'Identifier') {
        if (!consumeSeedOperation()) return;
        scope.setTainted(pattern.argument.name, sourceFor(segments, pattern.argument, null));
        seededBindings++;
      } else if (!limitations.includes('unsupported_framework_request_pattern')) {
        limitations.push('unsupported_framework_request_pattern');
      }
      return;
    }
    if (pattern.type !== 'ObjectPattern') {
      if (!limitations.includes('unsupported_framework_request_pattern')) {
        limitations.push('unsupported_framework_request_pattern');
      }
      return;
    }
    for (const property of pattern.properties || []) {
      if (property.type === 'RestElement') {
        walkPattern(property, segments);
        continue;
      }
      const key = property.computed
        ? getStringValue(property.key)
        : property.key?.name || getStringValue(property.key);
      if (!key) {
        if (!limitations.includes('unsupported_framework_request_pattern')) {
          limitations.push('unsupported_framework_request_pattern');
        }
        continue;
      }
      const nextSegments = [...segments, key];
      if (segments.length === 0 && !TAINT_PROPERTIES.has(key)) continue;
      walkPattern(property.value, nextSegments);
    }
  };

  walkPattern(parameterPattern, []);
  if (seededBindings === 0 &&
      !limitations.includes('unsupported_framework_request_pattern')) {
    limitations.push('unsupported_framework_request_pattern');
  }
}

/**
 * Analyzes an AST function or script body for intra-function taint flows.
 *
 * @param {Object} functionNode - AST node (FunctionDeclaration, ArrowFunctionExpression, Program, etc.)
 * @param {Object} options - Options: code, filePath, relativePath
 * @returns {Array<Object>} List of confirmed taint findings
 */
export function analyzeFunctionTaint(functionNode, options = {}) {
  const code = options.code || '';
  const relativePath = options.relativePath || options.filePath || 'source.js';
  const findings = [];
  const rootScope = new TaintScope(null, 'function_root');
  const childProcessAliases = new Map(options.childProcessAliases || []);
  const functionRegistry = options.functionRegistry || null;
  const initialParamTaint = options.initialParamTaint || null;
  const callStack = options.callStack || new Set();
  const callDepth = options.callDepth || 0;
  const limitations = options.limitations || [];
  const globalState = options.globalState || { totalInvocations: 0, limitsExceeded: false };
  const functionBudgetScope = `${relativePath}#${functionNode.id?.name || functionNode.type}@${functionNode.loc?.start?.line || 0}:${functionNode.loc?.start?.column || 0}`;

  for (const param of functionNode.params || []) {
    const binding = param.type === 'AssignmentPattern'
      ? param.left
      : param.type === 'RestElement'
        ? param.argument
        : param;
    if (binding?.type === 'Identifier') {
      rootScope.setClean(binding.name);
    }
  }

  // Bind initial parameters if passed by an inter-procedural caller
  if (initialParamTaint && functionNode.params) {
    const paramNames = extractParamNames(functionNode.params);
    paramNames.forEach((pName, idx) => {
      if (typeof pName === 'string') {
        const t = initialParamTaint.get(pName) || initialParamTaint.get(idx);
        if (t) {
          rootScope.setTainted(pName, t);
        }
        if (options.callerScope && options.callerArgNames?.[idx]) {
          options.callerScope.copyProperties(options.callerArgNames[idx], pName);
        }
      } else if (pName && pName.type === 'ObjectPattern') {
        for (const prop of pName.properties) {
          const propTaint = initialParamTaint.get(prop);
          if (propTaint) {
            rootScope.setTainted(prop, propTaint);
          }
        }
      }
    });
  }

  if (options.frameworkEntryPointSeed) {
    seedFrameworkRequestParameter(
      functionNode,
      options.frameworkEntryPointSeed,
      rootScope,
      relativePath,
      options
    );
  }

  let nodeCount = 0;
  let limitsExceeded = false;
  let callSitesInFunction = 0;

  function traverseStatements(bodyNode, currentScope) {
    if (!bodyNode || limitsExceeded || globalState.budgetExhausted) return;

    const statements = Array.isArray(bodyNode)
      ? bodyNode
      : (bodyNode.body && Array.isArray(bodyNode.body))
        ? bodyNode.body
        : [bodyNode];

    for (const stmt of statements) {
      if (!stmt || limitsExceeded || globalState.budgetExhausted) continue;
      nodeCount++;
      if (nodeCount > TAINT_ANALYZER_LIMITS.maxNodesPerFunction) {
        limitsExceeded = true;
        break;
      }

      // Check inner function declarations - do not descend into them as part of this function!
      // They are analyzed as independent function scopes.
      if (stmt.type === 'FunctionDeclaration') {
        continue;
      }

      // Track ES module import aliases for child_process
      if (stmt.type === 'ImportDeclaration' && stmt.source && (stmt.source.value === 'child_process' || stmt.source.value === 'node:child_process')) {
        for (const spec of stmt.specifiers || []) {
          if (spec.type === 'ImportSpecifier' && spec.imported && spec.local) {
            const importedName = spec.imported.name || spec.imported.value;
            if (/^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(importedName)) {
              childProcessAliases.set(spec.local.name, importedName);
            }
          }
        }
        continue;
      }

      // 1. Variable Declarations
      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations || []) {
          if (!decl) continue;
          const loc = getNodeLocation(decl);

          // Track require destructuring aliases for child_process: const { spawn: mySpawn } = require('child_process');
          if (decl.init && decl.init.type === 'CallExpression' && decl.init.callee?.name === 'require') {
            const firstArg = decl.init.arguments?.[0];
            if (firstArg && (firstArg.value === 'child_process' || firstArg.value === 'node:child_process')) {
              if (decl.id.type === 'ObjectPattern') {
                for (const prop of decl.id.properties || []) {
                  if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
                    const importedName = prop.key?.name || prop.key?.value;
                    const localName = prop.value?.name || importedName;
                    if (/^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(importedName)) {
                      childProcessAliases.set(localName, importedName);
                    }
                  }
                }
              }
            }
          }

          // Track direct property assignment alias: const myExec = child_process.exec;
          if (decl.id.type === 'Identifier' && decl.init && decl.init.type === 'MemberExpression') {
            const propName = decl.init.property?.name;
            const objName = decl.init.object?.name;
            if (/^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(propName || '')) {
              if (objName === 'child_process' || objName === 'childProcess' || objName === 'cp') {
                childProcessAliases.set(decl.id.name, propName);
              }
            }
          }

          // Destructuring source check: const { id } = req.query;
          if (decl.init && (decl.id.type === 'ObjectPattern' || decl.id.type === 'ArrayPattern')) {
            const inheritedSource = options.requireVerifiedFrameworkRequestSources
              ? evaluateExpressionTaint(decl.init, currentScope, code, null, options)
              : null;
            const destructured = options.requireVerifiedFrameworkRequestSources
              ? inheritedSource
                ? inspectDestructuredSources(decl.id, decl.init, code)
                : []
              : inspectDestructuredSources(decl.id, decl.init, code);
            for (const item of destructured) {
              if (!item.source.file && relativePath) {
                item.source.file = relativePath;
              }
              const record = inheritedSource
                ? inheritedSource.withStep(
                  item.variableName,
                  getNodeLocation(decl.id),
                  `${item.variableName} = ${item.source.expression}`
                )
                : new TaintRecord(item.source, item.variableName);
              currentScope.setTainted(item.variableName, record);
            }
            continue;
          }

          if (decl.id.type === 'Identifier') {
            const varName = decl.id.name;
            if (decl.init) {
              // Check object literal container: const data = { name: req.query.name };
              if (decl.init.type === 'ObjectExpression') {
                const opts = extractOptionsFromObjectNode(decl.init);
                if (opts) {
                  currentScope.setOption(varName, opts);
                }

                let anyTainted = false;
                for (const prop of decl.init.properties || []) {
                  if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
                    const keyName = prop.key.type === 'Identifier' ? prop.key.name : getStringValue(prop.key);
                    const propTaint = evaluateExpressionTaint(prop.value, currentScope, code, null, options);
                    if (propTaint && !isTaintSanitized(propTaint, null)) {
                      anyTainted = true;
                      const stepped = propTaint.withStep(`${varName}.${keyName}`, loc, `${varName}.${keyName} = ${propTaint.currentExpr}`);
                      currentScope.setPropertyTainted(varName, keyName, stepped);
                      currentScope.setTainted(varName, stepped);
                    }
                  }
                }
                if (!anyTainted) {
                  currentScope.setClean(varName, { clearParentProperties: false });
                }
                continue;
              }

              // Propagate options variable copy: const optsCopy = options;
              if (decl.init.type === 'Identifier') {
                const existingOpts = currentScope.getOption(decl.init.name);
                if (existingOpts) {
                  currentScope.setOption(varName, existingOpts);
                }
              }

              // Check array literal container: const values = [req.query.id];
              if (decl.init.type === 'ArrayExpression') {
                let anyTainted = false;
                decl.init.elements?.forEach((elem, index) => {
                  if (!elem) return;
                  const elemTaint = evaluateExpressionTaint(elem, currentScope, code, null, options);
                  if (elemTaint && !isTaintSanitized(elemTaint, null)) {
                    anyTainted = true;
                    const stepped = elemTaint.withStep(`${varName}[${index}]`, loc, `${varName}[${index}] = ${elemTaint.currentExpr}`);
                    currentScope.setPropertyTainted(varName, String(index), stepped);
                    currentScope.setTainted(varName, stepped);
                  }
                });
                if (!anyTainted) {
                  currentScope.setClean(varName, { clearParentProperties: false });
                }
                continue;
              }

              // Scalar expression evaluation
              const taintRecord = evaluateExpressionTaint(decl.init, currentScope, code, null, options);
              if (taintRecord && !isTaintSanitized(taintRecord, null)) {
                const exprSnippet = code && decl.init.start !== undefined && decl.init.end !== undefined
                  ? `${varName} = ${code.slice(decl.init.start, decl.init.end).trim()}`
                  : `${varName} = ${taintRecord.currentExpr}`;
                const stepped = taintRecord.withStep(varName, loc, exprSnippet);
                currentScope.setTainted(varName, stepped);
              } else {
                currentScope.setClean(varName, { clearParentProperties: false });
              }

              if (decl.init.type === 'Identifier') {
                currentScope.copyProperties(decl.init.name, varName);
              }
            }
          }
        }
        continue;
      }

      // 2. Expression Statement / Assignments / Sinks / Concise arrow body
      if (stmt.type === 'ExpressionStatement' && stmt.expression) {
        inspectStatementExpression(stmt.expression, currentScope);
        continue;
      }
      if (stmt.type === 'CallExpression' || stmt.type === 'AssignmentExpression' || stmt.type === 'AwaitExpression') {
        inspectStatementExpression(stmt, currentScope);
        continue;
      }

      // 3. Block Statement (e.g. if blocks, loops)
      if (stmt.type === 'BlockStatement') {
        const childScope = currentScope.createChildScope('block');
        traverseStatements(stmt.body, childScope);
        continue;
      }

      // 4. IfStatement
      if (stmt.type === 'IfStatement') {
        inspectStatementExpression(stmt.test, currentScope);
        if (stmt.consequent) {
          const ifScope = currentScope.createChildScope('if_consequent');
          traverseStatements(stmt.consequent, ifScope);
        }
        if (stmt.alternate) {
          const elseScope = currentScope.createChildScope('if_alternate');
          traverseStatements(stmt.alternate, elseScope);
        }
        continue;
      }

      // 5. ReturnStatement
      if (stmt.type === 'ReturnStatement' && stmt.argument) {
        inspectStatementExpression(stmt.argument, currentScope);
        continue;
      }
    }
  }

  function inspectStatementExpression(expr, currentScope) {
    if (!expr || limitsExceeded) return;

    // Unwrap AwaitExpression, e.g. await pool.query(query)
    if (expr.type === 'AwaitExpression') {
      inspectStatementExpression(expr.argument, currentScope);
      return;
    }

    // AssignmentExpression: x = req.query.name or data.name = req.query.name
    if (expr.type === 'AssignmentExpression') {
      const loc = getNodeLocation(expr);
      const isCompound = expr.operator !== '=';

      // Member assignment: data.name = ... or values[0] = ... or options.shell = true or data.nested.prop = ...
      if (expr.left.type === 'MemberExpression') {
        let objName = null;
        let propName = null;

        if (expr.left.object.type === 'Identifier') {
          objName = expr.left.object.name;
          if (expr.left.property.type === 'Identifier' && !expr.left.computed) {
            propName = expr.left.property.name;
          } else if (expr.left.computed && (expr.left.property.type === 'StringLiteral' || expr.left.property.type === 'NumericLiteral' || expr.left.property.type === 'Literal')) {
            propName = String(expr.left.property.value);
          }
        } else {
          const fullPath = getMemberExpressionPath(expr.left);
          if (fullPath) {
            const parts = fullPath.split('.');
            objName = parts[0];
            propName = parts.slice(1).join('.');
          }
        }

        if (objName) {
          // Track options object property mutations: options.shell = true/false/dynamic
          if (propName === 'shell') {
            let shellVal = 'ambiguous';
            if (expr.right.type === 'BooleanLiteral') {
              shellVal = expr.right.value;
            } else if (expr.right.type === 'StringLiteral') {
              shellVal = expr.right.value.length > 0;
            } else if (expr.right.type === 'Literal') {
              shellVal = Boolean(expr.right.value);
            } else if (expr.right.type === 'Identifier') {
              if (expr.right.name === 'true') shellVal = true;
              else if (expr.right.name === 'false') shellVal = false;
              else shellVal = 'ambiguous';
            } else {
              shellVal = 'ambiguous';
            }
            currentScope.setOptionProperty(objName, 'shell', shellVal);
          } else if (propName && currentScope.getOption(objName)) {
            currentScope.setOptionProperty(objName, propName, true);
          }

          const rightTaint = evaluateExpressionTaint(expr.right, currentScope, code, null, options);
          if (propName) {
            if (rightTaint && !isTaintSanitized(rightTaint, null)) {
              const stepped = rightTaint.withStep(`${objName}.${propName}`, loc, `${objName}.${propName} = ${rightTaint.currentExpr}`);
              currentScope.setPropertyTainted(objName, propName, stepped);
            } else if (expr.operator === '=') {
              currentScope.clearPropertyTaint(objName, propName);
            }
          }
        }
        return;
      }

      if (expr.left.type === 'Identifier') {
        const varName = expr.left.name;

        // Track options reassignment: options = { shell: true };
        if (expr.right && expr.right.type === 'ObjectExpression') {
          const opts = extractOptionsFromObjectNode(expr.right);
          if (opts) {
            currentScope.setOption(varName, opts);
          }
        } else if (expr.right && expr.right.type === 'Identifier') {
          const existingOpts = currentScope.getOption(expr.right.name);
          if (existingOpts) {
            currentScope.setOption(varName, existingOpts);
          } else {
            currentScope.setOption(varName, { shell: 'ambiguous' });
          }
        } else if (expr.right) {
          // Dynamic reassignment breaks previous options or makes it ambiguous
          currentScope.setOption(varName, { shell: 'ambiguous' });
        }

        const rightTaint = evaluateExpressionTaint(expr.right, currentScope, code, null, options);

        if (rightTaint && !isTaintSanitized(rightTaint, null)) {
          const exprSnippet = code && expr.right.start !== undefined && expr.right.end !== undefined
            ? `${varName} ${expr.operator} ${code.slice(expr.right.start, expr.right.end).trim()}`
            : `${varName} = ${rightTaint.currentExpr}`;
          const stepped = rightTaint.withStep(varName, loc, exprSnippet);
          currentScope.setTainted(varName, stepped);
        } else if (!isCompound) {
          // Plain reassignment to safe value clears previous taint
          currentScope.setClean(varName);
        }

        if (expr.right?.type === 'Identifier') {
          currentScope.copyProperties(expr.right.name, varName);
        }
        return;
      }
    }

    // Check CallExpression or NewExpression for Security Sinks
    if (expr.type === 'CallExpression' || expr.type === 'NewExpression') {
      const sink = inspectSecuritySink(
        expr,
        code,
        childProcessAliases,
        currentScope,
        options.sinkProvenanceResolver
      );
      if (sink && sink.isSink) {
        const args = expr.arguments || [];

        // Inspect only target arguments designated by the sink
        for (const argIndex of sink.targetArgIndices) {
          if (argIndex < args.length) {
            const targetArg = args[argIndex];

            // In command execution with argument array, inspect elements if targetArg is ArrayExpression
            if (sink.sinkType === 'command' && targetArg.type === 'ArrayExpression') {
              const argRole = sink.hasShell ? 'shell_argument' : 'command_argument';
              targetArg.elements?.forEach((el) => {
                if (!el) return;
                checkSinkArgument(el, sink, currentScope, argRole);
              });
            } else {
              const argRole = sink.sinkType === 'command'
                ? (sink.isShellDirect
                    ? 'shell_command'
                    : (argIndex === 0
                        ? ((sink.hasShell && (args.length === 1 || sink.isSecondArgOptions)) ? 'shell_command' : 'command_executable')
                        : (sink.hasShell ? 'shell_argument' : 'command_argument')))
                : null;
              checkSinkArgument(targetArg, sink, currentScope, argRole);
            }
          }
        }
      }

      // Inter-procedural propagation for user-defined function calls
      if (functionRegistry && expr.type === 'CallExpression') {
        callSitesInFunction++;
        const callSiteKey = `${expr.loc?.start?.line || 0}:${expr.loc?.start?.column || 0}`;
        const callSiteBudget = options.budgetManager
          ? options.budgetManager.consume('maxCallSitesPerFunction', 1, {
            scope: functionBudgetScope,
            key: callSiteKey
          })
          : { allowed: callSitesInFunction <= CALL_GRAPH_LIMITS.maxCallSitesPerFunction };
        if (!callSiteBudget.allowed) {
          recordBudgetFailure(callSiteBudget, { ...options, globalState });
          if (limitations && !limitations.includes('max_call_sites_per_function_exceeded')) {
            limitations.push(options.budgetManager
              ? callSiteBudget.code
              : 'max_call_sites_per_function_exceeded');
          }
        } else {
          const targetFunc = functionRegistry.resolveCallee(expr.callee, options);
          if (targetFunc) {
            const invocationLimit = options.budgetManager
              ? { allowed: true }
              : { allowed: globalState.totalInvocations < CALL_GRAPH_LIMITS.maxTotalInvocations };
            const depthLimit = options.budgetManager
              ? options.budgetManager.check('maxCallDepth', callDepth + 1)
              : { allowed: callDepth < CALL_GRAPH_LIMITS.maxCallDepth };
            if (!invocationLimit.allowed) {
              recordBudgetFailure(invocationLimit, { ...options, globalState });
              globalState.limitsExceeded = true;
              if (limitations && !limitations.includes('max_call_invocations_exceeded')) {
                limitations.push(options.budgetManager
                  ? invocationLimit.code
                  : 'max_call_invocations_exceeded');
              }
            } else if (callStack.has(targetFunc.id)) {
              if (limitations && !limitations.includes('recursive_call_cycle_detected')) {
                limitations.push('recursive_call_cycle_detected');
              }
            } else if (!depthLimit.allowed) {
              recordBudgetFailure(depthLimit, { ...options, globalState });
              globalState.limitsExceeded = true;
              if (limitations && !limitations.includes('call_graph_depth_limit_exceeded')) {
                limitations.push(options.budgetManager
                  ? depthLimit.code
                  : 'call_graph_depth_limit_exceeded');
              }
            } else {
              const argTaints = (expr.arguments || []).map((arg) =>
                evaluateExpressionTaint(arg, currentScope, code, null, options)
              );
              const anyTaintedArg = argTaints.some((t) => Boolean(t));

              if (anyTaintedArg) {
                // Ensure duplicate accounting does not prematurely exhaust invocation budget
                if (!globalState.evaluatedCallSites) globalState.evaluatedCallSites = new Set();
                const invocationKey = `${targetFunc.id}@${expr.loc?.start?.line || 0}:${expr.loc?.start?.column || 0}`;
                const sharedInvocation = options.budgetManager
                  ? options.budgetManager.consumeOnce('maxTotalInvocations', invocationKey)
                  : { allowed: true, duplicate: globalState.evaluatedCallSites.has(invocationKey) };
                if (!sharedInvocation.allowed) {
                  recordBudgetFailure(sharedInvocation, { ...options, globalState });
                } else {
                  if (!globalState.evaluatedCallSites.has(invocationKey)) {
                    globalState.evaluatedCallSites.add(invocationKey);
                    if (!options.budgetManager || !sharedInvocation.duplicate) {
                      globalState.totalInvocations++;
                    }
                  }

                const calleeParamTaints = new Map();
                const loc = getNodeLocation(expr);
                const callText = code && expr.start !== undefined && expr.end !== undefined
                  ? code.slice(expr.start, expr.end).trim()
                  : `${targetFunc.name}(...)`;
                const callMetadata = callBoundaryMetadata(options, expr, targetFunc);
                const callLocation = {
                  ...loc,
                  file: relativePath,
                  ...callMetadata
                };

                targetFunc.paramNames.forEach((pName, idx) => {
                  const argTaint = argTaints[idx];
                  if (!argTaint) return;
                  if (typeof pName === 'string') {
                    const stepped = argTaint.withStep(
                      `${targetFunc.name}(${pName})`,
                      callLocation,
                      `${pName} <- ${argTaint.currentExpr} in ${callText}`
                    );
                    calleeParamTaints.set(pName, stepped);
                    calleeParamTaints.set(idx, stepped);
                  } else if (pName && pName.type === 'ObjectPattern') {
                    const argNode = expr.arguments?.[idx];
                    for (const prop of pName.properties) {
                      let propTaint = null;
                      if (argNode?.type === 'ObjectExpression') {
                        const matchedProp = (argNode.properties || []).find((p) => {
                          const k = p.key?.name || getStringValue(p.key);
                          return k === prop;
                        });
                        if (matchedProp) {
                          propTaint = evaluateExpressionTaint(matchedProp.value, currentScope, code, null, options);
                        }
                      } else if (argNode?.type === 'Identifier') {
                        propTaint = currentScope.lookup(argNode.name, prop);
                      } else {
                        propTaint = argTaint;
                      }

                      if (propTaint) {
                        const stepped = propTaint.withStep(
                          `${targetFunc.name}({ ${prop} })`,
                          callLocation,
                          `${prop} <- ${propTaint.currentExpr} in ${callText}`
                        );
                        calleeParamTaints.set(prop, stepped);
                      }
                    }
                    calleeParamTaints.set(idx, argTaint);
                  }
                });

                const callerArgNames = (expr.arguments || []).map((arg) => (arg?.type === 'Identifier' ? arg.name : null));
                const nextCallStack = new Set([...callStack, targetFunc.id]);
                const childOpts = {
                  ...options,
                  code: targetFunc.sourceCode || code,
                  filePath: targetFunc.filePath || options.filePath,
                  relativePath: targetFunc.relativePath || relativePath,
                  functionRegistry: targetFunc.moduleRegistry || functionRegistry,
                  moduleChain: options.moduleChain
                    ? [...options.moduleChain, targetFunc.filePath || targetFunc.file]
                    : [options.filePath || 'source.js', targetFunc.filePath || targetFunc.file],
                  initialParamTaint: calleeParamTaints,
                  callerScope: currentScope,
                  callerArgNames,
                  callStack: nextCallStack,
                  callDepth: callDepth + 1,
                  globalState,
                  limitations
                };

                const calleeResult = analyzeFunctionTaint(targetFunc.node, childOpts);
                if (calleeResult && calleeResult.findings) {
                  for (const f of calleeResult.findings) {
                    if (!findings.some((existing) => hasSameFindingIdentity(existing, f))) {
                      findings.push(f);
                    }
                  }
                }
                if (calleeResult?.limitsExceeded) {
                  limitsExceeded = true;
                }

                // Reflect callee object parameter mutations back into caller scope
                if (calleeResult?.scope && targetFunc.paramNames) {
                  targetFunc.paramNames.forEach((pName, idx) => {
                    if (typeof pName === 'string' && expr.arguments[idx]?.type === 'Identifier') {
                      const argVarName = expr.arguments[idx].name;
                      for (const [key, record] of calleeResult.scope.propertyBindings.entries()) {
                        if (key.startsWith(`${pName}.`)) {
                          const subProp = key.slice(pName.length + 1);
                          const stepped = record.withStep(
                            `${argVarName}.${subProp}`,
                            loc,
                            `${argVarName}.${subProp} <- ${pName}.${subProp} in ${targetFunc.name}()`
                          );
                          currentScope.setPropertyTainted(argVarName, subProp, stepped);
                          currentScope.setTainted(argVarName, stepped);
                        }
                      }
                    }
                  });
                }
              }
            }
          }
        }
      }

      // Check Promise .then() callback propagation
      if (
        expr.type === 'CallExpression' &&
        expr.callee?.type === 'MemberExpression' &&
        expr.callee.property?.type === 'Identifier' &&
        expr.callee.property.name === 'then'
      ) {
        const promiseTaint = evaluateExpressionTaint(expr.callee.object, currentScope, code, null, options);
        if (promiseTaint) {
          const callback = expr.arguments?.[0];
          if (callback && (callback.type === 'FunctionExpression' || callback.type === 'ArrowFunctionExpression')) {
            const cbParamTaints = new Map();
            const paramNames = extractParamNames(callback.params);
            if (paramNames.length > 0 && typeof paramNames[0] === 'string') {
              cbParamTaints.set(paramNames[0], promiseTaint);
            }
            cbParamTaints.set(0, promiseTaint);

            const cbResult = analyzeFunctionTaint(callback, {
              ...options,
              code,
              filePath: options.filePath || relativePath,
              relativePath,
              functionRegistry,
              initialParamTaint: cbParamTaints,
              callStack,
              callDepth: callDepth + 1,
              globalState,
              limitations
            });
            if (cbResult?.findings) {
              for (const f of cbResult.findings) {
                if (!findings.some((existing) => hasSameFindingIdentity(existing, f))) {
                  findings.push(f);
                }
              }
            }
          }
        }
      }

      // Check arguments of any other call expression in case a nested sink is passed
      for (const arg of expr.arguments || []) {
        if (arg && (arg.type === 'CallExpression' || arg.type === 'NewExpression')) {
          inspectStatementExpression(arg, currentScope);
        }
      }
    }
  }
  }

  function checkSinkArgument(argNode, sink, currentScope, argRole = null) {
    if (!argNode) return;

    const taintRecord = evaluateExpressionTaint(argNode, currentScope, code, sink.sinkType, options);
    if (!taintRecord) return;

    // If a context-appropriate sanitizer was successfully applied, suppress finding
    if (isTaintSanitized(taintRecord, sink.sinkType, argRole)) {
      return;
    }

    // Check if duplicate finding already recorded in this file
    const dedupeKey = createSinkIdentity({
      ruleId: sink.ruleId,
      checkId: sink.checkId,
      file: relativePath,
      sourceSpan: sink.sourceSpan
    });
    const existingFinding = dedupeKey
      ? findings.find((finding) => finding._dedupeKey === dedupeKey)
      : null;
    if (existingFinding) {
      const alternateTrace = {
        source: {
          expression: taintRecord.source.expression,
          path: taintRecord.source.path,
          line: taintRecord.source.line,
          column: taintRecord.source.column,
          file: taintRecord.source.file || relativePath
        },
        steps: taintRecord.steps,
        sink: {
          type: sink.sinkType,
          ruleId: sink.ruleId,
          expression: sink.expression,
          line: sink.line,
          column: sink.column,
          file: relativePath,
          api: sink.methodName || sink.expression,
          argumentRole: argRole || (sink.sinkType === 'sql' ? 'sql_query' : 'sink_argument')
        },
        sanitized: false
      };
      const traces = existingFinding.taintTrace.alternatePaths || [];
      const serialized = JSON.stringify(alternateTrace);
      if (JSON.stringify(existingFinding.taintTrace) !== serialized &&
          !traces.some((trace) => JSON.stringify(trace) === serialized)) {
        traces.push(alternateTrace);
        traces.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
        existingFinding.taintTrace.alternatePaths = traces;
      }
      return;
    }

    const evidenceText = formatTaintEvidence(taintRecord.source, taintRecord.steps, sink);

    let title = sink.title;
    let description = sink.description;
    let cwe = sink.cwe;

    if (sink.sinkType === 'command' && argRole) {
      if (argRole === 'shell_command') {
        title = 'Potentially unsafe command construction via shell execution';
        description = `Potentially untrusted user input flows into a shell command string executed by child_process.${sink.methodName || 'exec'}(). An attacker can inject shell metacharacters to execute arbitrary commands.`;
        cwe = ['CWE-78'];
      } else if (argRole === 'shell_argument') {
        title = 'Potentially unsafe command construction via shell-enabled process execution';
        description = `Process execution API child_process.${sink.methodName || 'spawn'}() is called with shell: true and receives untrusted input. In shell mode, arguments are evaluated in shell context, allowing arbitrary shell command injection.`;
        cwe = ['CWE-78'];
      } else if (argRole === 'command_executable') {
        title = 'Potentially untrusted executable path in process execution';
        description = `Potentially untrusted user input is passed as the executable or file path to child_process.${sink.methodName || 'spawn'}(). An attacker may control which binary is executed (CWE-114: Process Control). Untrusted search-path behavior (CWE-426) is not assumed unless search-path manipulation evidence is present. Exploitability cannot be established from static path analysis alone.`;
        cwe = ['CWE-114'];
      } else if (argRole === 'command_argument') {
        let argTypeDesc = 'unknown argument semantics';
        const exprText = code && argNode.start !== undefined && argNode.end !== undefined
          ? code.slice(argNode.start, argNode.end).trim()
          : '';
        const varName = argNode.type === 'Identifier' ? argNode.name.toLowerCase() : '';

        if (/^['"]?-{1,2}/.test(exprText) || /option|flag|opt\b/i.test(varName)) {
          argTypeDesc = 'option-like argument (flag injection risk)';
        } else if (/subcommand|action|command|cmd\b/i.test(varName)) {
          argTypeDesc = 'subcommand selection';
        } else if (/file|path|url|branch|target|user|name|id\b/i.test(varName)) {
          argTypeDesc = 'ordinary operand';
        }

        title = 'Potentially untrusted argument in process execution (potential argument injection)';
        description = `Potentially untrusted user input is passed as a command argument (${argTypeDesc}) to child_process.${sink.methodName || 'spawn'}() without shell execution. While shell metacharacters are not interpreted by a shell, attacker-controlled arguments may alter target-program behavior, flags, or configuration depending on target binary semantics (CWE-88: Argument Injection). This finding represents potential argument injection; not every tainted argument is exploitable without specific target-binary vulnerabilities.`;
        cwe = ['CWE-88'];
      }
    }

    findings.push({
      _dedupeKey: dedupeKey,
      sinkIdentity: dedupeKey,
      sinkIdentityStatus: dedupeKey ? 'resolved' : 'unresolved',
      sourceSpan: sink.sourceSpan,
      sinkExpression: sink.sinkExpression,
      sinkProvenance: sink.sinkProvenance,
      ruleId: sink.ruleId,
      checkId: sink.checkId,
      category: sink.category,
      severity: sink.severity,
      confidence: sink.confidence || 'medium',
      cwe,
      title,
      description,
      remediation: sink.remediation,
      recommendation: sink.recommendation || sink.remediation,
      severityRationale: `${sink.severity}: confirmed data-flow path connects untrusted input from ${taintRecord.source.expression} (${taintRecord.source.file || relativePath}:L${taintRecord.source.line}) to ${sink.expression} (${relativePath}:L${sink.line}). Exploitability depends on runtime context and deployment architecture.`,
      evidence: evidenceText,
      file: relativePath,
      line: sink.line,
      column: sink.column,
      origin: 'ast_taint_analysis',
      isTaintConfirmed: true,
      taintTrace: {
        source: {
          expression: taintRecord.source.expression,
          path: taintRecord.source.path,
          line: taintRecord.source.line,
          column: taintRecord.source.column,
          file: taintRecord.source.file || relativePath
        },
        steps: taintRecord.steps,
        sink: {
          type: sink.sinkType,
          ruleId: sink.ruleId,
          expression: sink.expression,
          line: sink.line,
          column: sink.column,
          file: relativePath,
          api: sink.methodName || sink.expression,
          argumentRole: argRole || (sink.sinkType === 'sql' ? 'sql_query' : 'sink_argument')
        },
        sanitized: false
      }
    });
  }

  // Determine function body to traverse
  const body = functionNode.type === 'Program'
    ? functionNode.body
    : (functionNode.body?.type === 'BlockStatement' ? functionNode.body.body : functionNode.body);

  traverseStatements(body, rootScope);
  if (globalState.budgetExhausted) limitsExceeded = true;

  return {
    findings,
    limitsExceeded,
    nodeCount,
    scope: rootScope
  };
}

/**
 * Top-level coordinator for whole-file AST taint analysis.
 * Identifies all functions and script scopes and runs intra-function taint analysis.
 *
 * @param {Object} rootAst - Babel AST root node (File or Program)
 * @param {Object} options - Options: code, filePath, relativePath
 * @returns {Object} { findings, metrics, coverageStatus, limitations }
 */
export function analyzeAstTaint(rootAst, options = {}) {
  const code = options.code || '';
  const filePath = options.filePath || options.relativePath || 'source.js';
  const relativePath = options.relativePath || filePath;

  const findings = [];
  let totalFunctions = 0;
  let limitsExceeded = false;
  const limitations = [];

  if (!rootAst) {
    return {
      findings: [],
      metrics: { functionsAnalyzed: 0, findingsCount: 0 },
      coverageStatus: 'skipped',
      limitations: ['ast_not_available']
    };
  }

  const programNode = rootAst.type === 'File' ? rootAst.program : rootAst;
  if (!programNode) {
    return {
      findings: [],
      metrics: { functionsAnalyzed: 0, findingsCount: 0 },
      coverageStatus: 'skipped',
      limitations: ['program_node_not_found']
    };
  }

  const sinkProvenanceResolver = options.sinkProvenanceResolver ||
    createSinkProvenanceResolver(rootAst);

  // Collect file-level child_process import aliases
  const fileChildProcessAliases = new Map();
  for (const stmt of programNode.body || []) {
    if (!stmt) continue;
    if (stmt.type === 'ImportDeclaration') {
      const src = stmt.source?.value;
      if (src === 'child_process' || src === 'node:child_process') {
        for (const spec of stmt.specifiers || []) {
          if (spec.type === 'ImportSpecifier') {
            const importedName = spec.imported?.name || spec.imported?.value;
            const localName = spec.local?.name || importedName;
            if (/^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(importedName)) {
              fileChildProcessAliases.set(localName, importedName);
            }
          }
        }
      }
    }
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations || []) {
        if (decl?.init?.type === 'CallExpression' && decl.init.callee?.name === 'require') {
          const firstArg = decl.init.arguments?.[0];
          if (firstArg && (firstArg.value === 'child_process' || firstArg.value === 'node:child_process')) {
            if (decl.id?.type === 'ObjectPattern') {
              for (const prop of decl.id.properties || []) {
                if (prop.type === 'Property' || prop.type === 'ObjectProperty') {
                  const importedName = prop.key?.name || prop.key?.value;
                  const localName = prop.value?.name || importedName;
                  if (/^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(importedName)) {
                    fileChildProcessAliases.set(localName, importedName);
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  // Build FunctionRegistry for whole-file and imported function resolution
  const functionRegistry = options.functionRegistry || buildFunctionRegistry(programNode, {
    ...options,
    code,
    filePath,
    relativePath,
    limitations
  });

  const globalState = options.globalState || {
    totalInvocations: 0,
    limitsExceeded: false,
    limitations: []
  };

  const funcOpts = {
    ...options,
    sinkProvenanceResolver,
    code,
    filePath,
    relativePath,
    childProcessAliases: fileChildProcessAliases,
    functionRegistry,
    globalState,
    limitations,
    callStack: new Set(),
    callDepth: 0
  };

  // 1. Analyze top-level program statements (script level scope)
  const topLevelResult = analyzeFunctionTaint(programNode, funcOpts);
  findings.push(...topLevelResult.findings);
  if (topLevelResult.limitsExceeded) {
    limitsExceeded = true;
    limitations.push('top_level_taint_node_limit_exceeded');
  }

  // 2. Discover all functions in the AST
  function findFunctions(node, depth = 0) {
    if (!node || typeof node !== 'object' || depth > 100 || globalState.budgetExhausted) return;
    if (totalFunctions >= TAINT_ANALYZER_LIMITS.maxFunctionsPerFile) {
      limitsExceeded = true;
      limitations.push('file_function_count_limit_exceeded');
      return;
    }

    const isFunction =
      node.type === 'FunctionDeclaration' ||
      node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression' ||
      node.type === 'ObjectMethod' ||
      node.type === 'ClassMethod';

    if (isFunction) {
      totalFunctions++;
      const registrations = options.frameworkEntryPointSeeds?.get(node) || [];
      const seed = registrations[0] || null;
      const result = analyzeFunctionTaint(node, {
        ...funcOpts,
        ...(seed ? { frameworkEntryPointSeed: seed } : {})
      });
      findings.push(...result.findings);
      if (result.limitsExceeded) {
        limitsExceeded = true;
        limitations.push('function_taint_node_limit_exceeded');
      }
    }

    // Traverse children
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range' || key === 'comments' || key === 'tokens') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item && typeof item === 'object') findFunctions(item, depth + 1);
        }
      } else if (child && typeof child === 'object') {
        findFunctions(child, depth + 1);
      }
    }
  }

  findFunctions(programNode);

  if (globalState.limitsExceeded) {
    limitsExceeded = true;
  }
  if (options.budgetManager) {
    for (const limitation of options.budgetManager.getLimitationCodes()) {
      if (!limitations.includes(limitation)) limitations.push(limitation);
    }
  }
  if (globalState.limitations?.length > 0) {
    for (const lim of globalState.limitations) {
      if (!limitations.includes(lim)) {
        limitations.push(lim);
      }
      if (options.budgetManager) {
        for (const limitation of options.budgetManager.getLimitationCodes()) {
          if (!limitations.includes(limitation)) limitations.push(limitation);
        }
      }
    }
  }

  // Incomplete coverage if limitations or safety limits were encountered
  if (limitations.length > 0) {
    limitsExceeded = true;
  }

  // Clean dedupe internal property from findings
  const cleanFindings = findings.map((f) => {
    const copy = { ...f };
    delete copy._dedupeKey;
    return copy;
  });

  return {
    findings: cleanFindings,
    metrics: {
      functionsAnalyzed: totalFunctions + 1, // +1 for top-level script
      findingsCount: cleanFindings.length
    },
    coverageStatus: limitsExceeded ? 'partial' : 'completed',
    limitations: limitations.length > 0 ? limitations : []
  };
}
