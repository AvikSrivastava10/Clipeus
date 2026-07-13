/**
 * Lightweight cross-file taint tracker for JavaScript/TypeScript.
 *
 * Scope (intentionally reduced — not a full dataflow engine):
 *   - Intra-function forward flow: user-controlled sources (req.body, etc.)
 *     flowing into dangerous sinks (eval, child_process.exec, db.query, fs.*)
 *     without passing through a recognized sanitizer.
 *   - One-hop+ inter-procedural propagation: a tainted value passed to a local
 *     (same-file or relatively-imported) function taints that function's
 *     parameter, which is then analyzed for sinks.
 *
 * Deliberately favors precision on common, straightforward code over handling
 * deeply dynamic constructs. All findings are heuristic (medium/low confidence)
 * and clearly labeled. Read-only; never throws (bad files are skipped).
 */

import fs from 'node:fs';
import path from 'node:path';
import { parseJs, walkAst } from '../analysis/js-parse.js';
import { walk } from '../core/fswalk.js';
import { createFinding } from '../core/finding.js';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { log } from '../core/logger.js';

const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const RESOLVE_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];
const MAX_FILE_BYTES = 400_000;
const MAX_ITERATIONS = 20_000;

const SKIP_KEYS = new Set(['loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'extra', 'comments', 'tokens']);
const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod']);

/** Dotted path for a member/identifier chain; null if not statically nameable. */
function memberPath(node) {
  if (!node) return null;
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'ThisExpression':
      return 'this';
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const base = memberPath(node.object);
      if (node.computed) return base; // req.body['x'] -> "req.body"
      const prop = node.property?.name;
      if (base == null) return prop || null;
      return prop ? `${base}.${prop}` : base;
    }
    case 'CallExpression':
    case 'OptionalCallExpression':
      return memberPath(node.callee);
    default:
      return null;
  }
}

function lastSegment(dotted) {
  if (!dotted) return null;
  const parts = dotted.split('.');
  return parts[parts.length - 1];
}

function paramName(param) {
  if (!param) return null;
  switch (param.type) {
    case 'Identifier':
      return param.name;
    case 'AssignmentPattern':
      return paramName(param.left);
    case 'RestElement':
      return paramName(param.argument);
    case 'TSParameterProperty':
      return paramName(param.parameter);
    default:
      return null; // destructured params are not individually named
  }
}

function functionName(node, parent) {
  if (node.id?.name) return node.id.name;
  if (node.key?.name) return node.key.name; // object/class method
  if (parent) {
    if (parent.type === 'VariableDeclarator' && parent.id?.type === 'Identifier') return parent.id.name;
    if (parent.type === 'AssignmentExpression' && parent.left?.type === 'Identifier') return parent.left.name;
    if (parent.type === 'ObjectProperty' && parent.key?.name) return parent.key.name;
  }
  return null;
}

function bodyStatements(fn) {
  if (fn.isModule) return fn.statements;
  const node = fn.node;
  if (node.body?.type === 'BlockStatement') return node.body.body;
  // Arrow with expression body: treat as `return <expr>`.
  return [{ type: 'ReturnStatement', argument: node.body }];
}

/** Parse one file into its function/import/export model. */
function buildFileModel(rel, code) {
  const ast = parseJs(code, { filename: rel });
  if (!ast) return null;

  const functions = [];
  const functionsByName = new Map();
  const imports = new Map(); // localName -> { source, importedName }
  const exportsMap = new Map(); // exportName -> localName

  walkAst(ast, {
    Function(p) {
      const node = p.node;
      const name = functionName(node, p.parent);
      const fn = {
        key: `${rel}:${node.loc?.start.line ?? 0}:${node.loc?.start.column ?? 0}`,
        file: rel,
        name,
        params: node.params.map(paramName),
        node,
        line: node.loc?.start.line ?? null,
      };
      functions.push(fn);
      if (name && !functionsByName.has(name)) functionsByName.set(name, fn);
    },
    ImportDeclaration(p) {
      const source = p.node.source?.value;
      if (!source) return;
      for (const spec of p.node.specifiers) {
        if (spec.type === 'ImportSpecifier') imports.set(spec.local.name, { source, importedName: spec.imported?.name ?? spec.local.name });
        else if (spec.type === 'ImportDefaultSpecifier') imports.set(spec.local.name, { source, importedName: 'default' });
      }
    },
    VariableDeclarator(p) {
      // const x = require('./m'); const { a } = require('./m');
      const init = p.node.init;
      if (init?.type === 'CallExpression' && init.callee?.name === 'require' && init.arguments[0]?.type === 'StringLiteral') {
        const source = init.arguments[0].value;
        if (p.node.id.type === 'Identifier') imports.set(p.node.id.name, { source, importedName: '*' });
        else if (p.node.id.type === 'ObjectPattern') {
          for (const prop of p.node.id.properties) {
            if (prop.key?.name && prop.value?.type === 'Identifier') imports.set(prop.value.name, { source, importedName: prop.key.name });
          }
        }
      }
    },
  });

  // Module-scope pseudo-function (captures top-level sinks/assignments).
  functions.push({
    key: `${rel}:module`,
    file: rel,
    name: null,
    params: [],
    isModule: true,
    statements: ast.program.body,
    line: 1,
  });

  collectExports(ast.program.body, exportsMap);

  return { rel, functions, functionsByName, imports, exports: exportsMap };
}

function collectExports(body, exportsMap) {
  for (const stmt of body) {
    if (stmt.type === 'ExportNamedDeclaration') {
      if (stmt.declaration?.type === 'FunctionDeclaration' && stmt.declaration.id) {
        exportsMap.set(stmt.declaration.id.name, stmt.declaration.id.name);
      } else if (stmt.declaration?.type === 'VariableDeclaration') {
        for (const d of stmt.declaration.declarations) {
          if (d.id.type === 'Identifier') exportsMap.set(d.id.name, d.id.name);
        }
      }
      for (const spec of stmt.specifiers || []) {
        if (spec.exported?.name && spec.local?.name) exportsMap.set(spec.exported.name, spec.local.name);
      }
    } else if (stmt.type === 'ExportDefaultDeclaration') {
      const d = stmt.declaration;
      const local = d?.id?.name || (d?.type === 'Identifier' ? d.name : null);
      if (local) exportsMap.set('default', local);
    } else if (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'AssignmentExpression') {
      const { left, right } = stmt.expression;
      const leftPath = memberPath(left);
      if (leftPath === 'module.exports' || leftPath === 'exports') {
        if (right.type === 'ObjectExpression') {
          for (const prop of right.properties) {
            if (prop.key?.name && prop.value?.type === 'Identifier') exportsMap.set(prop.key.name, prop.value.name);
          }
        } else if (right.type === 'Identifier') {
          exportsMap.set('default', right.name);
        }
      } else if (leftPath?.startsWith('module.exports.') || leftPath?.startsWith('exports.')) {
        const exportName = leftPath.split('.').pop();
        if (right.type === 'Identifier') exportsMap.set(exportName, right.name);
      }
    }
  }
}

/** Resolve a relative import source to a known file (rel path) in the project. */
function resolveRelative(source, fromRel, fileSet) {
  if (!source || !source.startsWith('.')) return null;
  const baseDir = path.posix.dirname(fromRel.replace(/\\/g, '/'));
  const joined = path.posix.normalize(path.posix.join(baseDir, source));
  const candidates = [joined, ...RESOLVE_EXTS.map((e) => joined + e), ...RESOLVE_EXTS.map((e) => path.posix.join(joined, 'index' + e))];
  for (const c of candidates) {
    if (fileSet.has(c)) return c;
  }
  return null;
}

/**
 * Analyze the whole project for JS/TS taint.
 * @param {string} root
 * @param {object} config  Patronus config (uses config.taint).
 * @returns {object[]} findings
 */
export function analyzeJsTaint(root, config) {
  const taintCfg = config?.taint || {};
  const sources = (taintCfg.sources || []).map(String);
  const sinks = new Set((taintCfg.sinks || []).map(String));
  const sinkLast = new Set([...sinks].map(lastSegment).filter(Boolean));
  const sanitizerLast = new Set((taintCfg.sanitizers || []).map((s) => lastSegment(String(s))).filter(Boolean));

  const files = walk(root, { extensions: JS_EXTS, maxFiles: 5000 });
  const models = new Map(); // rel -> file model
  const fileSet = new Set();

  for (const abs of files) {
    let stat;
    try {
      stat = fs.statSync(abs);
    } catch {
      continue;
    }
    if (stat.size > MAX_FILE_BYTES) continue;
    let code;
    try {
      code = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const rel = path.relative(root, abs).replace(/\\/g, '/');
    fileSet.add(rel);
    try {
      const model = buildFileModel(rel, code);
      if (model) models.set(rel, model);
    } catch (err) {
      log.debug(`taint: failed to model ${rel}: ${err.message}`);
    }
  }

  const analysisCtx = {
    sources,
    sinks,
    sinkLast,
    sanitizerLast,
    models,
    fileSet,
    findings: new Map(), // dedupKey -> finding
    analyzed: new Set(),
    queue: [],
    iterations: 0,
  };

  // Seed the worklist: every function analyzed with no pre-tainted params.
  for (const model of models.values()) {
    for (const fn of model.functions) {
      analysisCtx.queue.push({ fn, seed: [], model });
    }
  }

  while (analysisCtx.queue.length && analysisCtx.iterations < MAX_ITERATIONS) {
    analysisCtx.iterations += 1;
    const task = analysisCtx.queue.shift();
    const stateKey = `${task.fn.key}|${[...task.seed].sort().join(',')}`;
    if (analysisCtx.analyzed.has(stateKey)) continue;
    analysisCtx.analyzed.add(stateKey);
    try {
      analyzeFunction(task.fn, task.seed, task.model, analysisCtx);
    } catch (err) {
      log.debug(`taint: analysis error in ${task.fn.key}: ${err.message}`);
    }
  }

  return [...analysisCtx.findings.values()];
}

function isSourceExpr(node, ctx) {
  const p = memberPath(node);
  if (!p) return null;
  for (const s of ctx.sources) {
    if (p === s || p.startsWith(`${s}.`)) return s;
  }
  return null;
}

function isSanitizerCall(node, ctx) {
  if (!node || (node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression')) return false;
  const last = lastSegment(memberPath(node.callee));
  return Boolean(last && ctx.sanitizerLast.has(last));
}

function isTainted(node, tainted, ctx) {
  if (!node || typeof node !== 'object') return false;
  switch (node.type) {
    case 'Identifier':
      return tainted.has(node.name);
    case 'MemberExpression':
    case 'OptionalMemberExpression':
      return Boolean(isSourceExpr(node, ctx)) || isTainted(node.object, tainted, ctx) || (node.computed && isTainted(node.property, tainted, ctx));
    case 'BinaryExpression':
    case 'LogicalExpression':
      return isTainted(node.left, tainted, ctx) || isTainted(node.right, tainted, ctx);
    case 'TemplateLiteral':
      return node.expressions.some((e) => isTainted(e, tainted, ctx));
    case 'ConditionalExpression':
      return isTainted(node.consequent, tainted, ctx) || isTainted(node.alternate, tainted, ctx);
    case 'AwaitExpression':
    case 'YieldExpression':
    case 'SpreadElement':
    case 'TSNonNullExpression':
    case 'TSAsExpression':
      return isTainted(node.argument ?? node.expression, tainted, ctx);
    case 'ParenthesizedExpression':
      return isTainted(node.expression, tainted, ctx);
    case 'SequenceExpression':
      return isTainted(node.expressions[node.expressions.length - 1], tainted, ctx);
    case 'ObjectExpression':
      return node.properties.some((pr) => pr.value && isTainted(pr.value, tainted, ctx));
    case 'ArrayExpression':
      return node.elements.some((el) => el && isTainted(el, tainted, ctx));
    default:
      return false;
  }
}

/** Human-readable description of what made an expression tainted. */
function taintReason(node, tainted, ctx) {
  let reason = null;
  const visit = (n) => {
    if (reason || !n || typeof n !== 'object' || FUNCTION_TYPES.has(n.type)) return;
    const src = isSourceExpr(n, ctx);
    if (src) {
      reason = `user input (${src})`;
      return;
    }
    if (n.type === 'Identifier' && tainted.has(n.name)) {
      reason = `tainted variable "${n.name}"`;
      return;
    }
    for (const key of Object.keys(n)) {
      if (SKIP_KEYS.has(key)) continue;
      const child = n[key];
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object' && child.type) visit(child);
    }
  };
  visit(node);
  return reason || 'untrusted input';
}

function sinkCategory(last) {
  if (['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream', 'unlink', 'unlinkSync'].includes(last)) {
    return CATEGORY.pathTraversal;
  }
  return CATEGORY.injection; // eval/exec/spawn/system/query/execute/...
}

function analyzeFunction(fn, seed, model, ctx) {
  const tainted = new Set(seed);
  const crossFn = seed.length > 0;
  const stmts = bodyStatements(fn);
  for (const stmt of stmts) {
    execStmt(stmt, tainted, { ...ctx, fn, model, crossFn });
  }
}

function execStmt(stmt, tainted, actx) {
  if (!stmt || typeof stmt !== 'object') return;
  switch (stmt.type) {
    case 'FunctionDeclaration':
    case 'ClassDeclaration':
      return; // analyzed independently
    case 'VariableDeclaration':
      for (const d of stmt.declarations) {
        if (d.init) {
          scanExpr(d.init, tainted, actx);
          applyAssign(d.id, d.init, tainted, actx);
        }
      }
      return;
    case 'ExpressionStatement': {
      const e = stmt.expression;
      if (e?.type === 'AssignmentExpression') {
        scanExpr(e.right, tainted, actx);
        if (e.operator === '=') applyAssign(e.left, e.right, tainted, actx);
        else if (e.left.type === 'Identifier' && isTainted(e.right, tainted, actx)) tainted.add(e.left.name);
      } else {
        scanExpr(e, tainted, actx);
      }
      return;
    }
    case 'ReturnStatement':
    case 'ThrowStatement':
      if (stmt.argument) scanExpr(stmt.argument, tainted, actx);
      return;
    case 'IfStatement':
      scanExpr(stmt.test, tainted, actx);
      execStmt(stmt.consequent, tainted, actx);
      if (stmt.alternate) execStmt(stmt.alternate, tainted, actx);
      return;
    case 'BlockStatement':
      for (const s of stmt.body) execStmt(s, tainted, actx);
      return;
    case 'ForStatement':
      if (stmt.init) stmt.init.type === 'VariableDeclaration' ? execStmt(stmt.init, tainted, actx) : scanExpr(stmt.init, tainted, actx);
      if (stmt.test) scanExpr(stmt.test, tainted, actx);
      if (stmt.update) scanExpr(stmt.update, tainted, actx);
      execStmt(stmt.body, tainted, actx);
      return;
    case 'ForInStatement':
    case 'ForOfStatement':
      scanExpr(stmt.right, tainted, actx);
      applyAssign(stmt.left.type === 'VariableDeclaration' ? stmt.left.declarations[0].id : stmt.left, stmt.right, tainted, actx);
      execStmt(stmt.body, tainted, actx);
      return;
    case 'WhileStatement':
    case 'DoWhileStatement':
      scanExpr(stmt.test, tainted, actx);
      execStmt(stmt.body, tainted, actx);
      return;
    case 'TryStatement':
      execStmt(stmt.block, tainted, actx);
      if (stmt.handler) execStmt(stmt.handler.body, tainted, actx);
      if (stmt.finalizer) execStmt(stmt.finalizer, tainted, actx);
      return;
    case 'SwitchStatement':
      scanExpr(stmt.discriminant, tainted, actx);
      for (const c of stmt.cases) for (const s of c.consequent) execStmt(s, tainted, actx);
      return;
    case 'LabeledStatement':
      execStmt(stmt.body, tainted, actx);
      return;
    default:
      // Unknown statement: still scan for sink calls so nothing is missed.
      scanExpr(stmt, tainted, actx);
  }
}

function applyAssign(lhs, rhs, tainted, actx) {
  const rhsTainted = isTainted(rhs, tainted, actx) && !isSanitizerCall(rhs, actx);
  if (!lhs) return;
  if (lhs.type === 'Identifier') {
    if (rhsTainted) tainted.add(lhs.name);
    else tainted.delete(lhs.name);
  } else if (lhs.type === 'ObjectPattern' && rhsTainted) {
    for (const prop of lhs.properties) {
      const n = prop.value?.name || prop.argument?.name;
      if (n) tainted.add(n);
    }
  } else if (lhs.type === 'ArrayPattern' && rhsTainted) {
    for (const el of lhs.elements) {
      if (el?.type === 'Identifier') tainted.add(el.name);
    }
  }
}

/** Recursively scan an expression for sink calls + inter-proc propagation. */
function scanExpr(node, tainted, actx) {
  if (!node || typeof node !== 'object') return;
  if (FUNCTION_TYPES.has(node.type)) return; // nested functions analyzed separately

  if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
    handleCall(node, tainted, actx);
  }

  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const c of child) if (c && typeof c === 'object' && c.type) scanExpr(c, tainted, actx);
    } else if (child && typeof child === 'object' && child.type) {
      scanExpr(child, tainted, actx);
    }
  }
}

function handleCall(call, tainted, actx) {
  const callee = call.callee;
  const cp = memberPath(callee);
  const last = lastSegment(cp);
  const args = call.arguments || [];

  // Sink detection
  const fullMatch = (cp && actx.sinks.has(cp)) || (callee.type === 'Identifier' && actx.sinks.has(callee.name));
  const lastMatch = last && actx.sinkLast.has(last);
  if ((fullMatch || lastMatch) && !isSanitizerCall(call, actx)) {
    const taintedArg = args.find((a) => a && isTainted(a, tainted, actx));
    if (taintedArg) {
      const line = call.loc?.start.line ?? null;
      const dedupKey = `${actx.fn.file}:${line}:${last}`;
      const confidence = fullMatch && !actx.crossFn ? CONFIDENCE.medium : CONFIDENCE.low;
      const reason = taintReason(taintedArg, tainted, actx);
      const category = sinkCategory(last);
      const existing = actx.findings.get(dedupKey);
      const finding = createFinding({
        tool: TOOL.taint,
        ruleId: `patronus.taint.${category}`,
        severity: SEVERITY.high,
        category,
        file: actx.fn.file,
        line,
        message: `Heuristic taint: ${reason} reaches sink ${cp || last}()${actx.crossFn ? ' via a function parameter (cross-function)' : ''} with no sanitization detected.`,
        confidence,
        aiCodegenRelevant: true,
        remediation:
          'Validate/sanitize the input before this call (parameterized queries for SQL, argument arrays without a shell for commands, path normalization + allowlist for file access), or avoid the dangerous API.',
        references: ['https://owasp.org/Top10/A03_2021-Injection/'],
      });
      // Keep the higher-confidence finding on duplicate.
      if (!existing || (existing.confidence === 'low' && confidence === 'medium')) {
        actx.findings.set(dedupKey, finding);
      }
    }
  }

  // Inter-procedural propagation to a resolvable local function.
  if (callee.type === 'Identifier') {
    const taintedParams = [];
    args.forEach((a, i) => {
      if (a && isTainted(a, tainted, actx)) taintedParams.push(i);
    });
    if (taintedParams.length) {
      const target = resolveCallee(callee.name, actx.model, actx);
      if (target && target.fn !== actx.fn) {
        const seed = [];
        for (const i of taintedParams) {
          const pn = target.fn.params[i];
          if (pn) seed.push(pn);
        }
        if (seed.length) {
          actx.queue.push({ fn: target.fn, seed, model: target.model });
        }
      }
    }
  }
}

/** Resolve a called identifier to a function definition (same file or import). */
function resolveCallee(name, model, ctx) {
  if (model.functionsByName.has(name)) {
    return { fn: model.functionsByName.get(name), model };
  }
  const imp = model.imports.get(name);
  if (imp) {
    const targetRel = resolveRelative(imp.source, model.rel, ctx.fileSet);
    if (targetRel && ctx.models.has(targetRel)) {
      const targetModel = ctx.models.get(targetRel);
      const local = targetModel.exports.get(imp.importedName) || imp.importedName;
      if (targetModel.functionsByName.has(local)) {
        return { fn: targetModel.functionsByName.get(local), model: targetModel };
      }
    }
  }
  return null;
}
