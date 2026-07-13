/**
 * Best-effort Python taint heuristic.
 *
 * A full Python taint engine would require parsing via the `ast` module; that
 * is out of scope for v1. This provides a pragmatic, line-oriented
 * intra-file analysis that catches the common cases:
 *   - a source read assigned to a variable, later passed to a sink, and
 *   - a source read passed directly into a sink on one statement.
 *
 * Low confidence by design; clearly labeled heuristic. Read-only, never throws.
 */

import fs from 'node:fs';
import path from 'node:path';
import { walk } from '../core/fswalk.js';
import { createFinding } from '../core/finding.js';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';

const SOURCE_RE = /\b(?:request\.(?:form|args|values|json|data|GET|POST|files|cookies|headers)|req\.(?:body|query|params))\b/;
const SANITIZER_RE = /\b(?:shlex\.quote|bleach\.clean|escape|markupsafe|secure_filename|int\(|float\()/;

const SINK_PATTERNS = [
  { re: /\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\(/, category: CATEGORY.injection, name: 'command execution' },
  { re: /(?:^|[^.\w])(?:eval|exec)\s*\(/, category: CATEGORY.injection, name: 'eval/exec' },
  { re: /\.(?:execute|executemany|executescript)\s*\(/, category: CATEGORY.injection, name: 'SQL execution' },
  { re: /(?:^|[^.\w])open\s*\(/, category: CATEGORY.pathTraversal, name: 'file access' },
];

const ASSIGN_RE = /^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$/;

function argRegionAfter(line, matchIndex) {
  const paren = line.indexOf('(', matchIndex);
  return paren >= 0 ? line.slice(paren) : line.slice(matchIndex);
}

function referencesTaintedVar(text, taintedVars) {
  for (const v of taintedVars) {
    if (new RegExp(`\\b${v}\\b`).test(text)) return v;
  }
  return null;
}

function analyzeFile(rel, code) {
  const lines = code.split(/\r?\n/);
  const tainted = new Set();
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*#/.test(line)) continue;

    // Track tainted variables from assignments.
    const assign = line.match(ASSIGN_RE);
    if (assign && !/[=!<>]=/.test(assign[0].replace(/^\s*[A-Za-z_]\w*\s*=/, ''))) {
      const [, varName, rhs] = assign;
      if (SANITIZER_RE.test(rhs)) {
        tainted.delete(varName);
      } else if (SOURCE_RE.test(rhs) || referencesTaintedVar(rhs, tainted)) {
        tainted.add(varName);
      }
    }

    // Sink detection on this line.
    for (const sink of SINK_PATTERNS) {
      const m = line.match(sink.re);
      if (!m) continue;
      const region = argRegionAfter(line, m.index);
      if (SANITIZER_RE.test(region)) continue;
      const sourceHit = SOURCE_RE.test(region);
      const varHit = referencesTaintedVar(region, tainted);
      if (!sourceHit && !varHit) continue;

      const reason = sourceHit ? 'user input' : `tainted variable "${varHit}"`;
      findings.push(
        createFinding({
          tool: TOOL.taint,
          ruleId: `clipeus.taint.${sink.category}`,
          severity: SEVERITY.high,
          category: sink.category,
          file: rel,
          line: i + 1,
          message: `Heuristic taint: ${reason} reaches ${sink.name} with no sanitization detected.`,
          confidence: CONFIDENCE.low,
          aiCodegenRelevant: true,
          remediation:
            'Sanitize/validate input before this call: use parameterized queries, subprocess arg lists (no shell), shlex.quote for shell args, and path allowlists for file access.',
          references: ['https://owasp.org/Top10/A03_2021-Injection/'],
        }),
      );
    }
  }

  return findings;
}

/**
 * @param {string} root
 * @returns {object[]} findings
 */
export function analyzePyTaint(root) {
  const files = walk(root, { extensions: ['.py'], maxFiles: 5000 });
  const findings = [];
  for (const abs of files) {
    let code;
    try {
      code = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const rel = path.relative(root, abs).replace(/\\/g, '/');
    try {
      findings.push(...analyzeFile(rel, code));
    } catch {
      /* skip file on error */
    }
  }
  return findings;
}
