/**
 * pip-audit adapter (Apache-2.0).
 *
 * Audits Python dependencies against the OSV / PyPI advisory databases. Scans
 * the requirements file(s) present at the project root. If none are found we
 * skip (rather than auditing an unrelated ambient environment).
 */

import path from 'node:path';
import { TOOL, SEVERITY, CONFIDENCE, CATEGORY } from '../constants.js';
import { createFinding } from '../core/finding.js';
import { normalizeSeverity } from './base.js';
import { walk } from '../core/fswalk.js';
import { commandExists } from '../core/runner.js';
import { resolveToolInEnvironments, venvPathEnv } from '../detectors/environments.js';

/**
 * Find requirements*.txt files anywhere in the main project layout, returned as
 * POSIX paths relative to `root` (so pip-audit can be invoked from the root even
 * when the files live in a subfolder like backend/). The shared walker already
 * skips venv/site-packages/node_modules dirs.
 */
function findRequirements(root) {
  try {
    const abs = walk(root, {
      maxDepth: 4,
      maxFiles: 2000,
      nameFilter: (n) => /^requirements.*\.txt$/i.test(n),
    });
    return abs.map((p) => path.relative(root, p).replace(/\\/g, '/'));
  } catch {
    return [];
  }
}

function referencesFor(vuln) {
  const ids = [vuln.id, ...(Array.isArray(vuln.aliases) ? vuln.aliases : [])].filter(Boolean);
  const refs = [];
  for (const id of ids) {
    if (/^CVE-/i.test(id)) refs.push(`https://nvd.nist.gov/vuln/detail/${id}`);
    else if (/^(PYSEC|GHSA|OSV)-/i.test(id)) refs.push(`https://osv.dev/vulnerability/${id}`);
  }
  return refs;
}

const adapter = {
  id: TOOL.pipAudit,
  displayName: 'pip-audit',
  command: 'pip-audit',
  versionArgs: ['--version'],
  license: 'Apache-2.0',
  homepage: 'https://github.com/pypa/pip-audit',
  install: {
    pip: 'pip install pip-audit',
    recommended: 'pip install pip-audit',
    url: 'https://github.com/pypa/pip-audit#installation',
  },

  async locate(ctx) {
    // Prefer pip-audit from the project's virtualenv; fall back to a global one.
    const viaVenv = resolveToolInEnvironments(ctx.detection?.pythonEnvs || [], 'pip-audit');
    if (viaVenv) return { command: viaVenv.command, env: venvPathEnv(viaVenv.env) };
    if (await commandExists('pip-audit')) return { command: 'pip-audit' };
    return null;
  },

  precheck(ctx) {
    const reqs = findRequirements(ctx.root);
    if (reqs.length === 0) {
      return {
        skip: true,
        reason: 'no requirements*.txt found in the project',
      };
    }
    return { skip: false };
  },

  buildInvocation(ctx) {
    const reqs = findRequirements(ctx.root);
    const args = ['-f', 'json', '--progress-spinner', 'off'];
    for (const r of reqs) {
      args.push('-r', r);
    }
    return {
      command: ctx.resolvedCommand || 'pip-audit',
      args,
      cwd: ctx.root,
      output: { type: 'stdout' },
    };
  },

  normalize(parsed, ctx) {
    const deps = Array.isArray(parsed) ? parsed : parsed?.dependencies;
    if (!Array.isArray(deps)) return [];
    const source = findRequirements(ctx?.root || '.')[0] || 'requirements.txt';

    const findings = [];
    for (const dep of deps) {
      const vulns = Array.isArray(dep.vulns) ? dep.vulns : [];
      for (const vuln of vulns) {
        const fixes = Array.isArray(vuln.fix_versions) ? vuln.fix_versions : [];
        const aliases = Array.isArray(vuln.aliases) && vuln.aliases.length
          ? ` (${vuln.aliases.join(', ')})`
          : '';
        findings.push(
          createFinding({
            tool: TOOL.pipAudit,
            ruleId: vuln.id || `pip-audit.${dep.name}`,
            // pip-audit does not emit CVSS severity by default; a confirmed
            // advisory match is treated as high with high confidence.
            severity: normalizeSeverity(vuln.severity, SEVERITY.high),
            category: CATEGORY.dependencyCve,
            file: source,
            line: null,
            message: `${vuln.id || 'Known vulnerability'}${aliases}: "${dep.name}" ${dep.version || ''} is affected.`,
            confidence: CONFIDENCE.high,
            aiCodegenRelevant: false,
            references: referencesFor(vuln),
            remediation: fixes.length
              ? `Upgrade "${dep.name}" to ${fixes.join(' or ')}.`
              : 'No fixed version listed; review the advisory for mitigation.',
          }),
        );
      }
    }
    return findings;
  },
};

export default adapter;
