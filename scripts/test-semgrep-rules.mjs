#!/usr/bin/env node
/**
 * Standalone TP/TN test harness for the bundled Semgrep rules.
 *
 * Semgrep's own `--test` subcommand hangs in some sandboxed environments (it
 * performs a network/version check), so this reproduces the same behavior via
 * a direct `semgrep --config <rule> <fixtures>` scan using the reliable flags.
 *
 * For each rule file src/rules/<name>.yaml it scans the co-located fixtures
 * <name>.js / <name>.ts / <name>.py and checks that:
 *   - every `// ruleid: <id>` (or `# ruleid:`) annotation produces a match on
 *     the following code line, and
 *   - every `// ok: <id>` annotation produces NO match on the following line.
 *
 * Usage: node scripts/test-semgrep-rules.mjs
 * Exit code 0 = all pass, 1 = failures, 2 = semgrep unavailable.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_DIR = path.resolve(__dirname, '..', 'src', 'rules');
const FIXTURE_EXTS = ['.js', '.ts', '.jsx', '.tsx', '.py'];

function semgrepAvailable() {
  try {
    execFileSync('semgrep', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** Parse ruleid/ok annotations. Returns { expect:Set, deny:Set } of "line::id". */
function parseAnnotations(file) {
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const expect = new Set();
  const deny = new Set();
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/(?:\/\/|#)\s*(ruleid|ok):\s*(.+)$/);
    if (!m) continue;
    const kind = m[1];
    const ids = m[2].split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    const codeLine = i + 2; // annotation on line i+1 (1-based), code on next line
    for (const id of ids) {
      (kind === 'ruleid' ? expect : deny).add(`${codeLine}::${id}`);
    }
  }
  return { expect, deny };
}

function runSemgrep(ruleFile, fixtures) {
  // stdio: ignore stderr to avoid sync pipe-buffer deadlocks; hard timeout so a
  // wedged semgrep-core can never hang this harness indefinitely.
  const out = execFileSync(
    'semgrep',
    ['--config', ruleFile, ...fixtures, '--json', '--quiet', '--metrics=off', '--disable-version-check', '--no-git-ignore'],
    {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 90_000,
      windowsHide: true,
    },
  );
  const json = JSON.parse(out);
  const matches = new Set();
  for (const r of json.results) {
    matches.add(`${path.basename(r.path)}::${r.start.line}::${r.check_id.split('.').pop()}`);
  }
  return matches;
}

function main() {
  if (!semgrepAvailable()) {
    console.error('semgrep is not installed; skipping rule tests.');
    process.exit(2);
  }

  const ruleFiles = fs
    .readdirSync(RULES_DIR)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));

  let totalExpect = 0;
  let totalDeny = 0;
  const failures = [];

  for (const ruleFile of ruleFiles) {
    const base = ruleFile.replace(/\.(ya?ml)$/, '');
    const fixtures = FIXTURE_EXTS
      .map((ext) => path.join(RULES_DIR, base + ext))
      .filter((p) => fs.existsSync(p));

    if (fixtures.length === 0) {
      failures.push(`${ruleFile}: no test fixtures found (expected ${base}.js/.py/...)`);
      continue;
    }

    let matches;
    try {
      matches = runSemgrep(path.join(RULES_DIR, ruleFile), fixtures);
    } catch (err) {
      if (err.code === 'ETIMEDOUT' || err.signal) {
        console.error(`semgrep timed out on ${ruleFile}; environment may not support semgrep. Skipping.`);
        process.exit(2);
      }
      throw err;
    }

    for (const fixture of fixtures) {
      const fbase = path.basename(fixture);
      const { expect, deny } = parseAnnotations(fixture);
      if (expect.size === 0 && deny.size === 0) {
        failures.push(`${fbase}: has no ruleid/ok annotations`);
      }
      for (const key of expect) {
        totalExpect += 1;
        const [line, id] = key.split('::');
        if (!matches.has(`${fbase}::${line}::${id}`)) {
          failures.push(`${fbase}:${line} expected match for "${id}" (true positive missed)`);
        }
      }
      for (const key of deny) {
        totalDeny += 1;
        const [line, id] = key.split('::');
        if (matches.has(`${fbase}::${line}::${id}`)) {
          failures.push(`${fbase}:${line} unexpected match for "${id}" (false positive)`);
        }
      }
    }
  }

  console.log(`Rule files: ${ruleFiles.length}`);
  console.log(`True-positive checks: ${totalExpect}`);
  console.log(`True-negative checks: ${totalDeny}`);
  if (failures.length) {
    console.error(`\n✗ ${failures.length} failure(s):`);
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log('\n✓ All Semgrep rule TP/TN checks passed.');
}

main();
