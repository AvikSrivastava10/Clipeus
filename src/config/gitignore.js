/**
 * .gitignore management.
 *
 * Keeps Clipeus's own generated artifacts (scan reports, cache) out of the
 * user's version control. It only ever APPENDS to a .gitignore that already
 * exists — it never creates one — so Clipeus never imposes git conventions on a
 * project that doesn't already use them. Idempotent, additive, never throws.
 */

import fs from 'node:fs';
import path from 'node:path';

const BEGIN = '# >>> clipeus >>>';
const END = '# <<< clipeus <<<';

/** Generated artifacts Clipeus may drop in a project that should not be committed. */
export const CLIPEUS_GITIGNORE_ENTRIES = Object.freeze([
  'clipeus-report.*',
  'clipeus.sarif',
  '.clipeus-cache/',
]);

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Append Clipeus's generated-artifact entries to an EXISTING .gitignore. If the
 * project has no .gitignore, this is a no-op — we never create one. Only entries
 * not already present are added, inside a marked block. Never throws.
 *
 * @param {string} root  Project root.
 * @param {string[]} [entries]
 * @returns {{changed:boolean, present:boolean, added:string[], path:string, error?:string}}
 */
export function ensureGitignore(root, entries = CLIPEUS_GITIGNORE_ENTRIES) {
  const file = path.join(root, '.gitignore');

  let existing;
  try {
    existing = fs.readFileSync(file, 'utf8');
  } catch {
    // No readable .gitignore present — do not create one.
    return { changed: false, present: false, added: [], path: file };
  }

  const isPresent = (entry) => new RegExp(`^\\s*${escapeRe(entry)}\\s*$`, 'm').test(existing);
  const added = entries.filter((e) => !isPresent(e));
  if (added.length === 0) {
    return { changed: false, present: true, added: [], path: file };
  }

  const block = [BEGIN, '# Clipeus security-scan generated files', ...added, END].join('\n');
  const needsNewline = existing && !existing.endsWith('\n');
  const body = `${existing}${needsNewline ? '\n' : ''}\n${block}\n`;

  try {
    fs.writeFileSync(file, body, 'utf8');
    return { changed: true, present: true, added, path: file };
  } catch (err) {
    return { changed: false, present: true, added: [], path: file, error: err.message };
  }
}

/**
 * Decide which host project root a postinstall run should update, or null when
 * it should do nothing. Returns null for global installs and for Clipeus's own
 * dev tree (a checkout that isn't nested under node_modules); otherwise prefers
 * npm's INIT_CWD, falling back to the directory that contains node_modules.
 *
 * @param {object} [opts]
 * @param {string} [opts.initCwd]    npm's INIT_CWD (where `npm install` ran).
 * @param {string} [opts.scriptDir]  Directory of the running postinstall script.
 * @param {boolean} [opts.global]    True for a global install.
 * @returns {string|null}
 */
export function resolvePostinstallTarget({ initCwd, scriptDir, global } = {}) {
  if (global) return null;
  if (!scriptDir) return null;
  const m = scriptDir.match(/^(.*?)[\\/]node_modules[\\/]/);
  if (!m) return null; // not installed as a dependency (dev/self install)
  return initCwd || m[1];
}
