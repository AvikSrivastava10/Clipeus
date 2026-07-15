/**
 * npm postinstall hook.
 *
 * When Clipeus is installed as a dependency in a project that already has a
 * .gitignore, add Clipeus's generated-artifact entries to it so scans never
 * leave committable clutter behind. It never creates a .gitignore, never fails
 * the install, and does nothing for global installs or Clipeus's own dev tree.
 *
 * Opt out with CLIPEUS_NO_POSTINSTALL=1.
 */

import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { ensureGitignore, resolvePostinstallTarget } from './config/gitignore.js';

try {
  if (!process.env.CLIPEUS_NO_POSTINSTALL) {
    const scriptDir = path.dirname(fileURLToPath(import.meta.url));
    const target = resolvePostinstallTarget({
      initCwd: process.env.INIT_CWD,
      scriptDir,
      global: process.env.npm_config_global === 'true',
    });
    if (target) {
      const res = ensureGitignore(target);
      if (res.changed) {
        // stderr only, so it never interferes with anything parsing stdout.
        process.stderr.write(`clipeus: added generated-file entries to ${res.path}\n`);
      }
    }
  }
} catch {
  /* A postinstall hook must never break `npm install`. */
}

// Always succeed, whatever happened above.
process.exit(0);
