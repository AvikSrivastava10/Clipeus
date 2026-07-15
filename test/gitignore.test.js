import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ensureGitignore,
  CLIPEUS_GITIGNORE_ENTRIES,
  resolvePostinstallTarget,
} from '../src/config/gitignore.js';

const tmpDirs = [];
function tmp() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-gi-'));
  tmpDirs.push(d);
  return d;
}
const readGi = (root) => fs.readFileSync(path.join(root, '.gitignore'), 'utf8');

afterEach(() => {
  while (tmpDirs.length) {
    try {
      fs.rmSync(tmpDirs.pop(), { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

describe('ensureGitignore', () => {
  it('does NOT create a .gitignore when none exists', () => {
    const root = tmp();
    const res = ensureGitignore(root);
    expect(res.changed).toBe(false);
    expect(res.present).toBe(false);
    expect(fs.existsSync(path.join(root, '.gitignore'))).toBe(false);
  });

  it('appends all Clipeus entries to an existing .gitignore', () => {
    const root = tmp();
    fs.writeFileSync(path.join(root, '.gitignore'), 'node_modules/\n');

    const res = ensureGitignore(root);
    expect(res.changed).toBe(true);
    expect(res.present).toBe(true);
    expect(res.added).toEqual([...CLIPEUS_GITIGNORE_ENTRIES]);

    const gi = readGi(root);
    expect(gi).toContain('node_modules/');
    for (const entry of CLIPEUS_GITIGNORE_ENTRIES) expect(gi).toContain(entry);
    expect(gi).toContain('# >>> clipeus >>>');
    expect(gi).toContain('# <<< clipeus <<<');
  });

  it('is idempotent — a second run changes nothing', () => {
    const root = tmp();
    fs.writeFileSync(path.join(root, '.gitignore'), 'dist/\n');
    ensureGitignore(root);
    const before = readGi(root);

    const res = ensureGitignore(root);
    expect(res.changed).toBe(false);
    expect(res.added).toEqual([]);
    expect(readGi(root)).toBe(before);
  });

  it('does not duplicate an entry already present in the file', () => {
    const root = tmp();
    fs.writeFileSync(path.join(root, '.gitignore'), 'node_modules/\nclipeus.sarif\n');

    const res = ensureGitignore(root);
    expect(res.added).toContain('clipeus-report.*');
    expect(res.added).not.toContain('clipeus.sarif');

    const gi = readGi(root);
    expect(gi.match(/^clipeus\.sarif$/gm)).toHaveLength(1);
  });

  it('does not add a second managed block on repeated runs', () => {
    const root = tmp();
    fs.writeFileSync(path.join(root, '.gitignore'), '');
    ensureGitignore(root);
    ensureGitignore(root);
    const gi = readGi(root);
    expect(gi.match(/# >>> clipeus >>>/g)).toHaveLength(1);
  });

  it('accepts a custom entry list', () => {
    const root = tmp();
    fs.writeFileSync(path.join(root, '.gitignore'), '');
    const res = ensureGitignore(root, ['coverage/', '*.tmp']);
    expect(res.added).toEqual(['coverage/', '*.tmp']);
    expect(readGi(root)).toContain('coverage/');
  });

  it('never throws and reports an error when .gitignore cannot be written', () => {
    const root = tmp();
    // Make the .gitignore path unwritable by turning it into a directory.
    fs.mkdirSync(path.join(root, '.gitignore'));
    const res = ensureGitignore(root);
    // Can't read it as a file → treated as "not present".
    expect(res.changed).toBe(false);
  });
});

describe('resolvePostinstallTarget', () => {
  it('returns null for a global install', () => {
    expect(resolvePostinstallTarget({ scriptDir: '/usr/lib/node_modules/clipeus/src', global: true })).toBeNull();
  });

  it('returns null when not installed under node_modules (Clipeus own dev tree)', () => {
    expect(resolvePostinstallTarget({ scriptDir: '/home/user/clipeus/src' })).toBeNull();
  });

  it('prefers INIT_CWD when installed as a dependency', () => {
    const res = resolvePostinstallTarget({
      scriptDir: '/project/node_modules/clipeus/src',
      initCwd: '/project',
    });
    expect(res).toBe('/project');
  });

  it('falls back to the dir above node_modules when no INIT_CWD', () => {
    const res = resolvePostinstallTarget({
      scriptDir: '/project/node_modules/clipeus/src',
    });
    expect(res).toBe('/project');
  });

  it('handles Windows paths', () => {
    const res = resolvePostinstallTarget({
      scriptDir: 'D:\\work\\myapp\\node_modules\\clipeus\\src',
      initCwd: 'D:\\work\\myapp',
    });
    expect(res).toBe('D:\\work\\myapp');
  });

  it('returns null when scriptDir is undefined', () => {
    expect(resolvePostinstallTarget({})).toBeNull();
  });
});
