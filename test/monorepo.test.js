import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

import {
  venvToolPath,
  looksLikeVenv,
  findPythonEnvironments,
  resolveToolInEnvironments,
  venvPathEnv,
  VENV_BIN_DIR,
} from '../src/detectors/environments.js';
import { detectProject } from '../src/detectors/detect.js';
import npmAudit from '../src/adapters/npm-audit.js';
import pipAudit from '../src/adapters/pip-audit.js';
import bandit from '../src/adapters/bandit.js';

const EXE = process.platform === 'win32' ? '.exe' : '';

/** Create a fake virtualenv containing the given tool executables. */
function makeVenv(dir, tools) {
  const bin = path.join(dir, VENV_BIN_DIR);
  fs.mkdirSync(bin, { recursive: true });
  for (const t of tools) fs.writeFileSync(path.join(bin, `${t}${EXE}`), '');
}

let root;
let savedVirtualEnv;

beforeAll(() => {
  // Isolate discovery from any venv activated in the test runner's own shell.
  savedVirtualEnv = process.env.VIRTUAL_ENV;
  delete process.env.VIRTUAL_ENV;

  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-monorepo-')));

  // Root-level venv (python + pip only — no tools installed).
  makeVenv(path.join(root, '.venv'), ['python', 'pip']);

  // Python module in backend/ whose own venv HAS the tools installed.
  fs.mkdirSync(path.join(root, 'backend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'backend', 'requirements.txt'), 'flask==0.5\n');
  makeVenv(path.join(root, 'backend', '.venv'), ['python', 'pip', 'pip-audit', 'bandit']);

  // Node module in frontend/ with a lockfile (there is no root-level package.json).
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'package.json'), '{"name":"fe"}\n');
  fs.writeFileSync(path.join(root, 'frontend', 'package-lock.json'), '{"lockfileVersion":3}\n');
});

afterAll(() => {
  if (savedVirtualEnv !== undefined) process.env.VIRTUAL_ENV = savedVirtualEnv;
  try {
    fs.rmSync(root, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('environments discovery', () => {
  it('venvToolPath resolves present tools and returns null for missing ones', () => {
    const backendVenv = path.join(root, 'backend', '.venv');
    expect(venvToolPath(backendVenv, 'pip-audit')).toBe(
      path.join(backendVenv, VENV_BIN_DIR, `pip-audit${EXE}`),
    );
    expect(venvToolPath(path.join(root, '.venv'), 'pip-audit')).toBeNull();
  });

  it('looksLikeVenv is true only for dirs with a python executable', () => {
    expect(looksLikeVenv(path.join(root, '.venv'))).toBe(true);
    expect(looksLikeVenv(path.join(root, 'frontend'))).toBe(false);
  });

  it('finds venvs in the root and in main subfolders', () => {
    const sources = findPythonEnvironments(root).map((e) => e.source).sort();
    expect(sources).toEqual(['.venv', 'backend/.venv']);
  });

  it('resolveToolInEnvironments prefers a venv that actually has the tool', () => {
    const envs = findPythonEnvironments(root);
    const res = resolveToolInEnvironments(envs, 'pip-audit');
    expect(res?.command).toBe(
      path.join(root, 'backend', '.venv', VENV_BIN_DIR, `pip-audit${EXE}`),
    );
    expect(resolveToolInEnvironments(envs, 'no-such-tool')).toBeNull();
  });

  it('venvPathEnv prepends the venv bin dir to PATH', () => {
    const [env] = findPythonEnvironments(root);
    expect(venvPathEnv(env).PATH.startsWith(env.binDir + path.delimiter)).toBe(true);
    expect(venvPathEnv(undefined)).toBeUndefined();
  });
});

describe('detectProject (monorepo layout)', () => {
  it('locates the node module/lockfile and python envs in subfolders', () => {
    const d = detectProject(root);
    expect(d.stacks.node).toBe(true);
    expect(d.stacks.python).toBe(true);
    expect(d.meta.npmLockfiles).toContain('frontend/package-lock.json');
    expect(path.resolve(d.meta.npmLockfileDir)).toBe(path.resolve(root, 'frontend'));
    expect(d.nodeModuleDirs.map((x) => path.basename(x))).toContain('frontend');
    expect(d.pythonEnvs.map((e) => e.source).sort()).toEqual(['.venv', 'backend/.venv']);
  });
});

describe('npm-audit (subfolder-aware)', () => {
  it('runs in the folder where the lockfile lives and does not skip', () => {
    const ctx = { root, detection: detectProject(root) };
    expect(npmAudit.precheck(ctx).skip).toBe(false);
    expect(npmAudit.buildInvocation(ctx).cwd).toBe(path.resolve(root, 'frontend'));
  });

  it('labels findings with a module-relative manifest path', () => {
    const detection = detectProject(root);
    const parsed = { vulnerabilities: { lodash: { name: 'lodash', severity: 'high', via: ['x'], range: '<1' } } };
    const [f] = npmAudit.normalize(parsed, { root, detection });
    expect(f.file).toBe('frontend/package.json');
  });

  it('falls back to a bare package.json when no ctx is given', () => {
    const parsed = { vulnerabilities: { lodash: { name: 'lodash', severity: 'high', via: ['x'], range: '<1' } } };
    const [f] = npmAudit.normalize(parsed);
    expect(f.file).toBe('package.json');
  });
});

describe('pip-audit (subfolder + venv aware)', () => {
  it('finds requirements in subfolders and audits them from the root', () => {
    const inv = pipAudit.buildInvocation({ root, detection: detectProject(root), resolvedCommand: 'PIPAUDIT' });
    expect(inv.command).toBe('PIPAUDIT');
    expect(inv.cwd).toBe(root);
    expect(inv.args).toContain('-r');
    expect(inv.args).toContain('backend/requirements.txt');
  });

  it('locate resolves pip-audit from the project virtualenv', async () => {
    const located = await pipAudit.locate({ detection: detectProject(root) });
    expect(located?.command).toBe(
      path.join(root, 'backend', '.venv', VENV_BIN_DIR, `pip-audit${EXE}`),
    );
    expect(located.env.PATH).toContain(path.join(root, 'backend', '.venv', VENV_BIN_DIR));
  });

  it('precheck skips when there are no requirements files', () => {
    const empty = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'clipeus-empty-')));
    try {
      expect(pipAudit.precheck({ root: empty }).skip).toBe(true);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });
});

describe('bandit (venv aware)', () => {
  it('locate resolves bandit from the project virtualenv', async () => {
    const located = await bandit.locate({ detection: detectProject(root) });
    expect(located?.command).toBe(
      path.join(root, 'backend', '.venv', VENV_BIN_DIR, `bandit${EXE}`),
    );
  });
});
