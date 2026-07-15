/**
 * Environment discovery.
 *
 * Locates Python virtualenvs within a project so Clipeus can install, detect,
 * and run Python tools (pip-audit, bandit, ...) in the same interpreter the
 * project actually uses — instead of a global one that may not exist or may be
 * shadowed once the project's venv is activated.
 *
 * The main filesystem walker deliberately skips `.venv`/`venv`/`env` dirs, so
 * environments are discovered here by probing known locations directly.
 *
 * Read-only; never throws.
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const IS_WIN = process.platform === 'win32';
/** Where executables live inside a virtualenv, per OS. */
export const VENV_BIN_DIR = IS_WIN ? 'Scripts' : 'bin';
const EXE = IS_WIN ? '.exe' : '';

/** Candidate virtualenv directory names, in priority order. */
const VENV_DIRNAMES = ['.venv', 'venv', 'env', '.env'];

/** Subdirectories that are never worth probing for sibling venvs. */
const SKIP_SUBDIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'coverage',
  '__pycache__', '.next', '.nuxt', 'vendor', 'target', '.gradle', '.idea',
  '.vscode', '.clipeus-cache', '.terraform', '.cache', 'site-packages',
  ...VENV_DIRNAMES,
]);

function safeReal(dir) {
  try {
    return fs.realpathSync(dir);
  } catch {
    return null;
  }
}

/**
 * Absolute path to a tool binary inside a virtualenv's bin dir, or null when
 * absent. Tries the plain name and, on Windows, the .exe form.
 * @param {string} venvDir
 * @param {string} tool  e.g. 'python', 'pip', 'pip-audit', 'bandit'
 * @returns {string|null}
 */
export function venvToolPath(venvDir, tool) {
  if (!venvDir) return null;
  const candidates = EXE ? [`${tool}${EXE}`, tool] : [tool];
  for (const name of candidates) {
    const p = path.join(venvDir, VENV_BIN_DIR, name);
    try {
      if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

/** True when `dir` looks like a Python virtualenv (has a python executable). */
export function looksLikeVenv(dir) {
  return Boolean(venvToolPath(dir, 'python') || venvToolPath(dir, 'python3'));
}

/** Immediate subdirectories of `dir` (absolute), skipping junk. Never throws. */
function immediateSubdirs(dir) {
  try {
    return fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !SKIP_SUBDIRS.has(e.name))
      .map((e) => path.join(dir, e.name));
  } catch {
    return [];
  }
}

/**
 * @typedef {Object} PythonEnv
 * @property {string} dir      Absolute venv directory.
 * @property {string} python   Absolute path to the venv's python.
 * @property {string|null} pip Absolute path to the venv's pip, if present.
 * @property {string} binDir   Absolute Scripts/bin directory.
 * @property {string} source   How it was found ('VIRTUAL_ENV' or a relative path).
 */

/**
 * Find Python virtualenvs for a project. Probes, in priority order:
 *   1. an already-activated environment ($VIRTUAL_ENV),
 *   2. the root, then each main subfolder, for `.venv`/`venv`/`env` dirs.
 *
 * @param {string} root
 * @param {object} [opts]
 * @param {string[]} [opts.searchDirs]  Extra absolute dirs to probe.
 * @returns {PythonEnv[]}
 */
export function findPythonEnvironments(root, opts = {}) {
  const abs = path.resolve(root);
  const found = [];
  const seen = new Set();

  const add = (dir, source) => {
    const real = safeReal(dir);
    if (!real || seen.has(real)) return;
    const python = venvToolPath(real, 'python') || venvToolPath(real, 'python3');
    if (!python) return;
    seen.add(real);
    found.push({
      dir: real,
      python,
      pip: venvToolPath(real, 'pip') || venvToolPath(real, 'pip3'),
      binDir: path.join(real, VENV_BIN_DIR),
      source,
    });
  };

  // 1. Activated environment wins.
  if (process.env.VIRTUAL_ENV && looksLikeVenv(process.env.VIRTUAL_ENV)) {
    add(process.env.VIRTUAL_ENV, 'VIRTUAL_ENV');
  }

  // 2. Probe root + each main subfolder (+ any explicit search dirs).
  const bases = [abs, ...immediateSubdirs(abs), ...(opts.searchDirs || [])];
  for (const base of bases) {
    for (const name of VENV_DIRNAMES) {
      const candidate = path.join(base, name);
      if (looksLikeVenv(candidate)) {
        const relSource = path.relative(abs, candidate).replace(/\\/g, '/') || name;
        add(candidate, relSource);
      }
    }
  }

  return found;
}

/**
 * Resolve a tool executable, preferring the project's virtualenv(s) over a
 * global install.
 *
 * @param {PythonEnv[]} envs
 * @param {string} tool
 * @returns {{ command: string, env: PythonEnv, viaVenv: true }|null}
 *   The absolute venv command when found in some env, else null (caller should
 *   fall back to a global lookup).
 */
export function resolveToolInEnvironments(envs, tool) {
  for (const env of envs || []) {
    const p = venvToolPath(env.dir, tool);
    if (p) return { command: p, env, viaVenv: true };
  }
  return null;
}

/**
 * Build a PATH-prepended env object so a venv's binaries take precedence for
 * the tool and any subprocesses it spawns. Returns undefined when no env.
 * @param {PythonEnv} [env]
 * @returns {Record<string,string>|undefined}
 */
export function venvPathEnv(env) {
  if (!env?.binDir) return undefined;
  const current = process.env.PATH || process.env.Path || '';
  return { PATH: `${env.binDir}${path.delimiter}${current}` };
}
