/**
 * Binary download system.
 *
 * Downloads prebuilt tool binaries from GitHub Releases and extracts them into
 * ~/.clipeus/bin/ so `clipeus init` can install gitleaks, trufflehog, and trivy
 * without requiring Go, Homebrew, Chocolatey, or any other dependency. The user
 * just needs an internet connection.
 *
 * Design:
 *   - Each downloadable tool has a descriptor (repo, asset template, binary name).
 *   - Platform/arch detection maps to the correct release asset.
 *   - Downloads to a temp file, extracts the binary, places it in CLIPEUS_BIN_DIR.
 *   - Never throws — returns { ok, error, path }.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pipeline } from 'node:stream/promises';
import { createWriteStream } from 'node:fs';
import { execSync } from 'node:child_process';

const IS_WIN = process.platform === 'win32';
const EXE = IS_WIN ? '.exe' : '';

/** Where Clipeus stores auto-downloaded binaries. */
export const CLIPEUS_BIN_DIR = path.join(os.homedir(), '.clipeus', 'bin');

/**
 * Map process.platform + process.arch to the conventions each tool uses in
 * its release asset filenames.
 */
function platformInfo() {
  const p = process.platform;
  const a = process.arch;

  // OS names per tool's convention
  const osGitleaks = p === 'win32' ? 'windows' : p === 'darwin' ? 'darwin' : 'linux';
  const osTrufflehog = osGitleaks; // same
  const osTrivy = p === 'win32' ? 'windows' : p === 'darwin' ? 'macOS' : 'Linux';

  // Arch names per tool
  const archGitleaks = a === 'arm64' ? 'arm64' : 'x64';
  const archTrufflehog = a === 'arm64' ? 'arm64' : 'amd64';
  const archTrivy = a === 'arm64' ? 'ARM64' : '64bit';

  // Extension
  const extGitleaks = p === 'win32' ? 'zip' : 'tar.gz';
  const extTrufflehog = 'tar.gz'; // always tar.gz
  const extTrivy = p === 'win32' ? 'zip' : 'tar.gz';

  return {
    gitleaks: { os: osGitleaks, arch: archGitleaks, ext: extGitleaks },
    trufflehog: { os: osTrufflehog, arch: archTrufflehog, ext: extTrufflehog },
    trivy: { os: osTrivy, arch: archTrivy, ext: extTrivy },
  };
}

/**
 * Downloadable tool descriptors. Each contains enough info to construct the
 * GitHub Releases download URL and know what binary to extract.
 */
export const DOWNLOAD_DESCRIPTORS = Object.freeze({
  gitleaks: {
    repo: 'gitleaks/gitleaks',
    binaryName: `gitleaks${EXE}`,
    assetName(ver, info) {
      return `gitleaks_${ver}_${info.os}_${info.arch}.${info.ext}`;
    },
  },
  trufflehog: {
    repo: 'trufflesecurity/trufflehog',
    binaryName: `trufflehog${EXE}`,
    assetName(ver, info) {
      return `trufflehog_${ver}_${info.os}_${info.arch}.${info.ext}`;
    },
  },
  trivy: {
    repo: 'aquasecurity/trivy',
    binaryName: `trivy${EXE}`,
    assetName(ver, info) {
      return `trivy_${ver}_${info.os}-${info.arch}.${info.ext}`;
    },
  },
});

/**
 * Fetch the latest release tag for a repo. Returns the version string without
 * the leading 'v' (e.g. "8.30.1"), or null on failure.
 */
async function fetchLatestVersion(repo) {
  try {
    const url = `https://api.github.com/repos/${repo}/releases/latest`;
    const res = await fetch(url, {
      headers: { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'clipeus' },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return (data.tag_name || '').replace(/^v/, '') || null;
  } catch {
    return null;
  }
}

/**
 * Download a file from a URL to a local path. Returns true on success.
 */
async function downloadFile(url, dest) {
  const res = await fetch(url, { headers: { 'User-Agent': 'clipeus' }, redirect: 'follow' });
  if (!res.ok || !res.body) return false;
  await pipeline(res.body, createWriteStream(dest));
  return true;
}

/**
 * Extract a binary from a tar.gz or zip archive into destDir.
 * Returns the path to the extracted binary, or null.
 */
function extractBinary(archivePath, binaryName, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  const destBin = path.join(destDir, binaryName);

  if (archivePath.endsWith('.zip')) {
    // Use PowerShell on Windows to extract
    const tmpExtract = path.join(path.dirname(archivePath), '_extract');
    fs.mkdirSync(tmpExtract, { recursive: true });
    try {
      if (IS_WIN) {
        execSync(
          `powershell -NoProfile -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${tmpExtract}' -Force"`,
          { stdio: 'pipe', timeout: 60000 },
        );
      } else {
        execSync(`unzip -o "${archivePath}" -d "${tmpExtract}"`, { stdio: 'pipe', timeout: 60000 });
      }
      const extracted = findFile(tmpExtract, binaryName);
      if (extracted) {
        fs.copyFileSync(extracted, destBin);
        if (!IS_WIN) fs.chmodSync(destBin, 0o755);
        return destBin;
      }
    } finally {
      try { fs.rmSync(tmpExtract, { recursive: true, force: true }); } catch { /* */ }
    }
  } else {
    // tar.gz — use tar (available on Windows 10+ and all Unix)
    const tmpExtract = path.join(path.dirname(archivePath), '_extract');
    fs.mkdirSync(tmpExtract, { recursive: true });
    try {
      execSync(`tar -xzf "${archivePath}" -C "${tmpExtract}"`, { stdio: 'pipe', timeout: 60000 });
      const extracted = findFile(tmpExtract, binaryName);
      if (extracted) {
        fs.copyFileSync(extracted, destBin);
        if (!IS_WIN) fs.chmodSync(destBin, 0o755);
        return destBin;
      }
    } finally {
      try { fs.rmSync(tmpExtract, { recursive: true, force: true }); } catch { /* */ }
    }
  }
  return null;
}

/** Recursively find a file by name in a directory (max depth 3). */
function findFile(dir, name, depth = 0) {
  if (depth > 3) return null;
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isFile() && entry.name === name) return path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const found = findFile(path.join(dir, entry.name), name, depth + 1);
        if (found) return found;
      }
    }
  } catch { /* */ }
  return null;
}

/**
 * Check if a tool binary exists in the Clipeus bin directory.
 * @param {string} toolId  One of: gitleaks, trufflehog, trivy
 * @returns {string|null}  Absolute path to the binary, or null.
 */
export function getDownloadedBinary(toolId) {
  const desc = DOWNLOAD_DESCRIPTORS[toolId];
  if (!desc) return null;
  const p = path.join(CLIPEUS_BIN_DIR, desc.binaryName);
  try {
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
  } catch { /* */ }
  return null;
}

/**
 * Download and install a tool binary.
 *
 * @param {string} toolId  One of: gitleaks, trufflehog, trivy
 * @param {object} [opts]
 * @param {string} [opts.version]  Specific version (without 'v'). Defaults to latest.
 * @param {(msg:string)=>void} [opts.onProgress]  Progress callback.
 * @returns {Promise<{ok:boolean, path?:string, version?:string, error?:string}>}
 */
export async function downloadTool(toolId, opts = {}) {
  const desc = DOWNLOAD_DESCRIPTORS[toolId];
  if (!desc) return { ok: false, error: `Unknown tool: ${toolId}` };

  const info = platformInfo()[toolId];
  if (!info) return { ok: false, error: `Unsupported platform for ${toolId}` };

  try {
    const version = opts.version || await fetchLatestVersion(desc.repo);
    if (!version) return { ok: false, error: `Could not determine latest version for ${toolId}` };

    const asset = desc.assetName(version, info);
    const url = `https://github.com/${desc.repo}/releases/download/v${version}/${asset}`;

    if (opts.onProgress) opts.onProgress(`Downloading ${toolId} v${version}...`);

    // Download to a temp file
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `clipeus-dl-${toolId}-`));
    const archivePath = path.join(tmpDir, asset);

    try {
      const downloaded = await downloadFile(url, archivePath);
      if (!downloaded) return { ok: false, error: `Failed to download ${url}` };

      if (opts.onProgress) opts.onProgress(`Extracting ${toolId}...`);

      const binPath = extractBinary(archivePath, desc.binaryName, CLIPEUS_BIN_DIR);
      if (!binPath) return { ok: false, error: `Failed to extract ${desc.binaryName} from ${asset}` };

      return { ok: true, path: binPath, version };
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* */ }
    }
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}
