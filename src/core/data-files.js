/**
 * Data-file noise reduction.
 *
 * Secret scanners flag high-entropy strings. Data files (CSV/Parquet/ML
 * datasets/…) are full of high-entropy-looking values, so a single row can trip
 * a "secret" detection that is almost certainly just data.
 *
 * Rather than HIDE such findings (a security tool must never silently drop a
 * potential leak from the user's own files), we automatically DEMOTE the
 * low-certainty ones to low severity/confidence, so they drop out of the
 * important results but remain on record. This is fully automatic — no config.
 *
 * We only demote LOW/MEDIUM-confidence, non-critical secret findings. That
 * targets trufflehog's unverified entropy matches while leaving high-confidence
 * rule matches (gitleaks) and verified/critical secrets fully loud, even in a
 * data file, because those are far more likely to be real.
 */

import { CATEGORY, CONFIDENCE, SEVERITY } from '../constants.js';

/** File extensions that hold data/datasets rather than source code. */
export const DATA_FILE_EXTENSIONS = new Set([
  '.csv', '.tsv', '.psv',
  '.parquet', '.parq', '.avro', '.orc', '.arrow', '.feather',
  '.npy', '.npz', '.pkl', '.pickle', '.h5', '.hdf5',
  '.sqlite', '.sqlite3', '.db',
  '.jsonl', '.ndjson',
  '.xlsx', '.xls',
  '.dat', '.data',
]);

/** True when the file looks like a data/dataset file by extension. */
export function isDataFile(file) {
  if (!file) return false;
  const base = String(file).replace(/\\/g, '/').split('/').pop().toLowerCase();
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return false;
  return DATA_FILE_EXTENSIONS.has(base.slice(dot));
}

/**
 * Auto-demote likely-false-positive secret findings inside data files.
 * Returns the (new) findings array and how many were demoted.
 * @param {object[]} findings
 * @returns {{findings: object[], demoted: number}}
 */
export function demoteDataFileSecrets(findings) {
  let demoted = 0;
  const out = (findings || []).map((f) => {
    if (
      f?.category === CATEGORY.secrets &&
      f.severity !== SEVERITY.critical &&
      f.confidence !== CONFIDENCE.high &&
      isDataFile(f.file)
    ) {
      demoted += 1;
      return { ...f, severity: SEVERITY.low, confidence: CONFIDENCE.low, demotedReason: 'data-file' };
    }
    return f;
  });
  return { findings: out, demoted };
}
