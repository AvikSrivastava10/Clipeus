/**
 * Test-file noise reduction.
 *
 * Test files legitimately contain patterns that a security linter flags in
 * production code. The clearest, zero-risk example is Bandit's `assert_used`
 * (B101): every `assert` in a test trips it, but assertions are the entire
 * point of a test. We suppress ONLY that specific check, and ONLY inside test
 * files — so a genuine assert-as-security-check in production code is still
 * reported. Nothing else in test files is touched (real issues in test infra,
 * e.g. a hardcoded live credential, still surface).
 */

/** Path segments that indicate a test directory. */
const TEST_DIR_SEGMENTS = new Set(['test', 'tests', '__tests__', 'spec', 'specs']);

/** Whether a file path looks like a test file (by directory or filename). */
export function isTestFile(file) {
  if (!file) return false;
  const norm = String(file).replace(/\\/g, '/').toLowerCase();
  const segments = norm.split('/');
  if (segments.some((s) => TEST_DIR_SEGMENTS.has(s))) return true;

  const base = segments[segments.length - 1] || '';
  // Python: test_*.py, *_test.py, conftest.py
  if (/^test_.+\.py$/.test(base) || /_test\.py$/.test(base) || base === 'conftest.py') return true;
  // JS/TS: *.test.{js,jsx,ts,tsx,mjs,cjs}, *.spec.{...}
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(base)) return true;
  return false;
}

/** Whether a finding is Bandit's assert_used (B101) check. */
function isAssertUsed(finding) {
  const id = String(finding?.ruleId || '');
  return /assert_used/i.test(id) || /\bB101\b/.test(id);
}

/**
 * Suppress Bandit `assert_used` findings that live in test files. Never touches
 * anything else. Returns the kept findings and how many were suppressed.
 * @param {object[]} findings
 * @returns {{findings: object[], suppressed: number}}
 */
export function suppressTestAssertNoise(findings) {
  let suppressed = 0;
  const kept = [];
  for (const f of findings || []) {
    if (isAssertUsed(f) && isTestFile(f?.file)) {
      suppressed += 1;
      continue;
    }
    kept.push(f);
  }
  return { findings: kept, suppressed };
}
