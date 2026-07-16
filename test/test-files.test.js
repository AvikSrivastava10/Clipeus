import { describe, it, expect } from 'vitest';
import { isTestFile, suppressTestAssertNoise } from '../src/core/test-files.js';

describe('isTestFile', () => {
  it('recognizes test directories (any separator)', () => {
    expect(isTestFile('backend/tests/test_chunking.py')).toBe(true);
    expect(isTestFile('backend\\tests\\test_health.py')).toBe(true);
    expect(isTestFile('src/__tests__/App.test.tsx')).toBe(true);
    expect(isTestFile('spec/models/user.rb')).toBe(true);
  });

  it('recognizes test filenames outside a test dir', () => {
    expect(isTestFile('app/test_api.py')).toBe(true);
    expect(isTestFile('app/api_test.py')).toBe(true);
    expect(isTestFile('src/utils.test.ts')).toBe(true);
    expect(isTestFile('src/utils.spec.jsx')).toBe(true);
    expect(isTestFile('conftest.py')).toBe(true);
  });

  it('does not flag ordinary source files', () => {
    expect(isTestFile('backend/app/routes/health.py')).toBe(false);
    expect(isTestFile('src/components/App.tsx')).toBe(false);
    expect(isTestFile('latest.py')).toBe(false); // contains "test" as a substring, not a segment/name
    expect(isTestFile('')).toBe(false);
    expect(isTestFile(null)).toBe(false);
  });
});

describe('suppressTestAssertNoise', () => {
  const assertFinding = (file) => ({
    tool: 'bandit',
    ruleId: 'B101 (assert_used)',
    category: 'other',
    severity: 'low',
    confidence: 'high',
    file,
  });

  it('suppresses assert_used findings inside test files', () => {
    const { findings, suppressed } = suppressTestAssertNoise([
      assertFinding('backend/tests/test_chunking.py'),
      assertFinding('backend/tests/test_health.py'),
    ]);
    expect(suppressed).toBe(2);
    expect(findings).toHaveLength(0);
  });

  it('keeps assert_used findings in NON-test (production) files', () => {
    const { findings, suppressed } = suppressTestAssertNoise([assertFinding('backend/app/security.py')]);
    expect(suppressed).toBe(0);
    expect(findings).toHaveLength(1);
  });

  it('keeps other bandit findings even in test files', () => {
    const other = {
      tool: 'bandit',
      ruleId: 'B105 (hardcoded_password_string)',
      severity: 'medium',
      file: 'backend/tests/test_auth.py',
    };
    const { findings, suppressed } = suppressTestAssertNoise([other]);
    expect(suppressed).toBe(0);
    expect(findings).toHaveLength(1);
  });

  it('matches by B101 id as well as the assert_used name', () => {
    const { suppressed } = suppressTestAssertNoise([
      { ruleId: 'B101', file: 'tests/test_x.py' },
    ]);
    expect(suppressed).toBe(1);
  });

  it('handles empty input', () => {
    expect(suppressTestAssertNoise([]).findings).toEqual([]);
  });
});
