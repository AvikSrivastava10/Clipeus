import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDefaultConfig } from '../src/index.js';
import { analyzeJsTaint, analyzePyTaint } from '../src/taint/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);
const config = getDefaultConfig();

describe('analyzeJsTaint', () => {
  const findings = analyzeJsTaint(fixture('taint-js'), config);
  const byFile = (f) => findings.filter((x) => x.file.endsWith(f));

  it('flags a direct intra-function source -> SQL sink', () => {
    const hits = byFile('handler.js').filter((f) => f.message.includes('query'));
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].category).toBe('injection');
  });

  it('flags eval of user input with medium confidence (full-match sink)', () => {
    const evalHit = byFile('handler.js').find((f) => f.message.includes('eval'));
    expect(evalHit).toBeTruthy();
    expect(evalHit.confidence).toBe('medium');
  });

  it('propagates taint across files into child_process.exec', () => {
    const crossFile = byFile('cmd.js').find((f) => f.message.includes('exec'));
    expect(crossFile).toBeTruthy();
    expect(crossFile.message).toMatch(/cross-function/);
    expect(crossFile.aiCodegenRelevant).toBe(true);
  });

  it('does not flag sanitized flows', () => {
    expect(byFile('safe.js')).toHaveLength(0);
  });

  it('marks taint findings as heuristic (medium/low confidence only)', () => {
    for (const f of findings) {
      expect(['medium', 'low']).toContain(f.confidence);
      expect(f.tool).toBe('patronus-taint');
    }
  });
});

describe('analyzePyTaint', () => {
  const findings = analyzePyTaint(fixture('taint-py'), config);

  it('flags a tainted variable reaching os.system', () => {
    const runHit = findings.find((f) => f.line >= 9 && f.line <= 12);
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(runHit).toBeTruthy();
    expect(runHit.category).toBe('injection');
  });

  it('flags a source flowing directly into a sink', () => {
    expect(findings.some((f) => f.message.includes('user input'))).toBe(true);
  });

  it('does not flag the shlex.quote-sanitized call', () => {
    // The safe() os.system is on the last line; ensure no finding there.
    const maxLine = Math.max(...findings.map((f) => f.line));
    const safeLine = 21;
    expect(findings.some((f) => f.line === safeLine)).toBe(false);
    expect(maxLine).toBeLessThan(safeLine);
  });
});
