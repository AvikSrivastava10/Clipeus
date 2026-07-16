import { describe, it, expect } from 'vitest';
import { isDataFile, demoteDataFileSecrets, DATA_FILE_EXTENSIONS } from '../src/core/data-files.js';

describe('isDataFile', () => {
  it('recognizes data/dataset extensions (any separator, any case)', () => {
    expect(isDataFile('data/raw/kaggle/train.csv')).toBe(true);
    expect(isDataFile('D:/proj/data/raw/train.CSV')).toBe(true);
    expect(isDataFile('data\\big.parquet')).toBe(true);
    expect(isDataFile('features.npy')).toBe(true);
    expect(isDataFile('export.jsonl')).toBe(true);
    expect(isDataFile('db/app.sqlite3')).toBe(true);
  });

  it('does not treat source/config files as data files', () => {
    expect(isDataFile('src/app.ts')).toBe(false);
    expect(isDataFile('.env')).toBe(false);
    expect(isDataFile('config.json')).toBe(false);
    expect(isDataFile('fix-missing-user.sql')).toBe(false);
    expect(isDataFile('README.md')).toBe(false);
    expect(isDataFile('noext')).toBe(false);
    expect(isDataFile('')).toBe(false);
    expect(isDataFile(null)).toBe(false);
  });
});

describe('demoteDataFileSecrets', () => {
  const secret = (over = {}) => ({
    category: 'secrets',
    severity: 'high',
    confidence: 'medium',
    file: 'data/raw/train.csv',
    ...over,
  });

  it('demotes an unverified (medium-confidence) secret in a data file', () => {
    const { findings, demoted } = demoteDataFileSecrets([secret()]);
    expect(demoted).toBe(1);
    expect(findings[0].severity).toBe('low');
    expect(findings[0].confidence).toBe('low');
    expect(findings[0].demotedReason).toBe('data-file');
  });

  it('leaves high-confidence secrets alone even in a data file (e.g. gitleaks rules)', () => {
    const { findings, demoted } = demoteDataFileSecrets([secret({ confidence: 'high' })]);
    expect(demoted).toBe(0);
    expect(findings[0].severity).toBe('high');
  });

  it('leaves verified/critical secrets alone even in a data file', () => {
    const { findings, demoted } = demoteDataFileSecrets([secret({ severity: 'critical', confidence: 'high' })]);
    expect(demoted).toBe(0);
    expect(findings[0].severity).toBe('critical');
  });

  it('does not touch secrets in source files', () => {
    const { demoted } = demoteDataFileSecrets([secret({ file: 'src/config.ts' })]);
    expect(demoted).toBe(0);
  });

  it('does not touch non-secret findings in data files', () => {
    const { demoted } = demoteDataFileSecrets([
      { category: 'dependency-cve', severity: 'high', confidence: 'high', file: 'data.csv' },
    ]);
    expect(demoted).toBe(0);
  });

  it('handles empty input', () => {
    expect(demoteDataFileSecrets([]).findings).toEqual([]);
    expect(DATA_FILE_EXTENSIONS.has('.csv')).toBe(true);
  });
});
