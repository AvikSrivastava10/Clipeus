import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { CATEGORY_VALUES } from '../src/constants.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_DIR = path.resolve(__dirname, '..', 'src', 'rules');
const VALID_SEVERITIES = new Set(['ERROR', 'WARNING', 'INFO']);
const FIXTURE_EXTS = ['.js', '.ts', '.jsx', '.tsx', '.py'];

function ruleFiles() {
  return fs.readdirSync(RULES_DIR).filter((f) => /\.ya?ml$/.test(f));
}

function loadRules(file) {
  const doc = YAML.parse(fs.readFileSync(path.join(RULES_DIR, file), 'utf8'));
  return doc?.rules ?? [];
}

function hasPatternClause(rule) {
  return Boolean(
    rule.patterns || rule.pattern || rule['pattern-either'] || rule['pattern-regex'] || rule['pattern-sources'],
  );
}

/** Read all annotation ids of a given kind from co-located fixtures for a rule file. */
function fixtureAnnotations(base) {
  const found = { ruleid: new Set(), ok: new Set() };
  for (const ext of FIXTURE_EXTS) {
    const p = path.join(RULES_DIR, base + ext);
    if (!fs.existsSync(p)) continue;
    for (const line of fs.readFileSync(p, 'utf8').split(/\r?\n/)) {
      const m = line.match(/(?:\/\/|#)\s*(ruleid|ok):\s*(.+)$/);
      if (!m) continue;
      for (const id of m[2].split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)) {
        found[m[1]].add(id);
      }
    }
  }
  return found;
}

describe('custom Semgrep rules', () => {
  const files = ruleFiles();

  it('has rule files', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it('parses every rule file as valid YAML with a rules array', () => {
    for (const file of files) {
      const doc = YAML.parse(fs.readFileSync(path.join(RULES_DIR, file), 'utf8'));
      expect(doc, `${file} should parse`).toBeTruthy();
      expect(Array.isArray(doc.rules), `${file} must have a rules array`).toBe(true);
      expect(doc.rules.length).toBeGreaterThan(0);
    }
  });

  it('every rule has valid id, message, severity, languages, pattern, and clipeus-category', () => {
    for (const file of files) {
      for (const rule of loadRules(file)) {
        const where = `${file}#${rule.id}`;
        expect(typeof rule.id, `${where} id`).toBe('string');
        expect(rule.id.length, `${where} id non-empty`).toBeGreaterThan(0);
        expect(typeof rule.message, `${where} message`).toBe('string');
        expect(rule.message.trim().length, `${where} message non-empty`).toBeGreaterThan(10);
        expect(VALID_SEVERITIES.has(rule.severity), `${where} severity ${rule.severity}`).toBe(true);
        expect(Array.isArray(rule.languages) && rule.languages.length > 0, `${where} languages`).toBe(true);
        expect(hasPatternClause(rule), `${where} has a pattern clause`).toBe(true);

        const category = rule.metadata?.['clipeus-category'];
        expect(CATEGORY_VALUES.includes(category), `${where} clipeus-category "${category}" in taxonomy`).toBe(true);
      }
    }
  });

  it('rule ids are globally unique', () => {
    const seen = new Map();
    for (const file of files) {
      for (const rule of loadRules(file)) {
        expect(seen.has(rule.id), `duplicate rule id "${rule.id}" (${file} and ${seen.get(rule.id)})`).toBe(false);
        seen.set(rule.id, file);
      }
    }
  });

  it('marks at least some rules as AI-codegen relevant', () => {
    let aiCount = 0;
    for (const file of files) {
      for (const rule of loadRules(file)) {
        if (rule.metadata?.['clipeus-ai-codegen'] === true) aiCount += 1;
      }
    }
    expect(aiCount).toBeGreaterThan(5);
  });

  it('every rule has a true-positive and a true-negative fixture annotation', () => {
    for (const file of files) {
      const base = file.replace(/\.ya?ml$/, '');
      const ann = fixtureAnnotations(base);
      for (const rule of loadRules(file)) {
        expect(ann.ruleid.has(rule.id), `${file}: missing "// ruleid: ${rule.id}" fixture (true positive)`).toBe(true);
        expect(ann.ok.has(rule.id), `${file}: missing "// ok: ${rule.id}" fixture (true negative)`).toBe(true);
      }
    }
  });

  it('fixtures only reference rule ids that exist', () => {
    for (const file of files) {
      const base = file.replace(/\.ya?ml$/, '');
      const ids = new Set(loadRules(file).map((r) => r.id));
      const ann = fixtureAnnotations(base);
      for (const id of [...ann.ruleid, ...ann.ok]) {
        expect(ids.has(id), `${base} fixture references unknown rule id "${id}"`).toBe(true);
      }
    }
  });

  it('covers the required Phase 2 concerns', () => {
    const allIds = files.flatMap((f) => loadRules(f).map((r) => r.id)).join(' ');
    for (const concern of [
      'cors', 'jwt', 'cookie', 'password-hash', 'tls', 'hallucinated',
      'debug', 'error-stack', 'introspection', 'webhook',
    ]) {
      expect(allIds.includes(concern), `expected a rule covering "${concern}"`).toBe(true);
    }
  });
});
