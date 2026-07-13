/**
 * Cross-file taint tracking analyzer (Phase 4).
 *
 * Exposed as a single internal analyzer conforming to the same interface as the
 * Phase 3 checkers, so the scan engine treats it uniformly. Runs the JS/TS
 * engine and/or the Python heuristic depending on the detected languages.
 */

import { TOOL } from '../constants.js';
import { STATUS } from '../adapters/base.js';
import { analyzeJsTaint } from './js-taint.js';
import { analyzePyTaint } from './py-taint.js';

const taintAnalyzer = {
  id: TOOL.taint,
  displayName: 'Taint tracking',

  appliesTo(detection) {
    return detection.languages.includes('javascript') || detection.languages.includes('python');
  },

  async run(ctx) {
    const findings = [];
    if (ctx.detection?.languages?.includes('javascript')) {
      findings.push(...analyzeJsTaint(ctx.root, ctx.config));
    }
    if (ctx.detection?.languages?.includes('python')) {
      findings.push(...analyzePyTaint(ctx.root, ctx.config));
    }
    return { status: STATUS.ok, findings };
  },
};

export const TAINT_ANALYZERS = [taintAnalyzer];

export { analyzeJsTaint, analyzePyTaint };
