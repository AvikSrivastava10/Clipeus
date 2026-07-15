/**
 * `clipeus doctor` command.
 *
 * Diagnostic only — never modifies anything. Reports the runtime, which
 * underlying tools are installed and runnable (with versions), and what a scan
 * of the current directory would run.
 */

import path from 'node:path';
import { ALL_ADAPTERS } from '../adapters/index.js';
import { commandExists, getToolVersion, runTool } from '../core/runner.js';
import { installHint } from '../adapters/base.js';
import { detectProject } from '../detectors/detect.js';
import { resolveToolInEnvironments } from '../detectors/environments.js';
import { selectAnalyzers } from '../scan/engine.js';
import { loadConfig } from '../config/config.js';
import { log, chalk } from '../core/logger.js';
import { VERSION, PRODUCT } from '../version.js';

async function runtimeVersion(cmd, args) {
  const res = await runTool({ command: cmd, args, timeoutMs: 8000 });
  if (!res.ran || res.notFound) return null;
  return (res.stdout || res.stderr || '').trim().split(/\r?\n/)[0] || null;
}

/**
 * @param {object} [opts]
 * @returns {Promise<number>} count of missing/broken tools
 */
export async function doctorCommand(opts = {}) {
  const out = [];
  out.push('');
  out.push(chalk.bold(`${PRODUCT} doctor`) + chalk.gray(` — v${VERSION}`));
  out.push('');

  // Runtime
  out.push(chalk.bold('Runtime'));
  const node = await runtimeVersion('node', ['--version']);
  const npm = await runtimeVersion('npm', ['--version']);
  out.push(`  ${node ? chalk.green('✓') : chalk.red('✗')} node ${chalk.gray(node || 'not found')}`);
  out.push(`  ${npm ? chalk.green('✓') : chalk.red('✗')} npm ${chalk.gray(npm || 'not found')}`);
  out.push('');

  // Detect the project once up front so tool availability can honor virtualenvs.
  const root = process.cwd();
  const detection = detectProject(root);

  // Security tools
  out.push(chalk.bold('Security tools'));
  let missing = 0;
  for (const adapter of ALL_ADAPTERS) {
    // Bundled adapters (ESLint) have a custom runner and ship with Clipeus.
    if (typeof adapter.runCustom === 'function') {
      let bundledVersion = null;
      try {
        const mod = await import('eslint');
        bundledVersion = mod.ESLint?.version ?? null;
      } catch {
        /* ignore */
      }
      out.push(
        `  ${chalk.green('✓')} ${adapter.id.padEnd(22)} ${chalk.gray(`bundled${bundledVersion ? ` (${bundledVersion})` : ''}`)}`,
      );
      continue;
    }

    // Honor the project's virtualenv(s) for Python tools before a PATH lookup.
    const viaVenv = resolveToolInEnvironments(detection.pythonEnvs || [], adapter.command);
    const resolvedCmd = viaVenv ? viaVenv.command : adapter.command;
    const exists = viaVenv ? true : await commandExists(adapter.command);
    if (exists) {
      const version = await getToolVersion(resolvedCmd, adapter.versionArgs);
      const where = viaVenv ? chalk.gray(`  [${viaVenv.env.source}]`) : '';
      out.push(`  ${chalk.green('✓')} ${adapter.id.padEnd(22)} ${chalk.gray(version || 'installed')}${where}`);
    } else {
      missing += 1;
      out.push(
        `  ${chalk.yellow('•')} ${chalk.yellow(adapter.id.padEnd(22))} ${chalk.gray('not installed')}`,
      );
      out.push(`      ${chalk.gray(`install: ${installHint(adapter)}`)}`);
    }
  }
  out.push('');

  // What a scan here would run
  try {
    const { config } = loadConfig(root);
    const { toolSet, checkerSet } = selectAnalyzers({ detection, config });
    const stacks = Object.entries(detection.stacks).filter(([, v]) => v).map(([k]) => k);
    out.push(chalk.bold('Current project'));
    out.push(`  ${chalk.gray('path:')} ${root}`);
    out.push(`  ${chalk.gray('detected:')} ${stacks.length ? stacks.join(', ') : 'unknown'}`);
    const selected = [...toolSet, ...checkerSet];
    out.push(`  ${chalk.gray('would run:')} ${selected.length ? selected.join(', ') : '(nothing detected)'}`);
    if (detection.nodeModuleDirs?.length) {
      const rels = detection.nodeModuleDirs.map((d) => path.relative(root, d).replace(/\\/g, '/') || '.');
      out.push(`  ${chalk.gray('node modules:')} ${rels.join(', ')}`);
    }
    if (detection.pythonEnvs?.length) {
      out.push(`  ${chalk.gray('python envs:')} ${detection.pythonEnvs.map((e) => e.source).join(', ')}`);
    }
    out.push('');
  } catch (err) {
    log.debug(`doctor project detection failed: ${err.message}`);
  }

  if (missing > 0) {
    out.push(chalk.yellow(`${missing} tool(s) not installed. Clipeus will skip them and scan with the rest.`));
  } else {
    out.push(chalk.green('All supported tools are installed.'));
  }
  out.push('');

  process.stdout.write(out.join('\n') + '\n');
  return missing;
}
