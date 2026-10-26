#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { formatJson, formatSarif } from './report/machine.ts';
import { formatText } from './report/text.ts';
import { RULES } from './rules/index.ts';
import { scan } from './scanner.ts';
import type { Severity } from './types.ts';
import { SEVERITIES, isSeverity, severityRank } from './types.ts';
import { NAME, VERSION } from './version.ts';

const USAGE = `${NAME} ${VERSION}
Static security scanner for FiveM resources.

Usage
  ${NAME} [paths...] [options]

Options
  -f, --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>              Write the report to a file
      --fail-on <severity>         Exit with code 1 at or above this severity (default: high, "none" to disable)
      --min-severity <severity>    Hide findings below this severity (default: low)
      --rules <ids>                Only run these rules, comma separated (e.g. FS001,FS004)
      --exclude-rules <ids>        Skip these rules, comma separated
  -i, --ignore <glob>              Ignore paths matching the glob (repeatable)
      --max-file-size <kb>         Skip files larger than this (default: 2048)
  -j, --concurrency <n>            Files read in parallel (default: auto)
      --no-color                   Disable colors (NO_COLOR and FORCE_COLOR are honoured)
      --verbose                    List skipped files and the reason
      --list-rules                 Print the rule catalog and exit
  -h, --help                       Show this help
  -v, --version                    Show the version

Severities: ${SEVERITIES.join(', ')}
Suppress a finding with a "fivem-sentinel-ignore FS00X" comment on the same or previous line.`;

class UsageError extends Error {}

function parseSeverity(value: string | undefined, fallback: Severity, flag: string): Severity {
  if (value === undefined) return fallback;
  const v = value.toLowerCase();
  if (!isSeverity(v)) throw new UsageError(`Invalid ${flag} "${value}". Expected one of: ${SEVERITIES.join(', ')}`);
  return v;
}

function parseIds(value: string | undefined, flag: string): Set<string> | undefined {
  if (value === undefined) return undefined;
  const ids = new Set(value.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean));
  for (const id of ids) if (!RULES.some((r) => r.id === id)) throw new UsageError(`Unknown rule "${id}" in ${flag}`);
  return ids;
}

function parsePositiveInt(value: string | undefined, flag: string): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new UsageError(`${flag} must be a positive integer`);
  return n;
}

function listRules(): string {
  return RULES.map((r) => `${r.id}  ${r.severity.padEnd(8)}  ${r.name}\n          ${r.description}`).join('\n\n');
}

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      format: { type: 'string', short: 'f' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string' },
      'min-severity': { type: 'string' },
      rules: { type: 'string' },
      'exclude-rules': { type: 'string' },
      ignore: { type: 'string', short: 'i', multiple: true },
      'max-file-size': { type: 'string' },
      concurrency: { type: 'string', short: 'j' },
      'no-color': { type: 'boolean' },
      verbose: { type: 'boolean' },
      'list-rules': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });

  if (values.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (values['list-rules']) {
    process.stdout.write(`${listRules()}\n`);
    return 0;
  }

  const format = values.format ?? 'text';
  if (format !== 'text' && format !== 'json' && format !== 'sarif') throw new UsageError(`Invalid --format "${format}"`);
  const failOnRaw = values['fail-on']?.toLowerCase();
  const failOn = failOnRaw === 'none' ? undefined : parseSeverity(failOnRaw, 'high', '--fail-on');
  const minSeverity = parseSeverity(values['min-severity'], 'low', '--min-severity');
  const only = parseIds(values.rules, '--rules');
  const exclude = parseIds(values['exclude-rules'], '--exclude-rules');
  const maxKb = parsePositiveInt(values['max-file-size'], '--max-file-size');
  const concurrency = parsePositiveInt(values.concurrency, '--concurrency');
  const rules = RULES.filter((r) => (only === undefined || only.has(r.id)) && !exclude?.has(r.id));

  const result = await scan(positionals.length > 0 ? positionals : ['.'], {
    rules,
    minSeverity,
    ...(values.ignore === undefined ? {} : { ignore: values.ignore }),
    ...(maxKb === undefined ? {} : { maxFileSize: maxKb * 1024 }),
    ...(concurrency === undefined ? {} : { concurrency }),
  });

  const forced = process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0';
  const color = format === 'text' && values.output === undefined && !values['no-color'] && process.env.NO_COLOR === undefined && (forced || process.stdout.isTTY === true);
  const report = format === 'json' ? formatJson(result) : format === 'sarif' ? formatSarif(result) : formatText(result, { color, verbose: values.verbose === true });

  if (values.output === undefined) process.stdout.write(`${report}\n`);
  else await writeFile(values.output, `${report}\n`, 'utf8');

  if (failOn === undefined) return 0;
  const threshold = severityRank(failOn);
  return result.findings.some((f) => severityRank(f.severity) >= threshold) ? 1 : 0;
}

process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EPIPE') process.exit(process.exitCode ?? 0);
  throw error;
});

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    const usage = error instanceof UsageError || (error instanceof TypeError && 'code' in error && String(error.code).startsWith('ERR_PARSE_ARGS'));
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${NAME}: ${message}${usage ? `\nRun "${NAME} --help" for usage.` : ''}\n`);
    process.exitCode = 2;
  },
);
