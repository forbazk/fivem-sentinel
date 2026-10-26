import { lstat, open, readdir, readFile } from 'node:fs/promises';
import { availableParallelism } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { EMPTY_MANIFEST, globToRegExp, parseManifest, sideOf } from './manifest.ts';
import type { Manifest } from './manifest.ts';
import { RULES } from './rules/index.ts';
import { findSecrets } from './rules/secrets.ts';
import type { SecretMatch } from './rules/secrets.ts';
import { createSource } from './source.ts';
import type { Finding, Language, ResourceResult, Rule, ScanOptions, ScanResult, Severity, SkippedFile, SkipReason, SourceFile } from './types.ts';
import { severityRank } from './types.ts';

const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;
const BINARY_PROBE = 8192;
const MAX_SNIPPET = 240;
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '.hg', '.idea', '.vscode', 'stream', '__macosx']);
const LANGUAGES: Readonly<Record<string, Language>> = {
  '.lua': 'lua',
  '.js': 'js',
  '.mjs': 'js',
  '.cjs': 'js',
  '.ts': 'js',
  '.jsx': 'js',
  '.tsx': 'js',
  '.html': 'js',
  '.htm': 'js',
  '.json': 'text',
  '.cfg': 'text',
  '.env': 'text',
  '.yml': 'text',
  '.yaml': 'text',
  '.toml': 'text',
  '.ini': 'text',
  '.sql': 'text',
};
const MANIFESTS = ['fxmanifest.lua', '__resource.lua'] as const;
const PENALTY: Readonly<Record<Severity, number>> = { critical: 40, high: 15, medium: 5, low: 1, info: 0 };
const SUPPRESS = /fivem-sentinel-ignore(?!-file)(?:[ \t]+((?:FS\d{3}[ \t,]*)+))?/;
const SUPPRESS_FILE = /fivem-sentinel-ignore-file/;

interface Resource {
  readonly name: string;
  readonly dir: string;
  readonly path: string;
  readonly manifest: Manifest;
  readonly kind: ResourceResult['manifest'];
  files: number;
  readonly findings: Finding[];
}

interface Candidate {
  readonly absolutePath: string;
  readonly base: string;
  readonly language: Language;
  readonly resource: Resource;
}

interface DirectoryTask {
  readonly dir: string;
  readonly parent: Resource | undefined;
}

type IgnoreMatcher = (relativePath: string, name: string) => boolean;

function languageOf(file: string): Language | undefined {
  const name = basename(file).toLowerCase();
  if (name === '.env' || name.startsWith('.env.')) return 'text';
  const dot = name.lastIndexOf('.');
  return dot === -1 ? undefined : LANGUAGES[name.slice(dot)];
}

function toPosix(path: string): string {
  return sep === '/' ? path : path.split(sep).join('/');
}

function compileIgnore(patterns: readonly string[]): IgnoreMatcher {
  const anchored: RegExp[] = [];
  const named: RegExp[] = [];
  for (const raw of patterns) {
    const pattern = raw.trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
    if (pattern === '') continue;
    if (pattern.includes('/')) anchored.push(globToRegExp(pattern));
    else named.push(globToRegExp(pattern));
  }
  return (relativePath, name) => named.some((r) => r.test(name)) || anchored.some((r) => r.test(relativePath));
}

function suppressed(file: SourceFile, finding: Finding): boolean {
  for (const line of [finding.line, finding.line - 1]) {
    if (line < 1) continue;
    const m = SUPPRESS.exec(file.lineText(line));
    if (m === null) continue;
    if (m[1] === undefined || m[1].includes(finding.ruleId)) return true;
  }
  return false;
}

function mask(snippet: string, from: number, length: number): string {
  const start = Math.max(0, from);
  const end = Math.min(snippet.length, from + length);
  if (end <= start) return snippet;
  const keep = Math.min(4, end - start);
  return snippet.slice(0, start + keep) + '*'.repeat(end - start - keep) + snippet.slice(end);
}

function clip(snippet: string, column: number): string {
  if (snippet.length <= MAX_SNIPPET) return snippet;
  const start = Math.max(0, Math.min(column - 80, snippet.length - MAX_SNIPPET));
  return `${start > 0 ? '…' : ''}${snippet.slice(start, start + MAX_SNIPPET)}${start + MAX_SNIPPET < snippet.length ? '…' : ''}`;
}

export function analyze(file: SourceFile, rules: readonly Rule[] = RULES, minSeverity: Severity = 'info'): Finding[] {
  if (SUPPRESS_FILE.test(file.text.slice(0, 2000))) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const floor = severityRank(minSeverity);
  let secrets: SecretMatch[] | undefined;
  for (const rule of rules) {
    if (!rule.languages.includes(file.language)) continue;
    rule.check(file, (match) => {
      const severity = match.severity ?? rule.severity;
      if (severityRank(severity) < floor) return;
      const { line, column } = file.position(match.offset);
      const key = `${rule.id}:${line}:${column}`;
      if (seen.has(key)) return;
      seen.add(key);
      const lineStart = match.offset - (column - 1);
      let snippet = file.lineText(line);
      secrets ??= findSecrets(file.text);
      for (const secret of secrets) {
        if (secret.offset < lineStart + snippet.length && secret.offset + secret.length > lineStart) {
          snippet = mask(snippet, secret.offset - lineStart, secret.length);
        }
      }
      if (match.redact) snippet = mask(snippet, column - 1, match.length ?? 0);
      const finding: Finding = {
        ruleId: rule.id,
        severity,
        message: match.message,
        resource: file.resource,
        file: file.path,
        uri: file.uri ?? file.path,
        line,
        column,
        snippet: clip(snippet, column),
      };
      if (!suppressed(file, finding)) findings.push(finding);
    });
  }
  return findings.sort((a, b) => a.line - b.line || a.column - b.column);
}

async function pool<T>(items: Iterable<T>, limit: number, task: (item: T) => Promise<void>): Promise<void> {
  const iterator = items[Symbol.iterator]();
  const run = async (): Promise<void> => {
    for (let next = iterator.next(); next.done !== true; next = iterator.next()) await task(next.value);
  };
  await Promise.all(Array.from({ length: limit }, run));
}

async function readCandidate(path: string, maxFileSize: number): Promise<{ text: string; size: number } | SkipReason> {
  const handle = await open(path, 'r');
  try {
    const info = await handle.stat();
    if (!info.isFile()) return 'unreadable';
    if (info.size > maxFileSize) return 'too-large';
    const buffer = await handle.readFile();
    if (buffer.subarray(0, BINARY_PROBE).includes(0)) return 'binary';
    const text = buffer.toString('utf8');
    return { text: text.charCodeAt(0) === 0xfeff ? text.slice(1) : text, size: buffer.length };
  } finally {
    await handle.close();
  }
}

export async function scan(roots: readonly string[], options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const concurrency = Math.max(1, Math.floor(options.concurrency ?? Math.min(16, availableParallelism() * 2)));
  const ignored = compileIgnore(options.ignore ?? []);
  const rules = options.rules ?? RULES;
  const minSeverity = options.minSeverity ?? 'info';
  const cwd = process.cwd();
  const resolvedRoots = [...new Set(roots.map((r) => resolve(r)))];
  const resources = new Map<string, Resource>();
  const candidates = new Map<string, Candidate>();
  const skipped: SkippedFile[] = [];

  const resourceFor = async (dir: string, root: string, parent: Resource | undefined): Promise<Resource | undefined> => {
    const existing = resources.get(dir);
    if (existing !== undefined) return existing;
    for (const name of MANIFESTS) {
      const path = join(dir, name);
      try {
        const info = await lstat(path);
        if (!info.isFile()) continue;
        const text = info.size <= maxFileSize ? await readFile(path, 'utf8') : '';
        const resource: Resource = {
          name: basename(dir) || dir,
          dir,
          path: toPosix(relative(root, dir)) || '.',
          manifest: parseManifest(text),
          kind: name === 'fxmanifest.lua' ? 'fxmanifest' : 'legacy',
          files: 0,
          findings: [],
        };
        resources.set(dir, resource);
        return resource;
      } catch {
        continue;
      }
    }
    return parent;
  };

  const looseResource = (root: string): Resource => {
    const key = `${root}\0loose`;
    let resource = resources.get(key);
    if (resource === undefined) {
      resource = { name: basename(root) || root, dir: '', path: '.', manifest: EMPTY_MANIFEST, kind: 'none', files: 0, findings: [] };
      resources.set(key, resource);
    }
    return resource;
  };

  const addCandidate = (candidate: Candidate): void => {
    if (!candidates.has(candidate.absolutePath)) candidates.set(candidate.absolutePath, candidate);
  };

  for (const root of resolvedRoots) {
    let info;
    try {
      info = await lstat(root);
    } catch {
      throw new Error(`Path not found: ${toPosix(relative(cwd, root)) || root}`);
    }
    if (info.isFile()) {
      const language = languageOf(root);
      if (language !== undefined) addCandidate({ absolutePath: root, base: dirname(root), language, resource: looseResource(root) });
      continue;
    }
    if (!info.isDirectory()) continue;

    let queue: DirectoryTask[] = [{ dir: root, parent: undefined }];
    const next: DirectoryTask[] = [];
    const visit = async (task: DirectoryTask): Promise<void> => {
      const resource = await resourceFor(task.dir, root, task.parent);
      let entries;
      try {
        entries = await readdir(task.dir, { withFileTypes: true });
      } catch {
        skipped.push({ path: toPosix(relative(cwd, task.dir)), reason: 'unreadable' });
        return;
      }
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const path = join(task.dir, entry.name);
        if (ignored(toPosix(relative(root, path)), entry.name)) continue;
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name.toLowerCase())) next.push({ dir: path, parent: resource });
          continue;
        }
        if (!entry.isFile()) continue;
        const language = languageOf(entry.name);
        if (language !== undefined) addCandidate({ absolutePath: path, base: root, language, resource: resource ?? looseResource(root) });
      }
    };
    while (queue.length > 0) {
      await pool(queue, concurrency, visit);
      queue = next.splice(0, next.length);
    }
  }

  let bytes = 0;
  let files = 0;
  await pool(candidates.values(), concurrency, async (candidate) => {
    const uri = toPosix(relative(cwd, candidate.absolutePath));
    let read: { text: string; size: number } | SkipReason;
    try {
      read = await readCandidate(candidate.absolutePath, maxFileSize);
    } catch {
      read = 'unreadable';
    }
    if (typeof read === 'string') {
      skipped.push({ path: uri, reason: read });
      return;
    }
    const inResource = toPosix(relative(candidate.resource.dir === '' ? candidate.base : candidate.resource.dir, candidate.absolutePath));
    const source = createSource({
      absolutePath: candidate.absolutePath,
      path: toPosix(relative(candidate.base, candidate.absolutePath)) || basename(candidate.absolutePath),
      uri,
      resource: candidate.resource.name,
      language: candidate.language,
      side: sideOf(candidate.resource.manifest, inResource),
      text: read.text,
    });
    candidate.resource.findings.push(...analyze(source, rules, minSeverity));
    candidate.resource.files++;
    bytes += read.size;
    files++;
  });

  const results: ResourceResult[] = [...resources.values()]
    .filter((r) => r.files > 0 || r.kind !== 'none')
    .map((r) => ({
      name: r.name,
      path: r.path,
      manifest: r.kind,
      files: r.files,
      score: Math.max(0, 100 - r.findings.reduce((sum, f) => sum + PENALTY[f.severity], 0)),
      findings: r.findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column),
    }))
    .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));

  return {
    roots: resolvedRoots.map((r) => toPosix(relative(cwd, r)) || '.'),
    resources: results,
    findings: results.flatMap((r) => r.findings),
    skipped: skipped.sort((a, b) => a.path.localeCompare(b.path)),
    stats: { files, skipped: skipped.length, bytes, durationMs: Math.round(performance.now() - started) },
  };
}
