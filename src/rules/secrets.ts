import type { Rule, Severity } from '../types.ts';
import { matches } from './util.ts';

interface Detector {
  readonly pattern: RegExp;
  readonly hints: readonly string[];
  readonly label: string;
  readonly severity: Severity;
  readonly group?: number;
}

const DETECTORS: readonly Detector[] = [
  { pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,22}\/[\w-]{40,100}/g, hints: ['/api/webhooks/'], label: 'Discord webhook URL', severity: 'high' },
  { pattern: /\b[MNO][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}\b/g, hints: [], label: 'Discord bot token', severity: 'critical' },
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g, hints: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'], label: 'GitHub token', severity: 'critical' },
  { pattern: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b/g, hints: ['_live_'], label: 'Stripe live key', severity: 'critical' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, hints: ['akia'], label: 'AWS access key', severity: 'critical' },
  { pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g, hints: ['xox'], label: 'Slack token', severity: 'high' },
  { pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, hints: ['private key-----'], label: 'Private key', severity: 'critical' },
  { pattern: /\bsv_licenseKey\s+["']?(cfxk_[\w]{10,}|[a-z0-9]{32})["']?/gi, hints: ['sv_licensekey'], label: 'FiveM server license key', severity: 'high', group: 1 },
  { pattern: /\bsteam_webApiKey\s+["']?([0-9A-F]{32})["']?/gi, hints: ['steam_webapikey'], label: 'Steam Web API key', severity: 'high', group: 1 },
  { pattern: /\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?):\/\/[^:\s/"'@]+:([^@\s"']{3,})@/gi, hints: ['://'], label: 'Database password in connection string', severity: 'high', group: 1 },
  { pattern: /\bpassword\s*=\s*([^;"'\s]{3,})(?=;|["'])/gi, hints: ['password'], label: 'Database password in connection string', severity: 'high', group: 1 },
];

let cachedText: string | undefined;
let cachedSecrets: SecretMatch[] = [];

const KEYWORD = /api[_-]?key|apikey|secret|token|passw(?:or)?d|auth[_-]?key|private[_-]?key/gi;
const ASSIGNMENT = /\s*[:=]\s*(["'`])([^"'`\s]{12,200})\1/y;

function* genericSecrets(text: string): Generator<{ name: string; value: string; offset: number }> {
  KEYWORD.lastIndex = 0;
  let consumed = 0;
  for (let m = KEYWORD.exec(text); m !== null; m = KEYWORD.exec(text)) {
    if (m.index < consumed) continue;
    let start = m.index;
    while (start > 0 && /\w/.test(text[start - 1]!)) start--;
    let end = m.index + m[0].length;
    while (end < text.length && /\w/.test(text[end]!)) end++;
    if (end - start > 64 || /\d/.test(text[start]!)) continue;
    ASSIGNMENT.lastIndex = end;
    const a = ASSIGNMENT.exec(text);
    if (a === null) continue;
    consumed = end + a[0].length;
    yield { name: text.slice(start, end), value: a[2]!, offset: end + a[0].lastIndexOf(a[2]!) };
  }
}

const PLACEHOLDER = /your|change|example|placeholder|xxxx|\*\*\*|<|>|\{|\}|\$|^(.)\1+$|insert|replace|token_here|secret_here|^convar/i;

export interface SecretMatch {
  readonly offset: number;
  readonly length: number;
  readonly severity: Severity;
  readonly message: string;
}

export function findSecrets(text: string): SecretMatch[] {
  if (text === cachedText) return cachedSecrets;
  const found: SecretMatch[] = [];
  const seen = new Set<number>();
  const lower = text.toLowerCase();
  for (const detector of DETECTORS) {
    if (detector.hints.length > 0 && !detector.hints.some((h) => lower.includes(h))) continue;
    for (const m of matches(text, detector.pattern)) {
      const value = detector.group === undefined ? m[0] : m[detector.group];
      if (value === undefined) continue;
      const offset = m.index + m[0].indexOf(value);
      if (seen.has(offset) || PLACEHOLDER.test(value)) continue;
      seen.add(offset);
      found.push({ offset, length: value.length, severity: detector.severity, message: `${detector.label} committed in plain text` });
    }
  }
  for (const { name, value, offset } of genericSecrets(text)) {
    if (seen.has(offset) || PLACEHOLDER.test(value) || /^(?:true|false|nil|null|undefined)$/i.test(value)) continue;
    if (!/\d/.test(value) || !/[A-Za-z]/.test(value)) continue;
    seen.add(offset);
    found.push({ offset, length: value.length, severity: 'medium', message: `Possible secret assigned to "${name}"` });
  }
  cachedText = text;
  cachedSecrets = found;
  return found;
}

export const secrets: Rule = {
  id: 'FS004',
  name: 'hardcoded-secret',
  severity: 'high',
  description: 'Credentials committed in plain text: webhooks, bot tokens, license keys, database passwords. Anyone who gets the resource can abuse them. Move them to server convars.',
  languages: ['lua', 'js', 'text'],
  check(file, report) {
    for (const secret of findSecrets(file.text)) report({ ...secret, redact: true });
  },
};
