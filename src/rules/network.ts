import type { Rule, Severity } from '../types.ts';
import { preview } from './util.ts';

const PRIVATE_IP = /^(?:127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|172\.(?:1[6-9]|2\d|3[01])\.)/;
const URL =/\bhttps?:\/\/([^/\s"'`:?#]+)(?::\d+)?[^\s"'`]*/gi;

interface HostRule {
  readonly test: RegExp;
  readonly severity: Severity;
  readonly reason: string;
}

const HOSTS: readonly HostRule[] = [
  { test: /(?:^|\.)(?:cipher-panel\.me|ciphercheats\.com)$/i, severity: 'critical', reason: 'known FiveM backdoor panel' },
  { test: /^\d{1,3}(?:\.\d{1,3}){3}$/, severity: 'medium', reason: 'raw IP address' },
  { test: /(?:^|\.)(?:pastebin\.com|hastebin\.com|hastebin\.skyra\.pw|paste\.ee|ghostbin\.\w+|rentry\.(?:co|org)|controlc\.com|privatebin\.net|dpaste\.\w+|termbin\.com)$/i, severity: 'high', reason: 'paste site often used to host payloads' },
  { test: /(?:^|\.)(?:ngrok\.io|ngrok-free\.app|ngrok\.app|trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt|transfer\.sh|file\.io|anonfiles\.com|temp\.sh)$/i, severity: 'high', reason: 'tunnel or anonymous file host' },
  { test: /(?:^|\.)(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|beeceptor\.com|hookbin\.com|interact\.sh|oast\.(?:fun|live|me|online|pro|site)|burpcollaborator\.net|canarytokens\.com)$/i, severity: 'high', reason: 'request capture service used for exfiltration' },
  { test: /(?:^|\.)(?:iplogger\.(?:org|com|ru|co)|grabify\.link|2no\.co|yip\.su|blasze\.tk)$/i, severity: 'high', reason: 'IP logger' },
  { test: /(?:^|\.)(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)$/i, severity: 'low', reason: 'raw file host' },
];

export const suspiciousHosts: Rule = {
  id: 'FS008',
  name: 'suspicious-endpoint',
  severity: 'medium',
  description: 'The resource talks to an endpoint commonly used by backdoors: known panels, paste sites, tunnels or raw IP addresses.',
  languages: ['lua', 'js', 'text'],
  check(file, report) {
    const whole = file.language === 'text' || /\.html?$/i.test(file.path);
    const sources = whole ? [{ value: file.text, offset: 0 }] : file.strings.map((s) => ({ value: s.value, offset: s.contentStart }));
    const reported = new Set<number>();
    for (const source of sources) {
      URL.lastIndex = 0;
      for (let m = URL.exec(source.value); m !== null; m = URL.exec(source.value)) {
        const host = m[1]!.toLowerCase();
        const rule = HOSTS.find((h) => h.test.test(host));
        if (rule === undefined) continue;
        if (rule.reason === 'raw IP address' && PRIVATE_IP.test(host)) continue;
        const offset = whole ? m.index : source.offset;
        if (reported.has(offset)) continue;
        reported.add(offset);
        report({ offset, length: Math.min(m[0].length, 80), severity: rule.severity, message: `Request target ${preview(m[0], 56)} (${rule.reason})` });
      }
    }
  },
};

export const legacyManifest: Rule = {
  id: 'FS009',
  name: 'legacy-manifest',
  severity: 'info',
  description: '__resource.lua is deprecated. Migrate to fxmanifest.lua with an fx_version so the resource keeps working with current server builds.',
  languages: ['lua'],
  check(file, report) {
    if (/(?:^|\/)__resource\.lua$/i.test(file.path)) {
      report({ offset: 0, length: 0, message: 'Deprecated __resource.lua manifest' });
    }
  },
};
