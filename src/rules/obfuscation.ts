import { callAt, stringAt } from '../source.ts';
import type { Rule, StringLiteral } from '../types.ts';
import { isMemberCall, matches, preview } from './util.ts';

const SENSITIVE = /PerformHttpRequest|loadstring|\bload\b|\bassert\b|RegisterCommand|ExecuteCommand|os\.execute|io\.popen|\b_G\b|\brequire\b|\beval\b|\bFunction\b|child_process|https?:\/\/|GetConvar|sv_licenseKey|rcon_password|webhook/;
const STRING_CHAR = /\bstring\s*\.\s*char\s*(?=\()/g;
const GLOBAL_INDEX = /\b(_G|_ENV|getfenv\s*\(\s*\d*\s*\))\s*\[/g;
const INVISIBLE = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/g;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const LUA_CODE_WORD = /\b(?:function|local|end|then|return|if|for|while|do)\b/g;
const MIN_ESCAPES = 12;
const LONG_LINE = 2500;
const MINIFIED = /\.min\.js$|(?:^|\/)(?:html|ui|web|nui|dist|build)\//i;

function printableAscii(value: string): number {
  let printable = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13) printable++;
  }
  return value.length === 0 ? 0 : printable / value.length;
}

function hidesCode(literal: StringLiteral): boolean {
  return literal.escapes >= MIN_ESCAPES && literal.escapes >= literal.value.length * 0.6 && printableAscii(literal.value) >= 0.9;
}

export const obfuscation: Rule = {
  id: 'FS003',
  name: 'obfuscated-code',
  severity: 'high',
  description: 'Escaped byte strings, string.char chains, dynamic global lookups, invisible or bidirectional characters and packed lines that hide what the code really does.',
  languages: ['lua', 'js'],
  check(file, report) {
    for (const literal of file.strings) {
      if (!hidesCode(literal)) continue;
      const hidden = SENSITIVE.test(literal.value);
      report({
        offset: literal.start,
        length: Math.min(literal.contentEnd - literal.contentStart + 2, 80),
        severity: hidden ? 'critical' : 'high',
        message: hidden ? `Escaped string hides "${preview(literal.value, 48)}"` : `String encoded as ${literal.escapes} byte escapes`,
      });
    }

    for (const m of matches(file.text, INVISIBLE)) {
      if (m.index === 0 && m[0] === '\uFEFF') continue;
      const bidi = BIDI.test(m[0]);
      const inCode = file.code[m.index] === file.text[m.index];
      report({
        offset: m.index,
        length: 1,
        severity: bidi ? (inCode ? 'critical' : 'high') : inCode ? 'high' : 'low',
        message: bidi
          ? `Bidirectional control character U+${m[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')} can make code display differently than it runs (Trojan Source)`
          : `Invisible character U+${m[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')} ${inCode ? 'inside code can hide identifiers' : 'inside a string'}`,
      });
    }

    if (file.language === 'lua') {
      for (const m of matches(file.code, STRING_CHAR)) {
        const call = callAt(file.code, m.index + m[0].length);
        if (call === undefined || call.args.length < 8) continue;
        const bytes = call.args.map((a) => file.code.slice(a.start, a.end).trim());
        if (!bytes.every((b) => /^(?:\d{1,3}|0x[0-9a-fA-F]{1,2})$/.test(b))) continue;
        const decoded = String.fromCharCode(...bytes.map((b) => Number(b) & 0xff));
        report({
          offset: m.index,
          length: m[0].length,
          severity: SENSITIVE.test(decoded) ? 'critical' : 'high',
          message: `string.char() builds "${preview(decoded, 48)}" from ${bytes.length} bytes`,
        });
      }
      for (const m of matches(file.code, GLOBAL_INDEX)) {
        if (isMemberCall(file.code, m.index)) continue;
        const open = m.index + m[0].length - 1;
        let close = open;
        let depth = 0;
        for (; close < file.code.length; close++) {
          if (file.code[close] === '[') depth++;
          else if (file.code[close] === ']' && --depth === 0) break;
        }
        const inner = file.code.slice(open + 1, close);
        const trimmed = inner.trim();
        const start = open + 1 + inner.indexOf(trimmed);
        const literal = stringAt(file.strings, { start, end: start + trimmed.length });
        if (literal !== undefined && literal.escapes === 0) continue;
        report({
          offset: m.index,
          length: m[0].length,
          severity: literal !== undefined ? (SENSITIVE.test(literal.value) ? 'critical' : 'high') : 'low',
          message: literal !== undefined ? `${m[1]} indexed with escaped name "${preview(literal.value, 32)}"` : `${m[1]} indexed with a computed name hides which global is used`,
        });
      }
    }

    if (file.language === 'js' && MINIFIED.test(file.path)) return;
    let lineStart = 0;
    while (lineStart <= file.text.length) {
      const next = file.text.indexOf('\n', lineStart);
      const end = next === -1 ? file.text.length : next;
      if (end - lineStart > LONG_LINE) {
        const segment = file.code.slice(lineStart, end);
        const dense = file.language === 'lua' ? (segment.match(LUA_CODE_WORD)?.length ?? 0) >= 8 : /\beval\s*\(|\bnew\s+Function\s*\(/.test(segment);
        if (dense) report({ offset: lineStart, length: 1, severity: 'medium', message: `Packed line of ${end - lineStart} characters` });
      }
      if (next === -1) break;
      lineStart = next + 1;
    }
  },
};
