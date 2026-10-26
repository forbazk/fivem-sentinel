import { callAt, hasTopLevel, stringsWithin } from '../source.ts';
import type { Span } from '../source.ts';
import type { Rule, SourceFile } from '../types.ts';
import { matches } from './util.ts';

const LUA_QUERY = /\bMySQL\s*\.\s*(?:Async|Sync)\s*\.\s*\w+\s*(?=\()|\bMySQL\s*\.\s*(?:query|single|scalar|insert|update|prepare|execute|transaction|rawExecute|fetch)(?:\s*\.\s*await)?\s*(?=\()|\bexports\s*(?:\.\s*\w+|\[\s*["'][^"']*["']\s*\])\s*:\s*(?:query|single|scalar|insert|update|prepare|execute|fetch|transaction|rawExecute|query_async|execute_async|scalar_async|insert_async|single_async)\w*\s*(?=\()/g;
const JS_QUERY = /\b(?:MySQL|oxmysql|exports\s*\.\s*oxmysql|exports\s*\[\s*["'][^"']*["']\s*\]|db|pool|connection|conn|knex)\s*\.\s*(?:query|execute|single|scalar|insert|update|prepare|rawExecute|raw)\s*(?=\()/g;
const DB_EXPORT = /oxmysql|ghmattimysql|mysql-async|mysql/i;
const SQL_WORD = /\b(?:select|insert|update|delete|replace|where|from|into|values|set|order\s+by|limit)\b/i;
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;
const LOOKBACK = 4000;

function looksLikeSql(file: SourceFile, span: Span): boolean {
  return stringsWithin(file.strings, span).some((s) => SQL_WORD.test(s.value));
}

function unsafeConstruction(file: SourceFile, span: Span): string | undefined {
  const code = file.code.slice(span.start, span.end);
  if (file.language === 'lua') {
    if (hasTopLevel(file.code, span, '..')) return 'string concatenation';
    if (/(?:\bstring\s*\.\s*format|:\s*format)\s*\(/.test(code) && stringsWithin(file.strings, span).some((s) => /%s/.test(s.value))) return 'string.format';
    return undefined;
  }
  if (stringsWithin(file.strings, span).filter((s) => s.template).length > 1) return 'template literal interpolation';
  if (hasTopLevel(file.code, span, '+')) return 'string concatenation';
  return undefined;
}

function assignmentBefore(file: SourceFile, name: string, before: number): Span | undefined {
  const from = Math.max(0, before - LOOKBACK);
  const escaped = name.replace(/\$/g, '\\$');
  const pattern = new RegExp(`(?<![\\w$.:])${escaped}\\s*\\+?=(?!=)\\s*`, 'g');
  let last: RegExpExecArray | undefined;
  for (const m of matches(file.code, pattern, from, before)) last = m;
  if (last === undefined) return undefined;
  const start = last.index + last[0].length;
  let end = start;
  let depth = 0;
  while (end < before) {
    const c = file.code[end]!;
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth <= 0 && (c === ';' || c === '\n') && !/(?:\.\.|\+)\s*$/.test(file.code.slice(start, end)) && !/^\s*(?:\.\.|\+)/.test(file.code.slice(end + 1, end + 40))) break;
    end++;
  }
  return { start, end };
}

export const sqlInjection: Rule = {
  id: 'FS005',
  name: 'sql-injection',
  severity: 'high',
  description: 'A SQL query is assembled with string concatenation, string.format or template literals. Use parameter placeholders (?) so player input can never change the query.',
  languages: ['lua', 'js'],
  check(file, report) {
    const pattern = file.language === 'lua' ? LUA_QUERY : JS_QUERY;
    for (const m of matches(file.code, pattern)) {
      if (m[0].startsWith('exports') && !DB_EXPORT.test(file.text.slice(m.index, m.index + m[0].length))) continue;
      const call = callAt(file.code, m.index + m[0].length);
      const arg = call?.args[0];
      if (arg === undefined) continue;
      const argCode = file.code.slice(arg.start, arg.end);
      let span: Span | undefined = arg;
      let via = '';
      if (IDENTIFIER.test(argCode)) {
        span = assignmentBefore(file, argCode, m.index);
        via = ` (via "${argCode}")`;
      }
      if (span === undefined) continue;
      const how = unsafeConstruction(file, span);
      if (how === undefined || !looksLikeSql(file, span)) continue;
      report({ offset: m.index, length: m[0].trim().length, message: `SQL query built with ${how}${via}; use ? placeholders` });
    }
  },
};
