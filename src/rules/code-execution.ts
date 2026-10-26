import { callAt, hasTopLevel, luaBlockEnd } from '../source.ts';
import type { Span } from '../source.ts';
import type { Rule, SourceFile } from '../types.ts';
import { isGlobalCall, isPureLiteral, matches } from './util.ts';

const LUA_GLOBALS = new Set(['_G', '_ENV']);
const JS_GLOBALS = new Set(['window', 'globalThis', 'global', 'self']);

const LUA_LOADERS = /\b(loadstring|load|dofile|loadfile)\s*(?=\()/g;
const LUA_LOADER_ALIAS = /(?:[=,{(]|\breturn)\s*(?:_G\s*\.\s*|_ENV\s*\.\s*)?(loadstring|load)\b(?!\s*(?:\(|=[^=]|["'[{]))/g;
const LUA_LOADER_SUGAR = /\b(loadstring|load)\s*(?=["']|\[=*\[)/g;
const LUA_HTTP_ANY =/\bPerformHttpRequest\b/;
const LUA_HTTP = /\bPerformHttpRequest\s*(?=\()/g;
const LUA_EXEC = /\b(load|loadstring)\s*\(/;
const LUA_OS = /\b(os|io)\s*\.\s*(execute|popen|remove|rename|open|lines|exit)\s*(?=\()/g;
const LUA_COMMAND = /\bExecuteCommand\s*(?=\()/g;

const JS_EVAL = /\beval\s*(?=\()|\bnew\s+Function\s*(?=\()|\bFunction\s*(?=\()|\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*(?=\()|\bnew\s+vm\s*\.\s*Script\s*(?=\()/g;
const JS_EVAL_ALIAS = /(?:[=,(]|\breturn)\s*(?:(?:window|globalThis|global|self)\s*\.\s*)?eval\b(?!\s*(?:\(|:|=[^=]))|\(\s*0\s*,\s*eval\s*\)/g;
const JS_TIMER = /\b(setTimeout|setInterval)\s*(?=\()/g;
const JS_CHILD = /\brequire\s*\(\s*(["'`])(?:node:)?child_process\1\s*\)|\bfrom\s+(["'])(?:node:)?child_process\2|\bimport\s*\(\s*(["'`])(?:node:)?child_process\3\s*\)/g;
const JS_BINDING = /\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*(?=\()/g;
const JS_NET = /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|request))?|https?\s*\.\s*(?:get|request)|PerformHttpRequest|request)\s*\(/g;
const JS_RUN = /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*run\w*\s*\(/;

function namedFunctionBody(file: SourceFile, name: string): Span | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?:\\bfunction\\s+${escaped}\\s*\\(|\\b${escaped}\\s*=\\s*function\\s*\\()[^)]*\\)`, 'g');
  const m = pattern.exec(file.code);
  if (m === null) return undefined;
  const start = m.index + m[0].length;
  return { start, end: luaBlockEnd(file.code, start) };
}

export const dynamicCode: Rule = {
  id: 'FS001',
  name: 'dynamic-code-execution',
  severity: 'medium',
  description: 'Code is compiled or executed at runtime (load, loadstring, dofile, eval, new Function). This is the core primitive of almost every FiveM backdoor.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.language === 'lua') {
      const networked = LUA_HTTP_ANY.test(file.code);
      for (const m of matches(file.code, LUA_LOADERS)) {
        if (!isGlobalCall(file.code, m.index, LUA_GLOBALS)) continue;
        const name = m[1]!;
        const call = callAt(file.code, m.index + m[0].length);
        if (call === undefined) continue;
        if (name === 'dofile' || name === 'loadfile') {
          report({ offset: m.index, length: name.length, severity: 'medium', message: `${name}() loads and runs Lua from disk at runtime` });
          continue;
        }
        const arg = call.args[0];
        const argCode = arg === undefined ? '' : file.text.slice(arg.start, arg.end);
        if (isPureLiteral(file, arg)) {
          report({ offset: m.index, length: name.length, severity: 'low', message: `${name}() compiles a constant string; prefer plain code` });
        } else if (/\bLoadResourceFile\s*\(\s*GetCurrentResourceName\s*\(\s*\)/.test(argCode)) {
          report({ offset: m.index, length: name.length, severity: 'low', message: `${name}() runs a file bundled with this resource` });
        } else {
          report({
            offset: m.index,
            length: name.length,
            severity: networked ? 'high' : 'medium',
            message: networked ? `${name}() compiles a runtime value in a file that also performs HTTP requests` : `${name}() compiles a runtime value into executable code`,
          });
        }
      }
      for (const m of matches(file.code, LUA_LOADER_SUGAR)) {
        if (!isGlobalCall(file.code, m.index, LUA_GLOBALS)) continue;
        report({ offset: m.index, length: m[1]!.length, message: `${m[1]} called without parentheses on an inline chunk` });
      }
      for (const m of matches(file.code, LUA_LOADER_ALIAS)) {
        const at = m.index + m[0].lastIndexOf(m[1]!);
        const target = /([A-Za-z_]\w*)\s*=\s*(?:_G\s*\.\s*|_ENV\s*\.\s*)?$/.exec(file.code.slice(Math.max(0, at - 80), at));
        if (target?.[1] === m[1]) continue;
        report({ offset: at, length: m[1]!.length, severity: 'high', message: `${m[1]} is referenced as a value (aliased or passed around), hiding later dynamic execution` });
      }
      return;
    }
    const networked = new RegExp(JS_NET.source).test(file.code);
    for (const m of matches(file.code, JS_EVAL)) {
      const head = m[0].trim();
      if (!head.startsWith('new') && !isGlobalCall(file.code, m.index, JS_GLOBALS)) continue;
      if (head.startsWith('Function') && /\bnew\s+$/.test(file.code.slice(Math.max(0, m.index - 6), m.index))) continue;
      report({
        offset: m.index,
        length: head.length,
        severity: networked ? 'high' : 'medium',
        message: `${head}() executes a runtime string as code${networked ? ' in a file that also performs network requests' : ''}`,
      });
    }
    for (const m of matches(file.code, JS_EVAL_ALIAS)) {
      const at = m.index + m[0].lastIndexOf('eval');
      report({ offset: at, length: 4, severity: 'high', message: 'eval is referenced indirectly, hiding later dynamic execution' });
    }
    for (const m of matches(file.code, JS_TIMER)) {
      if (!isGlobalCall(file.code, m.index, JS_GLOBALS)) continue;
      const call = callAt(file.code, m.index + m[0].length);
      const arg = call?.args[0];
      if (arg === undefined) continue;
      if (!isPureLiteral(file, arg) && !hasTopLevel(file.code, arg, '+')) continue;
      report({ offset: m.index, length: m[1]!.length, message: `${m[1]}() with a string argument evaluates it as code` });
    }
  },
};

export const remoteExecution: Rule = {
  id: 'FS002',
  name: 'remote-code-execution',
  severity: 'critical',
  description: 'An HTTP response is executed as code. This is the signature of remote-controlled backdoors that let a third party run arbitrary code on the server.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.language === 'lua') {
      for (const m of matches(file.code, LUA_HTTP)) {
        if (!isGlobalCall(file.code, m.index, LUA_GLOBALS)) continue;
        const call = callAt(file.code, m.index + m[0].length);
        if (call === undefined) continue;
        const callback = call.args[1];
        const callbackCode = callback === undefined ? '' : file.code.slice(callback.start, callback.end);
        const body: Span | undefined = /^[A-Za-z_][\w.]*$/.test(callbackCode) ? namedFunctionBody(file, callbackCode) : { start: call.open, end: call.close };
        if (body !== undefined && LUA_EXEC.test(file.code.slice(body.start, body.end))) {
          report({ offset: m.index, length: 18, message: 'PerformHttpRequest callback passes the response to load(): remote code execution' });
        }
      }
      return;
    }
    let reportedUntil = -1;
    for (const net of matches(file.code, JS_NET)) {
      if (net.index < reportedUntil) continue;
      const window = file.code.slice(net.index, net.index + 4000);
      const run = JS_RUN.exec(window);
      if (run === null) continue;
      report({ offset: net.index + run.index, length: run[0].length, message: 'Network response flows into dynamic code execution: remote code execution' });
      reportedUntil = net.index + run.index + run[0].length;
    }
  },
};

export const systemAccess: Rule = {
  id: 'FS007',
  name: 'system-access',
  severity: 'critical',
  description: 'Shell commands, process spawning or raw filesystem access from a resource. FiveM resources almost never need this; malware uses it to persist and spread.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.language === 'lua') {
      for (const m of matches(file.code, LUA_OS)) {
        if (!isGlobalCall(file.code, m.index, LUA_GLOBALS)) continue;
        const fn = `${m[1]}.${m[2]}`;
        const severity = fn === 'os.execute' || fn === 'io.popen' ? 'critical' : fn === 'os.remove' || fn === 'os.rename' ? 'high' : 'medium';
        report({ offset: m.index, length: m[0].length, severity, message: `${fn}() gives the resource ${severity === 'critical' ? 'shell access' : 'direct filesystem or process access'}` });
      }
      for (const m of matches(file.code, LUA_COMMAND)) {
        if (!isGlobalCall(file.code, m.index, LUA_GLOBALS)) continue;
        const call = callAt(file.code, m.index + m[0].length);
        const arg = call?.args[0];
        if (arg === undefined || isPureLiteral(file, arg)) continue;
        const built = hasTopLevel(file.code, arg, '..') || /\bformat\s*\(/.test(file.code.slice(arg.start, arg.end));
        report({
          offset: m.index,
          length: 14,
          severity: built ? 'high' : 'medium',
          message: built ? 'ExecuteCommand() runs a console command built from runtime values' : 'ExecuteCommand() runs a console command from a variable',
        });
      }
      return;
    }
    for (const m of matches(file.text, JS_CHILD)) {
      if (file.code[m.index] !== file.text[m.index]) continue;
      report({ offset: m.index, length: m[0].length, message: 'child_process gives the resource shell access' });
    }
    for (const m of matches(file.code, JS_BINDING)) {
      report({ offset: m.index, length: m[0].trim().length, message: 'Native process bindings bypass the Node.js sandbox' });
    }
  },
};
