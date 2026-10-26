import { callAt, luaFunctionIn, matchBracket } from '../source.ts';
import type { Span } from '../source.ts';
import type { Rule, SourceFile } from '../types.ts';
import { SINK } from './net-events.ts';
import { identifiersIn, isMemberCall, literalArgument, matches } from './util.ts';

const REGISTER_COMMAND = /\bRegisterCommand\s*(?=\()/g;
const PERMISSION = /\b(?:IsPlayerAceAllowed|IsPrincipalAceAllowed|IsAceAllowed|getGroup|GetGroup|getPermissions|GetPermission|HasPermission|hasPermission|HasGroup|hasGroup|isAdmin|IsAdmin|IsPlayerAdmin|CheckPermission|checkPermission|isStaff|IsStaff)\b|\.group\b|\bgroup\s*==/;
const COMMAND_SINK = new RegExp(`${SINK.source}|\\bExecuteCommand\\s*(?=\\()`, 'g');

const CONVAR_READ = /\b(GetConvar|GetConvarInt)\s*\(\s*(["'`])(rcon_password|mysql_connection_string|sv_licenseKey|steam_webApiKey|sv_tebexSecret|txAdmin-\w+|[\w-]*(?:token|secret|password|apikey|api_key)[\w-]*)\2/gi;
const CONVAR_WRITE = /\b(SetConvar|SetConvarReplicated|SetConvarServerInfo)\s*\(\s*(["'`])(rcon_password|sv_licenseKey|sv_endpointPrivacy|sv_hostname|sv_master\d*)\2/gi;
const NETWORK = /\bPerformHttpRequest\b|\bfetch\s*\(|\baxios\b|\bhttps?\s*\.\s*(?:get|request)\s*\(/;
const DB_DRIVERS = /^(?:oxmysql|mysql-async|ghmattimysql|mongodb|ox_lib)$/i;

interface Command {
  readonly name: string;
  readonly params: readonly string[];
  readonly body: Span;
  readonly restricted: boolean;
}

function luaCommands(file: SourceFile): Command[] {
  const commands: Command[] = [];
  for (const m of matches(file.code, REGISTER_COMMAND)) {
    if (isMemberCall(file.code, m.index)) continue;
    const call = callAt(file.code, m.index + m[0].length);
    if (call === undefined || call.args[1] === undefined) continue;
    const fn = luaFunctionIn(file.code, call.args[1]);
    if (fn === undefined) continue;
    const flag = call.args[2] === undefined ? 'false' : file.code.slice(call.args[2].start, call.args[2].end).trim();
    commands.push({
      name: literalArgument(file, call.args[0])?.value ?? '?',
      params: fn.params,
      body: { start: fn.bodyStart, end: fn.bodyEnd },
      restricted: flag !== 'false' && flag !== 'nil',
    });
  }
  return commands;
}

function jsCommands(file: SourceFile): Command[] {
  const commands: Command[] = [];
  for (const m of matches(file.code, REGISTER_COMMAND)) {
    if (isMemberCall(file.code, m.index)) continue;
    const call = callAt(file.code, m.index + m[0].length);
    const fnSpan = call?.args[1];
    if (call === undefined || fnSpan === undefined) continue;
    const head = /^(?:async\s+)?(?:function\s*\w*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>)/.exec(file.code.slice(fnSpan.start, fnSpan.end));
    if (head === null) continue;
    const brace = file.code.indexOf('{', fnSpan.start + head[0].length);
    if (brace === -1 || brace >= fnSpan.end) continue;
    const close = matchBracket(file.code, brace);
    if (close === -1) continue;
    const flag = call.args[2] === undefined ? 'false' : file.code.slice(call.args[2].start, call.args[2].end).trim();
    commands.push({
      name: literalArgument(file, call.args[0])?.value ?? '?',
      params: (head[1] ?? head[2] ?? '').split(',').map((p) => p.replace(/[=:].*$/, '').trim()).filter(Boolean),
      body: { start: brace + 1, end: close },
      restricted: flag !== 'false' && flag !== 'undefined' && flag !== 'null',
    });
  }
  return commands;
}

export const unrestrictedCommand: Rule = {
  id: 'FS010',
  name: 'unrestricted-command',
  severity: 'high',
  description: 'A server command registered with restricted = false gives money, items, jobs or runs console commands without checking the caller. Any player can type it.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.side === 'client') return;
    const commands = file.language === 'lua' ? luaCommands(file) : jsCommands(file);
    for (const command of commands) {
      if (command.restricted) continue;
      const args = new Set(command.params.slice(1));
      for (const sink of matches(file.code, COMMAND_SINK, command.body.start, command.body.end)) {
        const before = file.code.slice(command.body.start, sink.index);
        if (PERMISSION.test(before)) continue;
        const call = callAt(file.code, sink.index + sink[0].length);
        const usesArgs = call !== undefined && [...identifiersIn(file.code, { start: call.open, end: call.close })].some((id) => args.has(id));
        const name = sink[1] ?? 'ExecuteCommand';
        report({
          offset: sink.index,
          length: name.length,
          severity: usesArgs ? 'high' : 'medium',
          message: `Command "/${command.name}" is unrestricted and calls ${name}()${usesArgs ? ' with player-supplied arguments' : ''} without a permission check`,
        });
      }
    }
  },
};

export const sensitiveConvar: Rule = {
  id: 'FS011',
  name: 'sensitive-convar',
  severity: 'medium',
  description: 'The resource reads or overwrites server secrets such as rcon_password, the database connection string or the license key. Backdoors read them to exfiltrate credentials.',
  languages: ['lua', 'js'],
  check(file, report) {
    const networked = NETWORK.test(file.code);
    for (const m of matches(file.text, CONVAR_READ)) {
      if (file.code[m.index] !== file.text[m.index]) continue;
      const name = m[3]!;
      if (/^mysql_connection_string$/i.test(name) && DB_DRIVERS.test(file.resource)) continue;
      report({
        offset: m.index,
        length: m[1]!.length,
        severity: networked ? 'critical' : 'medium',
        message: `Reads convar "${name}"${networked ? ' in a file that also sends network requests' : ''}`,
      });
    }
    for (const m of matches(file.text, CONVAR_WRITE)) {
      if (file.code[m.index] !== file.text[m.index]) continue;
      report({ offset: m.index, length: m[1]!.length, severity: /rcon_password|sv_licenseKey/i.test(m[3]!) ? 'critical' : 'high', message: `Overwrites server convar "${m[3]}"` });
    }
  },
};
