# fivem-sentinel

Static security scanner for FiveM resources. Point it at your `resources` folder and it reports backdoors, exploitable server events, SQL injection, leaked credentials and obfuscated code before they reach your server.

- **Zero runtime dependencies.** Nothing to trust but Node.js itself.
- **Never executes what it scans.** Files are only read and tokenized; symlinks are not followed.
- **Understands Lua, JavaScript and NUI pages.** Comments and string contents are masked by a real lexer, so a `load()` inside a comment is not a finding and a `PerformHttpRequest` hidden in `\x50\x65…` escapes is. Inline `<script>` blocks in `.html` files are analyzed too.
- **Hard to fool.** Sees through `_G.load`, `window.eval`, aliased loaders, named HTTP callbacks, values copied into local variables and Trojan Source bidirectional characters.
- **Manifest aware.** `fxmanifest.lua` globs decide which files run on the server, so client-only code does not raise server-side alerts.
- **Safe output.** Secrets are redacted in every snippet and terminal control sequences are neutralised, so a malicious file cannot leak or inject anything through the report.
- **Fast.** 135 MB of Lua across 3,000 files in under 3 seconds on a desktop CPU.
- **CI ready.** Text, JSON and SARIF output, meaningful exit codes, GitHub code scanning support.

```
$ npx github:forbazk/fivem-sentinel ./resources

fivem-sentinel 0.3.0  1 resource · 3 files · 1 KiB · 0.02s

vulnerable_shop  0/100 F  vulnerable_shop
   CRITICAL  FS003  string.char() builds "PerformHttpRequest" from 18 bytes
             vulnerable_shop/server/main.lua:12:11
   CRITICAL  FS002  PerformHttpRequest callback passes the response to load(): remote code execution
             vulnerable_shop/server/main.lua:14:1
   CRITICAL  FS008  Request target https://cipher-panel.me/_i/i?to=shop (known FiveM backdoor panel)
             vulnerable_shop/server/main.lua:14:21
   HIGH      FS006  Net event "shop:buy" passes client value "item", "amount" to addInventoryItem() without validating it
             vulnerable_shop/server/main.lua:3:11
   HIGH      FS005  SQL query built with string concatenation; use ? placeholders
             vulnerable_shop/server/main.lua:7:3
   HIGH      FS001  load() compiles a runtime value in a file that also performs HTTP requests
             vulnerable_shop/server/main.lua:15:16
   HIGH      FS010  Command "/shopcash" is unrestricted and calls addMoney() with player-supplied arguments without a permission check
             vulnerable_shop/server/main.lua:20:11
   MEDIUM    FS004  Possible secret assigned to "LogApiKey"
             vulnerable_shop/config.lua:4:21

Summary  3 critical · 4 high · 1 medium
```

The sample above comes from [`examples/vulnerable_shop`](examples/vulnerable_shop).

## Install

Requires Node.js 20 or newer.

```sh
npx github:forbazk/fivem-sentinel ./resources
```

Or clone and build:

```sh
git clone https://github.com/forbazk/fivem-sentinel
cd fivem-sentinel
npm ci
npm run build
node dist/cli.js /path/to/resources
```

## Usage

```
fivem-sentinel [paths...] [options]

  -f, --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>              Write the report to a file
      --fail-on <severity>         Exit with code 1 at or above this severity (default: high, "none" to disable)
      --min-severity <severity>    Hide findings below this severity (default: low)
      --rules <ids>                Only run these rules, comma separated
      --exclude-rules <ids>        Skip these rules, comma separated
  -i, --ignore <glob>              Ignore paths matching the glob (repeatable)
      --max-file-size <kb>         Skip files larger than this (default: 2048)
  -j, --concurrency <n>            Files read in parallel (default: auto)
      --no-color                   Disable colors (NO_COLOR and FORCE_COLOR are honoured)
      --verbose                    List skipped files and the reason
      --list-rules                 Print the rule catalog and exit
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or runtime error.

Each resource gets a score out of 100 (critical −40, high −15, medium −5, low −1) and a grade from A to F, so the worst offenders are listed first.

## Rules

| ID | Severity | Detects |
| --- | --- | --- |
| <a id="fs001"></a>FS001 | low–high | `load`, `loadstring`, `dofile`, `eval`, `new Function`, string timers, and loaders reached through `_G`, `window` or aliases. Escalated when the same file makes HTTP requests, lowered for constants and files bundled with the resource. |
| <a id="fs002"></a>FS002 | critical | An HTTP response executed as code, including through a named callback: the classic remote-controlled backdoor. |
| <a id="fs003"></a>FS003 | low–critical | Byte-escaped strings, `string.char` chains, `_G[...]` lookups, packed lines, invisible characters and Trojan Source bidirectional controls. Critical when the hidden text is an API name such as `PerformHttpRequest`. |
| <a id="fs004"></a>FS004 | medium–critical | Discord webhooks and bot tokens, GitHub, Stripe, AWS and Slack keys, private keys, `sv_licenseKey`, Steam Web API keys, database passwords. Values are redacted in every report. |
| <a id="fs005"></a>FS005 | high | oxmysql, mysql-async and ghmattimysql queries built with `..`, `string.format` or template literals instead of `?` placeholders, including queries assembled in a variable first. |
| <a id="fs006"></a>FS006 | medium–high | `RegisterNetEvent` / `onNet` handlers that pass client arguments, directly or through local copies, into money, item, weapon, job or permission functions. Removal functions count too: a negative amount turns `removeMoney` into free money. Downgraded only when the flowing value itself is checked. |
| <a id="fs007"></a>FS007 | medium–critical | `os.execute`, `io.popen`, file access, `child_process`, native process bindings, and `ExecuteCommand` built from runtime values. |
| <a id="fs008"></a>FS008 | low–critical | Requests to known backdoor panels, paste sites, tunnels, request capture services, IP loggers and raw public IP addresses, in code and in HTML attributes. |
| <a id="fs009"></a>FS009 | info | Deprecated `__resource.lua` manifests. |
| <a id="fs010"></a>FS010 | medium–high | `RegisterCommand` with `restricted = false` that gives money, items or jobs, or runs console commands, without any permission check. |
| <a id="fs011"></a>FS011 | medium–critical | Reads of `rcon_password`, the database connection string, the license key or other secret convars, and writes to critical server convars. Critical when the file also sends network requests. |

## Suppressing findings

Add a comment on the same line or the line above:

```lua
local fn = load(chunk) -- fivem-sentinel-ignore FS001
```

Omit the rule ID to silence every rule on that line. Put `fivem-sentinel-ignore-file` in the first lines of a file to skip it entirely.

## GitHub Actions

```yaml
name: Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  fivem-sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 22
      - run: npx --yes github:forbazk/fivem-sentinel#v0.3.0 . --format sarif --output fivem-sentinel.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: fivem-sentinel.sarif
```

Findings then appear in the repository's **Security → Code scanning** tab and as annotations on pull requests.

## Programmatic API

```ts
import { scan, formatSarif } from 'fivem-sentinel';

const result = await scan(['./resources'], { minSeverity: 'medium' });
for (const resource of result.resources) {
  console.log(resource.name, resource.score, resource.findings.length);
}
```

## Limitations

fivem-sentinel is a static analyzer built on lexing and targeted pattern analysis, not a full interpreter. It catches the patterns real backdoors and exploits rely on, but a determined author can still hide code from it. Treat a clean report as a strong signal, not a guarantee, and keep reviewing resources from untrusted sources by hand.

## License

[MIT](LICENSE)
