# Changelog

## 0.3.0

### Changed

- The project is renamed from fivem-audit to fivem-sentinel. The command, package and repository now use the new name.
- Rule IDs move from `FA001`–`FA011` to `FS001`–`FS011`, and suppression comments become `fivem-sentinel-ignore` and `fivem-sentinel-ignore-file`. Update existing comments and `--rules` filters.

## 0.2.0

### Security

- Secrets are now redacted in the snippet of every finding, not only FA004 findings.
- Terminal control sequences and invisible characters in file names, messages and snippets are neutralised in text reports.
- Each file is opened once and checked through its handle, removing the gap between size, binary and content checks.

### Detection

- FA001 sees through `_G.load`, `_ENV.loadstring`, `window.eval`, `globalThis.eval`, aliased loaders, `pcall(load, …)`, `(0, eval)`, parenthesis-less `load "…"` calls and string timers.
- FA002 follows named callbacks passed to `PerformHttpRequest` and checks every network call in JavaScript files.
- FA003 detects Trojan Source bidirectional controls and invisible characters, ignores escaped non-ASCII text and long Lua data lines.
- FA005 follows queries assembled in a variable before the call; `string.format` is only reported for `%s`.
- FA006 tracks client values through local copies, watches removal functions, and only downgrades when the flowing value itself is validated.
- FA007 rates file access below shell access and detects native process bindings.
- FA008 adds request capture services and IP loggers, and reads URLs in HTML attributes.
- New FA010 `unrestricted-command`: unrestricted `RegisterCommand` handlers that give value or run console commands without a permission check.
- New FA011 `sensitive-convar`: reads of secret convars and writes to critical server convars.
- Inline `<script>` blocks in `.html` NUI pages are analyzed.

### Scanner

- Bounded directory traversal, case-insensitive skip of `stream` folders, deduplication of overlapping roots.
- Skipped files are reported with a reason (`too-large`, `binary`, `unreadable`); `--verbose` lists them.
- Ignore patterns without a slash match names anywhere; trailing slashes are accepted.
- Missing paths fail with a clear message.
- SARIF locations are relative to the working directory, so code scanning annotations resolve when a subfolder is scanned.
- `FORCE_COLOR` is honoured.
- Faster Lua and JavaScript lexers and cached secret detection: the 135 MB benchmark runs in 2.8 s instead of 2.9 s despite two extra rules.

### Project

- CI actions are pinned to commit SHAs, credentials are not persisted, the build runs on Node 20 and the scanner audits its own sources.

## 0.1.0

- Initial release with rules FA001 to FA009.
- Lua and JavaScript lexers that mask comments and strings while preserving offsets.
- fxmanifest-aware server/client detection.
- Text, JSON and SARIF 2.1.0 reports with per-resource scores.
- Inline and file-level suppressions.
