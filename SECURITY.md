# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems in fivem-sentinel itself.
Use GitHub's private vulnerability reporting instead: **Security → Report a vulnerability** on this repository.

Include the version, a minimal reproduction and the impact you observed. You will get an answer within a few days.

## Reporting a missed backdoor or false negative

If fivem-sentinel fails to detect a malicious pattern, open an issue with a minimal, defanged sample.
Never attach live payloads, working credentials or links to active backdoor panels.

## Scope

fivem-sentinel only reads files. It never executes, imports or evaluates the code it scans and does not follow symbolic links.
A finding or a clean report is a static signal, not a guarantee.
