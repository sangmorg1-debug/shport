# Security policy

## Supported versions

Security fixes are made on the latest released version and the default branch.
Older releases may be asked to upgrade rather than receive a backport while
the project remains in v0 development.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/sangmorg1-debug/shport/security/advisories/new).
Include a minimal reproducer, affected version, impact, and any suggested
mitigation. Do not include secrets or production shell scripts that cannot be
shared safely.

If private vulnerability reporting is unavailable, open a minimal public issue
asking the maintainer to enable a private channel, without disclosing exploit
details.

## Security boundaries

`shport` parses untrusted shell text but is designed never to execute it or any
command it contains. Reports that parsing a file can cause command execution,
write outside an explicitly requested output path, or uncontrolled resource
consumption are security-relevant.

Ordinary false positives, missed portability forms, target-catalog mistakes,
and malformed-script parse errors are normally correctness issues, not
vulnerabilities. `shport` is not a security scanner or a proof that a script is
safe or portable.

Reports can contain input paths, literal command names, literal options, and
diagnostic messages. Treat JSON and SARIF artifacts according to the
sensitivity of repository paths and command lines in your environment.

Run the tool with the least filesystem privilege needed to read the intended
sources and write the selected output file.
