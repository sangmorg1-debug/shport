# shport

`shport` is a conservative static linter for external utility invocations in
shell scripts. It catches a small, evidence-backed set of command-line forms
whose behavior differs across GNU, macOS, FreeBSD, BusyBox, and POSIX
userlands.

```text
scripts/release.sh:12:5: SP1001: sed -i without a separate backup suffix uses the GNU form [targets: freebsd-14.1, macos-14]
```

ShellCheck checks shell language and many scripting mistakes. `shport`
complements it by checking selected external-command interfaces. It is not a
replacement for ShellCheck, tests on supported systems, or a complete
portability verifier.

## Status

This repository contains an early v0.1 implementation. Its deliberately
bounded catalog currently has 12 rules for literal invocations of `sed`,
`readlink`, `stat`, `date`, `xargs`, and `grep`. See
[the rule catalog](docs/rules.md) for exact coverage.

Important constraints:

- `shport` never executes the script or the commands it finds.
- It does not evaluate variables, command output, aliases, sourced files, or
  dynamically constructed command names and options.
- It does not reason about control flow or platform guards. Commands inside
  `if`, `case`, functions, and unreachable branches are checked against the
  same selected targets.
- A clean run means that no implemented rule matched. It does not prove that a
  script is portable.

## Build and install

Go 1.23 or newer is required.

From a checkout:

```bash
go build -o ./bin/shport ./cmd/shport
./bin/shport version
```

After a tagged release is available, it can also be installed with:

```bash
go install github.com/sangmorg1-debug/shport/cmd/shport@latest
```

## Quick start

Check a file or directory against the default `portable` target set:

```bash
shport scripts/
```

Check compatibility with specific userlands:

```bash
shport --target gnu --target macos scripts/
shport -t macos11,busybox install.sh
shport --target posix script.sh
```

Read standard input:

```bash
shport --target freebsd --stdin-filename install.sh - < install.sh
```

Machine-readable output:

```bash
shport --format json scripts/
shport --format sarif --output shport.sarif scripts/
```

List the embedded target profiles and rules:

```bash
shport targets
shport targets --format json
shport --list-rules
shport --list-rules --format json
```

## CLI

```text
shport [flags] [FILE|DIR|-]...
shport targets [--format text|json]
shport version

  -t, --target ID[,ID...]  required targets; repeatable (default: portable)
  -f, --format FORMAT      text, json, or sarif
  -o, --output FILE        output file (default: stdout)
      --shell MODE         auto, posix, or bash
      --exclude GLOB       directory-discovery exclusion; repeatable
      --stdin-filename     display name and dialect hint for stdin
      --exit-zero          report findings without returning exit code 1
      --list-rules         print the rule catalog
      --version            print the version
```

There is intentionally no configuration-file support in v0. Analysis policy
is supplied on the command line or by the calling CI/pre-commit configuration.

Targets may be aliases such as `gnu` and `macos`, or stable IDs such as
`gnu-2026` and `macos-14`. With no `--target`, `portable` expands to GNU,
macOS 14, FreeBSD 14.1, and BusyBox 1.36.1. Profiles and their primary sources
are documented in [docs/profiles.md](docs/profiles.md).

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Analysis completed with no findings, or `--exit-zero` was used. |
| `1` | One or more unsuppressed portability findings. |
| `2` | The invocation or analysis was incomplete, such as a bad target, unreadable input, or shell parse error. |

When some inputs cannot be analyzed, `shport` still reports safe results from
the other inputs and returns 2. JSON and SARIF include the analysis errors.

### Output formats

Text output is one deterministic, compiler-style line per finding. JSON uses
`schemaVersion: 1` and includes tool metadata, resolved profile objects, the
number of successfully analyzed files, diagnostics, and analysis errors. SARIF
output conforms to SARIF 2.1.0, embeds the rule catalog, uses Unicode-code-point
columns, and includes a partial fingerprint for each result. Source ranges are
one-based and end-exclusive. The JSON contract is published as
[`schema/shport-report-v1.schema.json`](schema/shport-report-v1.schema.json).

## Input discovery

Explicit files are always analyzed, regardless of name. Directory inputs are
walked recursively and include:

- files ending in `.sh`, `.bash`, or `.bats`; and
- extensionless files with a recognized `sh`, `bash`, `dash`, or `ash`
  shebang.

Directory discovery does not follow symlinks and always skips `.git`, `.hg`,
`.svn`, `.venv`, `node_modules`, and `vendor`. v0 does **not** read
`.gitignore`.

`--exclude` uses Go `path.Match` segment syntax plus `**` for recursive path
segments, and is evaluated relative to each directory input. A pattern without
`/` is also matched against the entry basename. Quote patterns so that the
calling shell does not expand them:

```bash
shport --exclude '**/generated/**' --exclude '*.fixture.sh' .
```

In `--shell auto` mode, `.bash`, `.bats`, and a Bash shebang select the Bash
grammar; other inputs use the POSIX grammar. Use `--shell bash` or
`--shell posix` to force one grammar for all inputs.

## What static analysis means here

`shport` analyzes literal simple commands anywhere in the parsed syntax tree,
including command substitutions and function bodies. Literal `command` and
`env` wrappers are understood, as is `busybox APPLET ...`. Calls to a function
declared with the same name in the file are skipped unless `command` or an
accepted system path (`/bin` or `/usr/bin`) explicitly
bypasses it.

The analyzer deliberately does not infer that a branch is safe for one
platform:

```bash
case "$(uname -s)" in
  Darwin) stat -f '%z' "$file" ;;
  Linux)  stat -c '%s' "$file" ;;
esac
```

Both `stat` calls are checked against every selected target. This avoids
unsound guesses about runtime conditions, but it can report intentional
platform-specific code. Suppress that exact finding after reviewing the guard,
or run separate checks with the appropriate target selection.

Likewise, runtime-dependent words are left alone:

```bash
grep "$grep_mode" pattern file  # dynamic option: not diagnosed
$utility -P pattern file        # dynamic command: not diagnosed
```

## Suppressions

Suppressions name stable rule IDs. `all` is accepted when a narrowly scoped
line or file intentionally opts out of the complete catalog.

```bash
grep -P pattern file  # shport: ignore=SP1501

# shport: ignore-next-line=SP1201
stat -c '%s' "$file"

# shport: ignore-file=SP1501
```

`ignore` applies to diagnostics starting on the same physical line.
`ignore-next-line` applies to the next physical line. `ignore-file` applies to
the parsed file. Unknown rule IDs and malformed directives are analysis errors
rather than silent suppressions.

## CI

A basic CI gate can install the latest tagged release and analyze a repository:

```yaml
- uses: actions/setup-go@v5
  with:
    go-version: 1.23.x
    cache: false
- run: go install github.com/sangmorg1-debug/shport/cmd/shport@latest
- run: shport --target portable .
```

For code-scanning annotations, write SARIF and upload it even when the scan
step reports findings. The workflow also needs `security-events: write`
permission for SARIF upload:

```yaml
- name: Run shport
  id: shport
  continue-on-error: true
  run: shport --format sarif --output shport.sarif .
- name: Upload SARIF
  if: always() && hashFiles('shport.sarif') != ''
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: shport.sarif
- name: Enforce shport result
  if: steps.shport.outcome == 'failure'
  run: exit 1
```

## pre-commit

The repository publishes a `.pre-commit-hooks.yaml` manifest. Once a release
is tagged, consumers can add:

```yaml
repos:
  - repo: https://github.com/sangmorg1-debug/shport
    rev: v0.1.0
    hooks:
      - id: shport
        args: [--target, portable]
```

Pre-commit passes staged shell files explicitly, so they are analyzed even if
their parent directory is normally skipped during directory discovery.

## Project documents

- [Rules and suppressions](docs/rules.md)
- [Target profiles and source pins](docs/profiles.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

`shport` is available under the [MIT License](LICENSE).
