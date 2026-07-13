# Contributing to shport

Thanks for helping make shell portability failures easier to catch before they
reach users. `shport` favors a small, high-confidence catalog over speculative
coverage.

## Development setup

Install Go 1.23 or newer, then run:

```bash
go test ./...
go vet ./...
go build ./cmd/shport
```

Format changed Go files with `gofmt`. The repository CI also runs tests on
Linux, macOS, and Windows and runs the race detector on Linux.

## Reporting a portability case

An actionable issue includes:

- the smallest shell invocation that reproduces the difference;
- the affected target and exact utility version or OS release;
- observed and expected behavior;
- a primary manual, source, standard, or release reference; and
- when available, a link to a real project failure showing demand.

Please distinguish shell-language portability from an external utility
interface. Shell syntax generally belongs in ShellCheck; `shport` focuses on
external commands and options.

## Adding or changing a rule

A rule should be deterministic from literal syntax and the selected embedded
profiles. A typical contribution:

1. Adds or updates stable metadata in `internal/rules/catalog.go`.
2. Encodes the target matrix in `internal/rules/check.go`.
3. Includes positive, negative, and mixed-target tests.
4. Tests quoted forms, clustered options, option arguments, and `--` where
   relevant.
5. Adds conservative handling for dynamic words rather than guessing.
6. Updates `docs/rules.md` and, if necessary, `docs/profiles.md`.

Suggestions must be correct for every target named by the diagnostic. If no
semantics-preserving cross-target rewrite exists, explain the alternatives
instead of offering an automatic replacement.

Do not add control-flow or platform-guard inference as part of an unrelated
rule. The current analyzer deliberately checks every parsed branch against the
same target set. Any proposal to change that model needs an explicit soundness
design and adversarial tests.

## Rule IDs and compatibility

Published rule IDs and stable profile IDs are API. Do not reuse an ID for a
different condition. Structured JSON schema changes require a schema-version
decision; SARIF fields should remain compatible with SARIF 2.1.0 consumers.

## Tests and fixtures

Keep tests self-contained and platform-independent. They must not require the
host's `sed`, `grep`, or other target utility because `shport` is a static
analyzer and never executes them. Use table-driven unit tests for target
matrices and golden or decoded-structure tests for machine output.

Before opening a pull request:

```bash
gofmt -w ./cmd ./internal
go test -race ./...
go vet ./...
```

Review the diff for unrelated generated files and avoid committing built
binaries, coverage output, or SARIF reports.

## Security reports

Do not open a public issue for a vulnerability that could cause command
execution, unsafe file access, or another security boundary failure. Follow
[SECURITY.md](SECURITY.md) instead.

By contributing, you agree that your contribution is licensed under the
project's [MIT License](LICENSE).
