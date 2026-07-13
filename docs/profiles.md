# Target profiles

Target profiles make `shport` findings reproducible. Each stable ID names a
fixed interface snapshot embedded in the binary. Aliases are conveniences;
diagnostics and structured output always use stable IDs.

```bash
shport targets
shport targets --format json
```

## Built-in profiles

| Stable ID | Alias | Pinned interface |
| --- | --- | --- |
| `gnu-2026` | `gnu` | GNU sed 4.10, coreutils 9.11, PCRE2-enabled grep 3.12, and findutils 4.10.0 |
| `macos-11` | `macos11` | Stock command userland represented by Apple's macOS 11.0.1 source distribution |
| `macos-14` | `macos` | Stock command userland represented by Apple's macOS 14.0 source distribution |
| `freebsd-14.1` | `freebsd` | FreeBSD 14.1-RELEASE stock utilities |
| `busybox-1.36.1` | `busybox` | BusyBox 1.36.1 applets with upstream `defconfig` assumptions |
| `posix-2017` | `posix2017` | POSIX.1-2017 / The Open Group Base Specifications Issue 7 |
| `posix-2024` | `posix` | POSIX.1-2024 / The Open Group Base Specifications Issue 8 |

The special alias `portable` expands to `gnu`, `macos`, `freebsd`, and
`busybox`. It is the default when no target is supplied. Strict POSIX checking
is opt-in because it intentionally rejects common extensions covered by the
command-specific rules.

Multiple targets form a required compatibility set: a finding is emitted when
an implemented rule says a literal invocation is incompatible with at least
one selected target. Selecting a single target is useful for migration checks;
selecting several checks their intersection for the implemented catalog.

## Primary source pins

The links below are the primary artifacts used to identify each profile. Rule
references may additionally link to specific manuals, source files, or real
failure reports.

### GNU 2026

- [GNU sed 4.10 source archive](https://ftp.gnu.org/gnu/sed/sed-4.10.tar.xz)
- [GNU coreutils 9.11 source archive](https://ftp.gnu.org/gnu/coreutils/coreutils-9.11.tar.xz)
- [GNU grep 3.12 source archive](https://ftp.gnu.org/gnu/grep/grep-3.12.tar.xz)
- [GNU findutils 4.10.0 source archive](https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz)

The profile name is intentionally a `shport` catalog revision, not the version
of a single GNU package. GNU grep's PCRE support is a build-time capability;
this profile explicitly models a grep 3.12 build with PCRE2 enabled.

### macOS 11

The pin is Apple's official
[`macos-1101` distribution snapshot](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-1101),
whose command submodules resolve to:

- [`shell_cmds` at `eb0d59c`](https://github.com/apple-oss-distributions/shell_cmds/tree/eb0d59c54eb6fc643e5a4998d46e84067e69eb18)
- [`file_cmds` at `61c4b7b`](https://github.com/apple-oss-distributions/file_cmds/tree/61c4b7b2840e2850671255d849d4320666752a2f)
- [`text_cmds` at `26b7439`](https://github.com/apple-oss-distributions/text_cmds/tree/26b743953867382d59dfe09b9011dde610797e1a)

The public alias is coarse (`macos11`), but the source snapshot is exact.

### macOS 14

The pin is Apple's official
[`macos-140` distribution snapshot](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-140),
whose command submodules resolve to:

- [`shell_cmds` at `e256b9a`](https://github.com/apple-oss-distributions/shell_cmds/tree/e256b9a97f9bbd751305b7af36cf751668fbb849)
- [`file_cmds` at `f8c8400`](https://github.com/apple-oss-distributions/file_cmds/tree/f8c84000d1f02be159053846a3d730b0290f9614)
- [`text_cmds` at `c0780aa`](https://github.com/apple-oss-distributions/text_cmds/tree/c0780aa3432383e0acde7dc7cf42972716925de6)

### FreeBSD 14.1

- [FreeBSD source tag `release/14.1.0`](https://cgit.freebsd.org/src/tag/?h=release/14.1.0)
- [FreeBSD 14.1-RELEASE manual pages](https://man.freebsd.org/cgi/man.cgi?manpath=FreeBSD+14.1-RELEASE)

The release tag, rather than the moving `releng/14.1` branch, defines the
profile baseline.

### BusyBox 1.36.1

- [BusyBox 1.36.1 source archive](https://busybox.net/downloads/busybox-1.36.1.tar.bz2)
- [BusyBox source and stable-branch instructions](https://busybox.net/source.html)

BusyBox is highly configurable. The built-in profile describes upstream
1.36.1 with its default configuration assumptions; a downstream firmware or
distribution may omit applets or options. A clean BusyBox-targeted run is not
proof that a particular device image contains those features.

### POSIX

- [POSIX.1-2017 utility index (Issue 7)](https://pubs.opengroup.org/onlinepubs/9699919799/idx/utilities.html)
- [POSIX.1-2024 utility index (Issue 8)](https://pubs.opengroup.org/onlinepubs/9799919799/idx/utilities.html)
- [POSIX.1-2024 utility syntax guidelines](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap12.html)

These profiles mean “specified by this POSIX edition,” not “observed on an
arbitrary Unix system.” An implementation can provide additional extensions.

## Scope and limitations

Profiles are not exhaustive databases of all commands or options. They contain
only the facts needed by the current rule catalog. Consequently:

- no finding means no implemented profile fact was violated;
- target selection does not establish that a command exists at runtime;
- environment changes, `PATH`, aliases, functions from sourced files, and
  vendor-patched utilities are outside the model; and
- `shport` does not infer that a runtime platform guard narrows the target for
  a branch.

The analyzer recognizes an explicit `busybox APPLET ...` wrapper and checks
that invocation against `busybox-1.36.1`. This is an implementation assertion
for that invocation, not a claim about an arbitrary downstream BusyBox build.

## Updating a profile

Existing stable IDs must not silently change meaning. A material upstream
interface change requires a new stable ID, source pin, rule matrix tests, and
documentation. An alias may move to a newer stable ID only in a release that
calls out the change. Reports retain stable IDs so consumers can compare runs.
