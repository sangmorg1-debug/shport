# Rule catalog

The v0 catalog is intentionally small. Every rule represents a command-line
form or semantic difference with a concrete source and a deterministic target
matrix. All findings currently have warning severity, but unsuppressed findings
produce exit code 1.

The live catalog is also available from the binary:

```bash
shport --list-rules
shport --list-rules --format json
```

## Coverage summary

| Rule | Command | Checked form |
| --- | --- | --- |
| `SP1001` | `sed` | Incompatible GNU/BSD in-place option forms |
| `SP1002` | `sed` | In-place editing against a POSIX target |
| `SP1101` | `readlink` | `-f` and `--canonicalize` availability |
| `SP1102` | `readlink` | GNU `-e`, `-m`, and related long modes |
| `SP1201` | `stat` | GNU formatting options |
| `SP1202` | `stat` | BSD `-f FORMAT` semantics |
| `SP1301` | `date` | GNU/BusyBox date parsing with `-d` or `--date` |
| `SP1302` | `date` | BSD parsing options `-j`, `-v`, and `-f FORMAT` |
| `SP1303` | `date` | Incompatible `-r` semantics for numeric arguments |
| `SP1401` | `xargs` | GNU delimiter option `-d`/`--delimiter` |
| `SP1402` | `xargs` | BSD replacement option `-J` |
| `SP1501` | `grep` | GNU PCRE mode `-P`/`--perl-regexp` |

## `SP1001`: sed in-place option form

GNU and BSD `sed` do not parse every spelling of `-i` alike.

- `sed -i SCRIPT FILE` and `sed --in-place` are diagnosed for macOS and
  FreeBSD targets.
- `sed -i '' -e SCRIPT FILE` is diagnosed for GNU and BusyBox targets.
- A separate non-empty suffix is diagnosed for GNU and BusyBox when the
  surrounding literal command shape identifies it as a BSD suffix, such as
  `sed -i .bak -e SCRIPT FILE`.
- An attached non-empty suffix such as `-i.bak` is accepted by the concrete
  GNU/BSD/BusyBox profiles.

An attached suffix still triggers `SP1002` when a POSIX profile is selected.
There is no generally safe automatic conversion between the no-backup GNU and
BSD forms.

## `SP1002`: sed in-place editing is not POSIX

Diagnoses `-i`, clustered forms such as `-ni`, an attached `-iSUFFIX`,
`--in-place`, and `--in-place=SUFFIX` when POSIX.1-2017 or POSIX.1-2024 is
selected. POSIX `sed` does not specify in-place editing. A temporary output
followed by an explicit replacement is the portable strategy.

## `SP1101`: readlink canonicalization

Checks two related forms:

- `readlink -f` is diagnosed for macOS 11 and both POSIX profiles. It is
  accepted by the macOS 14 profile.
- `readlink --canonicalize` is diagnosed for macOS, FreeBSD, BusyBox, and
  POSIX profiles; it is a GNU long option.

`readlink` itself was added to POSIX in Issue 8. The `-f` mode is still outside
the selected POSIX interface.

## `SP1102`: GNU readlink modes

Diagnoses `-e`, `-m`, `--canonicalize-existing`, and
`--canonicalize-missing` for every built-in target except GNU. Dynamic option
words are not interpreted.

## `SP1201`: GNU stat formatting

Diagnoses GNU `stat -c FORMAT`, common short clusters containing `-c`,
`--format`, and `--printf` forms for macOS, FreeBSD, and POSIX profiles.
BusyBox accepts the short `-c` form in the pinned catalog but not the GNU long
forms. It also recognizes target-dependent `-f`/`-t` clusters where BSD parses
the GNU-looking `-c` word as option data.

## `SP1202`: BSD stat formatting

Diagnoses `stat -f FORMAT`, including supported BSD short clusters, for GNU,
BusyBox, and POSIX targets when the literal format contains `%`. On BSD this is
a formatting interface; on GNU and BusyBox, `-f` selects filesystem status.
Because the rule is literal-only, a format supplied through a variable is not
diagnosed.

## `SP1301`: GNU date parsing

Diagnoses `date -d VALUE` and `date --date VALUE` for macOS, FreeBSD, and
POSIX targets. The pinned GNU and BusyBox profiles provide this interface.

## `SP1302`: BSD date parsing

Diagnoses BSD `date -j` and `date -v` for GNU, BusyBox, and POSIX targets. It
also diagnoses `date -f FORMAT` when the literal option argument contains `%`:
BSD treats it as an input format, while GNU treats `-f` as an input filename.

## `SP1303`: date `-r` semantic divergence

When the literal `-r` argument is a base-0 integer (decimal, octal, or
hexadecimal), BSD interprets it as epoch
seconds while GNU and BusyBox interpret it as a reference filename. The rule
is emitted for GNU, BusyBox, and POSIX targets. Non-literal and non-numeric
arguments are not diagnosed by this rule.

## `SP1401`: xargs delimiter selection

Diagnoses `xargs -d DELIM` and `xargs --delimiter DELIM` for macOS, FreeBSD,
BusyBox, and POSIX targets. The v0 catalog treats this interface as GNU-only.
If the producer is under project control, NUL-delimited data and `-0` may be a
better cross-userland design, but `shport` does not automatically rewrite it.

## `SP1402`: BSD xargs replacement

Diagnoses `xargs -J REPL` for GNU, BusyBox, and POSIX targets. `-I` is not
offered as an automatic fix because its grouping and replacement behavior is
not identical.

## `SP1501`: grep PCRE mode

Diagnoses `grep -P` and `grep --perl-regexp` for macOS, FreeBSD, BusyBox, and
POSIX targets. The PCRE2-enabled GNU profile is the only built-in profile that
accepts the checked form. The deprecated `egrep` and `fgrep` aliases are not
treated as plain `grep`: GNU rejects combining their implicit matcher with
`-P`. `grep -E` is suitable only when the expression does not require PCRE
features.

## Literal option parsing

Rules understand literal quoted words, common clustered short options, option
arguments, and `--` termination where applicable. They deliberately skip words
requiring runtime expansion. For example:

```bash
grep -Pn pattern file         # literal cluster: SP1501 can match
grep "$options" pattern file  # dynamic: not interpreted
grep -- -P file               # after terminator: not an option
```

The analyzer recognizes literal `command`, `env`, and `busybox APPLET`
wrappers. A `busybox APPLET` invocation is checked specifically against the
pinned BusyBox implementation, irrespective of the broader selected target
set.

## Suppressions

```bash
grep -P pattern file  # shport: ignore=SP1501

# shport: ignore-next-line=SP1201,SP1202
stat -c '%s' "$file"

# shport: ignore-file=all
```

The forms are exact:

- `# shport: ignore=ID[,ID...]` applies to diagnostics starting on that line.
- `# shport: ignore-next-line=ID[,ID...]` applies to the next physical line.
- `# shport: ignore-file=ID[,ID...]` applies throughout the parsed file.

IDs are case-insensitive in directives and normalized to uppercase. `all` is
also accepted. Misspelled IDs and malformed directives are analysis errors so
that a suppression cannot silently fail.

Suppressions are an assertion by the maintainer, not control-flow evidence.
For platform-guarded code, include a brief nearby comment explaining why the
guard makes the invocation intentional.
