package rules

import "github.com/sangmorg1-debug/shport/internal/model"

// Definition is stable metadata for one portability rule.
type Definition struct {
	ID          string
	Name        string
	Summary     string
	Description string
	Suggestion  string
	Reference   string
	Severity    model.Severity
}

var definitions = []Definition{
	{
		ID:          "SP1001",
		Name:        "sed-in-place-form",
		Summary:     "sed -i has incompatible GNU and BSD argument forms",
		Description: "GNU and BSD sed parse an omitted or separately supplied -i backup suffix differently.",
		Suggestion:  "Use an attached backup suffix such as -i.bak and remove backups explicitly, or write through a temporary file.",
		Reference:   "https://github.com/koalaman/shellcheck/issues/2902",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1002",
		Name:        "sed-in-place-posix",
		Summary:     "sed in-place editing is not specified by POSIX",
		Description: "POSIX sed does not specify the -i or --in-place option.",
		Suggestion:  "Write to a temporary file and replace the input after sed succeeds.",
		Reference:   "https://pubs.opengroup.org/onlinepubs/9799919799/utilities/sed.html",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1101",
		Name:        "readlink-canonicalize",
		Summary:     "readlink canonicalization options are not portable",
		Description: "GNU readlink -f is unavailable in macOS 11 and POSIX, while --canonicalize is unavailable outside GNU in the pinned profiles.",
		Suggestion:  "Use a project-owned realpath helper or explicitly depend on a known realpath implementation.",
		Reference:   "https://github.com/wxWidgets/wxWidgets/issues/25675",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1102",
		Name:        "readlink-gnu-modes",
		Summary:     "GNU readlink canonicalization modes are not portable",
		Description: "The -e, -m, --canonicalize-existing, and --canonicalize-missing modes are GNU extensions.",
		Suggestion:  "Use a target-specific realpath command or a language filesystem API.",
		Reference:   "https://www.gnu.org/software/coreutils/manual/html_node/readlink-invocation.html",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1201",
		Name:        "stat-gnu-format",
		Summary:     "GNU stat format syntax is unavailable on macOS",
		Description: "GNU and BusyBox stat use -c for a format string; BSD stat uses -f.",
		Suggestion:  "Branch explicitly by userland or use a language filesystem API.",
		Reference:   "https://www.gnu.org/software/coreutils/manual/html_node/stat-invocation.html",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1202",
		Name:        "stat-bsd-format",
		Summary:     "BSD stat format syntax has different GNU and BusyBox semantics",
		Description: "BSD stat uses -f FORMAT, while GNU and BusyBox stat use -f for filesystem status.",
		Suggestion:  "Branch explicitly by userland or use a language filesystem API.",
		Reference:   "https://man.freebsd.org/cgi/man.cgi?query=stat&sektion=1&manpath=FreeBSD+14.1-RELEASE",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1301",
		Name:        "date-gnu-parse",
		Summary:     "GNU date parsing options are unavailable on macOS",
		Description: "GNU and BusyBox date accept -d; BSD date uses a different interface for parsing dates.",
		Suggestion:  "Use a language date API or an explicit userland-specific branch.",
		Reference:   "https://www.gnu.org/software/coreutils/manual/html_node/date-invocation.html",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1302",
		Name:        "date-bsd-parse",
		Summary:     "BSD date parsing options have incompatible GNU semantics",
		Description: "BSD date uses -j, -v, and -f FORMAT; GNU date either lacks them or assigns a different meaning.",
		Suggestion:  "Use a language date API or an explicit userland-specific branch.",
		Reference:   "https://github.com/apple-oss-distributions/shell_cmds/blob/e256b9a97f9bbd751305b7af36cf751668fbb849/date/date.1",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1303",
		Name:        "date-r-semantics",
		Summary:     "date -r has incompatible BSD and GNU meanings",
		Description: "BSD date -r NUMBER interprets seconds since the epoch; GNU and BusyBox interpret the argument as a reference filename.",
		Suggestion:  "Use a language date API or an explicit userland-specific branch.",
		Reference:   "https://github.com/apple-oss-distributions/shell_cmds/blob/e256b9a97f9bbd751305b7af36cf751668fbb849/date/date.1",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1401",
		Name:        "xargs-delimiter",
		Summary:     "xargs delimiter selection is GNU-specific",
		Description: "GNU xargs supports -d and --delimiter; the pinned macOS, FreeBSD, BusyBox, and POSIX profiles do not.",
		Suggestion:  "If the producer is under your control, emit NUL-delimited input and use -0 on targets that provide it.",
		Reference:   "https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1402",
		Name:        "xargs-bsd-replace",
		Summary:     "xargs -J is BSD-specific",
		Description: "BSD xargs supports -J REPL; GNU, BusyBox, and POSIX xargs do not.",
		Suggestion:  "Review whether -I is suitable; it changes grouping and replacement behavior and is not an automatic rewrite.",
		Reference:   "https://github.com/apple-oss-distributions/shell_cmds/blob/e256b9a97f9bbd751305b7af36cf751668fbb849/xargs/xargs.1",
		Severity:    model.SeverityWarning,
	},
	{
		ID:          "SP1501",
		Name:        "grep-perl-regexp",
		Summary:     "grep PCRE mode is GNU-specific in the selected profiles",
		Description: "The -P and --perl-regexp options are available in the PCRE2-enabled GNU profile and unavailable in the pinned macOS, FreeBSD, BusyBox, and POSIX profiles.",
		Suggestion:  "Use grep -E when the expression permits it, or invoke Perl as an explicit dependency.",
		Reference:   "https://www.gnu.org/software/grep/manual/grep.html",
		Severity:    model.SeverityWarning,
	},
}

var byID = func() map[string]Definition {
	result := make(map[string]Definition, len(definitions))
	for _, definition := range definitions {
		result[definition.ID] = definition
	}
	return result
}()

// All returns all rule definitions in stable ID order.
func All() []Definition {
	return append([]Definition(nil), definitions...)
}

// Lookup returns rule metadata by stable ID.
func Lookup(id string) (Definition, bool) {
	definition, ok := byID[id]
	return definition, ok
}
