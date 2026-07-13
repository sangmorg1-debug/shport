package analyzer

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sangmorg1-debug/shport/internal/profile"
)

func TestAnalyzeRuleMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		source  string
		targets []string
		wantIDs []string
	}{
		{name: "gnu sed form on gnu", source: `sed -i 's/a/b/' file`, targets: []string{"gnu"}},
		{name: "gnu sed form on macos", source: `sed -i 's/a/b/' file`, targets: []string{"macos"}, wantIDs: []string{"SP1001"}},
		{name: "bsd sed form on gnu", source: `sed -i '' -e 's/a/b/' file`, targets: []string{"gnu"}, wantIDs: []string{"SP1001"}},
		{name: "bsd nonempty suffix on gnu", source: `sed -i .bak -e 's/a/b/' file`, targets: []string{"gnu"}, wantIDs: []string{"SP1001"}},
		{name: "bsd nonempty suffix on macos", source: `sed -i .bak -e 's/a/b/' file`, targets: []string{"macos"}},
		{name: "bsd suffix before inline script on gnu", source: `sed -i .bak 's/a/b/' file`, targets: []string{"gnu"}, wantIDs: []string{"SP1001"}},
		{name: "backup suffix is cross userland", source: `sed -i.bak 's/a/b/' file`, targets: []string{"gnu", "macos", "busybox"}},
		{name: "clustered gnu sed form", source: `sed -ni 's/a/b/' file`, targets: []string{"macos"}, wantIDs: []string{"SP1001"}},
		{name: "clustered sed backup suffix", source: `sed -ni.bak 's/a/b/' file`, targets: []string{"gnu", "macos", "busybox"}},
		{name: "clustered sed suffix ending in i", source: `sed -nii 's/a/b/' file`, targets: []string{"gnu", "macos", "busybox"}},
		{name: "clustered sed suffix ending in i is not posix", source: `sed -nii 's/a/b/' file`, targets: []string{"posix"}, wantIDs: []string{"SP1002"}},
		{name: "sed line length argument is not i option", source: `sed -li 's/a/b/' file`, targets: []string{"posix"}},
		{name: "sed separate line length argument is not i option", source: `sed -l -i 's/a/b/' file`, targets: []string{"posix"}},
		{name: "sed in place is not posix", source: `sed -i.bak 's/a/b/' file`, targets: []string{"posix"}, wantIDs: []string{"SP1002"}},
		{name: "readlink f on legacy macos", source: `readlink -f "$path"`, targets: []string{"macos11"}, wantIDs: []string{"SP1101"}},
		{name: "readlink f on current profile", source: `readlink -f "$path"`, targets: []string{"macos"}},
		{name: "readlink f is not posix", source: `readlink -f "$path"`, targets: []string{"posix"}, wantIDs: []string{"SP1101"}},
		{name: "invalid canonicalize argument is not modeled", source: `readlink --canonicalize=foo file`, targets: []string{"macos"}},
		{name: "gnu stat", source: `stat -c '%s' file`, targets: []string{"macos"}, wantIDs: []string{"SP1201"}},
		{name: "clustered gnu stat", source: `stat -Lc '%s' file`, targets: []string{"macos"}, wantIDs: []string{"SP1201"}},
		{name: "stat bsd f consumes gnu-looking word", source: `stat -f -c '%s' fs`, targets: []string{"gnu", "macos"}, wantIDs: []string{"SP1201"}},
		{name: "stat bsd f consumes gnu cluster", source: `stat -f -Lc '%s' fs`, targets: []string{"gnu", "macos"}, wantIDs: []string{"SP1201"}},
		{name: "stat bsd f consumes gnu-looking word on posix", source: `stat -f -c '%s' fs`, targets: []string{"posix"}, wantIDs: []string{"SP1201"}},
		{name: "stat bsd t consumes gnu-looking word", source: `stat -t -c '%s' file`, targets: []string{"gnu", "macos"}, wantIDs: []string{"SP1201"}},
		{name: "clustered bsd stat format", source: `stat -Lf%z file`, targets: []string{"gnu"}, wantIDs: []string{"SP1202"}},
		{name: "clustered bsd stat format after noarg options", source: `stat -nqf%z file`, targets: []string{"gnu"}, wantIDs: []string{"SP1202"}},
		{name: "clustered bsd stat separate format", source: `stat -Lf '%z' file`, targets: []string{"gnu"}, wantIDs: []string{"SP1202"}},
		{name: "ambiguous stat cluster across families", source: `stat -fc '%s' file`, targets: []string{"gnu", "macos"}, wantIDs: []string{"SP1201"}},
		{name: "ambiguous multi-option stat cluster", source: `stat -Lftc '%s' file`, targets: []string{"gnu", "macos"}, wantIDs: []string{"SP1201"}},
		{name: "ambiguous stat cluster on gnu", source: `stat -fc '%s' file`, targets: []string{"gnu"}},
		{name: "invalid bsd F format combination is not modeled", source: `stat -Ff%z file`, targets: []string{"gnu"}},
		{name: "bsd stat semantic divergence", source: `stat -f '%z' file`, targets: []string{"gnu", "busybox"}, wantIDs: []string{"SP1202"}},
		{name: "gnu date", source: `date -d yesterday`, targets: []string{"macos"}, wantIDs: []string{"SP1301"}},
		{name: "date iso argument is not d option", source: `date -Idate`, targets: []string{"macos"}},
		{name: "busybox date input format argument is not d option", source: `date -D -d`, targets: []string{"macos"}},
		{name: "large numeric bsd epoch", source: `date -r 999999999999999999999999`, targets: []string{"gnu"}, wantIDs: []string{"SP1303"}},
		{name: "hexadecimal bsd epoch", source: `date -r 0x10`, targets: []string{"gnu"}, wantIDs: []string{"SP1303"}},
		{name: "space-prefixed bsd epoch", source: `date -r ' 10'`, targets: []string{"gnu"}, wantIDs: []string{"SP1303"}},
		{name: "invalid octal remains filename", source: `date -r 08`, targets: []string{"gnu"}},
		{name: "xargs r is accepted on macos", source: `xargs -0r echo`, targets: []string{"macos"}},
		{name: "gnu xargs delimiter on macos", source: `xargs -d ',' echo`, targets: []string{"macos"}, wantIDs: []string{"SP1401"}},
		{name: "xargs optional eof argument contains d", source: `xargs -e-d, echo`, targets: []string{"busybox"}},
		{name: "bsd xargs replacement on gnu", source: `xargs -J % echo %`, targets: []string{"gnu"}, wantIDs: []string{"SP1402"}},
		{name: "clustered grep", source: `grep -Pn pattern file`, targets: []string{"busybox"}, wantIDs: []string{"SP1501"}},
		{name: "repeated grep option is one finding", source: `grep -PP pattern file`, targets: []string{"busybox"}, wantIDs: []string{"SP1501"}},
		{name: "grep devices argument is not P option", source: `grep -D-P pattern file`, targets: []string{"busybox"}},
		{name: "grep include directory argument is not perl option", source: `grep --include-dir --perl-regexp pattern`, targets: []string{"macos"}},
		{name: "grep optional context precedes perl option", source: `grep --context --perl-regexp pattern`, targets: []string{"macos"}, wantIDs: []string{"SP1501"}},
		{name: "specific long option is not duplicated", source: `grep --perl-regexp pattern`, targets: []string{"posix"}, wantIDs: []string{"SP1501"}},
		{name: "deprecated matcher alias is not modeled as grep", source: `egrep -P pattern`, targets: []string{"macos"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			targets, err := profile.Resolve(test.targets)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Analyze("script.sh", []byte(test.source), targets, ShellAuto)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			got := make([]string, 0, len(result.Diagnostics))
			for _, diagnostic := range result.Diagnostics {
				got = append(got, diagnostic.RuleID)
			}
			if strings.Join(got, ",") != strings.Join(test.wantIDs, ",") {
				t.Fatalf("rule IDs = %v, want %v; diagnostics: %#v", got, test.wantIDs, result.Diagnostics)
			}
		})
	}
}

func TestAnalyzeOptionArgumentsAreNotReparsed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		source  string
		targets []string
	}{
		{name: "grep pattern beginning with dash", source: `grep -e -P file`, targets: []string{"macos"}},
		{name: "xargs attached replacement", source: `xargs -Ireplace echo replace`, targets: []string{"macos"}},
		{name: "sed expression beginning with dash", source: `sed -e -i file`, targets: []string{"macos"}},
		{name: "date format beginning with dash", source: `date -f -d 2020`, targets: []string{"macos"}},
		{name: "printf operand beginning with dashes", source: `printf '%s\n' --help`, targets: []string{"posix"}},
		{name: "find exec payload beginning with dashes", source: `find . -exec echo --help ';'`, targets: []string{"posix"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			targets, err := profile.Resolve(test.targets)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Analyze("script.sh", []byte(test.source), targets, ShellAuto)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Diagnostics) != 0 {
				t.Fatalf("unexpected diagnostics: %#v", result.Diagnostics)
			}
		})
	}
}

func TestAnalyzeCommandClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		source     string
		targets    []string
		wantCount  int
		wantTarget string
	}{
		{name: "project local grep is unknown", source: `./grep -P pattern`, targets: []string{"macos"}},
		{name: "unmodeled system family is unknown", source: `/usr/xpg4/bin/grep -P pattern`, targets: []string{"macos"}},
		{name: "standard absolute grep bypasses function", source: "grep() { :; }\n/usr/bin/grep -P pattern", targets: []string{"macos"}, wantCount: 1, wantTarget: "macos-14"},
		{name: "env invokes external command", source: "grep() { :; }\nenv grep -P pattern", targets: []string{"macos"}, wantCount: 1, wantTarget: "macos-14"},
		{name: "env option is unwrapped", source: `env -i grep -P pattern`, targets: []string{"macos"}, wantCount: 1, wantTarget: "macos-14"},
		{name: "command option terminator is unwrapped", source: `command -- grep -P pattern`, targets: []string{"macos"}, wantCount: 1, wantTarget: "macos-14"},
		{name: "busybox multicall pins implementation", source: `busybox grep -P pattern`, targets: []string{"gnu"}, wantCount: 1, wantTarget: "busybox-1.36.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			targets, err := profile.Resolve(test.targets)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Analyze("script.sh", []byte(test.source), targets, ShellAuto)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Diagnostics) != test.wantCount {
				t.Fatalf("diagnostic count = %d, want %d: %#v", len(result.Diagnostics), test.wantCount, result.Diagnostics)
			}
			if test.wantCount == 0 {
				return
			}
			diagnostic := result.Diagnostics[0]
			if diagnostic.RuleID != "SP1501" {
				t.Fatalf("rule ID = %q, want SP1501", diagnostic.RuleID)
			}
			if len(diagnostic.IncompatibleTargets) != 1 || diagnostic.IncompatibleTargets[0] != test.wantTarget {
				t.Fatalf("incompatible targets = %v, want [%s]", diagnostic.IncompatibleTargets, test.wantTarget)
			}
		})
	}
}

func TestAnalyzeColumnsCountUnicodeCodePoints(t *testing.T) {
	t.Parallel()
	source := `printf 'é😀'; grep -P pattern`
	targets, err := profile.Resolve([]string{"macos"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Analyze("script.sh", []byte(source), targets, ShellAuto)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one", result.Diagnostics)
	}
	optionOffset := strings.Index(source, "-P")
	wantStart := uint(utf8.RuneCountInString(source[:optionOffset])) + 1
	if got := result.Diagnostics[0].Range.Start.Column; got != wantStart {
		t.Fatalf("start column = %d, want %d Unicode code points", got, wantStart)
	}
	if got, want := result.Diagnostics[0].Range.End.Column, wantStart+2; got != want {
		t.Fatalf("end column = %d, want %d Unicode code points", got, want)
	}
}

func TestAnalyzeConservativeExtraction(t *testing.T) {
	t.Parallel()
	targets, err := profile.Resolve([]string{"macos"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		source     string
		wantCount  int
		wantColumn uint
	}{
		{name: "dynamic command is ignored", source: `$command -P pattern`, wantCount: 0},
		{name: "dynamic option is ignored", source: `grep "$option" pattern`, wantCount: 0},
		{name: "declared function shadows external", source: "grep() { :; }\ngrep -P pattern", wantCount: 0},
		{name: "command bypasses function", source: "grep() { :; }\ncommand grep -P pattern", wantCount: 1, wantColumn: 14},
		{name: "simple env wrapper", source: `env LC_ALL=C grep -P pattern`, wantCount: 1, wantColumn: 19},
		{name: "nested command substitution", source: `value=$(grep -P pattern file)`, wantCount: 1, wantColumn: 14},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := Analyze("script.sh", []byte(test.source), targets, ShellAuto)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Diagnostics) != test.wantCount {
				t.Fatalf("diagnostic count = %d, want %d: %#v", len(result.Diagnostics), test.wantCount, result.Diagnostics)
			}
			if test.wantCount > 0 && result.Diagnostics[0].Range.Start.Column != test.wantColumn {
				t.Fatalf("column = %d, want %d", result.Diagnostics[0].Range.Start.Column, test.wantColumn)
			}
		})
	}
}

func TestAnalyzeSuppressions(t *testing.T) {
	t.Parallel()
	targets, err := profile.Resolve([]string{"macos"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		source    string
		wantCount int
		wantError string
	}{
		{name: "inline", source: `grep -P pattern # shport: ignore=SP1501`},
		{name: "next line", source: "# shport: ignore-next-line=SP1501\ngrep -P pattern"},
		{name: "file", source: "# shport: ignore-file=SP1501\ngrep -P one\ngrep -P two"},
		{name: "unrelated rule", source: `grep -P pattern # shport: ignore=SP1001`, wantCount: 1},
		{name: "unknown rule", source: `grep -P pattern # shport: ignore=SP9999`, wantError: "unknown rule ID"},
		{name: "malformed", source: `grep -P pattern # shport: ignore SP1501`, wantError: "malformed shport directive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := Analyze("script.sh", []byte(test.source), targets, ShellAuto)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Diagnostics) != test.wantCount {
				t.Fatalf("diagnostic count = %d, want %d: %#v", len(result.Diagnostics), test.wantCount, result.Diagnostics)
			}
		})
	}
}

func TestAnalyzeParseError(t *testing.T) {
	t.Parallel()
	targets := profile.Default()
	_, err := Analyze("broken.sh", []byte("if then"), targets, ShellAuto)
	if err == nil || !strings.Contains(err.Error(), "parse:") {
		t.Fatalf("error = %v, want parse error", err)
	}
}
