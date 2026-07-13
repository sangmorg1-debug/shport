package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sangmorg1-debug/shport/internal/report"
)

func TestRunExitCodesAndText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		stdin      string
		wantCode   int
		wantOutput string
	}{
		{name: "clean", args: []string{"--target", "gnu", "-"}, stdin: "grep -P pattern", wantCode: 0},
		{name: "finding", args: []string{"--target", "macos", "-"}, stdin: "grep -P pattern", wantCode: 1, wantOutput: "SP1501"},
		{name: "exit zero", args: []string{"--target", "macos", "--exit-zero", "-"}, stdin: "grep -P pattern", wantCode: 0, wantOutput: "SP1501"},
		{name: "analysis error", args: []string{"--target", "macos", "-"}, stdin: "if then", wantCode: 2},
		{name: "bad target", args: []string{"--target", "plan9", "-"}, stdin: ":", wantCode: 2},
		{name: "bad exclude with stdin", args: []string{"--exclude", "[", "-"}, stdin: ":", wantCode: 2},
		{name: "version rejects operands", args: []string{"version", "extra"}, wantCode: 2},
		{name: "empty stdin filename", args: []string{"--stdin-filename=", "-"}, stdin: "grep -P pattern", wantCode: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := Run(test.args, strings.NewReader(test.stdin), &stdout, &stderr)
			if code != test.wantCode {
				t.Fatalf("exit code = %d, want %d; stdout=%q stderr=%q", code, test.wantCode, stdout.String(), stderr.String())
			}
			if test.wantOutput != "" && !strings.Contains(stdout.String(), test.wantOutput) {
				t.Fatalf("stdout = %q, want containing %q", stdout.String(), test.wantOutput)
			}
		})
	}
}

func TestRunJSONAlwaysProducesDocument(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--format", "json", "--target", "macos", "-"}, strings.NewReader("if then"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output %q: %v", stdout.String(), err)
	}
	if len(result.AnalysisErrors) != 1 {
		t.Fatalf("analysis errors = %#v", result.AnalysisErrors)
	}
}

func TestRunTargets(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"targets", "--format", "json"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"macos-11"`) || !strings.Contains(stdout.String(), `"posix-2024"`) {
		t.Fatalf("target output = %q", stdout.String())
	}
}

func TestRunSARIFUsesUnicodeColumnsAndExitZero(t *testing.T) {
	t.Parallel()
	source := `printf 'é😀'; grep -P pattern`
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"--format", "sarif", "--target", "macos", "--exit-zero", "-"},
		strings.NewReader(source),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("invalid SARIF JSON %q: %v", stdout.String(), err)
	}
	run := document["runs"].([]any)[0].(map[string]any)
	if got := run["columnKind"]; got != "unicodeCodePoints" {
		t.Fatalf("columnKind = %#v, want unicodeCodePoints", got)
	}
	invocation := run["invocations"].([]any)[0].(map[string]any)
	if got := invocation["exitCode"]; got != float64(0) {
		t.Fatalf("SARIF exit code = %#v, want 0", got)
	}
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %#v, want one", results)
	}
	location := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)
	physical := location["physicalLocation"].(map[string]any)
	region := physical["region"].(map[string]any)
	optionOffset := strings.Index(source, "-P")
	wantColumn := float64(utf8.RuneCountInString(source[:optionOffset]) + 1)
	if got := region["startColumn"]; got != wantColumn {
		t.Fatalf("SARIF start column = %#v, want %.0f Unicode code points", got, wantColumn)
	}
}

func TestRunAnalyzesValidInputsAlongsideDiscoveryErrors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	valid := filepath.Join(root, "valid.sh")
	if err := os.WriteFile(valid, []byte("grep -P pattern\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing.sh")

	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"--format", "json", "--target", "macos", missing, valid},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 because one input is missing; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result report.Report
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output %q: %v", stdout.String(), err)
	}
	if result.FilesAnalyzed != 1 {
		t.Fatalf("files analyzed = %d, want 1", result.FilesAnalyzed)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].RuleID != "SP1501" {
		t.Fatalf("diagnostics = %#v, want SP1501 from valid input", result.Diagnostics)
	}
	if len(result.AnalysisErrors) != 1 || !strings.Contains(result.AnalysisErrors[0].Message, "missing.sh") {
		t.Fatalf("analysis errors = %#v, want missing input error", result.AnalysisErrors)
	}
}
