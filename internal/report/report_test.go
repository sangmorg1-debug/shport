package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sangmorg1-debug/shport/internal/model"
	"github.com/sangmorg1-debug/shport/internal/profile"
)

func TestWriteSARIF(t *testing.T) {
	t.Parallel()
	report := Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "shport", Version: "test"},
		Targets:       profile.Default(),
		FilesAnalyzed: 1,
		Diagnostics: []model.Diagnostic{{
			RuleID:   "SP1501",
			Severity: model.SeverityWarning,
			Message:  "grep PCRE mode is unavailable",
			Path:     "scripts/check.sh",
			Range: model.Range{
				Start: model.Position{Line: 2, Column: 6},
				End:   model.Position{Line: 2, Column: 8},
			},
			Command:             "grep",
			Option:              "-P",
			IncompatibleTargets: []string{"macos-14"},
		}},
	}
	var output bytes.Buffer
	if err := Write(&output, "sarif", report); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("SARIF version = %#v", document["version"])
	}
	runs := document["runs"].([]any)
	run := runs[0].(map[string]any)
	if got := run["columnKind"]; got != "unicodeCodePoints" {
		t.Fatalf("SARIF columnKind = %#v, want unicodeCodePoints", got)
	}
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %#v", results)
	}
	invocations := run["invocations"].([]any)
	if got := invocations[0].(map[string]any)["exitCode"]; got != float64(1) {
		t.Fatalf("SARIF exit code = %#v, want 1", got)
	}
}

func TestWriteSARIFHonorsExitZero(t *testing.T) {
	t.Parallel()
	input := Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "shport", Version: "test"},
		ExitZero:      true,
		Diagnostics: []model.Diagnostic{{
			RuleID:   "SP1501",
			Severity: model.SeverityWarning,
			Message:  "grep PCRE mode is unavailable",
			Path:     "scripts/check.sh",
			Range: model.Range{
				Start: model.Position{Line: 1, Column: 6},
				End:   model.Position{Line: 1, Column: 8},
			},
			Command:             "grep",
			Option:              "-P",
			IncompatibleTargets: []string{"macos-14"},
		}},
	}
	var output bytes.Buffer
	if err := Write(&output, "sarif", input); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	run := document["runs"].([]any)[0].(map[string]any)
	invocation := run["invocations"].([]any)[0].(map[string]any)
	if got := invocation["exitCode"]; got != float64(0) {
		t.Fatalf("SARIF exit code = %#v, want 0 when ExitZero is set", got)
	}
}

func TestArtifactURI(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"scripts/a file.sh":            "scripts/a%20file.sh",
		`C:\work dir\scripts\check.sh`: "file:///C:/work%20dir/scripts/check.sh",
		`\\server\share\check.sh`:      "file://server/share/check.sh",
		"/tmp/work dir/check.sh":       "file:///tmp/work%20dir/check.sh",
	}
	for input, want := range tests {
		if got := artifactURI(input); got != want {
			t.Errorf("artifactURI(%q) = %q, want %q", input, got, want)
		}
	}
}
