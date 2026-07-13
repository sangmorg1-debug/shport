package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/sangmorg1-debug/shport/internal/model"
	"github.com/sangmorg1-debug/shport/internal/profile"
	"github.com/sangmorg1-debug/shport/internal/rules"
)

const SchemaVersion = 1

// Tool identifies the producer of a structured report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Report is shport's stable JSON document.
type Report struct {
	SchemaVersion  int                   `json:"schemaVersion"`
	Tool           Tool                  `json:"tool"`
	Targets        []profile.Profile     `json:"targets"`
	FilesAnalyzed  int                   `json:"filesAnalyzed"`
	Diagnostics    []model.Diagnostic    `json:"diagnostics"`
	AnalysisErrors []model.AnalysisError `json:"analysisErrors"`
	ExitZero       bool                  `json:"-"`
}

// Write renders a report in text, JSON, or SARIF 2.1.0 format.
func Write(writer io.Writer, format string, report Report) error {
	switch format {
	case "text":
		return writeText(writer, report)
	case "json":
		return writeJSON(writer, report)
	case "sarif":
		return writeSARIF(writer, report)
	default:
		return fmt.Errorf("unknown output format %q", format)
	}
}

func writeText(writer io.Writer, report Report) error {
	for _, diagnostic := range report.Diagnostics {
		_, err := fmt.Fprintf(
			writer,
			"%s:%d:%d: %s: %s [targets: %s]\n",
			diagnostic.Path,
			diagnostic.Range.Start.Line,
			diagnostic.Range.Start.Column,
			diagnostic.RuleID,
			diagnostic.Message,
			strings.Join(diagnostic.IncompatibleTargets, ", "),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(writer io.Writer, report Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	ColumnKind  string            `json:"columnKind"`
	Artifacts   []sarifArtifact   `json:"artifacts,omitempty"`
	Results     []sarifResult     `json:"results,omitempty"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   uint `json:"startLine"`
	StartColumn uint `json:"startColumn"`
	EndLine     uint `json:"endLine,omitempty"`
	EndColumn   uint `json:"endColumn,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ExitCode                   int                 `json:"exitCode"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

func writeSARIF(writer io.Writer, report Report) error {
	definitions := rules.All()
	sarifRules := make([]sarifRule, 0, len(definitions))
	for _, definition := range definitions {
		sarifRules = append(sarifRules, sarifRule{
			ID:               definition.ID,
			Name:             definition.Name,
			ShortDescription: sarifMessage{Text: definition.Summary},
			FullDescription:  sarifMessage{Text: definition.Description},
			HelpURI:          definition.Reference,
			Properties:       map[string]any{"suggestion": definition.Suggestion},
		})
	}

	artifactSet := make(map[string]struct{})
	results := make([]sarifResult, 0, len(report.Diagnostics))
	for _, diagnostic := range report.Diagnostics {
		uri := artifactURI(diagnostic.Path)
		artifactSet[uri] = struct{}{}
		results = append(results, sarifResult{
			RuleID:  diagnostic.RuleID,
			Level:   "warning",
			Message: sarifMessage{Text: diagnostic.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
				Region: sarifRegion{
					StartLine:   diagnostic.Range.Start.Line,
					StartColumn: diagnostic.Range.Start.Column,
					EndLine:     diagnostic.Range.End.Line,
					EndColumn:   diagnostic.Range.End.Column,
				},
			}}},
			PartialFingerprints: map[string]string{"shportFingerprint/v1": fingerprint(diagnostic)},
			Properties: map[string]any{
				"command":             diagnostic.Command,
				"option":              diagnostic.Option,
				"incompatibleTargets": diagnostic.IncompatibleTargets,
				"suggestion":          diagnostic.Suggestion,
			},
		})
	}

	artifactURIs := make([]string, 0, len(artifactSet))
	for uri := range artifactSet {
		artifactURIs = append(artifactURIs, uri)
	}
	sort.Strings(artifactURIs)
	artifacts := make([]sarifArtifact, 0, len(artifactURIs))
	for _, uri := range artifactURIs {
		artifacts = append(artifacts, sarifArtifact{Location: sarifArtifactLocation{URI: uri}})
	}

	exitCode := 0
	if len(report.Diagnostics) > 0 && !report.ExitZero {
		exitCode = 1
	}
	success := len(report.AnalysisErrors) == 0
	var notifications []sarifNotification
	for _, analysisError := range report.AnalysisErrors {
		exitCode = 2
		message := analysisError.Message
		if analysisError.Path != "" {
			message = analysisError.Path + ": " + message
		}
		notifications = append(notifications, sarifNotification{
			Level:   "error",
			Message: sarifMessage{Text: message},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			ColumnKind: "unicodeCodePoints",
			Tool: sarifTool{Driver: sarifDriver{
				Name:           report.Tool.Name,
				Version:        report.Tool.Version,
				InformationURI: "https://github.com/sangmorg1-debug/shport",
				Rules:          sarifRules,
			}},
			Artifacts: artifacts,
			Results:   results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful:        success,
				ExitCode:                   exitCode,
				ToolExecutionNotifications: notifications,
			}},
		}},
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func artifactURI(path string) string {
	normalized := strings.ReplaceAll(path, "\\", "/")
	if strings.HasPrefix(normalized, "//") {
		hostAndPath := strings.TrimPrefix(normalized, "//")
		host, rest, _ := strings.Cut(hostAndPath, "/")
		return (&url.URL{Scheme: "file", Host: host, Path: "/" + rest}).String()
	}
	if isWindowsAbsolutePath(normalized) {
		return (&url.URL{Scheme: "file", Path: "/" + normalized}).String()
	}
	if strings.HasPrefix(normalized, "/") {
		return (&url.URL{Scheme: "file", Path: normalized}).String()
	}
	return (&url.URL{Path: normalized}).String()
}

func isWindowsAbsolutePath(path string) bool {
	if len(path) < 3 || path[1] != ':' || path[2] != '/' {
		return false
	}
	letter := path[0]
	return letter >= 'a' && letter <= 'z' || letter >= 'A' && letter <= 'Z'
}

func fingerprint(diagnostic model.Diagnostic) string {
	value := fmt.Sprintf(
		"%s\x00%s\x00%d\x00%d\x00%s",
		diagnostic.RuleID,
		diagnostic.Path,
		diagnostic.Range.Start.Line,
		diagnostic.Range.Start.Column,
		diagnostic.Command,
	)
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:12])
}
