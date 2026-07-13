package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sangmorg1-debug/shport/internal/analyzer"
	"github.com/sangmorg1-debug/shport/internal/discovery"
	"github.com/sangmorg1-debug/shport/internal/model"
	"github.com/sangmorg1-debug/shport/internal/profile"
	"github.com/sangmorg1-debug/shport/internal/report"
	"github.com/sangmorg1-debug/shport/internal/rules"
)

// Version is replaced by release builds using -ldflags.
var Version = "0.1.0-dev"

// Run executes the CLI and returns its process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "targets":
			return runTargets(args[1:], stdout, stderr)
		case "version":
			if len(args) != 1 {
				_, _ = fmt.Fprintln(stderr, "usage: shport version")
				return 2
			}
			_, _ = fmt.Fprintln(stdout, Version)
			return 0
		}
	}

	flags := flag.NewFlagSet("shport", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var targetValues stringList
	var excludes stringList
	var format string
	var output string
	var shell string
	var stdinFilename string
	var exitZero bool
	var showVersion bool
	var listRules bool
	flags.Var(&targetValues, "target", "required target ID or comma-separated IDs; repeatable")
	flags.Var(&targetValues, "t", "alias for --target")
	flags.Var(&excludes, "exclude", "discovery glob relative to each input directory; repeatable")
	flags.StringVar(&format, "format", "text", "output format: text, json, or sarif")
	flags.StringVar(&format, "f", "text", "alias for --format")
	flags.StringVar(&output, "output", "-", "write results to this file instead of stdout")
	flags.StringVar(&output, "o", "-", "alias for --output")
	flags.StringVar(&shell, "shell", "auto", "parser grammar: auto, posix, or bash")
	flags.StringVar(&stdinFilename, "stdin-filename", "<stdin>", "display name and dialect hint for standard input")
	flags.BoolVar(&exitZero, "exit-zero", false, "return zero when findings are present; analysis errors still return 2")
	flags.BoolVar(&showVersion, "version", false, "print the version and exit")
	flags.BoolVar(&listRules, "list-rules", false, "print the built-in rule catalog and exit")
	flags.Usage = func() { writeUsage(stderr) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	}
	if format != "text" && format != "json" && format != "sarif" {
		_, _ = fmt.Fprintf(stderr, "shport: unknown format %q\n", format)
		return 2
	}
	mode := analyzer.ShellMode(shell)
	if mode != analyzer.ShellAuto && mode != analyzer.ShellPOSIX && mode != analyzer.ShellBash {
		_, _ = fmt.Fprintf(stderr, "shport: unknown shell mode %q\n", shell)
		return 2
	}
	if stdinFilename == "" {
		_, _ = fmt.Fprintln(stderr, "shport: --stdin-filename must not be empty")
		return 2
	}
	targets, err := profile.Resolve(targetValues)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "shport: %v\n", err)
		return 2
	}
	if listRules {
		return writeRuleCatalog(format, stdout, stderr)
	}

	paths := flags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	stdinCount := 0
	var diskInputs []string
	for _, input := range paths {
		if input == "-" {
			stdinCount++
			continue
		}
		diskInputs = append(diskInputs, input)
	}
	if stdinCount > 1 {
		_, _ = fmt.Fprintln(stderr, "shport: standard input may be specified only once")
		return 2
	}

	result := report.Report{
		SchemaVersion:  report.SchemaVersion,
		Tool:           report.Tool{Name: "shport", Version: Version},
		Targets:        targets,
		Diagnostics:    []model.Diagnostic{},
		AnalysisErrors: []model.AnalysisError{},
		ExitZero:       exitZero,
	}
	cwd, cwdErr := os.Getwd()
	if cwdErr != nil {
		cwd = "."
	}

	files, discoverErr := discovery.Discover(diskInputs, excludes)
	if discoverErr != nil {
		result.AnalysisErrors = append(result.AnalysisErrors, model.AnalysisError{Message: discoverErr.Error()})
	}
	for _, filePath := range files {
		source, readErr := os.ReadFile(filePath)
		displayPath := discovery.DisplayPath(cwd, filePath)
		if readErr != nil {
			result.AnalysisErrors = append(result.AnalysisErrors, model.AnalysisError{Path: displayPath, Message: readErr.Error()})
			continue
		}
		analysis, analyzeErr := analyzer.Analyze(displayPath, source, targets, mode)
		if analyzeErr != nil {
			result.AnalysisErrors = append(result.AnalysisErrors, model.AnalysisError{Path: displayPath, Message: analyzeErr.Error()})
			continue
		}
		result.FilesAnalyzed++
		result.Diagnostics = append(result.Diagnostics, analysis.Diagnostics...)
	}
	if stdinCount == 1 {
		source, readErr := io.ReadAll(stdin)
		if readErr != nil {
			result.AnalysisErrors = append(result.AnalysisErrors, model.AnalysisError{Path: stdinFilename, Message: readErr.Error()})
		} else {
			analysis, analyzeErr := analyzer.Analyze(stdinFilename, source, targets, mode)
			if analyzeErr != nil {
				result.AnalysisErrors = append(result.AnalysisErrors, model.AnalysisError{Path: stdinFilename, Message: analyzeErr.Error()})
			} else {
				result.FilesAnalyzed++
				result.Diagnostics = append(result.Diagnostics, analysis.Diagnostics...)
			}
		}
	}
	sortDiagnostics(result.Diagnostics)
	sort.Slice(result.AnalysisErrors, func(i, j int) bool {
		if result.AnalysisErrors[i].Path == result.AnalysisErrors[j].Path {
			return result.AnalysisErrors[i].Message < result.AnalysisErrors[j].Message
		}
		return result.AnalysisErrors[i].Path < result.AnalysisErrors[j].Path
	})

	writer := stdout
	var outputFile *os.File
	if output != "" && output != "-" {
		outputFile, err = os.Create(output)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "shport: create output: %v\n", err)
			return 2
		}
		writer = outputFile
	}
	if err := report.Write(writer, format, result); err != nil {
		if outputFile != nil {
			_ = outputFile.Close()
		}
		_, _ = fmt.Fprintf(stderr, "shport: write output: %v\n", err)
		return 2
	}
	if outputFile != nil {
		if err := outputFile.Close(); err != nil {
			_, _ = fmt.Fprintf(stderr, "shport: close output: %v\n", err)
			return 2
		}
	}
	for _, analysisError := range result.AnalysisErrors {
		if analysisError.Path == "" {
			_, _ = fmt.Fprintf(stderr, "shport: %s\n", analysisError.Message)
		} else {
			_, _ = fmt.Fprintf(stderr, "shport: %s: %s\n", analysisError.Path, analysisError.Message)
		}
	}
	if len(result.AnalysisErrors) > 0 {
		return 2
	}
	if len(result.Diagnostics) > 0 && !exitZero {
		return 1
	}
	return 0
}

func runTargets(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("shport targets", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || (*format != "text" && *format != "json") {
		_, _ = fmt.Fprintln(stderr, "usage: shport targets [--format text|json]")
		return 2
	}
	targets := profile.All()
	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(targets); err != nil {
			_, _ = fmt.Fprintf(stderr, "shport: %v\n", err)
			return 2
		}
		return 0
	}
	for _, target := range targets {
		_, _ = fmt.Fprintf(stdout, "%s (%s): %s\n", target.ID, target.Alias, target.Description)
		for _, reference := range target.References {
			_, _ = fmt.Fprintf(stdout, "  %s\n", reference)
		}
	}
	return 0
}

func writeRuleCatalog(format string, stdout, stderr io.Writer) int {
	definitions := rules.All()
	if format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(definitions); err != nil {
			_, _ = fmt.Fprintf(stderr, "shport: %v\n", err)
			return 2
		}
		return 0
	}
	if format == "sarif" {
		_, _ = fmt.Fprintln(stderr, "shport: --list-rules supports text and json formats")
		return 2
	}
	for _, definition := range definitions {
		_, _ = fmt.Fprintf(stdout, "%s  %-28s %s\n", definition.ID, definition.Name, definition.Summary)
	}
	return 0
}

func writeUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `Usage:
  shport [flags] [FILE|DIR|-]...
  shport targets [--format text|json]
  shport version

Lint external utility invocations for known cross-userland incompatibilities.
No paths means the current directory. Use - to read standard input.

Core flags:
  -t, --target ID[,ID...]  required targets; repeatable (default: portable)
  -f, --format FORMAT      text, json, or sarif
  -o, --output FILE        output file (default: stdout)
      --shell MODE         auto, posix, or bash
      --exclude GLOB       directory-discovery exclusion; repeatable
      --stdin-filename     display name and dialect hint for stdin
      --exit-zero          do not fail because of findings
      --list-rules         print the rule catalog
      --version            print the version`)
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func sortDiagnostics(diagnostics []model.Diagnostic) {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		left, right := diagnostics[i], diagnostics[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Range.Start.Line != right.Range.Start.Line {
			return left.Range.Start.Line < right.Range.Start.Line
		}
		if left.Range.Start.Column != right.Range.Start.Column {
			return left.Range.Start.Column < right.Range.Start.Column
		}
		return left.RuleID < right.RuleID
	})
}
