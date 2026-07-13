package analyzer

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sangmorg1-debug/shport/internal/model"
	"github.com/sangmorg1-debug/shport/internal/profile"
	"github.com/sangmorg1-debug/shport/internal/rules"
	"mvdan.cc/sh/v3/syntax"
)

// ShellMode controls which shell grammar is used to parse a source file.
type ShellMode string

const (
	ShellAuto  ShellMode = "auto"
	ShellPOSIX ShellMode = "posix"
	ShellBash  ShellMode = "bash"
)

// Result is the complete analysis result for one source file.
type Result struct {
	Diagnostics []model.Diagnostic
	Invocations int
}

// Analyze parses source without executing it and reports known external-command
// incompatibilities. Runtime-dependent command names and arguments are ignored.
func Analyze(path string, source []byte, targets []profile.Profile, mode ShellMode) (Result, error) {
	lang, err := languageFor(path, source, mode)
	if err != nil {
		return Result{}, err
	}

	parser := syntax.NewParser(syntax.Variant(lang), syntax.KeepComments(true))
	file, err := parser.Parse(strings.NewReader(string(source)), path)
	if err != nil {
		return Result{}, fmt.Errorf("parse: %w", err)
	}

	declaredFunctions := collectFunctions(file)
	suppress, err := collectSuppressions(file)
	if err != nil {
		return Result{}, err
	}

	var diagnostics []model.Diagnostic
	invocations := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		invocation, bypassFunctions, ok := extractInvocation(path, source, call)
		if !ok {
			return true
		}
		if !bypassFunctions {
			if _, shadowed := declaredFunctions[invocation.Command]; shadowed {
				return true
			}
		}
		invocations++
		for _, diagnostic := range rules.Check(invocation, targets) {
			if suppress.ignored(diagnostic.RuleID, diagnostic.Range.Start.Line) {
				continue
			}
			diagnostics = append(diagnostics, diagnostic)
		}
		return true
	})

	if err := suppress.validate(invocations); err != nil {
		return Result{}, err
	}
	sortDiagnostics(diagnostics)
	return Result{Diagnostics: diagnostics, Invocations: invocations}, nil
}

func languageFor(path string, source []byte, mode ShellMode) (syntax.LangVariant, error) {
	switch mode {
	case ShellBash:
		return syntax.LangBash, nil
	case ShellPOSIX:
		return syntax.LangPOSIX, nil
	case ShellAuto:
	default:
		return 0, fmt.Errorf("unknown shell mode %q", mode)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".bash" || ext == ".bats" {
		return syntax.LangBash, nil
	}
	firstLine := string(source)
	if index := strings.IndexByte(firstLine, '\n'); index >= 0 {
		firstLine = firstLine[:index]
	}
	firstLine = strings.ToLower(firstLine)
	if strings.HasPrefix(firstLine, "#!") && strings.Contains(firstLine, "bash") {
		return syntax.LangBash, nil
	}
	return syntax.LangPOSIX, nil
}

func collectFunctions(file *syntax.File) map[string]struct{} {
	functions := make(map[string]struct{})
	syntax.Walk(file, func(node syntax.Node) bool {
		decl, ok := node.(*syntax.FuncDecl)
		if !ok || decl.Name == nil {
			return true
		}
		functions[decl.Name.Value] = struct{}{}
		return true
	})
	return functions
}

func extractInvocation(filePath string, source []byte, call *syntax.CallExpr) (model.Invocation, bool, bool) {
	words := make([]model.Token, 0, len(call.Args))
	for _, word := range call.Args {
		value, constant := constantWord(word)
		words = append(words, model.Token{
			Value:    value,
			Constant: constant,
			Range:    sourceRange(source, word.Pos(), word.End()),
		})
	}
	if len(words) == 0 || !words[0].Constant || words[0].Value == "" {
		return model.Invocation{}, false, false
	}

	index := 0
	bypassFunctions := false
	implementation := ""
	command, pathCommand, ok := classifyCommand(words[index].Value)
	if !ok {
		return model.Invocation{}, false, false
	}
	bypassFunctions = pathCommand
	switch command {
	case "command":
		bypassFunctions = true
		index++
		for index < len(words) && words[index].Constant && (words[index].Value == "-p" || words[index].Value == "--") {
			index++
		}
		if index >= len(words) || !words[index].Constant || strings.HasPrefix(words[index].Value, "-") {
			return model.Invocation{}, false, false
		}
	case "env":
		bypassFunctions = true
		index++
		for index < len(words) && words[index].Constant {
			value := words[index].Value
			switch {
			case isAssignment(value), value == "-i", value == "--ignore-environment", value == "--":
				index++
			case value == "-u", value == "--unset", value == "-C", value == "--chdir":
				index += 2
			case strings.HasPrefix(value, "--unset="), strings.HasPrefix(value, "--chdir="):
				index++
			default:
				goto envDone
			}
		}
	envDone:
		if index >= len(words) || !words[index].Constant || strings.HasPrefix(words[index].Value, "-") {
			return model.Invocation{}, false, false
		}
	case "busybox":
		bypassFunctions = true
		implementation = "busybox-1.36.1"
		index++
		if index >= len(words) || !words[index].Constant || strings.HasPrefix(words[index].Value, "-") {
			return model.Invocation{}, false, false
		}
	}

	command, explicitPath, ok := classifyCommand(words[index].Value)
	if !ok {
		return model.Invocation{}, false, false
	}
	bypassFunctions = bypassFunctions || explicitPath
	args := append([]model.Token(nil), words[index:]...)
	return model.Invocation{
		Path:           filepath.ToSlash(filePath),
		Command:        command,
		Implementation: implementation,
		Words:          args,
		Range:          sourceRange(source, call.Pos(), call.End()),
	}, bypassFunctions, true
}

func constantWord(word *syntax.Word) (string, bool) {
	var builder strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			builder.WriteString(part.Value)
		case *syntax.SglQuoted:
			builder.WriteString(part.Value)
		case *syntax.DblQuoted:
			value, ok := constantParts(part.Parts)
			if !ok {
				return "", false
			}
			builder.WriteString(value)
		default:
			return "", false
		}
	}
	return builder.String(), true
}

func constantParts(parts []syntax.WordPart) (string, bool) {
	var builder strings.Builder
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			builder.WriteString(part.Value)
		case *syntax.SglQuoted:
			builder.WriteString(part.Value)
		case *syntax.DblQuoted:
			value, ok := constantParts(part.Parts)
			if !ok {
				return "", false
			}
			builder.WriteString(value)
		default:
			return "", false
		}
	}
	return builder.String(), true
}

func classifyCommand(value string) (name string, explicitPath bool, ok bool) {
	if !strings.ContainsRune(value, '/') {
		return value, false, value != ""
	}
	cleaned := path.Clean(value)
	directory, base := path.Split(cleaned)
	directory = strings.TrimSuffix(directory, "/")
	switch directory {
	case "/bin", "/usr/bin":
		return base, true, base != ""
	default:
		// A project-local or third-party pathname may implement entirely
		// different semantics despite sharing a familiar basename.
		return "", true, false
	}
}

func isAssignment(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	if !ok || name == "" {
		return false
	}
	for index, char := range name {
		if !(char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || index > 0 && char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func sourceRange(source []byte, start, end syntax.Pos) model.Range {
	return model.Range{
		Start: model.Position{Line: start.Line(), Column: codePointColumn(source, start)},
		End:   model.Position{Line: end.Line(), Column: codePointColumn(source, end)},
	}
}

func codePointColumn(source []byte, position syntax.Pos) uint {
	if !position.IsValid() || position.Col() == 0 {
		return 0
	}
	offset := position.Offset()
	lineBytes := position.Col() - 1
	if offset > uint(len(source)) || lineBytes > offset {
		return position.Col()
	}
	lineStart := offset - lineBytes
	return uint(utf8.RuneCount(source[lineStart:offset])) + 1
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

type suppressions struct {
	lines          map[uint]map[string]struct{}
	file           map[string]struct{}
	fileDirectives []uint
}

func collectSuppressions(file *syntax.File) (suppressions, error) {
	result := suppressions{
		lines: make(map[uint]map[string]struct{}),
		file:  make(map[string]struct{}),
	}
	var directiveErr error
	syntax.Walk(file, func(node syntax.Node) bool {
		comment, ok := node.(*syntax.Comment)
		if !ok || directiveErr != nil {
			return true
		}
		kind, ids, found, err := parseDirective(comment.Text)
		if err != nil {
			directiveErr = fmt.Errorf("line %d: %w", comment.Pos().Line(), err)
			return true
		}
		if !found {
			return true
		}
		line := comment.Pos().Line()
		switch kind {
		case "ignore":
			result.addLine(line, ids)
		case "ignore-next-line":
			result.addLine(line+1, ids)
		case "ignore-file":
			for _, id := range ids {
				result.file[id] = struct{}{}
			}
			result.fileDirectives = append(result.fileDirectives, line)
		}
		return true
	})
	return result, directiveErr
}

func parseDirective(text string) (string, []string, bool, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "shport:") {
		return "", nil, false, nil
	}
	rest := strings.TrimSpace(strings.TrimPrefix(text, "shport:"))
	for _, kind := range []string{"ignore-next-line", "ignore-file", "ignore"} {
		prefix := kind + "="
		if !strings.HasPrefix(rest, prefix) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(rest, prefix))
		if fields := strings.Fields(value); len(fields) > 0 {
			value = fields[0]
		}
		if value == "" {
			return "", nil, true, fmt.Errorf("%s requires a rule ID or all", kind)
		}
		var ids []string
		for _, raw := range strings.Split(value, ",") {
			id := strings.ToUpper(strings.TrimSpace(raw))
			if id == "ALL" {
				ids = append(ids, "all")
				continue
			}
			if _, ok := rules.Lookup(id); !ok {
				return "", nil, true, fmt.Errorf("unknown rule ID %q", raw)
			}
			ids = append(ids, id)
		}
		return kind, ids, true, nil
	}
	return "", nil, true, fmt.Errorf("malformed shport directive %q", rest)
}

func (s *suppressions) addLine(line uint, ids []string) {
	if s.lines[line] == nil {
		s.lines[line] = make(map[string]struct{})
	}
	for _, id := range ids {
		s.lines[line][id] = struct{}{}
	}
}

func (s suppressions) ignored(id string, line uint) bool {
	if _, ok := s.file["all"]; ok {
		return true
	}
	if _, ok := s.file[id]; ok {
		return true
	}
	if _, ok := s.lines[line]["all"]; ok {
		return true
	}
	_, ok := s.lines[line][id]
	return ok
}

func (s suppressions) validate(invocations int) error {
	if invocations == 0 {
		return nil
	}
	// File directives are intentionally accepted anywhere before v0.2 gains
	// richer source-order validation. Keeping their lines lets us add that check
	// without changing the directive model.
	return nil
}
