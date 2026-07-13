package model

// Severity is the user-facing importance of a diagnostic.
type Severity string

const (
	SeverityWarning Severity = "warning"
)

// Position is a one-based source position. Column counts Unicode code points,
// which is also the columnKind declared in SARIF output.
type Position struct {
	Line   uint `json:"line"`
	Column uint `json:"column"`
}

// Range is an end-exclusive source range.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Token is one shell word. Constant is false when evaluating the word would
// require runtime expansion; rules must not reason about those values.
type Token struct {
	Value    string
	Constant bool
	Range    Range
}

// Invocation is a statically identified simple command.
type Invocation struct {
	Path           string
	Command        string
	Implementation string
	Words          []Token
	Range          Range
}

// Diagnostic is one known incompatibility with one or more selected targets.
type Diagnostic struct {
	RuleID              string   `json:"ruleId"`
	Severity            Severity `json:"severity"`
	Message             string   `json:"message"`
	Path                string   `json:"path"`
	Range               Range    `json:"range"`
	Command             string   `json:"command"`
	Option              string   `json:"option,omitempty"`
	IncompatibleTargets []string `json:"incompatibleTargets"`
	Suggestion          string   `json:"suggestion,omitempty"`
	Reference           string   `json:"reference,omitempty"`
}

// AnalysisError records a file that could not be completely analyzed.
type AnalysisError struct {
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}
