package rules

import (
	"sort"
	"strings"

	"github.com/sangmorg1-debug/shport/internal/model"
	"github.com/sangmorg1-debug/shport/internal/profile"
)

const (
	targetGNU       = "gnu-2026"
	targetMacOS11   = "macos-11"
	targetMacOS14   = "macos-14"
	targetFreeBSD   = "freebsd-14.1"
	targetBusyBox   = "busybox-1.36.1"
	targetPOSIX2017 = "posix-2017"
	targetPOSIX2024 = "posix-2024"
)

// Check applies the built-in, literal-only portability rules to an invocation.
func Check(invocation model.Invocation, targets []profile.Profile) []model.Diagnostic {
	selected := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		selected[target.ID] = struct{}{}
	}
	if invocation.Implementation != "" {
		selected = map[string]struct{}{invocation.Implementation: {}}
	}

	var diagnostics []model.Diagnostic
	switch invocation.Command {
	case "sed":
		diagnostics = checkSed(invocation, selected)
	case "readlink":
		diagnostics = checkReadlink(invocation, selected)
	case "stat":
		diagnostics = checkStat(invocation, selected)
	case "date":
		diagnostics = checkDate(invocation, selected)
	case "xargs":
		diagnostics = checkXargs(invocation, selected)
	case "grep":
		diagnostics = checkGrep(invocation, selected)
	}

	return deduplicateDiagnostics(diagnostics)
}

func checkSed(invocation model.Invocation, selected map[string]struct{}) []model.Diagnostic {
	var diagnostics []model.Diagnostic
	skipNext := false
	for index := 1; index < len(invocation.Words); index++ {
		word := invocation.Words[index]
		if skipNext {
			skipNext = false
			continue
		}
		if !word.Constant {
			break
		}
		value := word.Value
		if value == "--" {
			break
		}
		if value == "-" || !strings.HasPrefix(value, "-") {
			break
		}
		if value == "-e" || value == "-f" || value == "--expression" || value == "--file" {
			skipNext = true
			continue
		}
		if value == "-l" || value == "--line-length" {
			// GNU -l consumes a line-length argument while BSD -l does not.
			// A later option-looking word therefore cannot be classified
			// consistently without first choosing an implementation grammar.
			break
		}
		if strings.HasPrefix(value, "-e") && len(value) > 2 || strings.HasPrefix(value, "-f") && len(value) > 2 || strings.HasPrefix(value, "--expression=") || strings.HasPrefix(value, "--file=") {
			continue
		}

		clusteredInPlace, clusteredSuffix := sedClusterInPlace(value)
		switch {
		case value == "-i":
			family := sedInPlaceFamily(invocation.Words, index)
			switch family {
			case "gnu":
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1001",
					word,
					value,
					[]string{targetMacOS11, targetMacOS14, targetFreeBSD},
					"sed -i without a separate backup suffix uses the GNU form",
					selected,
				)...)
			case "bsd":
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1001",
					word,
					value,
					[]string{targetGNU, targetBusyBox},
					"sed -i with a separate backup suffix uses the BSD form",
					selected,
				)...)
			}
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1002",
				word,
				value,
				[]string{targetPOSIX2017, targetPOSIX2024},
				"sed in-place editing is not specified by POSIX",
				selected,
			)...)
		case strings.HasPrefix(value, "-i") && len(value) > 2:
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1002",
				word,
				value,
				[]string{targetPOSIX2017, targetPOSIX2024},
				"sed in-place editing is not specified by POSIX",
				selected,
			)...)
		case clusteredInPlace:
			if clusteredSuffix == "" {
				family := sedInPlaceFamily(invocation.Words, index)
				switch family {
				case "gnu":
					diagnostics = append(diagnostics, emit(
						invocation,
						"SP1001",
						word,
						value,
						[]string{targetMacOS11, targetMacOS14, targetFreeBSD},
						"sed clustered -i without a separate backup suffix uses the GNU form",
						selected,
					)...)
				case "bsd":
					diagnostics = append(diagnostics, emit(
						invocation,
						"SP1001",
						word,
						value,
						[]string{targetGNU, targetBusyBox},
						"sed clustered -i with a separate backup suffix uses the BSD form",
						selected,
					)...)
				}
			}
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1002",
				word,
				value,
				[]string{targetPOSIX2017, targetPOSIX2024},
				"sed in-place editing is not specified by POSIX",
				selected,
			)...)
		case value == "--in-place" || strings.HasPrefix(value, "--in-place="):
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1001",
				word,
				value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD},
				"sed --in-place is a GNU option form",
				selected,
			)...)
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1002",
				word,
				value,
				[]string{targetPOSIX2017, targetPOSIX2024},
				"sed in-place editing is not specified by POSIX",
				selected,
			)...)
		}
	}
	return diagnostics
}

// sedInPlaceFamily classifies only command shapes whose intent can be inferred
// without parsing the full sed language. A bare -i has an optional attached
// argument on GNU/BusyBox, but a required next-word argument on BSD. Ambiguous
// forms are left unclassified rather than guessed.
func sedInPlaceFamily(words []model.Token, optionIndex int) string {
	if optionIndex+1 >= len(words) {
		return "gnu"
	}
	next := words[optionIndex+1]
	if !next.Constant {
		return ""
	}
	if next.Value == "" {
		return "bsd"
	}
	if next.Value == "--" || strings.HasPrefix(next.Value, "-") {
		return "gnu"
	}
	if hasLaterSedProgramOption(words, optionIndex+2) {
		return "bsd"
	}
	if looksLikeSedProgram(next.Value) {
		return "gnu"
	}
	if optionIndex+2 < len(words) && words[optionIndex+2].Constant && looksLikeSedProgram(words[optionIndex+2].Value) {
		return "bsd"
	}
	return ""
}

func hasLaterSedProgramOption(words []model.Token, start int) bool {
	for index := start; index < len(words); index++ {
		if !words[index].Constant {
			return false
		}
		value := words[index].Value
		if value == "--" {
			return false
		}
		if value == "-e" || value == "-f" || value == "--expression" || value == "--file" ||
			strings.HasPrefix(value, "-e") && len(value) > 2 ||
			strings.HasPrefix(value, "-f") && len(value) > 2 ||
			strings.HasPrefix(value, "--expression=") || strings.HasPrefix(value, "--file=") {
			return true
		}
	}
	return false
}

func looksLikeSedProgram(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.ContainsRune("sy", rune(value[0])) {
		delimiter := value[1]
		return delimiter != '\\' && !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", rune(delimiter))
	}
	return len(value) == 1 && strings.ContainsRune("dDgGhHnNpPqQx=", rune(value[0]))
}

func sedClusterInPlace(value string) (found bool, attachedSuffix string) {
	if len(value) < 3 || value[0] != '-' || strings.HasPrefix(value, "--") || value[1] == 'i' {
		return false, ""
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'i':
			return true, value[index+1:]
		case 'n', 'E', 'r':
			// These are shared no-argument options that may precede -i.
			continue
		default:
			// Other options can consume the remainder on at least one modeled
			// implementation; for example GNU sed parses the i in -li as the
			// optional argument to -l.
			return false, ""
		}
	}
	return false, ""
}

func checkReadlink(invocation model.Invocation, selected map[string]struct{}) []model.Diagnostic {
	var diagnostics []model.Diagnostic
	for _, word := range optionWords(invocation.Words) {
		if shortOption(word.Value, 'f') {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1101",
				word,
				"-f",
				[]string{targetMacOS11, targetPOSIX2017, targetPOSIX2024},
				"readlink -f is unavailable in the selected legacy macOS and POSIX profiles",
				selected,
			)...)
		}
		if word.Value == "--canonicalize" {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1101",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"readlink --canonicalize is a GNU option",
				selected,
			)...)
		}
		if shortOption(word.Value, 'e') || shortOption(word.Value, 'm') || word.Value == "--canonicalize-existing" || word.Value == "--canonicalize-missing" {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1102",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"readlink canonicalization mode is a GNU extension",
				selected,
			)...)
		}
	}
	return diagnostics
}

func checkStat(invocation model.Invocation, selected map[string]struct{}) []model.Diagnostic {
	var diagnostics []model.Diagnostic
	for index := 1; index < len(invocation.Words); index++ {
		word := invocation.Words[index]
		if !word.Constant {
			break
		}
		value := word.Value
		if value == "--" {
			break
		}
		if value == "-" || !strings.HasPrefix(value, "-") {
			break
		}

		clusteredFormat, _ := statGNUFormatCluster(value)
		if value == "-c" || strings.HasPrefix(value, "-c") && len(value) > 2 || value == "--format" || strings.HasPrefix(value, "--format=") || value == "--printf" || strings.HasPrefix(value, "--printf=") || clusteredFormat {
			incompatible := []string{targetMacOS11, targetMacOS14, targetFreeBSD, targetPOSIX2017, targetPOSIX2024}
			if strings.HasPrefix(value, "--") {
				incompatible = append(incompatible, targetBusyBox)
			}
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1201",
				word,
				value,
				incompatible,
				"stat GNU format syntax is unavailable on macOS and is not specified by POSIX",
				selected,
			)...)
			return diagnostics
		}
		if value == "-f" && index+1 < len(invocation.Words) {
			format := invocation.Words[index+1]
			if format.Constant && strings.Contains(format.Value, "%") {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1202",
					word,
					value,
					[]string{targetGNU, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
					"stat -f FORMAT uses BSD syntax; -f selects filesystem status on GNU and BusyBox",
					selected,
				)...)
			}
			if format.Constant && isGNUStatFormatWord(format.Value) && shouldDiagnoseAmbiguousGNUStat(selected) {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1201",
					format,
					format.Value,
					[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetPOSIX2017, targetPOSIX2024},
					"stat parses this word as the argument to BSD -f, not as a GNU format option",
					selected,
				)...)
			}
			return diagnostics
		}
		if ambiguous, _ := statAmbiguousGNUFormatCluster(value); ambiguous {
			if shouldDiagnoseAmbiguousGNUStat(selected) {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1201",
					word,
					value,
					[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetPOSIX2017, targetPOSIX2024},
					"stat parses clustered -c as a GNU format option but as data for a BSD -f/-t option",
					selected,
				)...)
			}
			return diagnostics
		}
		if format, _, ok := statBSDFormatCluster(invocation.Words, index); ok {
			if strings.Contains(format, "%") {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1202",
					word,
					value,
					[]string{targetGNU, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
					"stat -f FORMAT uses BSD syntax; -f selects filesystem status on GNU and BusyBox",
					selected,
				)...)
			}
			return diagnostics
		}
		if value == "-t" && index+1 < len(invocation.Words) {
			next := invocation.Words[index+1]
			if next.Constant && isGNUStatFormatWord(next.Value) && shouldDiagnoseAmbiguousGNUStat(selected) {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1201",
					next,
					next.Value,
					[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetPOSIX2017, targetPOSIX2024},
					"stat parses this word as the argument to BSD -t, not as a GNU format option",
					selected,
				)...)
			}
			return diagnostics
		}
		if value == "--cached" {
			index++
		}
	}
	return diagnostics
}

func statGNUFormatCluster(value string) (found, consumesNext bool) {
	if len(value) < 3 || value[0] != '-' || strings.HasPrefix(value, "--") || value[1] == 'c' {
		return false, false
	}
	for index := 1; index < len(value); index++ {
		if value[index] == 'c' {
			return true, index == len(value)-1
		}
		// L is the only no-argument short option shared by the modeled GNU
		// stat grammar that we accept before c. In particular, BSD -f and
		// -t consume the rest of the cluster as their argument.
		if value[index] != 'L' {
			return false, false
		}
	}
	return false, false
}

func statAmbiguousGNUFormatCluster(value string) (found, consumesNext bool) {
	if len(value) < 3 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return false, false
	}
	sawTargetDependentOption := false
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'L':
			continue
		case 'f', 't':
			sawTargetDependentOption = true
		case 'c':
			return sawTargetDependentOption, sawTargetDependentOption && index+1 == len(value)
		default:
			return false, false
		}
	}
	return false, false
}

func statBSDFormatCluster(words []model.Token, optionIndex int) (format string, consumesNext, ok bool) {
	value := words[optionIndex].Value
	if len(value) < 3 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return "", false, false
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case 'L', 'n', 'q':
			continue
		case 'f':
			if attached := value[index+1:]; attached != "" {
				return attached, false, true
			}
			if optionIndex+1 < len(words) && words[optionIndex+1].Constant {
				return words[optionIndex+1].Value, true, true
			}
			return "", false, true
		default:
			return "", false, false
		}
	}
	return "", false, false
}

func isGNUStatFormatWord(value string) bool {
	if value == "-c" || strings.HasPrefix(value, "-c") && len(value) > 2 ||
		value == "--format" || strings.HasPrefix(value, "--format=") ||
		value == "--printf" || strings.HasPrefix(value, "--printf=") {
		return true
	}
	if found, _ := statGNUFormatCluster(value); found {
		return true
	}
	found, _ := statAmbiguousGNUFormatCluster(value)
	return found
}

func shouldDiagnoseAmbiguousGNUStat(selected map[string]struct{}) bool {
	_, gnu := selected[targetGNU]
	_, busybox := selected[targetBusyBox]
	_, mac11 := selected[targetMacOS11]
	_, mac14 := selected[targetMacOS14]
	_, freebsd := selected[targetFreeBSD]
	_, posix2017 := selected[targetPOSIX2017]
	_, posix2024 := selected[targetPOSIX2024]
	return posix2017 || posix2024 || (gnu || busybox) && (mac11 || mac14 || freebsd)
}

func checkDate(invocation model.Invocation, selected map[string]struct{}) []model.Diagnostic {
	var diagnostics []model.Diagnostic
	dateLongArguments := map[string]bool{
		"--date": true, "--file": true, "--reference": true, "--rfc-3339": true, "--set": true,
	}
	walkUtilityOptions(invocation.Words, "Ddfsrvz", "I", dateLongArguments, func(index int, word model.Token, option byte, attached string) {
		switch option {
		case 'd':
			incompatible := []string{targetMacOS11, targetMacOS14, targetFreeBSD, targetPOSIX2017, targetPOSIX2024}
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1301",
				word,
				word.Value,
				incompatible,
				"date -d/--date uses the GNU parsing interface",
				selected,
			)...)
		case 'j', 'v':
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1302",
				word,
				"-"+string(option),
				[]string{targetGNU, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"date option uses the BSD parsing interface",
				selected,
			)...)
		case 'f':
			if argument, ok := optionArgument(invocation.Words, index, attached); ok && strings.Contains(argument, "%") {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1302",
					word,
					"-f",
					[]string{targetGNU, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
					"date -f FORMAT uses BSD syntax; GNU date -f reads dates from a file",
					selected,
				)...)
			}
		case 'r':
			if argument, ok := optionArgument(invocation.Words, index, attached); ok && isBSDDateTimestamp(argument) {
				diagnostics = append(diagnostics, emit(
					invocation,
					"SP1303",
					word,
					"-r",
					[]string{targetGNU, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
					"date -r NUMBER means epoch seconds on BSD but a reference filename on GNU and BusyBox",
					selected,
				)...)
			}
		}
	})
	for _, word := range longOptionWords(invocation.Words, "Ddfsrvz", "I", dateLongArguments) {
		if word.Value == "--date" || strings.HasPrefix(word.Value, "--date=") {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1301",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetPOSIX2017, targetPOSIX2024},
				"date --date uses the GNU/BusyBox parsing interface",
				selected,
			)...)
		}
	}
	return diagnostics
}

func checkXargs(invocation model.Invocation, selected map[string]struct{}) []model.Diagnostic {
	var diagnostics []model.Diagnostic
	xargsLongArguments := map[string]bool{
		"--arg-file": true, "--delimiter": true, "--max-args": true,
		"--max-chars": true, "--max-procs": true, "--process-slot-var": true,
	}
	walkUtilityOptions(invocation.Words, "aEIJLnPRSsd", "eil", xargsLongArguments, func(_ int, word model.Token, option byte, attached string) {
		if option == 'd' {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1401",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"xargs delimiter selection is a GNU extension",
				selected,
			)...)
		}
		if option == 'J' {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1402",
				word,
				word.Value,
				[]string{targetGNU, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"xargs -J is a BSD extension",
				selected,
			)...)
		}
	})
	for _, word := range longOptionWords(invocation.Words, "aEIJLnPRSsd", "eil", xargsLongArguments) {
		if word.Value == "--delimiter" || strings.HasPrefix(word.Value, "--delimiter=") {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1401",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"xargs delimiter selection is a GNU extension",
				selected,
			)...)
		}
	}
	return diagnostics
}

func checkGrep(invocation model.Invocation, selected map[string]struct{}) []model.Diagnostic {
	var diagnostics []model.Diagnostic
	grepLongArguments := map[string]bool{
		"--after-context": true, "--before-context": true, "--binary-files": true,
		"--devices": true, "--directories": true, "--exclude": true,
		"--exclude-dir": true, "--exclude-from": true, "--file": true, "--group-separator": true,
		"--include": true, "--include-dir": true, "--label": true, "--max-count": true, "--regexp": true,
	}
	walkUtilityOptions(invocation.Words, "dDefmABC", "", grepLongArguments, func(_ int, word model.Token, option byte, attached string) {
		if option == 'P' {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1501",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"grep PCRE mode is unavailable in the selected macOS, FreeBSD, BusyBox, and POSIX profiles",
				selected,
			)...)
		}
	})
	for _, word := range longOptionWords(invocation.Words, "dDefmABC", "", grepLongArguments) {
		if word.Value == "--perl-regexp" {
			diagnostics = append(diagnostics, emit(
				invocation,
				"SP1501",
				word,
				word.Value,
				[]string{targetMacOS11, targetMacOS14, targetFreeBSD, targetBusyBox, targetPOSIX2017, targetPOSIX2024},
				"grep PCRE mode is unavailable in the selected macOS, FreeBSD, BusyBox, and POSIX profiles",
				selected,
			)...)
		}
	}
	return diagnostics
}

func walkUtilityOptions(words []model.Token, takesArgument, optionalAttachedArgument string, longTakesArgument map[string]bool, visit func(int, model.Token, byte, string)) {
	for index := 1; index < len(words); index++ {
		word := words[index]
		if !word.Constant {
			break
		}
		value := word.Value
		if value == "--" {
			break
		}
		if len(value) < 2 || value[0] != '-' {
			break
		}
		if strings.HasPrefix(value, "--") {
			name, _, hasAttached := strings.Cut(value, "=")
			if longTakesArgument[name] && !hasAttached {
				index++
			}
			continue
		}
		for optionIndex := 1; optionIndex < len(value); optionIndex++ {
			option := value[optionIndex]
			attached := ""
			if strings.ContainsRune(optionalAttachedArgument, rune(option)) {
				attached = value[optionIndex+1:]
				visit(index, word, option, attached)
				break
			}
			if strings.ContainsRune(takesArgument, rune(option)) {
				attached = value[optionIndex+1:]
				visit(index, word, option, attached)
				if attached == "" {
					index++
				}
				break
			}
			visit(index, word, option, attached)
		}
	}
}

func longOptionWords(words []model.Token, shortTakesArgument, shortOptionalAttachedArgument string, longTakesArgument map[string]bool) []model.Token {
	var result []model.Token
	for index := 1; index < len(words); index++ {
		word := words[index]
		if !word.Constant {
			break
		}
		value := word.Value
		if value == "--" {
			break
		}
		if strings.HasPrefix(value, "--") {
			result = append(result, word)
			name, _, attached := strings.Cut(value, "=")
			if longTakesArgument[name] && !attached {
				index++
			}
			continue
		}
		if len(value) < 2 || value[0] != '-' {
			break
		}
		for optionIndex := 1; optionIndex < len(value); optionIndex++ {
			if strings.ContainsRune(shortOptionalAttachedArgument, rune(value[optionIndex])) {
				break
			}
			if strings.ContainsRune(shortTakesArgument, rune(value[optionIndex])) {
				if optionIndex == len(value)-1 {
					index++
				}
				break
			}
		}
	}
	return result
}

func optionArgument(words []model.Token, optionIndex int, attached string) (string, bool) {
	if attached != "" {
		return attached, true
	}
	if optionIndex+1 >= len(words) || !words[optionIndex+1].Constant {
		return "", false
	}
	return words[optionIndex+1].Value, true
}

func optionWords(words []model.Token) []model.Token {
	result := make([]model.Token, 0, len(words))
	for index := 1; index < len(words); index++ {
		word := words[index]
		if !word.Constant {
			break
		}
		if word.Value == "--" {
			break
		}
		if !strings.HasPrefix(word.Value, "-") || word.Value == "-" {
			break
		}
		result = append(result, word)
	}
	return result
}

func shortOption(value string, option byte) bool {
	if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
		return false
	}
	return strings.ContainsRune(value[1:], rune(option))
}

func emit(
	invocation model.Invocation,
	ruleID string,
	word model.Token,
	option string,
	incompatible []string,
	message string,
	selected map[string]struct{},
) []model.Diagnostic {
	var affected []string
	for _, target := range incompatible {
		if _, ok := selected[target]; ok {
			affected = append(affected, target)
		}
	}
	if len(affected) == 0 {
		return nil
	}
	sort.Strings(affected)
	definition, ok := Lookup(ruleID)
	if !ok {
		panic("missing rule definition: " + ruleID)
	}
	return []model.Diagnostic{{
		RuleID:              ruleID,
		Severity:            definition.Severity,
		Message:             message,
		Path:                invocation.Path,
		Range:               word.Range,
		Command:             invocation.Command,
		Option:              option,
		IncompatibleTargets: affected,
		Suggestion:          definition.Suggestion,
		Reference:           definition.Reference,
	}}
}

func isBSDDateTimestamp(value string) bool {
	value = strings.TrimLeft(value, " \t\n\v\f\r")
	if value == "" {
		return false
	}
	if value[0] == '+' || value[0] == '-' {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	if len(value) > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		for _, character := range value[2:] {
			if !isHexDigit(character) {
				return false
			}
		}
		return true
	}
	if len(value) > 1 && value[0] == '0' {
		for _, character := range value[1:] {
			if character < '0' || character > '7' {
				return false
			}
		}
		return true
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isHexDigit(character rune) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'f' ||
		character >= 'A' && character <= 'F'
}

func deduplicateDiagnostics(diagnostics []model.Diagnostic) []model.Diagnostic {
	type diagnosticKey struct {
		ruleID  string
		path    string
		range_  model.Range
		targets string
	}
	seen := make(map[diagnosticKey]struct{}, len(diagnostics))
	result := make([]model.Diagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		key := diagnosticKey{
			ruleID:  diagnostic.RuleID,
			path:    diagnostic.Path,
			range_:  diagnostic.Range,
			targets: strings.Join(diagnostic.IncompatibleTargets, "\x00"),
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, diagnostic)
	}
	return result
}
