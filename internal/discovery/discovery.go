package discovery

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

var ignoredDirectories = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	".venv":        {},
	"node_modules": {},
	"vendor":       {},
}

// Discover expands explicit files and directories into a deterministic,
// deduplicated list of shell source files. Explicit files are always included.
func Discover(inputs, excludes []string) ([]string, error) {
	for _, pattern := range excludes {
		if err := validateGlob(filepath.ToSlash(strings.TrimSpace(pattern))); err != nil {
			return nil, fmt.Errorf("invalid exclusion glob %q: %w", pattern, err)
		}
	}
	seen := make(map[string]struct{})
	var files []string
	var discoveryErrors []error
	for _, input := range inputs {
		info, err := os.Stat(input)
		if err != nil {
			discoveryErrors = append(discoveryErrors, fmt.Errorf("%s: %w", input, err))
			continue
		}
		if !info.IsDir() {
			addFile(input, seen, &files)
			continue
		}
		root, err := filepath.Abs(input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", input, err)
		}
		err = filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if filePath != root {
					if _, ignored := ignoredDirectories[entry.Name()]; ignored {
						return filepath.SkipDir
					}
					if excluded(root, filePath, excludes) {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 || excluded(root, filePath, excludes) {
				return nil
			}
			if eligible(filePath) {
				addFile(filePath, seen, &files)
			}
			return nil
		})
		if err != nil {
			discoveryErrors = append(discoveryErrors, fmt.Errorf("walk %s: %w", input, err))
		}
	}
	sort.Strings(files)
	return files, errors.Join(discoveryErrors...)
}

// DisplayPath returns a stable slash-separated path relative to cwd when the
// file is inside it, otherwise an absolute slash-separated path.
func DisplayPath(cwd, filePath string) string {
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return filepath.ToSlash(filePath)
	}
	relative, err := filepath.Rel(cwd, absolute)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(relative)
	}
	return filepath.ToSlash(absolute)
}

func addFile(filePath string, seen map[string]struct{}, files *[]string) {
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		absolute = filepath.Clean(filePath)
	}
	key := filepath.Clean(absolute)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*files = append(*files, absolute)
}

func eligible(filePath string) bool {
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".sh", ".bash", ".bats":
		return true
	case "":
		return hasShellShebang(filePath)
	default:
		return false
	}
}

func hasShellShebang(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 256)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return false
	}
	interpreter := strings.ToLower(path.Base(filepath.ToSlash(fields[0])))
	if isShellName(interpreter) {
		return true
	}
	if interpreter == "busybox" && len(fields) > 1 {
		return isShellName(strings.ToLower(path.Base(filepath.ToSlash(fields[1]))))
	}
	if interpreter != "env" {
		return false
	}
	for index := 1; index < len(fields); index++ {
		field := fields[index]
		switch {
		case field == "-S" || field == "--split-string", field == "-i", field == "--ignore-environment":
			continue
		case field == "-u" || field == "--unset" || field == "-C" || field == "--chdir":
			index++
			continue
		case strings.HasPrefix(field, "--unset="), strings.HasPrefix(field, "--chdir="), strings.Contains(field, "="):
			continue
		case strings.HasPrefix(field, "-"):
			continue
		default:
			return isShellName(strings.ToLower(path.Base(filepath.ToSlash(field))))
		}
	}
	return false
}

func isShellName(name string) bool {
	switch name {
	case "sh", "bash", "dash", "ash":
		return true
	default:
		return false
	}
}

func excluded(root, filePath string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	relative, err := filepath.Rel(root, filePath)
	if err != nil {
		return false
	}
	relative = filepath.ToSlash(relative)
	for _, pattern := range patterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/") {
			pattern += "**"
		}
		if matchGlob(pattern, relative) {
			return true
		}
		if !strings.ContainsRune(pattern, '/') && matchGlob(pattern, path.Base(relative)) {
			return true
		}
	}
	return false
}

func validateGlob(pattern string) error {
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "probe"); err != nil {
			return err
		}
	}
	return nil
}

// matchGlob uses slash-separated paths and gives a whole path segment named
// ** its conventional recursive meaning. Other segments retain path.Match's
// character classes and wildcard behavior.
func matchGlob(pattern, name string) bool {
	patternParts := splitPath(pattern)
	nameParts := splitPath(name)
	var match func(int, int) bool
	match = func(patternIndex, nameIndex int) bool {
		if patternIndex == len(patternParts) {
			return nameIndex == len(nameParts)
		}
		if patternParts[patternIndex] == "**" {
			for patternIndex+1 < len(patternParts) && patternParts[patternIndex+1] == "**" {
				patternIndex++
			}
			if patternIndex+1 == len(patternParts) {
				return true
			}
			for candidate := nameIndex; candidate <= len(nameParts); candidate++ {
				if match(patternIndex+1, candidate) {
					return true
				}
			}
			return false
		}
		if nameIndex == len(nameParts) {
			return false
		}
		matched, _ := path.Match(patternParts[patternIndex], nameParts[nameIndex])
		return matched && match(patternIndex+1, nameIndex+1)
	}
	return match(0, 0)
}

func splitPath(value string) []string {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}
