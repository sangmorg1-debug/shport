package profile

import (
	"fmt"
	"sort"
	"strings"
)

// Profile pins a portability target to a documented userland revision.
// Aliases are accepted by the CLI, while diagnostics always use the stable ID.
type Profile struct {
	ID          string   `json:"id"`
	Alias       string   `json:"alias"`
	Description string   `json:"description"`
	References  []string `json:"references"`
}

var catalog = []Profile{
	{
		ID:          "gnu-2026",
		Alias:       "gnu",
		Description: "GNU sed 4.10, coreutils 9.11, PCRE2-enabled grep 3.12, and findutils 4.10",
		References: []string{
			"https://ftp.gnu.org/gnu/sed/sed-4.10.tar.xz",
			"https://ftp.gnu.org/gnu/coreutils/coreutils-9.11.tar.xz",
			"https://ftp.gnu.org/gnu/grep/grep-3.12.tar.xz",
			"https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz",
		},
	},
	{
		ID:          "macos-11",
		Alias:       "macos11",
		Description: "stock command-line userland shipped with macOS 11",
		References:  []string{"https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-1101"},
	},
	{
		ID:          "macos-14",
		Alias:       "macos",
		Description: "stock command-line userland shipped with macOS 14",
		References:  []string{"https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-140"},
	},
	{
		ID:          "freebsd-14.1",
		Alias:       "freebsd",
		Description: "stock utilities from FreeBSD 14.1-RELEASE",
		References:  []string{"https://cgit.freebsd.org/src/tag/?h=release/14.1.0"},
	},
	{
		ID:          "busybox-1.36.1",
		Alias:       "busybox",
		Description: "BusyBox 1.36.1 applets with the upstream default configuration",
		References:  []string{"https://busybox.net/downloads/busybox-1.36.1.tar.bz2"},
	},
	{
		ID:          "posix-2017",
		Alias:       "posix2017",
		Description: "POSIX.1-2017 (Issue 7) utility interfaces",
		References:  []string{"https://pubs.opengroup.org/onlinepubs/9699919799/idx/utilities.html"},
	},
	{
		ID:          "posix-2024",
		Alias:       "posix",
		Description: "POSIX.1-2024 (Issue 8) utility interfaces",
		References:  []string{"https://pubs.opengroup.org/onlinepubs/9799919799/idx/utilities.html"},
	},
}

// All returns a copy of the built-in target catalog.
func All() []Profile {
	result := make([]Profile, len(catalog))
	for index, item := range catalog {
		result[index] = item
		result[index].References = append([]string(nil), item.References...)
	}
	return result
}

// Default returns the practical cross-userland target set. Strict POSIX is
// opt-in because it intentionally rejects many commonly available extensions.
func Default() []Profile {
	profiles, _ := Resolve([]string{"gnu", "macos", "freebsd", "busybox"})
	return profiles
}

// Resolve converts aliases or stable IDs to a sorted, deduplicated profile set.
// The special alias "portable" expands to GNU, macOS, FreeBSD, and BusyBox.
func Resolve(values []string) ([]Profile, error) {
	if len(values) == 0 {
		return Default(), nil
	}

	lookup := make(map[string]Profile, len(catalog)*2)
	for _, item := range catalog {
		lookup[item.ID] = item
		lookup[item.Alias] = item
	}

	selected := make(map[string]Profile)
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			if name == "portable" {
				for _, alias := range []string{"gnu", "macos", "freebsd", "busybox"} {
					item := lookup[alias]
					selected[item.ID] = item
				}
				continue
			}
			item, ok := lookup[name]
			if !ok {
				return nil, fmt.Errorf("unknown target %q", raw)
			}
			selected[item.ID] = item
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}

	result := make([]Profile, 0, len(selected))
	for _, item := range selected {
		item.References = append([]string(nil), item.References...)
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// IDs returns sorted stable IDs for a selected profile set.
func IDs(profiles []Profile) []string {
	ids := make([]string, 0, len(profiles))
	for _, item := range profiles {
		ids = append(ids, item.ID)
	}
	sort.Strings(ids)
	return ids
}
