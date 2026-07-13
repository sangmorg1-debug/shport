package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscover(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write := func(relative, contents string) string {
		t.Helper()
		filePath := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
		return filePath
	}
	write("a.sh", "#!/bin/sh\n:")
	write("bin/tool", "#!/usr/bin/env bash\n:")
	write("bin/split-tool", "#!/usr/bin/env -S bash -eu\n:")
	write("bin/not-shell", "#!/usr/bin/python /tmp/sh\n:")
	ignoredText := write("notes.txt", "#!/bin/sh\n:")
	write("node_modules/b.sh", "#!/bin/sh\n:")
	write("generated/c.sh", "#!/bin/sh\n:")

	files, err := Discover([]string{root}, []string{"generated/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("files = %v, want three discovered scripts", files)
	}

	explicit, err := Discover([]string{ignoredText}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(explicit) != 1 || explicit[0] != ignoredText {
		t.Fatalf("explicit files = %v, want %s", explicit, ignoredText)
	}
}

func TestDisplayPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	filePath := filepath.Join(root, "scripts", "a.sh")
	if got := DisplayPath(root, filePath); got != "scripts/a.sh" {
		t.Fatalf("DisplayPath() = %q", got)
	}
}

func TestDiscoverRejectsInvalidExclusionGlob(t *testing.T) {
	t.Parallel()
	files, err := Discover([]string{t.TempDir()}, []string{"["})
	if err == nil || !strings.Contains(err.Error(), "invalid exclusion glob") {
		t.Fatalf("Discover() files = %v, error = %v; want invalid exclusion glob", files, err)
	}
	if files != nil {
		t.Fatalf("files = %v, want nil when configuration is invalid", files)
	}
}

func TestDiscoverReturnsValidFilesAlongsideInputErrors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	valid := filepath.Join(root, "valid.sh")
	if err := os.WriteFile(valid, []byte("#!/bin/sh\n:"), 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing.sh")

	files, err := Discover([]string{missing, valid}, nil)
	if err == nil || !strings.Contains(err.Error(), "missing.sh") {
		t.Fatalf("Discover() error = %v, want missing input error", err)
	}
	if len(files) != 1 || files[0] != valid {
		t.Fatalf("files = %v, want valid input %s despite the other input error", files, valid)
	}
}

func TestDiscoverRecursiveExclusionGlob(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, relative := range []string{"root.sh", "one/keep.sh", "one/generated/drop.sh", "two/deep/generated/drop.sh"} {
		filePath := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, []byte("#!/bin/sh\n:"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := Discover([]string{root}, []string{"**/generated/**"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %v, want root.sh and one/keep.sh", files)
	}
	for _, filePath := range files {
		if strings.Contains(filepath.ToSlash(filePath), "/generated/") {
			t.Fatalf("recursive glob did not exclude %s", filePath)
		}
	}
}
