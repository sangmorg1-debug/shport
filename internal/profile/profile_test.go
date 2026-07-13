package profile

import (
	"reflect"
	"testing"
)

func TestResolveAliasesAndStableIDs(t *testing.T) {
	t.Parallel()
	profiles, err := Resolve([]string{"macos", "gnu-2026", "macos", "busybox"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"busybox-1.36.1", "gnu-2026", "macos-14"}
	if got := IDs(profiles); !reflect.DeepEqual(got, want) {
		t.Fatalf("IDs() = %v, want %v", got, want)
	}
}

func TestDefaultPortableSet(t *testing.T) {
	t.Parallel()
	want := []string{"busybox-1.36.1", "freebsd-14.1", "gnu-2026", "macos-14"}
	if got := IDs(Default()); !reflect.DeepEqual(got, want) {
		t.Fatalf("default IDs = %v, want %v", got, want)
	}
}

func TestResolveRejectsUnknownOrEmptyTargets(t *testing.T) {
	t.Parallel()
	for _, values := range [][]string{{"plan9"}, {","}} {
		if _, err := Resolve(values); err == nil {
			t.Fatalf("Resolve(%q) unexpectedly succeeded", values)
		}
	}
}
