//go:build integration

package main

import (
	"encoding/json"
	"os"
	"runtime"
	"slices"
	"testing"
)

// TestScanRealHome scans this machine's real home, read-only, as mintrun scan does. It is opt-in
// (`go test -tags integration`) so `go test ./...` stays hermetic (rule 22), and it logs only how
// many rows each provider and kind has, never an id, label, or value.
func TestScanRealHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	rows := scanHome(home, runtime.GOOS, false)
	out, err := marshalJSON(rows, "  ")
	if err != nil || !json.Valid(out) {
		t.Fatalf("scan output is not valid JSON: %v", err)
	}
	counts := map[string]int{}
	for _, r := range rows {
		if r.Error != "" {
			t.Errorf("%s at %s: %s", r.Provider, r.Where, r.Error)
		}
		counts[r.Provider+" "+r.Kind]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		t.Logf("%s: %d", k, counts[k])
	}
}
