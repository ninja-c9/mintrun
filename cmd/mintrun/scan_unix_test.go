//go:build unix

package main

import (
	"path/filepath"
	"syscall"
	"testing"
)

// TestScanFIFO pins that scan never opens a FIFO, which would block it, directly or through a link.
func TestScanFIFO(t *testing.T) {
	for _, src := range scanSources {
		for _, link := range []bool{false, true} {
			t.Run(src.rel+map[bool]string{false: "/fifo", true: "/link to a fifo"}[link], func(t *testing.T) {
				home := scanEnv(t)
				p := filepath.Join(home, src.rel)
				fifo := p
				if link {
					fifo = filepath.Join(home, "fifo")
					symlink(t, fifo, p)
				}
				mkdir(t, filepath.Dir(fifo))
				if err := syscall.Mkfifo(fifo, 0o600); err != nil {
					t.Fatal(err)
				}
				scanRows(t, home, scanErr(src.row.Provider, src.rel, "not a regular file"))
			})
		}
	}
}
