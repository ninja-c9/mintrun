//go:build unix

package core

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// waitFor polls for path until timeout and reports whether it appeared.
func waitFor(path string, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// TestKillProcessGroupFork cancels a child while it forks: the mark comes before the forks, so the
// group kill lands while the child is creating processes. On macOS 27.0 a plain group kill missed
// a process still being created in 396 of 2000 kills (rule 20).
func TestKillProcessGroupFork(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "forking")
	for i := range 20 {
		os.Remove(mark)
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "sh", "-c", `touch "$0"; i=0; while [ $i -lt 50 ]; do sleep 3 & i=$((i+1)); done; wait`, mark)
		killProcessGroup(cmd)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		started := waitFor(mark, 5*time.Second)
		cancel()
		cmd.Wait()
		if !started {
			t.Fatal("the child never wrote its mark")
		}
		// kill(-pgid, 0) sends nothing, so polling a group that was reused harms no one.
		pgid := cmd.Process.Pid
		for deadline := time.Now().Add(time.Second); syscall.Kill(-pgid, 0) == nil && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		if syscall.Kill(-pgid, 0) == nil {
			t.Errorf("run %d: a process forked during the group kill survived it", i)
		}
	}
}

// TestKillProcessGroupAfterReap pins rule 20's guard: once Go has reaped the child, its pid (the
// group id) may be reused, so Cancel signals nothing, not even the child's own leftovers.
func TestKillProcessGroupAfterReap(t *testing.T) {
	done := filepath.Join(t.TempDir(), "done")
	cmd := exec.CommandContext(context.Background(), "sh", "-c", `(sleep 0.3; touch "$0") & exit 0`, done)
	killProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("Cancel after the reap = %v, want os.ErrProcessDone", err)
	}
	if !waitFor(done, 2*time.Second) {
		t.Fatal("the group's other process was stopped or killed after the child was reaped")
	}
}

// TestKillProcessGroupReapedDuringSettle pins the guard after the settle: a child that has exited
// cannot be stopped, so Go may reap it while Cancel waits, and then Cancel must signal nothing.
func TestKillProcessGroupReapedDuringSettle(t *testing.T) {
	defer func(d time.Duration) { forkSettle = d }(forkSettle)
	forkSettle = 400 * time.Millisecond
	dir := t.TempDir()
	running, done := filepath.Join(dir, "running"), filepath.Join(dir, "done")
	cmd := exec.CommandContext(context.Background(), "sh", "-c", `(touch "$1"; sleep 0.8; touch "$0") & exit 0`, done, running)
	killProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(running, 5*time.Second) {
		t.Fatal("the child never started its background process")
	}
	time.Sleep(100 * time.Millisecond) // the child has exited by now, and nothing has reaped it
	canceled := make(chan error, 1)
	go func() { canceled <- cmd.Cancel() }()
	time.Sleep(100 * time.Millisecond) // Cancel is in its settle
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := <-canceled; !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("Cancel for a child reaped during the settle = %v, want os.ErrProcessDone", err)
	}
	if !waitFor(done, 2*time.Second) {
		t.Fatal("the group's other process was stopped or killed after the child was reaped")
	}
}
