// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdsrelay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuffer) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *logBuffer) count(substr string) int {
	return strings.Count(l.String(), substr)
}

// fakeExec stands in for runsc exec. Gated syncs call once. Poller runs call
// poll with their number, counted from 1, and a channel that kill closes.
type fakeExec struct {
	once func(ctx context.Context) error
	poll func(run int, stderr *os.File, killed <-chan struct{}) error

	mu       sync.Mutex
	syncs    [][]string
	runs     int
	kills    []chan struct{}
	finished int
}

func (f *fakeExec) exec(ctx context.Context, extra []string, stderr *os.File) error {
	if stderr == nil {
		f.mu.Lock()
		f.syncs = append(f.syncs, slices.Clone(extra))
		f.mu.Unlock()
		if f.once == nil {
			return nil
		}
		return f.once(ctx)
	}
	defer stderr.Close()
	if len(extra) != 0 {
		return fmt.Errorf("poller run with %q", extra)
	}
	if ctx.Done() != nil {
		return errors.New("poller run under a context that can end")
	}
	kill := make(chan struct{})
	f.mu.Lock()
	f.runs++
	run := f.runs
	f.kills = append(f.kills, kill)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.finished++
		f.mu.Unlock()
	}()
	if f.poll != nil {
		return f.poll(run, stderr, kill)
	}
	<-kill
	return fmt.Errorf("run %d killed", run)
}

func (f *fakeExec) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

// kill ends poller run n, counted from 1.
func (f *fakeExec) kill(t *testing.T, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("run %d", n), func() bool { return f.runCount() >= n })
	f.mu.Lock()
	defer f.mu.Unlock()
	close(f.kills[n-1])
}

func (f *fakeExec) killAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.kills {
		select {
		case <-k:
		default:
			close(k)
		}
	}
}

func newSupervisor(t *testing.T, f *fakeExec) (*Supervisor, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	s := NewSupervisor(f.exec, nil, logs.logf)
	s.syncTimeout = 2 * time.Second
	s.exitSettle = 5 * time.Millisecond
	s.minBackoff = 10 * time.Millisecond
	s.maxBackoff = 40 * time.Millisecond
	s.resetAfter = time.Hour
	t.Cleanup(func() {
		s.Stop()
		f.killAll()
	})
	return s, logs
}

func TestNewSupervisorDefaults(t *testing.T) {
	s := NewSupervisor(nil, nil, nil)
	if s.syncTimeout != 10*time.Second || s.minBackoff != time.Second || s.maxBackoff != 5*time.Second || s.resetAfter != time.Minute || s.exitSettle != exitSettle {
		t.Errorf("defaults = %v %v %v %v %v", s.syncTimeout, s.minBackoff, s.maxBackoff, s.resetAfter, s.exitSettle)
	}
	// A genuine failure restarts the poller after the settle delay has passed.
	if s.exitSettle >= s.minBackoff {
		t.Errorf("exitSettle %v is not below minBackoff %v", s.exitSettle, s.minBackoff)
	}
	// Sync never waits for the poller, and a restart is never slower than a
	// gated sync is allowed to be.
	if s.maxBackoff >= s.syncTimeout {
		t.Errorf("maxBackoff %v is not below syncTimeout %v", s.maxBackoff, s.syncTimeout)
	}
	if maxLogLine != 4096 {
		t.Errorf("maxLogLine = %d", maxLogLine)
	}
}

func TestSupervisorStartRunsPoller(t *testing.T) {
	f := &fakeExec{}
	s, _ := newSupervisor(t, f)
	s.Start()
	s.Start()
	waitFor(t, "the poller", func() bool { return f.runCount() == 1 })
	time.Sleep(50 * time.Millisecond)
	if n := f.runCount(); n != 1 {
		t.Errorf("%d pollers after two Starts, want 1", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.syncs) != 0 {
		t.Errorf("Start ran %d syncs", len(f.syncs))
	}
}

func TestSupervisorStartAfterStop(t *testing.T) {
	f := &fakeExec{}
	s, _ := newSupervisor(t, f)
	s.Stop()
	s.Stop()
	s.Start()
	time.Sleep(50 * time.Millisecond)
	if n := f.runCount(); n != 0 {
		t.Errorf("Start after Stop ran %d pollers", n)
	}
}

func TestSupervisorSyncRunsOnce(t *testing.T) {
	f := &fakeExec{}
	s, _ := newSupervisor(t, f)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.syncs) != 1 || !slices.Equal(f.syncs[0], []string{OnceFlag}) {
		t.Errorf("syncs = %q, want one with %q", f.syncs, OnceFlag)
	}
	// A sync does not need the poller.
	if f.runs != 0 {
		t.Errorf("Sync started %d pollers", f.runs)
	}
}

func TestSupervisorSyncReportsFailure(t *testing.T) {
	cause := errors.New("exit status 1: sync failed: a source file is still being written")
	f := &fakeExec{once: func(context.Context) error { return cause }}
	s, _ := newSupervisor(t, f)
	err := s.Sync(context.Background())
	if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "SDS relay sync: ") {
		t.Errorf("Sync = %v, want the relay's failure", err)
	}
}

// waitDone returns once ctx ends, or fails after a while so that a sync
// without a deadline fails rather than hangs.
func waitDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("the sync's context never ended")
	}
}

func TestSupervisorSyncTimesOut(t *testing.T) {
	var deadline time.Duration
	f := &fakeExec{once: func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		if ok {
			deadline = time.Until(d)
		}
		return waitDone(ctx)
	}}
	s, _ := newSupervisor(t, f)
	s.syncTimeout = 50 * time.Millisecond
	start := time.Now()
	if err := s.Sync(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Sync = %v, want a timeout", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Sync took %v", d)
	}
	if deadline <= 0 || deadline > 50*time.Millisecond {
		t.Errorf("the sync ran with %v left, want at most 50ms", deadline)
	}
}

func TestSupervisorSyncHonorsContext(t *testing.T) {
	f := &fakeExec{once: waitDone}
	s, _ := newSupervisor(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Sync(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Sync = %v, want the context's error", err)
	}
}

func TestSupervisorSyncAfterStop(t *testing.T) {
	f := &fakeExec{once: func(context.Context) error { return errors.New("container stopped") }}
	s, _ := newSupervisor(t, f)
	s.Stop()
	if err := s.Sync(context.Background()); err != nil {
		t.Errorf("Sync after Stop = %v, want nil", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.syncs) != 0 {
		t.Errorf("Sync after Stop ran the relay")
	}
}

// TestSupervisorSyncWhilePollerFails checks that a gated sync succeeds while
// the poller keeps failing and is backing off.
func TestSupervisorSyncWhilePollerFails(t *testing.T) {
	f := &fakeExec{poll: func(int, *os.File, <-chan struct{}) error { return errors.New("no such container") }}
	s, logs := newSupervisor(t, f)
	s.minBackoff = time.Hour
	s.maxBackoff = time.Hour
	s.Start()
	waitFor(t, "the first failure", func() bool { return logs.count("restarting in 1h0m0s") == 1 })
	start := time.Now()
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Sync took %v", d)
	}
}

func TestSupervisorRestartsPoller(t *testing.T) {
	f := &fakeExec{}
	s, logs := newSupervisor(t, f)
	s.Start()
	f.kill(t, 1)
	waitFor(t, "the restart", func() bool { return f.runCount() == 2 })
	if !strings.Contains(logs.String(), "SDS relay exited, restarting in 10ms: run 1 killed") {
		t.Errorf("log = %q", logs.String())
	}
}

func TestSupervisorRestartsPollerThatExitsCleanly(t *testing.T) {
	f := &fakeExec{poll: func(run int, _ *os.File, killed <-chan struct{}) error {
		if run == 1 {
			return nil
		}
		<-killed
		return nil
	}}
	s, logs := newSupervisor(t, f)
	s.Start()
	waitFor(t, "the restart", func() bool { return f.runCount() == 2 })
	if !strings.Contains(logs.String(), "exited without an error") {
		t.Errorf("log = %q", logs.String())
	}
}

func TestSupervisorBacksOff(t *testing.T) {
	f := &fakeExec{poll: func(int, *os.File, <-chan struct{}) error { return errors.New("failed") }}
	s, logs := newSupervisor(t, f)
	s.Start()
	waitFor(t, "five restarts", func() bool { return logs.count("restarting") >= 5 })
	s.Stop()
	got := logs.String()
	for i, want := range []string{"10ms", "20ms", "40ms", "40ms", "40ms"} {
		line := strings.Split(got, "\n")[i]
		if !strings.Contains(line, "restarting in "+want+":") {
			t.Errorf("restart %d: %q, want a delay of %s", i+1, line, want)
		}
	}
}

func TestSupervisorWaitsBeforeRestart(t *testing.T) {
	f := &fakeExec{poll: func(int, *os.File, <-chan struct{}) error { return errors.New("failed") }}
	s, _ := newSupervisor(t, f)
	s.minBackoff = 200 * time.Millisecond
	s.maxBackoff = 200 * time.Millisecond
	start := time.Now()
	s.Start()
	waitFor(t, "the second run", func() bool { return f.runCount() == 2 })
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Errorf("restarted after %v, want at least 200ms", d)
	}
}

func TestSupervisorResetsBackoff(t *testing.T) {
	f := &fakeExec{poll: func(run int, _ *os.File, _ <-chan struct{}) error {
		if run == 4 {
			time.Sleep(60 * time.Millisecond)
		}
		return errors.New("failed")
	}}
	s, logs := newSupervisor(t, f)
	s.resetAfter = 50 * time.Millisecond
	s.Start()
	waitFor(t, "five restarts", func() bool { return logs.count("restarting") >= 5 })
	s.Stop()
	lines := strings.Split(logs.String(), "\n")
	for i, want := range []string{"10ms", "20ms", "40ms", "10ms", "20ms"} {
		if !strings.Contains(lines[i], "restarting in "+want+":") {
			t.Errorf("restart %d: %q, want a delay of %s", i+1, lines[i], want)
		}
	}
}

func TestSupervisorStopsRestarting(t *testing.T) {
	f := &fakeExec{}
	s, logs := newSupervisor(t, f)
	s.Start()
	waitFor(t, "the poller", func() bool { return f.runCount() == 1 })
	s.Stop()
	f.kill(t, 1)
	time.Sleep(100 * time.Millisecond)
	if n := f.runCount(); n != 1 {
		t.Errorf("%d runs after Stop, want 1", n)
	}
	if strings.Contains(logs.String(), "restarting") {
		t.Errorf("log = %q after Stop", logs.String())
	}
}

func TestSupervisorStopDuringBackoff(t *testing.T) {
	f := &fakeExec{poll: func(int, *os.File, <-chan struct{}) error { return errors.New("failed") }}
	s, logs := newSupervisor(t, f)
	s.minBackoff = time.Hour
	s.Start()
	waitFor(t, "the backoff", func() bool { return logs.count("restarting") == 1 })
	s.Stop()
	time.Sleep(50 * time.Millisecond)
	if n := f.runCount(); n != 1 {
		t.Errorf("%d runs, want 1", n)
	}
}

// The poller dies with its sandbox, which can be before the shim calls Stop.
func TestSupervisorQuietWhenSandboxGone(t *testing.T) {
	f := &fakeExec{}
	s, logs := newSupervisor(t, f)
	var gone atomic.Bool
	s.gone = func(context.Context) bool { return gone.Load() }
	s.Start()
	waitFor(t, "the poller", func() bool { return f.runCount() == 1 })
	gone.Store(true)
	f.kill(t, 1)
	waitFor(t, "the poller to finish", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.finished == 1
	})
	time.Sleep(100 * time.Millisecond)
	if n := f.runCount(); n != 1 {
		t.Errorf("%d runs after the sandbox stopped, want 1", n)
	}
	if strings.Contains(logs.String(), "restarting") {
		t.Errorf("log = %q after the sandbox stopped", logs.String())
	}
}

// Stop arriving just after the poller exits is also quiet.
func TestSupervisorStopJustAfterPollerExit(t *testing.T) {
	f := &fakeExec{}
	s, logs := newSupervisor(t, f)
	s.exitSettle = time.Hour
	s.Start()
	waitFor(t, "the poller", func() bool { return f.runCount() == 1 })
	f.kill(t, 1)
	waitFor(t, "the poller to finish", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.finished == 1
	})
	s.Stop()
	time.Sleep(100 * time.Millisecond)
	if n := f.runCount(); n != 1 {
		t.Errorf("%d runs, want 1", n)
	}
	if strings.Contains(logs.String(), "restarting") {
		t.Errorf("log = %q", logs.String())
	}
}

// A poller that fails while its sandbox runs is logged and restarted.
func TestSupervisorRestartsWhileSandboxRuns(t *testing.T) {
	f := &fakeExec{}
	s, logs := newSupervisor(t, f)
	s.gone = func(context.Context) bool { return false }
	s.Start()
	f.kill(t, 1)
	waitFor(t, "the restart", func() bool { return f.runCount() == 2 })
	if got := logs.count("SDS relay exited, restarting in"); got != 1 {
		t.Errorf("%d exit lines, want 1; log = %q", got, logs.String())
	}
}

func TestSupervisorForwardsLog(t *testing.T) {
	long := strings.Repeat("x", 2*maxLogLine)
	f := &fakeExec{poll: func(run int, stderr *os.File, killed <-chan struct{}) error {
		if run == 1 {
			// A line too long to log, then more than a pipe holds.
			fmt.Fprintf(stderr, "updated \"envoy.yaml\"\n%s\n", long)
			for i := 0; i < 32; i++ {
				fmt.Fprintln(stderr, long)
			}
			return errors.New("done")
		}
		fmt.Fprintln(stderr, "sync recovered")
		<-killed
		return nil
	}}
	s, logs := newSupervisor(t, f)
	s.Start()
	waitFor(t, "the second run's log", func() bool { return strings.Contains(logs.String(), "SDS relay: sync recovered") })
	if !strings.Contains(logs.String(), `SDS relay: updated "envoy.yaml"`) {
		t.Errorf("log = %q", logs.String())
	}
	if strings.Contains(logs.String(), long[:maxLogLine]) {
		t.Errorf("logged a line longer than %d bytes", maxLogLine)
	}
}

// fakeRunsc writes a runsc that records its arguments and process spec in
// dir, writes to stderr, and exits with the status in $FAKE_RUNSC_EXIT.
func fakeRunsc(t *testing.T) (*runsccmd.Runsc, string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "runsc")
	body := `#!/bin/sh
echo "$@" > "` + dir + `/args"
while [ $# -gt 0 ]; do
	if [ "$1" = --process ]; then cp "$2" "` + dir + `/process.json"; fi
	shift
done
echo "relay says hello" >&2
exit ${FAKE_RUNSC_EXIT:-0}
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return &runsccmd.Runsc{Command: script, Root: "/run/runsc"}, dir
}

func TestRunscExecSync(t *testing.T) {
	runtime, dir := fakeRunsc(t)
	run := RunscExec(runtime, "c1")
	if err := run(context.Background(), []string{OnceFlag}, nil); err != nil {
		t.Fatalf("exec: %v", err)
	}
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(args)); got[0] != "--root=/run/runsc" || got[1] != "exec" || got[len(got)-1] != "c1" || slices.Contains(got, "--detach") {
		t.Errorf("runsc %q", got)
	}
	data, err := os.ReadFile(filepath.Join(dir, "process.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p specs.Process
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if want := Process(OnceFlag); !slices.Equal(p.Args, want.Args) || !slices.Equal(p.Env, want.Env) {
		t.Errorf("process = %+v, want %+v", p, want)
	}

	// A failed sync carries the relay's output.
	t.Setenv("FAKE_RUNSC_EXIT", "1")
	if err := run(context.Background(), []string{OnceFlag}, nil); err == nil || !strings.Contains(err.Error(), "relay says hello") {
		t.Errorf("exec = %v, want the relay's output", err)
	}
}

func TestRunscExecPoller(t *testing.T) {
	runtime, dir := fakeRunsc(t)
	run := RunscExec(runtime, "c1")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := run(context.Background(), nil, w); err != nil {
		t.Fatalf("exec: %v", err)
	}
	// RunscExec closed the write end, so the read ends.
	sc := bufio.NewScanner(r)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if !slices.Equal(lines, []string{"relay says hello"}) {
		t.Errorf("stderr = %q", lines)
	}
	data, err := os.ReadFile(filepath.Join(dir, "process.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p specs.Process
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if want := Process(); !slices.Equal(p.Args, want.Args) {
		t.Errorf("args = %q, want %q", p.Args, want.Args)
	}

	t.Setenv("FAKE_RUNSC_EXIT", "3")
	_, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), nil, w2); err == nil {
		t.Error("exec of a failed poller succeeded")
	}
	if _, err := w2.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Error("RunscExec left the write end open")
	}

	// A runsc that cannot start still closes the write end.
	_, w3, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	missing := RunscExec(&runsccmd.Runsc{Command: filepath.Join(dir, "missing")}, "c1")
	if err := missing(context.Background(), nil, w3); err == nil {
		t.Error("exec of a missing runsc succeeded")
	}
	if _, err := w3.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Error("RunscExec left the write end open")
	}
}

func TestRunscGone(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "runsc")
	body := `#!/bin/sh
case "$FAKE_RUNSC_STATE" in
	fail) echo "no such container" >&2; exit 1 ;;
	garbage) echo "not json" ;;
	*) echo "{\"id\":\"c1\",\"status\":\"$FAKE_RUNSC_STATE\"}" ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	gone := RunscGone(&runsccmd.Runsc{Command: script, Root: "/run/runsc"}, "c1")
	for _, tc := range []struct {
		state string
		want  bool
	}{
		{"stopped", true},
		{"running", false},
		{"created", false},
		{"paused", false},
		{"fail", false},
		{"garbage", false},
	} {
		t.Setenv("FAKE_RUNSC_STATE", tc.state)
		if got := gone(context.Background()); got != tc.want {
			t.Errorf("gone with state %q = %v, want %v", tc.state, got, tc.want)
		}
	}
	missing := RunscGone(&runsccmd.Runsc{Command: filepath.Join(dir, "missing")}, "c1")
	if missing(context.Background()) {
		t.Error("gone with a missing runsc = true")
	}
}

func TestStderrIO(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	fio := &stderrIO{stderr: f}
	cmd := &exec.Cmd{}
	fio.Set(cmd)
	if cmd.Stdin != nil || cmd.Stdout != nil || cmd.Stderr != f {
		t.Errorf("Set = %v %v %v", cmd.Stdin, cmd.Stdout, cmd.Stderr)
	}
	if fio.Stdin() != nil || fio.Stdout() != nil || fio.Stderr() != nil {
		t.Error("stderrIO returned a parent end")
	}
	if err := fio.CloseAfterStart(); err != nil {
		t.Fatal(err)
	}
	if err := fio.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Error("stderr still open")
	}
}

// TestSupervisorWithRelay runs the supervisor against the real relay in a
// process, as RunscExec does in a sandbox, and checks that a sync makes a new
// file visible before it returns.
func TestSupervisorWithRelay(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	target := filepath.Join(r.Target, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)

	var mu sync.Mutex
	var pollers []*exec.Cmd
	run := func(ctx context.Context, extra []string, stderr *os.File) error {
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestHelperMain$", "--", "--source", r.Source, "--target", r.Target}, extra...)...)
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		if stderr == nil {
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, out)
			}
			return nil
		}
		defer stderr.Close()
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		mu.Lock()
		pollers = append(pollers, cmd)
		mu.Unlock()
		stderr.Close()
		return cmd.Wait()
	}
	killPollers := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range pollers {
			c.Process.Kill()
		}
	}
	logs := &logBuffer{}
	s := NewSupervisor(run, nil, logs.logf)
	s.minBackoff = 10 * time.Millisecond
	t.Cleanup(func() {
		s.Stop()
		killPollers()
	})
	s.Start()
	waitFor(t, "the poller's first copy", func() bool { return content(target) == "serial: 1\n" })

	replaceFile(t, path, "serial: 2\n")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := content(target); got != "serial: 2\n" {
		t.Errorf("copy = %q after Sync", got)
	}

	// Kill the poller; it is restarted, and a sync works meanwhile.
	killPollers()
	replaceFile(t, path, "serial: 3\n")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync after the poller died: %v", err)
	}
	if got := content(target); got != "serial: 3\n" {
		t.Errorf("copy = %q after the poller died", got)
	}
	waitFor(t, "the restart", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(pollers) == 2
	})
	replaceFile(t, path, "serial: 4\n")
	waitFor(t, "the new poller's copy", func() bool { return content(target) == "serial: 4\n" })
	waitFor(t, "the poller's log", func() bool { return strings.Contains(logs.String(), `SDS relay: updated "sds-id-cert-and-key.yaml"`) })

	// A sync fails when the source is gone.
	if err := os.RemoveAll(r.Source); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "sync failed") {
		t.Errorf("Sync without a source = %v, want the relay's failure", err)
	}
}
