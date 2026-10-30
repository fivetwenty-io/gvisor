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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRelay speaks the relay's protocol from inside the test.
type fakeRelay struct {
	// ready makes a run announce readiness.
	ready func(run int) bool
	// answer returns the lines a run writes for a request.
	answer func(run int, id string) []string
	// stderr is written to stderr when a run starts.
	stderr string

	runs  atomic.Int32
	mu    sync.Mutex
	kills []chan struct{}
	reqs  []string
}

func (f *fakeRelay) exec(stdin, stdout, stderr *os.File) error {
	run := int(f.runs.Add(1))
	kill := make(chan struct{})
	f.mu.Lock()
	f.kills = append(f.kills, kill)
	f.mu.Unlock()
	defer stdin.Close()
	defer stdout.Close()
	defer stderr.Close()

	if f.stderr != "" {
		fmt.Fprint(stderr, f.stderr)
	}
	if f.ready == nil || f.ready(run) {
		fmt.Fprintln(stdout, readyLine)
	}
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	for {
		select {
		case <-kill:
			return fmt.Errorf("run %d killed", run)
		case l, ok := <-lines:
			if !ok {
				<-kill
				return fmt.Errorf("run %d killed", run)
			}
			f.mu.Lock()
			f.reqs = append(f.reqs, l)
			f.mu.Unlock()
			id := strings.TrimPrefix(l, syncVerb+" ")
			replies := []string{okReply + " " + id}
			if f.answer != nil {
				replies = f.answer(run, id)
			}
			for _, r := range replies {
				fmt.Fprintln(stdout, r)
			}
		}
	}
}

// kill ends run n, counted from 1.
func (f *fakeRelay) kill(t *testing.T, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("run %d", n), func() bool { return int(f.runs.Load()) >= n })
	f.mu.Lock()
	defer f.mu.Unlock()
	close(f.kills[n-1])
}

func (f *fakeRelay) killAll() {
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

func newSupervisor(t *testing.T, run ExecFunc) (*Supervisor, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	s := NewSupervisor(run, logs.logf)
	s.readyTimeout = 2 * time.Second
	s.syncTimeout = 2 * time.Second
	s.minBackoff = 10 * time.Millisecond
	s.maxBackoff = 40 * time.Millisecond
	s.resetAfter = time.Hour
	t.Cleanup(s.Stop)
	return s, logs
}

func TestNewSupervisorDefaults(t *testing.T) {
	s := NewSupervisor(nil, nil)
	if s.readyTimeout != readyTimeout || s.syncTimeout != syncTimeout || s.minBackoff != minBackoff || s.maxBackoff != maxBackoff || s.resetAfter != resetAfter {
		t.Errorf("NewSupervisor = %+v", s)
	}
	if readyTimeout != 10*time.Second || syncTimeout != 10*time.Second || minBackoff != time.Second || maxBackoff != 30*time.Second || resetAfter != time.Minute {
		t.Errorf("defaults changed")
	}
}

func TestSupervisorStartAndSync(t *testing.T) {
	f := &fakeRelay{stderr: "started\n"}
	t.Cleanup(f.killAll)
	s, logs := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Sync(context.Background()); err != nil {
			t.Fatalf("Sync: %v", err)
		}
	}
	f.mu.Lock()
	reqs := fmt.Sprint(f.reqs)
	f.mu.Unlock()
	if reqs != "[sync 1 sync 2 sync 3]" {
		t.Errorf("requests = %v", reqs)
	}
	// A second Start does nothing.
	if err := s.Start(context.Background()); err != nil {
		t.Errorf("second Start: %v", err)
	}
	if n := f.runs.Load(); n != 1 {
		t.Errorf("%d runs, want 1", n)
	}
	waitFor(t, "the relay's log", func() bool { return strings.Contains(logs.String(), "SDS relay: started") })
}

func TestSupervisorStartTimesOut(t *testing.T) {
	f := &fakeRelay{ready: func(int) bool { return false }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	s.readyTimeout = 50 * time.Millisecond
	err := s.Start(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start = %v, want DeadlineExceeded", err)
	}
	// Every later sync fails, so that no process starts without the relay.
	if err := s.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Errorf("Sync after a failed Start = %v", err)
	}
}

func TestSupervisorStartReportsExit(t *testing.T) {
	s, _ := newSupervisor(t, func(stdin, stdout, stderr *os.File) error {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return errors.New("runsc exec failed")
	})
	s.readyTimeout = 100 * time.Millisecond
	if err := s.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "runsc exec failed") {
		t.Errorf("Start = %v, want the exit error", err)
	}
}

func TestSupervisorStartHonorsContext(t *testing.T) {
	f := &fakeRelay{ready: func(int) bool { return false }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Start = %v, want Canceled", err)
	}
}

func TestSupervisorStartAfterStop(t *testing.T) {
	f := &fakeRelay{ready: func(int) bool { return false }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.Stop()
	}()
	if err := s.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Errorf("Start = %v", err)
	}
}

// TestSupervisorRestartsRelay checks that a relay that dies is restarted, and
// that a sync waits for the new one.
func TestSupervisorRestartsRelay(t *testing.T) {
	f := &fakeRelay{}
	t.Cleanup(f.killAll)
	s, logs := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.kill(t, 1)
	waitFor(t, "the relay to be gone", func() bool { return s.state().conn == nil })
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync after the relay died: %v", err)
	}
	if n := f.runs.Load(); n != 2 {
		t.Errorf("%d runs, want 2", n)
	}
	if !strings.Contains(logs.String(), "run 1 killed") {
		t.Errorf("log = %q, want the exit", logs.String())
	}
}

// TestSupervisorSyncRetriesWhenRelayDies kills the relay while a request is in
// flight.
func TestSupervisorSyncRetriesWhenRelayDies(t *testing.T) {
	f := &fakeRelay{}
	f.answer = func(run int, id string) []string {
		if run == 1 {
			go f.killAll()
			return nil
		}
		return []string{okReply + " " + id}
	}
	s, _ := newSupervisor(t, f.exec)
	t.Cleanup(f.killAll)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if n := f.runs.Load(); n != 2 {
		t.Errorf("%d runs, want 2", n)
	}
}

func TestSupervisorBacksOff(t *testing.T) {
	var (
		mu     sync.Mutex
		starts []time.Time
	)
	s, _ := newSupervisor(t, func(stdin, stdout, stderr *os.File) error {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return errors.New("exited")
	})
	s.minBackoff = 20 * time.Millisecond
	s.maxBackoff = 80 * time.Millisecond
	go s.run()
	waitFor(t, "six runs", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(starts) >= 6
	})
	s.Stop()
	mu.Lock()
	defer mu.Unlock()
	// The delays are 20, 40, 80, 80, and 80 ms.
	want := []time.Duration{20, 40, 80, 80, 80}
	for i, w := range want {
		got := starts[i+1].Sub(starts[i])
		w *= time.Millisecond
		if got < w || got > w+60*time.Millisecond {
			t.Errorf("delay %d = %v, want about %v", i, got, w)
		}
	}
}

func TestSupervisorResetsBackoff(t *testing.T) {
	var (
		mu     sync.Mutex
		starts []time.Time
	)
	s, _ := newSupervisor(t, func(stdin, stdout, stderr *os.File) error {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return errors.New("exited")
	})
	s.minBackoff = 20 * time.Millisecond
	s.maxBackoff = 500 * time.Millisecond
	// Every run counts as a long one.
	s.resetAfter = 0
	go s.run()
	waitFor(t, "four runs", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(starts) >= 4
	})
	s.Stop()
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < 4; i++ {
		if d := starts[i].Sub(starts[i-1]); d > 70*time.Millisecond {
			t.Errorf("delay %d = %v, want about 20ms", i, d)
		}
	}
}

// TestSupervisorStopsRestarting covers a container that stops: the relay
// gets SIGTERM with every other process and must not come back.
func TestSupervisorStopsRestarting(t *testing.T) {
	f := &fakeRelay{}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Stop()
	s.Stop()
	f.kill(t, 1)
	time.Sleep(100 * time.Millisecond)
	if n := f.runs.Load(); n != 1 {
		t.Errorf("%d runs after Stop, want 1", n)
	}
	// Processes started while the container stops are not held up.
	if err := s.Sync(context.Background()); err != nil {
		t.Errorf("Sync while stopping = %v", err)
	}
}

func TestSupervisorStopDuringBackoff(t *testing.T) {
	f := &fakeRelay{}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	s.minBackoff = time.Hour
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.kill(t, 1)
	waitFor(t, "the relay to be gone", func() bool { return s.state().conn == nil })
	s.Stop()
	if err := s.Sync(context.Background()); err != nil {
		t.Errorf("Sync while stopping = %v", err)
	}
	if n := f.runs.Load(); n != 1 {
		t.Errorf("%d runs, want 1", n)
	}
}

// TestSupervisorRelayReadyAfterStop checks that a relay that becomes ready
// after Stop is not used.
func TestSupervisorRelayReadyAfterStop(t *testing.T) {
	s, _ := newSupervisor(t, nil)
	s.Stop()
	c := &conn{dead: make(chan struct{})}
	s.setConn(c)
	if s.state().conn != nil {
		t.Error("setConn installed a relay after Stop")
	}
	s2, _ := newSupervisor(t, nil)
	close(c.dead)
	s2.setConn(c)
	if s2.state().conn != nil {
		t.Error("setConn installed a relay that had exited")
	}
}

func TestSupervisorSyncWaitsForRestart(t *testing.T) {
	f := &fakeRelay{ready: func(run int) bool { return run != 2 }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.kill(t, 1)
	waitFor(t, "the relay to be gone", func() bool { return s.state().conn == nil })
	// Run 2 never becomes ready; the sync waits for run 3.
	go func() {
		for f.runs.Load() < 2 {
			time.Sleep(time.Millisecond)
		}
		f.mu.Lock()
		close(f.kills[1])
		f.mu.Unlock()
	}()
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if n := f.runs.Load(); n != 3 {
		t.Errorf("%d runs, want 3", n)
	}
}

func TestSupervisorSyncTimesOutWithoutRelay(t *testing.T) {
	f := &fakeRelay{ready: func(run int) bool { return run == 1 }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.kill(t, 1)
	waitFor(t, "the relay to be gone", func() bool { return s.state().conn == nil })
	s.syncTimeout = 50 * time.Millisecond
	if err := s.Sync(context.Background()); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "not running") {
		t.Errorf("Sync = %v, want a timeout", err)
	}
}

func TestSupervisorSyncBeforeStart(t *testing.T) {
	s, _ := newSupervisor(t, nil)
	s.syncTimeout = 50 * time.Millisecond
	if err := s.Sync(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Sync = %v, want a timeout", err)
	}
}

func TestSupervisorSyncTimesOutWithoutReply(t *testing.T) {
	f := &fakeRelay{answer: func(int, string) []string { return nil }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.syncTimeout = 50 * time.Millisecond
	if err := s.Sync(context.Background()); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "waiting for the SDS relay") {
		t.Errorf("Sync = %v, want a timeout", err)
	}
}

func TestSupervisorSyncHonorsContext(t *testing.T) {
	f := &fakeRelay{answer: func(int, string) []string { return nil }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Sync(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Sync = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Sync took %v", d)
	}
}

func TestSupervisorSyncReportsFailure(t *testing.T) {
	f := &fakeRelay{answer: func(_ int, id string) []string { return []string{errorReply + " " + id} }}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to sync") {
		t.Errorf("Sync = %v, want a failure", err)
	}
}

// TestSupervisorIgnoresStaleReplies checks that a reply to an earlier request
// that timed out, or a malformed line, is not taken for the current reply.
func TestSupervisorIgnoresStaleReplies(t *testing.T) {
	f := &fakeRelay{}
	f.answer = func(_ int, id string) []string {
		return []string{"error 999", "garbage", "ok", "ok x", errorReply, okReply + " " + id}
	}
	t.Cleanup(f.killAll)
	s, logs := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s.Sync(context.Background()); err != nil {
			t.Fatalf("Sync %d: %v", i, err)
		}
	}
	if !strings.Contains(logs.String(), "malformed") {
		t.Errorf("log = %q, want the malformed lines", logs.String())
	}
}

// TestSupervisorKeepsNewestReply checks that replies nobody waits for never
// block the relay.
func TestSupervisorKeepsNewestReply(t *testing.T) {
	f := &fakeRelay{}
	f.answer = func(_ int, id string) []string {
		lines := make([]string, 0, 101)
		for i := 0; i < 100; i++ {
			lines = append(lines, fmt.Sprintf("ok %d", 1000+i))
		}
		return append(lines, okReply+" "+id)
	}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Sync(context.Background()); err != nil {
			t.Fatalf("Sync %d: %v", i, err)
		}
	}
}

// TestSupervisorDrainsLongLines checks that a line too long to parse does not
// leave the relay blocked on a full pipe.
func TestSupervisorDrainsLongLines(t *testing.T) {
	long := strings.Repeat("x", 2*maxLine)
	// More than a pipe holds.
	flood := strings.Repeat(long+"\n", 32)
	f := &fakeRelay{stderr: flood}
	f.answer = func(run int, id string) []string {
		if run == 1 {
			return []string{flood}
		}
		return []string{okReply + " " + id}
	}
	t.Cleanup(f.killAll)
	s, _ := newSupervisor(t, f.exec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The reader gives up on the protocol after the long line, so this sync
	// times out, but it keeps draining the relay's output.
	s.syncTimeout = 100 * time.Millisecond
	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("Sync succeeded")
	}
	// A relay that is not blocked exits when it is killed, and is restarted.
	f.kill(t, 1)
	waitFor(t, "the restart", func() bool { return f.runs.Load() == 2 })
	s.syncTimeout = 2 * time.Second
	if err := s.Sync(context.Background()); err != nil {
		t.Errorf("Sync after the restart: %v", err)
	}
}

func TestParseReply(t *testing.T) {
	for line, want := range map[string]struct {
		r  reply
		ok bool
	}{
		"ok 1":    {reply{1, true}, true},
		"error 2": {reply{2, false}, true},
		"ok":      {reply{}, false},
		"ok x":    {reply{}, false},
		"fine 1":  {reply{}, false},
		"ready":   {reply{}, false},
		"ok -1":   {reply{}, false},
		"OK 1":    {reply{}, false},
	} {
		r, ok := parseReply(line)
		if ok != want.ok || r != want.r {
			t.Errorf("parseReply(%q) = %+v, %v; want %+v, %v", line, r, ok, want.r, want.ok)
		}
	}
}

func TestConnSyncWriteErrors(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	c := &conn{stdin: w, replies: make(chan reply, 1), dead: make(chan struct{})}
	defer w.Close()
	// The relay closed its stdin.
	if err := c.sync(context.Background(), 1); !errors.Is(err, errConnGone) {
		t.Errorf("sync = %v, want errConnGone", err)
	}
	close(c.dead)
	if err := c.sync(context.Background(), 2); !errors.Is(err, errConnGone) {
		t.Errorf("sync = %v, want errConnGone", err)
	}

	// A relay that stops reading fills the pipe, and the write times out.
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	defer w2.Close()
	big := make([]byte, 1<<20)
	w2.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	w2.Write(big)
	c2 := &conn{stdin: w2, replies: make(chan reply, 1), dead: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c2.sync(ctx, 3); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "sending") {
		t.Errorf("sync = %v, want a send timeout", err)
	}
}

// TestSupervisorWithRelay runs the supervisor against the real relay in a
// process, as RunscExec does in a sandbox, and checks that a sync makes a new
// file visible before it returns.
func TestSupervisorWithRelay(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)

	var cmds sync.Map
	run := func(stdin, stdout, stderr *os.File) error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$", "--", "--source", r.Source, "--target", r.Target, "--interval", "1h")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		fio := &fileIO{stdin: stdin, stdout: stdout, stderr: stderr}
		defer fio.Close()
		fio.Set(cmd)
		if err := cmd.Start(); err != nil {
			return err
		}
		cmds.Store(cmd, true)
		fio.CloseAfterStart()
		return cmd.Wait()
	}
	s, logs := newSupervisor(t, run)
	t.Cleanup(func() {
		s.Stop()
		cmds.Range(func(k, _ any) bool {
			k.(*exec.Cmd).Process.Kill()
			return true
		})
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 1\n" {
		t.Errorf("copy = %q after Start", got)
	}
	replaceFile(t, path, "serial: 2\n")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 2\n" {
		t.Errorf("copy = %q after Sync", got)
	}

	// Kill the relay; the next sync uses its replacement.
	cmds.Range(func(k, _ any) bool {
		k.(*exec.Cmd).Process.Kill()
		return true
	})
	replaceFile(t, path, "serial: 3\n")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync after the relay died: %v", err)
	}
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 3\n" {
		t.Errorf("copy = %q after the restart", got)
	}
	waitFor(t, "the relay's log", func() bool { return strings.Contains(logs.String(), `SDS relay: updated "sds-id-cert-and-key.yaml"`) })
}

func TestFileIO(t *testing.T) {
	var files []*os.File
	for i := 0; i < 3; i++ {
		f, err := os.CreateTemp(t.TempDir(), "io")
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	fio := &fileIO{stdin: files[0], stdout: files[1], stderr: files[2]}
	cmd := &exec.Cmd{}
	fio.Set(cmd)
	if cmd.Stdin != files[0] || cmd.Stdout != files[1] || cmd.Stderr != files[2] {
		t.Errorf("Set = %v %v %v", cmd.Stdin, cmd.Stdout, cmd.Stderr)
	}
	if fio.Stdin() != nil || fio.Stdout() != nil || fio.Stderr() != nil {
		t.Error("the parent ends are not the fileIO's")
	}
	if err := fio.CloseAfterStart(); err != nil {
		t.Fatal(err)
	}
	if err := fio.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := f.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
			t.Errorf("%s still open", f.Name())
		}
	}
}
