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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// served is a relay running Serve in the background.
type served struct {
	t     *testing.T
	in    *io.PipeWriter
	lines chan string
	stop  chan struct{}
	done  chan error
	// finished is closed when Serve has returned.
	finished chan struct{}
}

func serve(t *testing.T, r *Relay, interval time.Duration) *served {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &served{t: t, in: inW, lines: make(chan string, 100), stop: make(chan struct{}), done: make(chan error, 1), finished: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	go func() {
		defer close(s.finished)
		err := r.Serve(inR, outW, interval, s.stop)
		outW.Close()
		s.done <- err
	}()
	// Serve must be done with the directories before they are removed.
	t.Cleanup(func() {
		s.close()
		inW.Close()
		<-s.finished
	})
	return s
}

func (s *served) close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

func (s *served) send(line string) {
	s.t.Helper()
	if _, err := fmt.Fprintln(s.in, line); err != nil {
		s.t.Fatal(err)
	}
}

func (s *served) next(timeout time.Duration) (string, bool) {
	select {
	case l, ok := <-s.lines:
		return l, ok
	case <-time.After(timeout):
		return "", false
	}
}

func (s *served) expect(want string) {
	s.t.Helper()
	got, ok := s.next(5 * time.Second)
	if !ok || got != want {
		s.t.Fatalf("relay wrote %q (%v), want %q", got, ok, want)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func content(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// TestServeReadyAfterFirstSync checks the startup order: the relay announces
// readiness only once the copies exist, and keeps trying until they do.
func TestServeReadyAfterFirstSync(t *testing.T) {
	r, _ := newRelay(t)
	if err := os.Remove(r.Source); err != nil {
		t.Fatal(err)
	}
	s := serve(t, r, 10*time.Millisecond)
	if l, ok := s.next(100 * time.Millisecond); ok {
		t.Fatalf("relay wrote %q before its first sync succeeded", l)
	}

	if err := os.Mkdir(r.Source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(r.Source, "sds-id-cert-and-key.yaml"), "serial: 1\n", 0o644)
	s.expect(readyLine)
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 1\n" {
		t.Errorf("copy = %q when the relay became ready", got)
	}
}

func TestServeAnswersRequests(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)
	// The ticker never fires, so only requests sync.
	s := serve(t, r, time.Hour)
	s.expect(readyLine)

	replaceFile(t, path, "serial: 2\n")
	s.send("sync 7")
	s.expect("ok 7")
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 2\n" {
		t.Errorf("copy = %q after ok", got)
	}

	// Malformed requests get no reply.
	for _, l := range []string{"", "bogus", "sync", "sync x", "sync -1", "ok 1", "sync 1 2"} {
		s.send(l)
	}
	s.send("sync 18446744073709551615")
	s.expect("ok 18446744073709551615")

	os.RemoveAll(r.Source)
	s.send("sync 8")
	s.expect("error 8")
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 2\n" {
		t.Errorf("copy = %q after the source vanished", got)
	}
}

// TestServeSettlesBeforeReplying checks that a request waits for a file that
// is being written rather than failing.
func TestServeSettlesBeforeReplying(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "v1\n", 0o644)
	s := serve(t, r, time.Hour)
	s.expect(readyLine)

	writeFile(t, path, "v2\n", 0o644)
	writes := 0
	afterRead = func(p string) {
		if writes < 2 {
			writes++
			writeFile(t, p, fmt.Sprintf("v%d-long\n", writes+2), 0o644)
		}
	}
	defer func() { afterRead = nil }()
	s.send("sync 1")
	s.expect("ok 1")
	if got := content(filepath.Join(r.Target, "envoy.yaml")); got != "v4-long\n" {
		t.Errorf("copy = %q, want v4-long", got)
	}
}

func TestServePolls(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)
	s := serve(t, r, 10*time.Millisecond)
	s.expect(readyLine)

	replaceFile(t, path, "serial: 2\n")
	waitFor(t, "the poll to copy serial 2", func() bool {
		return content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")) == "serial: 2\n"
	})

	// Without the shim, the relay keeps the copies current.
	s.in.Close()
	replaceFile(t, path, "serial: 3\n")
	waitFor(t, "the poll to copy serial 3", func() bool {
		return content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")) == "serial: 3\n"
	})
	if l, ok := s.next(50 * time.Millisecond); ok {
		t.Errorf("relay wrote %q", l)
	}
}

func TestServeStops(t *testing.T) {
	r, _ := newRelay(t)
	s := serve(t, r, time.Hour)
	s.expect(readyLine)
	s.close()
	select {
	case err := <-s.done:
		if err != nil {
			t.Errorf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestServeStopsBeforeReady(t *testing.T) {
	r, _ := newRelay(t)
	os.Remove(r.Source)
	s := serve(t, r, 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	s.close()
	select {
	case err := <-s.done:
		if err != nil {
			t.Errorf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	if l, ok := s.next(time.Second); ok {
		t.Errorf("relay wrote %q", l)
	}
}

// TestServeStopsWhileReading checks that Serve stops when a request is pending
// in its reader.
func TestServeStopsWhileReading(t *testing.T) {
	r, _ := newRelay(t)
	inR, inW := io.Pipe()
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- r.Serve(inR, io.Discard, time.Hour, stop) }()
	go func() {
		for {
			if _, err := fmt.Fprintln(inW, "bogus"); err != nil {
				return
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	inW.Close()
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestServeFailsWhenItCannotAnnounce(t *testing.T) {
	r, _ := newRelay(t)
	if err := r.Serve(strings.NewReader(""), failingWriter{}, time.Hour, nil); err == nil || !strings.Contains(err.Error(), "announcing readiness") {
		t.Errorf("Serve = %v", err)
	}
}

func TestParseRequest(t *testing.T) {
	for line, want := range map[string]struct {
		id uint64
		ok bool
	}{
		"sync 0":    {0, true},
		"sync 42":   {42, true},
		"sync":      {0, false},
		"sync ":     {0, false},
		"sync a":    {0, false},
		"sync 1 2":  {0, false},
		"Sync 1":    {0, false},
		"ok 1":      {0, false},
		" sync 1":   {0, false},
		"sync\t1":   {0, false},
		"sync 1\r":  {0, false},
		"syncs 1":   {0, false},
		"sync -1":   {0, false},
		"sync +1":   {0, false},
		"sync 0x10": {0, false},
	} {
		id, ok := parseRequest(line)
		if ok != want.ok || (ok && id != want.id) {
			t.Errorf("parseRequest(%q) = %d, %v; want %d, %v", line, id, ok, want.id, want.ok)
		}
	}
}

func TestMainRejectsBadArguments(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{},
		{"--source", dir},
		{"--target", dir},
		{"--source", "rel", "--target", dir},
		{"--source", dir, "--target", "rel"},
		{"--source", dir, "--target", dir, "extra"},
		{"--source", dir, "--target", dir, "--interval", "0s"},
		{"--source", dir, "--target", dir, "--interval", "-1s"},
		{"--source", dir, "--target", dir, "--interval", "soon"},
		{"--bogus"},
	} {
		if code := Main(args); code != 2 {
			t.Errorf("Main(%q) = %d, want 2", args, code)
		}
	}
}

const helperEnv = "SDS_RELAY_TEST_MAIN"

// TestHelperMain runs Main when the test binary is started by
// TestMainProcess.
func TestHelperMain(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("run by TestMainProcess")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Exit(Main(args))
}

// TestMainProcess runs the relay as a process, as the sandbox does.
func TestMainProcess(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, secret, 0o600)

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$", "--", "--source", r.Source, "--target", r.Target, "--interval", "1h")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	out := bufio.NewScanner(stdout)
	expect := func(want string) {
		t.Helper()
		if !out.Scan() || out.Text() != want {
			t.Fatalf("relay wrote %q, want %q; stderr: %s", out.Text(), want, stderr.String())
		}
	}
	expect(readyLine)
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != secret {
		t.Errorf("copy has the wrong content")
	}

	// Signals sent to every process in the container leave the relay alone.
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGPIPE} {
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
	}
	replaceFile(t, path, "serial: 2\n")
	fmt.Fprintln(stdin, "sync 1")
	expect("ok 1")
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != "serial: 2\n" {
		t.Errorf("copy = %q", got)
	}

	// SIGTERM stops it, so that the container can stop.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Errorf("relay exited with %v, want SIGTERM", err)
	}
	if strings.Contains(stderr.String(), "PRIVATE KEY") {
		t.Errorf("key material in the log: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), `updated "sds-id-cert-and-key.yaml"`) {
		t.Errorf("log = %q, want the update", stderr.String())
	}
}

// TestMainSurvivesClosedStdout checks that a relay whose shim is gone keeps
// running instead of dying of SIGPIPE.
func TestMainSurvivesClosedStdout(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "v1\n", 0o644)

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$", "--", "--source", r.Source, "--target", r.Target, "--interval", "10ms")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	out := bufio.NewScanner(stdout)
	if !out.Scan() || out.Text() != readyLine {
		t.Fatalf("relay wrote %q", out.Text())
	}
	stdout.Close()
	// The reply goes to a closed pipe.
	fmt.Fprintln(stdin, "sync 1")
	time.Sleep(50 * time.Millisecond)
	writeFile(t, path, "v2\n", 0o644)
	waitFor(t, "the poll to copy v2", func() bool { return content(filepath.Join(r.Target, "envoy.yaml")) == "v2\n" })
	if cmd.ProcessState != nil {
		t.Fatalf("relay exited: %v", cmd.ProcessState)
	}
	stdin.Close()
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
}

// TestMainFailsWithoutStdout checks that a relay that cannot announce that it
// is ready exits with an error.
func TestMainFailsWithoutStdout(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "v1\n", 0o644)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	pr.Close()
	defer pw.Close()

	var stderr strings.Builder
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$", "--", "--source", r.Source, "--target", r.Target, "--interval", "10ms")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdout = pw
	cmd.Stderr = &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("relay kept running without a stdout")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Errorf("relay exited with %v, want status 1", err)
	}
	if !strings.Contains(stderr.String(), "announcing readiness") {
		t.Errorf("log = %q, want the announce error", stderr.String())
	}
}
