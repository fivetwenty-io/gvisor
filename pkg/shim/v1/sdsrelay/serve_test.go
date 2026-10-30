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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
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

// poll runs r.Poll in the background until the test ends.
func poll(t *testing.T, r *Relay, interval time.Duration) (stop func()) {
	t.Helper()
	ch := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Poll(interval, ch)
	}()
	var stopped bool
	stop = func() {
		if !stopped {
			stopped = true
			close(ch)
			<-done
		}
	}
	// Poll must be done with the directories before they are removed.
	t.Cleanup(stop)
	return stop
}

// pollRelay returns a relay whose log is safe to read while it polls.
func pollRelay(t *testing.T) (*Relay, *logBuffer) {
	r, _ := newRelay(t)
	logs := &logBuffer{}
	r.Logf = logs.logf
	return r, logs
}

func TestPollSyncsAtOnceAndOnEveryTick(t *testing.T) {
	r, logs := pollRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	target := filepath.Join(r.Target, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)
	stop := poll(t, r, time.Hour)
	waitFor(t, "the first sync", func() bool { return content(target) == "serial: 1\n" })
	stop()

	stop = poll(t, r, 10*time.Millisecond)
	replaceFile(t, path, "serial: 2\n")
	waitFor(t, "a poll to copy serial 2", func() bool { return content(target) == "serial: 2\n" })
	stop()

	// After Poll returns, nothing changes the copies.
	replaceFile(t, path, "serial: 3\n")
	time.Sleep(50 * time.Millisecond)
	if got := content(target); got != "serial: 2\n" {
		t.Errorf("copy = %q after Poll returned", got)
	}
	if !strings.Contains(logs.String(), `updated "sds-id-cert-and-key.yaml"`) {
		t.Errorf("log = %q", logs.String())
	}
}

func TestPollReportsErrorsOnceAndRecovers(t *testing.T) {
	r, logs := pollRelay(t)
	if err := os.Remove(r.Source); err != nil {
		t.Fatal(err)
	}
	poll(t, r, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	if err := os.Mkdir(r.Source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	waitFor(t, "the recovery", func() bool { return strings.Contains(logs.String(), "sync recovered") })
	if n := strings.Count(logs.String(), "sync failed"); n != 1 {
		t.Errorf("logged %d failures, want 1: %s", n, logs.String())
	}
}

func TestPollInterval(t *testing.T) {
	if pollInterval != time.Second {
		t.Errorf("pollInterval = %v, want 1s", pollInterval)
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
		{"--source", dir, "--target", dir, "--interval", "1s"},
		{"--source", dir, "--target", dir, "--once=maybe"},
		{"--bogus"},
	} {
		if code := Main(args); code != 2 {
			t.Errorf("Main(%q) = %d, want 2", args, code)
		}
	}
}

func TestMainOnce(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	if code := Main([]string{"--source", r.Source, "--target", r.Target, OnceFlag}); code != 0 {
		t.Fatalf("Main = %d, want 0", code)
	}
	if got := content(filepath.Join(r.Target, "envoy.yaml")); got != "admin: {}\n" {
		t.Errorf("copy = %q", got)
	}
	if code := Main([]string{"--source", filepath.Join(r.Source, "missing"), "--target", r.Target, OnceFlag}); code != 1 {
		t.Errorf("Main without a source = %d, want 1", code)
	}
}

const helperEnv = "SDS_RELAY_TEST_MAIN"

// TestHelperMain runs Main when the test binary is started by another test.
func TestHelperMain(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("run by TestMainPolls and TestMainOnceProcess")
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

func relayCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestHelperMain$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	return cmd
}

// TestMainOnceProcess runs a gated sync as a process, as the shim does, and
// checks that it waits for a file that is still being written.
func TestMainOnceProcess(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, secret, 0o600)

	var stderr strings.Builder
	cmd := relayCommand("--source", r.Source, "--target", r.Target, OnceFlag)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("relay: %v; stderr: %s", err, stderr.String())
	}
	if got := content(filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != secret {
		t.Errorf("copy has the wrong content")
	}
	if strings.Contains(stderr.String(), "PRIVATE KEY") || strings.Contains(stderr.String(), "c2VjcmV0") {
		t.Errorf("key material in the log: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), `updated "sds-id-cert-and-key.yaml"`) {
		t.Errorf("log = %q, want the update", stderr.String())
	}

	stderr.Reset()
	cmd = relayCommand("--source", filepath.Join(r.Source, "missing"), "--target", r.Target, OnceFlag)
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Errorf("relay without a source exited with %v, want status 1", err)
	}
	if !strings.Contains(stderr.String(), "sync failed") {
		t.Errorf("log = %q, want the failure", stderr.String())
	}
}

// TestMainPolls runs the poller as a process, as the sandbox does.
func TestMainPolls(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	target := filepath.Join(r.Target, "sds-id-cert-and-key.yaml")
	writeFile(t, path, secret, 0o600)

	var stderr strings.Builder
	cmd := relayCommand("--source", r.Source, "--target", r.Target)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	waitFor(t, "the first copy", func() bool { return content(target) == secret })

	// Signals sent to every process in the container leave the poller alone.
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGPIPE} {
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
	}
	replaceFile(t, path, "serial: 2\n")
	waitFor(t, "a poll to copy serial 2", func() bool { return content(target) == "serial: 2\n" })

	// SIGTERM stops it, so that the container can stop.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Errorf("relay exited with %v, want SIGTERM", err)
	}
	if strings.Contains(stderr.String(), "PRIVATE KEY") || strings.Contains(stderr.String(), "c2VjcmV0") {
		t.Errorf("key material in the log: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), `updated "sds-id-cert-and-key.yaml"`) {
		t.Errorf("log = %q, want the update", stderr.String())
	}
}
