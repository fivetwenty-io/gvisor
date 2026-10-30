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
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	runc "github.com/containerd/go-runc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

const (
	// syncTimeout bounds how long Sync waits for the relay to sync once.
	syncTimeout = 10 * time.Second

	// minBackoff and maxBackoff bound the delay before the poller is
	// restarted. The delay doubles on each restart and goes back to minBackoff
	// once a poller has run for resetAfter. Sync never waits for the poller,
	// and maxBackoff stays below syncTimeout all the same.
	minBackoff = time.Second
	maxBackoff = 5 * time.Second
	resetAfter = time.Minute

	// maxLogLine bounds a line of the poller's log.
	maxLogLine = 4096

	// exitSettle is how long the supervisor waits, after the poller exits,
	// for Stop or for the container to be reported gone before it logs the
	// exit. The poller dies with the container, usually just before the shim
	// learns that the container is stopping. A genuine failure restarts the
	// poller after at least minBackoff, which is longer.
	exitSettle = 200 * time.Millisecond

	// goneTimeout bounds the check whether the container is gone.
	goneTimeout = 5 * time.Second
)

// ExecFunc runs the relay in the sandbox with extra appended to its arguments
// and returns once it has exited. With a nil stderr, the error carries the
// relay's output. Otherwise ExecFunc owns stderr and closes it once the relay
// has started or has failed to start.
type ExecFunc func(ctx context.Context, extra []string, stderr *os.File) error

// RunscExec returns an ExecFunc that runs the relay in container id.
func RunscExec(runtime *runsccmd.Runsc, id string) ExecFunc {
	return func(ctx context.Context, extra []string, stderr *os.File) error {
		var opts *runsccmd.ExecOpts
		if stderr != nil {
			fio := &stderrIO{stderr: stderr}
			defer fio.Close()
			opts = &runsccmd.ExecOpts{IO: fio}
		}
		return runtime.Exec(ctx, id, Process(extra...), opts)
	}
}

// GoneFunc reports whether the sandbox the poller runs in has stopped, so that
// the poller's exit is expected. It reports false when it cannot tell.
type GoneFunc func(ctx context.Context) bool

// RunscGone returns a GoneFunc that asks runsc for the state of container id.
// A container that runsc cannot report on is not taken to be gone.
func RunscGone(runtime *runsccmd.Runsc, id string) GoneFunc {
	return func(ctx context.Context) bool {
		ctx, cancel := context.WithTimeout(ctx, goneTimeout)
		defer cancel()
		c, err := runtime.State(ctx, id)
		return err == nil && c.Status == "stopped"
	}
}

// stderrIO hands the relay's end of its stderr pipe to runsc exec. The
// supervisor holds the other end, so Stdin, Stdout, and Stderr return nil, as
// they do for runc.NullIO.
type stderrIO struct {
	stderr    *os.File
	closeOnce sync.Once
}

var _ runc.IO = (*stderrIO)(nil)
var _ runc.StartCloser = (*stderrIO)(nil)

func (f *stderrIO) Close() error {
	f.closeOnce.Do(func() { f.stderr.Close() })
	return nil
}

func (f *stderrIO) CloseAfterStart() error { return f.Close() }

func (f *stderrIO) Stdin() io.WriteCloser { return nil }

func (f *stderrIO) Stdout() io.ReadCloser { return nil }

func (f *stderrIO) Stderr() io.ReadCloser { return nil }

func (f *stderrIO) Set(cmd *exec.Cmd) { cmd.Stderr = f.stderr }

// Supervisor runs the polling relay in a sandbox and restarts it when it
// exits, and runs the relay once to gate a process start.
type Supervisor struct {
	exec ExecFunc
	gone GoneFunc
	logf func(format string, args ...any)

	syncTimeout time.Duration
	exitSettle  time.Duration
	minBackoff  time.Duration
	maxBackoff  time.Duration
	resetAfter  time.Duration

	// stopCh is closed by Stop.
	stopCh chan struct{}

	mu sync.Mutex
	// +checklocks:mu
	started bool
	// +checklocks:mu
	stopping bool
}

// NewSupervisor returns a Supervisor that runs the relay with run and logs
// with logf. The poller exits quietly, without a restart, once gone reports
// that its sandbox has stopped. A nil gone never does.
func NewSupervisor(run ExecFunc, gone GoneFunc, logf func(format string, args ...any)) *Supervisor {
	return &Supervisor{
		exec:        run,
		gone:        gone,
		logf:        logf,
		syncTimeout: syncTimeout,
		exitSettle:  exitSettle,
		minBackoff:  minBackoff,
		maxBackoff:  maxBackoff,
		resetAfter:  resetAfter,
		stopCh:      make(chan struct{}),
	}
}

// Start starts the polling relay in the background. It cannot fail: a poller
// that does not start is retried, and Sync does not depend on it. Start does
// nothing after the first call or after Stop.
func (s *Supervisor) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopping {
		return
	}
	s.started = true
	go s.run()
}

// Sync runs the relay once in the sandbox and returns once Target mirrors
// Source, or with an error when the relay could not make it so within the
// sync timeout. It returns nil at once after Stop, so that a process started
// while the container stops is not held up.
func (s *Supervisor) Sync(ctx context.Context) error {
	if s.isStopping() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.syncTimeout)
	defer cancel()
	if err := s.exec(ctx, []string{OnceFlag}, nil); err != nil {
		return fmt.Errorf("SDS relay sync: %w", err)
	}
	return nil
}

// Stop stops restarting the poller, which exits with its container. It is
// safe to call more than once.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	s.stopping = true
	close(s.stopCh)
}

func (s *Supervisor) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func (s *Supervisor) run() {
	backoff := s.minBackoff
	for {
		begin := time.Now()
		err := s.runOnce()
		select {
		case <-s.stopCh:
			return
		default:
		}
		if s.sandboxGone() {
			return
		}
		if time.Since(begin) >= s.resetAfter {
			backoff = s.minBackoff
		}
		if err == nil {
			err = errors.New("exited without an error")
		}
		s.logf("SDS relay exited, restarting in %v: %v", backoff, err)
		select {
		case <-time.After(backoff):
		case <-s.stopCh:
			return
		}
		backoff = min(2*backoff, s.maxBackoff)
	}
}

// sandboxGone reports whether the poller's exit is the sandbox stopping, which
// the shim has not yet reported with Stop. It waits for exitSettle first, as
// the container may not yet show as stopped, and returns true early when Stop
// is called.
func (s *Supervisor) sandboxGone() bool {
	select {
	case <-s.stopCh:
		return true
	case <-time.After(s.exitSettle):
	}
	return s.gone != nil && s.gone(context.Background())
}

// runOnce runs the poller until it exits, and logs each line of its stderr.
func (s *Supervisor) runOnce() error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, maxLogLine), maxLogLine)
		for sc.Scan() {
			s.logf("SDS relay: %s", sc.Text())
		}
		// Drain the rest so that the poller never blocks on its stderr.
		io.Copy(io.Discard, r)
	}()
	// The poller outlives any request, so it must not run under a request's
	// context, whose end would kill it.
	err = s.exec(context.Background(), nil, w)
	// Closing the read end unblocks the reader even when a copy of the write
	// end outlives the poller.
	r.Close()
	<-done
	return err
}
