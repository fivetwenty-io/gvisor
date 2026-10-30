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
	"strconv"
	"strings"
	"sync"
	"time"

	runc "github.com/containerd/go-runc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

const (
	// readyTimeout bounds how long Start waits for the relay's first sync.
	readyTimeout = 10 * time.Second

	// syncTimeout bounds how long Sync waits for the relay.
	syncTimeout = 10 * time.Second

	// minBackoff and maxBackoff bound the delay before the relay is restarted.
	// The delay doubles on each restart and goes back to minBackoff once a
	// relay has run for resetAfter.
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
	resetAfter = time.Minute
)

// errConnGone means the relay exited while a request was in flight.
var errConnGone = errors.New("SDS relay exited")

// ExecFunc runs the relay in the sandbox with the given standard streams and
// returns once it has exited. It owns the three files and closes them once the
// relay has started or has failed to start.
type ExecFunc func(stdin, stdout, stderr *os.File) error

// RunscExec returns an ExecFunc that runs the relay in container id.
func RunscExec(runtime *runsccmd.Runsc, id string) ExecFunc {
	return func(stdin, stdout, stderr *os.File) error {
		fio := &fileIO{stdin: stdin, stdout: stdout, stderr: stderr}
		defer fio.Close()
		// The relay outlives any request, so it must not run under a request's
		// context, whose end would kill it.
		return runtime.Exec(context.Background(), id, Process(), &runsccmd.ExecOpts{IO: fio})
	}
}

// fileIO hands the relay's ends of its pipes to runsc exec. The supervisor
// holds the other ends, so Stdin, Stdout, and Stderr return nil, as they do
// for runc.NullIO.
type fileIO struct {
	stdin, stdout, stderr *os.File
	closeOnce             sync.Once
}

var _ runc.IO = (*fileIO)(nil)
var _ runc.StartCloser = (*fileIO)(nil)

func (f *fileIO) Close() error {
	f.closeOnce.Do(func() {
		f.stdin.Close()
		f.stdout.Close()
		f.stderr.Close()
	})
	return nil
}

func (f *fileIO) CloseAfterStart() error { return f.Close() }

func (f *fileIO) Stdin() io.WriteCloser { return nil }

func (f *fileIO) Stdout() io.ReadCloser { return nil }

func (f *fileIO) Stderr() io.ReadCloser { return nil }

func (f *fileIO) Set(cmd *exec.Cmd) {
	cmd.Stdin = f.stdin
	cmd.Stdout = f.stdout
	cmd.Stderr = f.stderr
}

// Supervisor runs the relay in a sandbox, restarts it when it exits, and
// gates process starts on its syncs.
type Supervisor struct {
	exec ExecFunc
	logf func(format string, args ...any)

	readyTimeout time.Duration
	syncTimeout  time.Duration
	minBackoff   time.Duration
	maxBackoff   time.Duration
	resetAfter   time.Duration

	// stopCh is closed by Stop.
	stopCh chan struct{}

	mu sync.Mutex
	// conn is the running relay once it is ready, or nil.
	//
	// +checklocks:mu
	conn *conn
	// changed is closed and replaced whenever conn, stopping, or failed
	// changes.
	//
	// +checklocks:mu
	changed chan struct{}
	// +checklocks:mu
	started bool
	// +checklocks:mu
	stopping bool
	// failed is set when the relay never became ready, and fails every sync.
	//
	// +checklocks:mu
	failed error
	// lastExit is why the relay last exited.
	//
	// +checklocks:mu
	lastExit error
	// +checklocks:mu
	seq uint64
}

// NewSupervisor returns a Supervisor that runs the relay with run and logs
// with logf.
func NewSupervisor(run ExecFunc, logf func(format string, args ...any)) *Supervisor {
	return &Supervisor{
		exec:         run,
		logf:         logf,
		readyTimeout: readyTimeout,
		syncTimeout:  syncTimeout,
		minBackoff:   minBackoff,
		maxBackoff:   maxBackoff,
		resetAfter:   resetAfter,
		changed:      make(chan struct{}),
		stopCh:       make(chan struct{}),
	}
}

// conn is one running relay.
type conn struct {
	stdin   *os.File
	replies chan reply
	// dead is closed once the relay has exited.
	dead chan struct{}
	// reqMu allows one request at a time.
	reqMu sync.Mutex
}

type reply struct {
	id uint64
	ok bool
}

// snapshot is the supervisor's state at one moment.
type snapshot struct {
	conn     *conn
	stopping bool
	failed   error
	// changed is closed on the next change of the state.
	changed <-chan struct{}
}

func (s *Supervisor) state() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot{conn: s.conn, stopping: s.stopping, failed: s.failed, changed: s.changed}
}

// +checklocks:s.mu
func (s *Supervisor) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// setConn makes c the ready relay unless it has exited or the supervisor is
// stopping.
func (s *Supervisor) setConn(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-c.dead:
		return
	default:
	}
	if s.stopping {
		return
	}
	s.conn = c
	s.notifyLocked()
}

// exited marks c as exited with exit. Under the lock, so that setConn never
// installs a relay that has exited.
func (s *Supervisor) exited(c *conn, exit error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(c.dead)
	s.lastExit = exit
	if s.conn == c {
		s.conn = nil
		s.notifyLocked()
	}
}

// Start runs the relay and waits until its first sync has succeeded. When the
// relay does not become ready in time, Start stops the supervisor and every
// later Sync fails.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.mu.Unlock()

	go s.run()

	ctx, cancel := context.WithTimeout(ctx, s.readyTimeout)
	defer cancel()
	for {
		st := s.state()
		if st.conn != nil {
			return nil
		}
		if st.stopping {
			return errors.New("SDS relay stopped before it was ready")
		}
		select {
		case <-st.changed:
		case <-ctx.Done():
			s.mu.Lock()
			err := fmt.Errorf("SDS relay did not become ready: %w (last exit: %v)", ctx.Err(), s.lastExit)
			s.failed = err
			s.mu.Unlock()
			s.Stop()
			return err
		}
	}
}

// Sync asks the relay to bring the copies up to date and waits until it has.
// It returns nil once the supervisor is stopping, so that processes started
// while the container stops are not held up.
func (s *Supervisor) Sync(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.syncTimeout)
	defer cancel()
	for {
		st := s.state()
		c := st.conn
		switch {
		case st.failed != nil:
			return st.failed
		case st.stopping:
			return nil
		case c == nil:
			// The relay is restarting.
			select {
			case <-st.changed:
				continue
			case <-ctx.Done():
				return fmt.Errorf("SDS relay is not running: %w", ctx.Err())
			}
		}
		s.mu.Lock()
		s.seq++
		id := s.seq
		s.mu.Unlock()
		err := c.sync(ctx, id)
		if !errors.Is(err, errConnGone) {
			return err
		}
		// Wait for the relay to be restarted, or for Stop.
		select {
		case <-c.dead:
		case <-ctx.Done():
			return fmt.Errorf("SDS relay is not running: %w", ctx.Err())
		}
	}
}

// Stop stops restarting the relay, which exits with its container. It is safe
// to call more than once.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	s.stopping = true
	close(s.stopCh)
	s.notifyLocked()
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
		if time.Since(begin) >= s.resetAfter {
			backoff = s.minBackoff
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

// runOnce runs the relay until it exits.
func (s *Supervisor) runOnce() error {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		return err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		return err
	}

	c := &conn{
		stdin:   stdinW,
		replies: make(chan reply, 1),
		dead:    make(chan struct{}),
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		s.readReplies(c, stdoutR)
	}()
	go func() {
		defer readers.Done()
		s.forwardLog(stderrR)
	}()

	err = s.exec(stdinR, stdoutW, stderrW)
	if err == nil {
		err = errors.New("exited without an error")
	}
	s.exited(c, err)
	// Closing the read ends unblocks the readers even when a copy of a write
	// end outlives the relay.
	stdinW.Close()
	stdoutR.Close()
	stderrR.Close()
	readers.Wait()
	return err
}

// readReplies reads the relay's protocol lines from r.
func (s *Supervisor) readReplies(c *conn, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		line := sc.Text()
		if line == readyLine {
			s.setConn(c)
			continue
		}
		rep, ok := parseReply(line)
		if !ok {
			s.logf("SDS relay sent a malformed line")
			continue
		}
		// Keep only the newest reply: a reply that nobody waits for belongs to
		// a request that timed out, and the relay must never block on stdout.
		for sent := false; !sent; {
			select {
			case c.replies <- rep:
				sent = true
			default:
				select {
				case <-c.replies:
				default:
				}
			}
		}
	}
	// Drain the rest so that the relay is never blocked writing to stdout.
	io.Copy(io.Discard, r)
}

// forwardLog logs each line the relay writes to stderr.
func (s *Supervisor) forwardLog(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		s.logf("SDS relay: %s", sc.Text())
	}
	io.Copy(io.Discard, r)
}

func parseReply(line string) (reply, bool) {
	verb, arg, found := strings.Cut(line, " ")
	if !found || (verb != okReply && verb != errorReply) {
		return reply{}, false
	}
	id, err := strconv.ParseUint(arg, 10, 64)
	if err != nil {
		return reply{}, false
	}
	return reply{id: id, ok: verb == okReply}, true
}

// sync sends one request to the relay and waits for its reply.
func (c *conn) sync(ctx context.Context, id uint64) error {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		c.stdin.SetWriteDeadline(deadline)
	}
	if _, err := fmt.Fprintf(c.stdin, "%s %d\n", syncVerb, id); err != nil {
		select {
		case <-c.dead:
			return errConnGone
		default:
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("sending a sync request to the SDS relay: %w", context.DeadlineExceeded)
		}
		// The relay closed its stdin, so it is exiting.
		return errConnGone
	}
	for {
		select {
		case r := <-c.replies:
			if r.id != id {
				continue
			}
			if !r.ok {
				return errors.New("SDS relay failed to sync, see its log")
			}
			return nil
		case <-c.dead:
			return errConnGone
		case <-ctx.Done():
			return fmt.Errorf("waiting for the SDS relay: %w", ctx.Err())
		}
	}
}
