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
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The relay and the shim talk over the relay's stdin and stdout, one line per
// message. The relay writes readyLine once its first sync has succeeded. The
// shim then sends "sync ID" before it starts a process in the container, and
// the relay answers "ok ID" once Target mirrors Source, or "error ID".
const (
	readyLine  = "ready"
	syncVerb   = "sync"
	okReply    = "ok"
	errorReply = "error"

	// maxLine bounds a protocol or log line.
	maxLine = 4096
)

// DefaultInterval is how often the relay polls Source.
const DefaultInterval = time.Second

// Serve runs the relay until stop is closed. It syncs before it writes
// readyLine, retrying every interval until a sync succeeds, then syncs every
// interval and on each request read from in. When in reaches EOF the relay
// keeps polling. Serve returns an error only when it cannot write to out
// before it is ready.
func (r *Relay) Serve(in io.Reader, out io.Writer, interval time.Duration, stop <-chan struct{}) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		err := r.syncSettled()
		r.report(err)
		if err == nil {
			break
		}
		select {
		case <-ticker.C:
		case <-stop:
			return nil
		}
	}
	if _, err := fmt.Fprintln(out, readyLine); err != nil {
		return fmt.Errorf("announcing readiness: %w", err)
	}

	requests := make(chan string)
	go func() {
		defer close(requests)
		s := bufio.NewScanner(in)
		s.Buffer(make([]byte, 0, maxLine), maxLine)
		for s.Scan() {
			select {
			case requests <- s.Text():
			case <-stop:
				return
			}
		}
	}()

	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			r.report(r.Sync())
		case line, ok := <-requests:
			if !ok {
				// The shim is gone. Keep the copies current without it.
				requests = nil
				continue
			}
			id, valid := parseRequest(line)
			if !valid {
				r.logf("ignoring a malformed request")
				continue
			}
			err := r.syncSettled()
			r.report(err)
			reply := okReply
			if err != nil {
				reply = errorReply
			}
			// A write error means the shim is gone; the next read sees EOF.
			fmt.Fprintf(out, "%s %d\n", reply, id)
		}
	}
}

func parseRequest(line string) (uint64, bool) {
	verb, arg, found := strings.Cut(line, " ")
	if !found || verb != syncVerb {
		return 0, false
	}
	id, err := strconv.ParseUint(arg, 10, 64)
	return id, err == nil
}

// Main runs the relay subcommand with args and returns its exit code.
func Main(args []string) int {
	logger := log.New(os.Stderr, "", 0)
	fs := flag.NewFlagSet(Subcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "directory to mirror")
	target := fs.String("target", "", "directory that receives the copies")
	interval := fs.Duration("interval", DefaultInterval, "how often to poll the source")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !filepath.IsAbs(*source) || !filepath.IsAbs(*target) || fs.NArg() != 0 {
		logger.Print("--source and --target must be absolute paths, and no other argument is accepted")
		return 2
	}
	if *interval <= 0 {
		logger.Print("--interval must be positive")
		return 2
	}

	// A write to a closed stdout must fail rather than kill the relay, and a
	// stray signal sent to every process in the container must not stop it.
	// SIGTERM and SIGKILL still do, so that the container can stop.
	signal.Ignore(syscall.SIGPIPE, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	r := &Relay{Source: *source, Target: *target, Logf: logger.Printf}
	if err := r.Serve(os.Stdin, os.Stdout, *interval, nil); err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}
