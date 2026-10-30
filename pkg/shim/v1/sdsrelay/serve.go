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
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// OnceFlag makes the relay sync once, waiting for files that are still being
// written, and exit with status 0 only when Target mirrors Source.
const OnceFlag = "--once"

// pollInterval is how often the relay polls Source.
const pollInterval = time.Second

// Poll syncs at once and then every interval until stop is closed.
func (r *Relay) Poll(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.report(r.Sync())
		select {
		case <-ticker.C:
		case <-stop:
			return
		}
	}
}

// Main runs the relay subcommand with args and returns its exit code.
func Main(args []string) int {
	logger := log.New(os.Stderr, "", 0)
	fs := flag.NewFlagSet(Subcommand, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "directory to mirror")
	target := fs.String("target", "", "directory that receives the copies")
	once := fs.Bool(OnceFlag[2:], false, "sync once and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !filepath.IsAbs(*source) || !filepath.IsAbs(*target) || fs.NArg() != 0 {
		logger.Print("--source and --target must be absolute paths, and no other argument is accepted")
		return 2
	}

	r := &Relay{Source: *source, Target: *target, Logf: logger.Printf}
	if *once {
		if err := r.syncSettled(); err != nil {
			logger.Printf("sync failed: %v", err)
			return 1
		}
		return 0
	}

	// A stray signal sent to every process in the container must not stop the
	// poller. SIGTERM and SIGKILL still do, so that the container can stop.
	signal.Ignore(syscall.SIGPIPE, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	r.Poll(pollInterval, nil)
	return 0
}
