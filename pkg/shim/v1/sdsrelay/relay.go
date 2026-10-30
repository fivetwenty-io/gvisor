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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	// tmpPrefix names the relay's temporary files in the target. Source files
	// with this prefix are never copied, and target files with it are removed.
	tmpPrefix = ".sds-relay-"

	// maxFileSize bounds the size of a file the relay copies.
	maxFileSize = 16 << 20

	// settleAttempts and settleDelay bound how long a requested sync waits for
	// a file that is being written to settle.
	settleAttempts = 20
	settleDelay    = 50 * time.Millisecond
)

var (
	// errPending means a file changed while it was read, so the sync must be
	// repeated.
	errPending = errors.New("a source file changed while it was read")

	// errUnstable is the per-file form of errPending.
	errUnstable = errors.New("file changed while it was read")

	// afterRead, when set by a test, runs after a source file is read and
	// before it is checked for changes.
	afterRead func(path string)
)

// Relay mirrors the regular files of Source into Target. Each copy is written
// to a temporary file and renamed into place with the mode and owner of its
// source file. Errors and log messages name files but never carry their
// contents.
type Relay struct {
	// Source is the directory to mirror.
	Source string
	// Target is the directory that receives the copies.
	Target string
	// Logf reports changes of state. It may be nil.
	Logf func(format string, args ...any)

	// settleAttempts and settleDelay override the package defaults in tests.
	settleAttempts int
	settleDelay    time.Duration

	// lastErr is the last error reported, so that a repeated error is
	// logged once.
	lastErr string
}

// fileState is the content and attributes the relay mirrors for one file.
type fileState struct {
	data []byte
	perm os.FileMode
	uid  uint32
	gid  uint32
}

func (f *fileState) equal(o *fileState) bool {
	return f.perm == o.perm && f.uid == o.uid && f.gid == o.gid && bytes.Equal(f.data, o.data)
}

func (r *Relay) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// report logs err when it differs from the last error, and logs a recovery
// once when a sync succeeds after a failure.
func (r *Relay) report(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg == r.lastErr {
		return
	}
	if err == nil {
		r.logf("sync recovered")
	} else {
		r.logf("sync failed: %v", err)
	}
	r.lastErr = msg
}

// Sync mirrors Source into Target once. A file that Source no longer lists is
// removed from Target, but Target is left as it is when Source cannot be read.
// Sync returns an error wrapping errPending when a file changed while it was
// read, and the caller should then sync again.
func (r *Relay) Sync() error {
	info, err := os.Stat(r.Source)
	if err != nil {
		return fmt.Errorf("reading source directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source %q is not a directory", r.Source)
	}
	entries, err := os.ReadDir(r.Source)
	if err != nil {
		return fmt.Errorf("listing source directory: %w", err)
	}

	var (
		errs    []error
		pending []string
	)
	listed := make(map[string]bool, len(entries))
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, tmpPrefix) {
			continue
		}
		listed[name] = true
		if !e.Type().IsRegular() {
			continue
		}
		err := r.syncFile(name)
		switch {
		case err == nil:
		case errors.Is(err, errUnstable), errors.Is(err, os.ErrNotExist):
			// The file is being replaced; the next sync copies its successor.
			pending = append(pending, name)
		default:
			errs = append(errs, err)
		}
	}

	targets, err := os.ReadDir(r.Target)
	if err != nil {
		errs = append(errs, fmt.Errorf("listing target directory: %w", err))
	}
	for _, e := range targets {
		name := e.Name()
		if listed[name] || !e.Type().IsRegular() {
			continue
		}
		// Either the source removed the file, or this is a temporary file left
		// by a relay that died while writing it.
		if err := os.Remove(filepath.Join(r.Target, name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("removing %q: %w", name, err))
		}
	}

	// The target directory takes the group and other bits of the source
	// directory's mode but keeps its owner, the relay, who must still write
	// to it.
	if tinfo, err := os.Stat(r.Target); err != nil {
		errs = append(errs, fmt.Errorf("reading target directory: %w", err))
	} else if perm := info.Mode().Perm() | 0o700; tinfo.Mode().Perm() != perm {
		if err := os.Chmod(r.Target, perm); err != nil {
			errs = append(errs, fmt.Errorf("setting target directory mode: %w", err))
		}
	}

	if len(pending) > 0 {
		sort.Strings(pending)
		errs = append(errs, fmt.Errorf("%w: %s", errPending, strings.Join(pending, ", ")))
	}
	return errors.Join(errs...)
}

// syncSettled syncs until no file is pending, within the settle bound.
func (r *Relay) syncSettled() error {
	attempts, delay := r.settleAttempts, r.settleDelay
	if attempts <= 0 {
		attempts, delay = settleAttempts, settleDelay
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = r.Sync(); !errors.Is(err, errPending) {
			return err
		}
		time.Sleep(delay)
	}
	return err
}

// syncFile copies Source/name to Target/name unless the copy is current.
func (r *Relay) syncFile(name string) error {
	want, err := readStable(filepath.Join(r.Source, name))
	if err != nil {
		return err
	}
	have, err := readTarget(filepath.Join(r.Target, name))
	if err != nil {
		return err
	}
	if have != nil && have.equal(want) {
		return nil
	}
	return r.write(name, want)
}

// readStable reads a regular file and its attributes. It fails with
// errUnstable when the file was replaced or changed while it was read.
func readStable(path string) (*fileState, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", filepath.Base(path))
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%q: %w", filepath.Base(path), errUnstable)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", filepath.Base(path), err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%q is larger than %d bytes", filepath.Base(path), maxFileSize)
	}
	if afterRead != nil {
		afterRead(path)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if after.Size() != int64(len(data)) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, fmt.Errorf("%q: %w", filepath.Base(path), errUnstable)
	}
	if now, err := os.Lstat(path); err != nil || !os.SameFile(now, opened) {
		return nil, fmt.Errorf("%q: %w", filepath.Base(path), errUnstable)
	}
	st := opened.Sys().(*syscall.Stat_t)
	return &fileState{data: data, perm: opened.Mode().Perm(), uid: st.Uid, gid: st.Gid}, nil
}

// readTarget reads a copy in Target. It returns nil when there is no regular
// file at path, so that the copy is written.
func readTarget(path string) (*fileState, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading copy of %q: %w", filepath.Base(path), err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return &fileState{data: data, perm: info.Mode().Perm(), uid: st.Uid, gid: st.Gid}, nil
}

// write replaces Target/name with want through a temporary file and a rename,
// so that a reader never sees a partial copy and the Sentry raises IN_MOVED_TO.
func (r *Relay) write(name string, want *fileState) (err error) {
	tmp, err := os.CreateTemp(r.Target, tmpPrefix+"*")
	if err != nil {
		return fmt.Errorf("creating copy of %q: %w", name, err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(want.data); err != nil {
		return fmt.Errorf("writing copy of %q: %w", name, err)
	}
	// Set the mode before the owner: once the file belongs to another user,
	// changing its mode would need CAP_FOWNER.
	if err := tmp.Chmod(want.perm); err != nil {
		return fmt.Errorf("setting mode of copy of %q: %w", name, err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return err
	}
	if st := info.Sys().(*syscall.Stat_t); st.Uid != want.uid || st.Gid != want.gid {
		if err := tmp.Chown(int(want.uid), int(want.gid)); err != nil {
			return fmt.Errorf("setting owner of copy of %q: %w", name, err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing copy of %q: %w", name, err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(r.Target, name)); err != nil {
		return fmt.Errorf("renaming copy of %q: %w", name, err)
	}
	r.logf("updated %q", name)
	return nil
}
