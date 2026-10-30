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
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// tmpPrefix starts the names of the relays' temporary files in the target.
	// Each relay adds its pid, so that two relays never remove each other's.
	tmpPrefix = ".sds-relay-"

	// staleTemp is the age at which a temporary file of another relay is
	// taken to be left by a relay that died while writing it.
	staleTemp = time.Minute

	// maxFileSize bounds the size of a file the relay copies.
	maxFileSize = 16 << 20

	// settleAttempts and settleDelay bound how long a gated sync waits for a
	// file that is being written to settle.
	settleAttempts = 20
	settleDelay    = 50 * time.Millisecond

	// quietTime is how long a source file must go unchanged before the relay
	// copies it, so that it never copies a file that Diego is still writing.
	quietTime = 100 * time.Millisecond

	// fullCheckEvery is how many syncs pass between two syncs that compare
	// every file in full, which catches a rewrite that keeps every attribute
	// the relay compares.
	fullCheckEvery = 60
)

var (
	// errPending means a source file is still being written, so the sync
	// must be repeated.
	errPending = errors.New("a source file is still being written")

	// errUnstable is the per-file form of errPending.
	errUnstable = errors.New("file is still being written")

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
	// now overrides time.Now in tests.
	now func() time.Time

	// lastErr is the last error reported, so that a repeated error is
	// logged once.
	lastErr string
	// copied holds, for each file the relay knows to be current, the
	// attributes of the source and of the copy at that time.
	copied map[string]copiedFile
	// syncs counts the calls to Sync.
	syncs int
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

// fileKey holds the attributes that change whenever a file is replaced or
// written, so that a file whose key is unchanged needs no read.
type fileKey struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
	mode         uint32
	uid, gid     uint32
}

func keyOf(info os.FileInfo) fileKey {
	st := info.Sys().(*syscall.Stat_t)
	return fileKey{
		dev:   uint64(st.Dev),
		ino:   st.Ino,
		size:  st.Size,
		mtime: st.Mtim.Nano(),
		ctime: st.Ctim.Nano(),
		mode:  st.Mode,
		uid:   st.Uid,
		gid:   st.Gid,
	}
}

type copiedFile struct {
	source, target fileKey
}

func (r *Relay) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *Relay) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
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

// skipped reports whether the relay ignores a source file. Diego writes each
// SDS file to NAME.tmp before it renames it into place, and the relay's own
// temporary files start with a dot.
func skipped(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".tmp")
}

// ownTmpPrefix starts the names of this relay's temporary files.
func ownTmpPrefix() string {
	return tmpPrefix + strconv.Itoa(os.Getpid()) + "-"
}

// Sync mirrors Source into Target once. A file that Source no longer lists is
// removed from Target, but Target is left as it is when Source cannot be read.
// Sync returns an error wrapping errPending when a file is still being
// written, and the caller should then sync again.
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
	if r.syncs%fullCheckEvery == 0 {
		r.copied = nil
	}
	r.syncs++
	if r.copied == nil {
		r.copied = make(map[string]copiedFile)
	}

	var (
		errs    []error
		pending []string
	)
	listed := make(map[string]bool, len(entries))
	for _, e := range entries {
		name := e.Name()
		if skipped(name) {
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
			// The file is being written or replaced; a later sync copies it.
			pending = append(pending, name)
		default:
			errs = append(errs, err)
		}
	}
	for name := range r.copied {
		if !listed[name] {
			delete(r.copied, name)
		}
	}

	if err := r.removeUnlisted(listed); err != nil {
		errs = append(errs, err)
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

// removeUnlisted removes the regular files in Target that Source does not
// list. It leaves the temporary files of other relays alone until they are
// stale, so that it never removes one between its write and its rename.
func (r *Relay) removeUnlisted(listed map[string]bool) error {
	targets, err := os.ReadDir(r.Target)
	if err != nil {
		return fmt.Errorf("listing target directory: %w", err)
	}
	var errs []error
	own := ownTmpPrefix()
	for _, e := range targets {
		name := e.Name()
		if listed[name] || !e.Type().IsRegular() {
			continue
		}
		if strings.HasPrefix(name, tmpPrefix) && !strings.HasPrefix(name, own) {
			info, err := e.Info()
			if err != nil || r.clock().Sub(info.ModTime()) < staleTemp {
				continue
			}
		}
		if err := os.Remove(filepath.Join(r.Target, name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("removing %q: %w", name, err))
		}
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

// syncFile copies Source/name to Target/name unless the copy is current. A
// file whose source and copy both keep the attributes they had when the relay
// last found the copy current is not read again.
func (r *Relay) syncFile(name string) error {
	src, dst := filepath.Join(r.Source, name), filepath.Join(r.Target, name)
	sinfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if c, ok := r.copied[name]; ok && c.source == keyOf(sinfo) {
		if tinfo, err := os.Lstat(dst); err == nil && keyOf(tinfo) == c.target {
			return nil
		}
	}
	delete(r.copied, name)

	want, skey, err := r.readStable(src)
	if err != nil {
		return err
	}
	have := readTarget(dst)
	if len(want.data) == 0 && have != nil && len(have.data) > 0 {
		// Diego writes envoy.yaml in place, so an empty file is one it has
		// truncated and not yet written.
		return fmt.Errorf("%q is empty: %w", name, errUnstable)
	}
	if have == nil || !have.equal(want) {
		if err := r.write(name, want); err != nil {
			return err
		}
	}
	tinfo, err := os.Lstat(dst)
	if err != nil {
		return err
	}
	r.copied[name] = copiedFile{source: skey, target: keyOf(tinfo)}
	return nil
}

// readStable reads a regular file and its attributes without following a
// symbolic link. It fails with errUnstable when the file was replaced or
// changed while it was read, or changed less than quietTime ago.
func (r *Relay) readStable(path string) (*fileState, fileKey, error) {
	name := filepath.Base(path)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fileKey{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fileKey{}, err
	}
	if !opened.Mode().IsRegular() {
		return nil, fileKey{}, fmt.Errorf("%q is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fileKey{}, fmt.Errorf("reading %q: %w", name, err)
	}
	if len(data) > maxFileSize {
		return nil, fileKey{}, fmt.Errorf("%q is larger than %d bytes", name, maxFileSize)
	}
	if afterRead != nil {
		afterRead(path)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, fileKey{}, err
	}
	key := keyOf(after)
	if key != keyOf(opened) || key.size != int64(len(data)) {
		return nil, fileKey{}, fmt.Errorf("%q: %w", name, errUnstable)
	}
	if now, err := os.Lstat(path); err != nil || !os.SameFile(now, after) {
		return nil, fileKey{}, fmt.Errorf("%q: %w", name, errUnstable)
	}
	if age := r.clock().Sub(time.Unix(0, key.ctime)); age >= 0 && age < quietTime {
		return nil, fileKey{}, fmt.Errorf("%q: %w", name, errUnstable)
	}
	return &fileState{data: data, perm: after.Mode().Perm(), uid: key.uid, gid: key.gid}, key, nil
}

// readTarget reads a copy in Target without following a symbolic link or
// blocking on a FIFO. It returns nil when there is no regular file at path
// that it can read, so that the copy is written.
func readTarget(path string) *fileState {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil
	}
	st := info.Sys().(*syscall.Stat_t)
	return &fileState{data: data, perm: info.Mode().Perm(), uid: st.Uid, gid: st.Gid}
}

// write replaces Target/name with want through a temporary file and a rename,
// so that a reader never sees a partial copy and the Sentry raises IN_MOVED_TO.
func (r *Relay) write(name string, want *fileState) (err error) {
	tmp, err := os.CreateTemp(r.Target, ownTmpPrefix()+"*")
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
	dst := filepath.Join(r.Target, name)
	err = os.Rename(tmp.Name(), dst)
	if errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.ENOTEMPTY) {
		// A directory holds the name, which a rename cannot replace.
		// RemoveAll never follows a symbolic link.
		if err = os.RemoveAll(dst); err == nil {
			err = os.Rename(tmp.Name(), dst)
		}
	}
	if err != nil {
		return fmt.Errorf("renaming copy of %q: %w", name, err)
	}
	r.logf("updated %q", name)
	return nil
}
