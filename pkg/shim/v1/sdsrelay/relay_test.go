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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const secret = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"

// newRelay returns a relay between two new directories, and a buffer that
// collects its log.
func newRelay(t *testing.T) (*Relay, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	r := &Relay{
		Source:         filepath.Join(dir, "source"),
		Target:         filepath.Join(dir, "target"),
		settleAttempts: 3,
		settleDelay:    time.Millisecond,
		// Every file is past its quiet time, and every temporary file left
		// in the target is stale.
		now: func() time.Time { return time.Now().Add(time.Hour) },
	}
	for _, d := range []string{r.Source, r.Target} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	r.Logf = func(format string, args ...any) { fmt.Fprintf(&logs, format+"\n", args...) }
	return r, &logs
}

func writeFile(t *testing.T, path, data string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), perm); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

// replaceFile writes path the way Diego writes the SDS files.
func replaceFile(t *testing.T, path, data string) {
	t.Helper()
	writeFile(t, path+".tmp", data, 0o644)
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func owner(t *testing.T, path string) (uint32, uint32, os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid, info.Mode().Perm()
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to set file owners")
	}
}

// watch returns the inotify events raised in dir until stop is called.
func watch(t *testing.T, dir string) func() []string {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_ALL_EVENTS); err != nil {
		t.Fatal(err)
	}
	return func() []string {
		defer unix.Close(fd)
		var out []string
		buf := make([]byte, 64<<10)
		n, err := unix.Read(fd, buf)
		if err != nil && err != unix.EAGAIN {
			t.Fatal(err)
		}
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			name := strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:off+unix.SizeofInotifyEvent+int(ev.Len)]), "\x00")
			out = append(out, fmt.Sprintf("%s %s", eventName(ev.Mask), name))
			off += unix.SizeofInotifyEvent + int(ev.Len)
		}
		return out
	}
}

func eventName(mask uint32) string {
	var parts []string
	for _, e := range []struct {
		bit  uint32
		name string
	}{
		{unix.IN_CREATE, "CREATE"},
		{unix.IN_MODIFY, "MODIFY"},
		{unix.IN_ATTRIB, "ATTRIB"},
		{unix.IN_CLOSE_WRITE, "CLOSE_WRITE"},
		{unix.IN_MOVED_FROM, "MOVED_FROM"},
		{unix.IN_MOVED_TO, "MOVED_TO"},
		{unix.IN_DELETE, "DELETE"},
	} {
		if mask&e.bit != 0 {
			parts = append(parts, e.name)
		}
	}
	return strings.Join(parts, "|")
}

// finalEvents returns the events that name one of the given files, leaving
// out the relay's temporary files and plain reads.
func finalEvents(events []string, files ...string) []string {
	var out []string
	for _, e := range events {
		mask, name, _ := strings.Cut(e, " ")
		if mask == "" {
			continue
		}
		for _, f := range files {
			if name == f {
				out = append(out, e)
			}
		}
	}
	return out
}

func TestSyncCopiesNewFiles(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	writeFile(t, filepath.Join(r.Source, "sds-id-cert-and-key.yaml"), secret, 0o600)

	if err := r.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "admin: {}\n" {
		t.Errorf("envoy.yaml = %q", got)
	}
	if got := readFile(t, filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); got != secret {
		t.Errorf("sds-id-cert-and-key.yaml has the wrong content")
	}
	if _, _, perm := owner(t, filepath.Join(r.Target, "envoy.yaml")); perm != 0o644 {
		t.Errorf("envoy.yaml mode = %o, want 644", perm)
	}
	if _, _, perm := owner(t, filepath.Join(r.Target, "sds-id-cert-and-key.yaml")); perm != 0o600 {
		t.Errorf("sds-id-cert-and-key.yaml mode = %o, want 600", perm)
	}
}

func TestSyncDetectsChanges(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		change func()
		want   string
		perm   os.FileMode
	}{
		{"replaced by rename", func() { replaceFile(t, path, "serial: 2\n") }, "serial: 2\n", 0o644},
		{"rewritten in place", func() { writeFile(t, path, "serial: 3\n", 0o644) }, "serial: 3\n", 0o644},
		// The same size and the same mtime: only the content differs.
		{"same size and mtime", func() {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, "serial: 4\n", 0o644)
			if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}, "serial: 4\n", 0o644},
		{"mode only", func() {
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		}, "serial: 4\n", 0o640},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			if err := r.Sync(); err != nil {
				t.Fatalf("Sync: %v", err)
			}
			target := filepath.Join(r.Target, "sds-id-cert-and-key.yaml")
			if got := readFile(t, target); got != tc.want {
				t.Errorf("copy = %q, want %q", got, tc.want)
			}
			if _, _, perm := owner(t, target); perm != tc.perm {
				t.Errorf("copy mode = %o, want %o", perm, tc.perm)
			}
		})
	}
}

// TestSyncRenamesIntoPlace checks that each copy lands with a rename, which is
// the only event Envoy's watch reacts to, and that no temporary file is left.
func TestSyncRenamesIntoPlace(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, "serial: 1\n", 0o644)

	events := watch(t, r.Target)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	replaceFile(t, path, "serial: 2\n")
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}

	got := events()
	want := []string{"MOVED_TO sds-id-cert-and-key.yaml", "MOVED_TO sds-id-cert-and-key.yaml"}
	if final := finalEvents(got, "sds-id-cert-and-key.yaml"); fmt.Sprint(final) != fmt.Sprint(want) {
		t.Errorf("events on the copy = %v, want %v (all events: %v)", final, want, got)
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[sds-id-cert-and-key.yaml]" {
		t.Errorf("target holds %v", n)
	}
}

func TestSyncLeavesCurrentCopies(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(r.Target, "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	events := watch(t, r.Target)
	for i := 0; i < 3; i++ {
		if err := r.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range events() {
		if !strings.HasPrefix(e, " ") {
			t.Errorf("unexpected event %q", e)
		}
	}
	after, err := os.Stat(filepath.Join(r.Target, "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Errorf("an unchanged copy was rewritten")
	}
}

func TestSyncMirrorsOwner(t *testing.T) {
	requireRoot(t)
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "sds-c2c-cert-and-key.yaml")
	writeFile(t, path, secret, 0o600)
	if err := os.Chown(path, 2000, 3000); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(r.Target, "sds-c2c-cert-and-key.yaml")
	if uid, gid, perm := owner(t, target); uid != 2000 || gid != 3000 || perm != 0o600 {
		t.Errorf("copy is %d:%d %o, want 2000:3000 600", uid, gid, perm)
	}

	// A change of owner alone is mirrored too.
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if uid, gid, _ := owner(t, target); uid != 0 || gid != 0 {
		t.Errorf("copy is owned by %d:%d, want 0:0", uid, gid)
	}

	// So is a change of the user or the group alone.
	for _, o := range [][2]int{{2000, 0}, {0, 3000}} {
		if err := os.Chown(path, o[0], o[1]); err != nil {
			t.Fatal(err)
		}
		if err := r.Sync(); err != nil {
			t.Fatal(err)
		}
		if uid, gid, _ := owner(t, target); int(uid) != o[0] || int(gid) != o[1] {
			t.Errorf("copy is owned by %d:%d, want %d:%d", uid, gid, o[0], o[1])
		}
	}
}

func TestSyncMirrorsDirectoryMode(t *testing.T) {
	r, _ := newRelay(t)
	if err := os.Chmod(r.Source, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.Target, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, _, perm := owner(t, r.Target); perm != 0o750 {
		t.Errorf("target mode = %o, want 750", perm)
	}

	// The relay keeps write access to the target.
	if err := os.Chmod(r.Source, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, _, perm := owner(t, r.Target); perm != 0o755 {
		t.Errorf("target mode = %o, want 755", perm)
	}
}

// TestSyncKeepsTargetWithoutSource covers a missing bind mount and a source
// directory that disappears: Envoy keeps the copies it has.
func TestSyncKeepsTargetWithoutSource(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(r.Source); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Sync without a source = %v, want ErrNotExist", err)
	}
	if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "admin: {}\n" {
		t.Errorf("copy = %q after the source vanished", got)
	}

	// A source that is not a directory is refused the same way.
	writeFile(t, r.Source, "", 0o644)
	if err := r.Sync(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("Sync with a file as source = %v", err)
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[envoy.yaml]" {
		t.Errorf("target holds %v", n)
	}
}

func TestSyncFailsWithoutTarget(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	if err := os.Remove(r.Target); err != nil {
		t.Fatal(err)
	}
	err := r.Sync()
	if err == nil || !strings.Contains(err.Error(), "listing target directory") || !strings.Contains(err.Error(), "reading target directory") {
		t.Errorf("Sync without a target = %v", err)
	}
}

func TestSyncRemovesVanishedFiles(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	writeFile(t, filepath.Join(r.Source, "sds-c2c-cert-and-key.yaml"), secret, 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(r.Source, "sds-c2c-cert-and-key.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[envoy.yaml]" {
		t.Errorf("target holds %v, want [envoy.yaml]", n)
	}
}

func TestSyncCleansUpTemporaryFiles(t *testing.T) {
	r, _ := newRelay(t)
	// A relay that died while it wrote a copy leaves its temporary file.
	writeFile(t, filepath.Join(r.Target, tmpPrefix+"123-456"), "partial", 0o600)
	writeFile(t, filepath.Join(r.Target, ownTmpPrefix()+"789"), "partial", 0o600)
	// Source files with the reserved prefix are never copied.
	writeFile(t, filepath.Join(r.Source, tmpPrefix+"456"), "x", 0o644)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[envoy.yaml]" {
		t.Errorf("target holds %v, want [envoy.yaml]", n)
	}
}

// TestSyncLeavesOtherRelaysTemporaryFiles runs two relays at once, as the
// poller and a gated sync do, and checks that neither removes a temporary
// file the other is still writing.
func TestSyncLeavesOtherRelaysTemporaryFiles(t *testing.T) {
	r, _ := newRelay(t)
	now := time.Now()
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	// One second later, envoy.yaml is quiet, and a temporary file written now
	// is not yet stale.
	r.now = func() time.Time { return now.Add(time.Second) }

	other := filepath.Join(r.Target, tmpPrefix+"1-123")
	stale := filepath.Join(r.Target, tmpPrefix+"2-123")
	mine := filepath.Join(r.Target, ownTmpPrefix()+"123")
	for _, p := range []string{other, stale, mine} {
		writeFile(t, p, "partial", 0o600)
	}
	if err := os.Chtimes(other, now, now); err != nil {
		t.Fatal(err)
	}
	// stale is exactly staleTemp old.
	staleTime := now.Add(time.Second - staleTemp)
	if err := os.Chtimes(stale, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if n, want := names(t, r.Target), []string{filepath.Base(other), "envoy.yaml"}; fmt.Sprint(n) != fmt.Sprint(want) {
		t.Errorf("target holds %v, want %v", n, want)
	}
	if staleTemp != time.Minute {
		t.Errorf("staleTemp = %v, want 1m", staleTemp)
	}
}

// TestSyncSkipsDiegoTemporaryFiles covers Diego's NAME.tmp, which it writes
// before it renames it over NAME.
func TestSyncSkipsDiegoTemporaryFiles(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "sds-id-cert-and-key.yaml"), "serial: 1\n", 0o644)
	writeFile(t, filepath.Join(r.Source, "sds-id-cert-and-key.yaml.tmp"), "seri", 0o644)
	writeFile(t, filepath.Join(r.Source, ".hidden"), "x", 0o644)
	// A copy of such a file, left by an older relay, is removed.
	writeFile(t, filepath.Join(r.Target, "envoy.yaml.tmp"), "x", 0o644)
	events := watch(t, r.Target)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[sds-id-cert-and-key.yaml]" {
		t.Errorf("target holds %v, want [sds-id-cert-and-key.yaml]", n)
	}
	got := events()
	if final := finalEvents(got, "sds-id-cert-and-key.yaml.tmp", ".hidden"); len(final) != 0 {
		t.Errorf("events on skipped files: %v", final)
	}
}

func TestSkipped(t *testing.T) {
	for name, want := range map[string]bool{
		"envoy.yaml":                   false,
		"sds-id-cert-and-key.yaml":     false,
		"sds-id-cert-and-key.yaml.tmp": true,
		".sds-relay-1-2":               true,
		".x":                           true,
		"tmp":                          false,
		"x.tmpl":                       false,
	} {
		if got := skipped(name); got != want {
			t.Errorf("skipped(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestSyncKeepsCopyOfTruncatedFile covers Diego's in-place write of
// envoy.yaml, which truncates the file before it writes it.
func TestSyncKeepsCopyOfTruncatedFile(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "admin: {}\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "", 0o644)
	if err := r.Sync(); !errors.Is(err, errPending) || !strings.Contains(err.Error(), "envoy.yaml") {
		t.Errorf("Sync of an empty file = %v, want errPending", err)
	}
	if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "admin: {}\n" {
		t.Errorf("copy = %q, want the previous copy", got)
	}
	writeFile(t, path, "admin: []\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "admin: []\n" {
		t.Errorf("copy = %q", got)
	}

	// An empty file with no copy, or with an empty copy, is copied. The
	// second sync compares the files in full.
	writeFile(t, filepath.Join(r.Source, "empty"), "", 0o644)
	for i := 0; i < 2; i++ {
		r.copied = nil
		if err := r.Sync(); err != nil {
			t.Fatalf("Sync %d: %v", i, err)
		}
	}
	if got := readFile(t, filepath.Join(r.Target, "empty")); got != "" {
		t.Errorf("copy of the empty file = %q", got)
	}
}

// TestSyncWaitsForQuietFiles checks that a file changed less than quietTime
// ago is not copied, so that a write in progress is never copied.
func TestSyncWaitsForQuietFiles(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "admin: {}\n", 0o644)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := time.Unix(0, keyOf(info).ctime)
	for _, tc := range []struct {
		age     time.Duration
		pending bool
	}{
		{0, true},
		{quietTime - time.Nanosecond, true},
		{-time.Second, false}, // A clock behind the file's time does not hold it.
		{quietTime, false},
	} {
		r.copied = nil
		os.Remove(filepath.Join(r.Target, "envoy.yaml"))
		r.now = func() time.Time { return changed.Add(tc.age) }
		err := r.Sync()
		if got := errors.Is(err, errPending); got != tc.pending {
			t.Errorf("age %v: Sync = %v, want pending %v", tc.age, err, tc.pending)
		}
		if _, err := os.Stat(filepath.Join(r.Target, "envoy.yaml")); os.IsNotExist(err) != tc.pending {
			t.Errorf("age %v: copied = %v, want %v", tc.age, err == nil, !tc.pending)
		}
	}
	if quietTime != 100*time.Millisecond {
		t.Errorf("quietTime = %v, want 100ms", quietTime)
	}
}

// TestSyncReadsOnlyChangedFiles checks that a file whose source and copy keep
// their attributes is not read again, except in a full check.
func TestSyncReadsOnlyChangedFiles(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	target := filepath.Join(r.Target, "envoy.yaml")
	writeFile(t, path, "admin: {}\n", 0o644)
	reads := 0
	afterRead = func(string) { reads++ }
	defer func() { afterRead = nil }()
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Errorf("read %d times, want 1", reads)
	}

	// A copy changed in the target is read and replaced at once.
	writeFile(t, target, "admin: [] \n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "admin: {}\n" {
		t.Errorf("copy = %q after it was changed", got)
	}
	if reads != 2 {
		t.Errorf("read %d times, want 2", reads)
	}

	// A change that keeps every attribute the relay compares, made here by
	// recording the changed copy as current, is caught by the next full check.
	writeFile(t, target, "admin: [] \n", 0o644)
	tinfo, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	c := r.copied["envoy.yaml"]
	c.target = keyOf(tinfo)
	r.copied["envoy.yaml"] = c
	for r.syncs%fullCheckEvery != 0 {
		if err := r.Sync(); err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, target); got != "admin: [] \n" {
			t.Fatalf("copy was replaced %d syncs before the full check", fullCheckEvery-r.syncs%fullCheckEvery)
		}
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "admin: {}\n" {
		t.Errorf("copy = %q after the full check", got)
	}
	if fullCheckEvery != 60 {
		t.Errorf("fullCheckEvery = %d, want 60", fullCheckEvery)
	}

	// A file that leaves the source is forgotten.
	os.Remove(path)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if len(r.copied) != 0 {
		t.Errorf("relay still tracks %v", r.copied)
	}
}

func TestSyncSkipsOtherFileTypes(t *testing.T) {
	r, _ := newRelay(t)
	if err := os.Mkdir(filepath.Join(r.Source, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	writeFile(t, outside, secret, 0o600)
	if err := os.Symlink(outside, filepath.Join(r.Source, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(r.Source, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Entries in the target that are not regular files are not the relay's.
	if err := os.Mkdir(filepath.Join(r.Target, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[envoy.yaml keep]" {
		t.Errorf("target holds %v, want [envoy.yaml keep]", n)
	}
}

// TestSyncReplacesNonRegularTarget puts what root in the container could put
// at a copy's name, and checks that the relay replaces it without following a
// link, blocking on a FIFO, or failing.
func TestSyncReplacesNonRegularTarget(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	for _, tc := range []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{"dangling symlink", func(t *testing.T, path string) {
			if err := os.Symlink("/nonexistent", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink to a file", func(t *testing.T, path string) {
			writeFile(t, outside, "outside\n", 0o644)
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink to a directory", func(t *testing.T, path string) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "keep"), "keep\n", 0o644)
			if err := os.Symlink(dir, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, path string) {
			if err := unix.Mkfifo(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, path string) {
			if err := os.MkdirAll(filepath.Join(path, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(path, "sub", "x"), "x", 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newRelay(t)
			writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
			tc.make(t, filepath.Join(r.Target, "envoy.yaml"))
			done := make(chan error, 1)
			go func() { done <- r.Sync() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Sync blocked")
			}
			info, err := os.Lstat(filepath.Join(r.Target, "envoy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() {
				t.Errorf("copy is %v, want a regular file", info.Mode())
			}
			if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "admin: {}\n" {
				t.Errorf("copy = %q", got)
			}
			if data, err := os.ReadFile(outside); err == nil && string(data) != "outside\n" {
				t.Errorf("the link's target was changed to %q", data)
			}
		})
	}
}

func TestSyncRefusesLargeFiles(t *testing.T) {
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "big"), strings.Repeat("x", maxFileSize+1), 0o644)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o644)
	err := r.Sync()
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("Sync = %v, want a size error", err)
	}
	if errors.Is(err, errPending) {
		t.Errorf("a size error is not pending")
	}
	if n := names(t, r.Target); fmt.Sprint(n) != "[envoy.yaml]" {
		t.Errorf("target holds %v, want [envoy.yaml]", n)
	}

	// A file of exactly the limit is copied.
	writeFile(t, filepath.Join(r.Source, "big"), strings.Repeat("x", maxFileSize), 0o644)
	if err := r.Sync(); err != nil {
		t.Errorf("Sync at the limit: %v", err)
	}
	before, err := os.Stat(filepath.Join(r.Target, "big"))
	if err != nil {
		t.Fatal(err)
	}
	// This sync compares the files in full.
	r.copied = nil
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(r.Target, "big"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Errorf("an unchanged copy at the limit was rewritten")
	}
}

func TestSyncReportsUnreadableFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	r, _ := newRelay(t)
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "admin: {}\n", 0o000)
	if err := r.Sync(); err == nil || errors.Is(err, errPending) {
		t.Errorf("Sync = %v, want a permission error", err)
	}
}

// TestSyncWaitsForPartialWrites changes a file while the relay reads it, as an
// in-place write does, and checks that the half-read file is never copied.
func TestSyncWaitsForPartialWrites(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "admin: {}\n", 0o644)
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		write func(path string)
	}{
		{"appended", func(path string) {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("more: {}\n")
			f.Close()
		}},
		{"rewritten with the same size", func(path string) {
			// Same size, so only the mtime shows the change.
			time.Sleep(10 * time.Millisecond)
			writeFile(t, path, "half: []\n", 0o644)
		}},
		{"replaced", func(path string) { replaceFile(t, path, "other: {}\n") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, path, "half: {}\n", 0o644)
			calls := 0
			afterRead = func(p string) {
				calls++
				if p == path {
					tc.write(p)
				}
			}
			defer func() { afterRead = nil }()

			err := r.Sync()
			if !errors.Is(err, errPending) || !strings.Contains(err.Error(), "envoy.yaml") {
				t.Fatalf("Sync = %v, want errPending naming envoy.yaml", err)
			}
			if calls != 1 {
				t.Errorf("read %d times, want 1", calls)
			}
			if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "admin: {}\n" {
				t.Errorf("copy = %q, want the previous copy", got)
			}
		})
	}
}

func TestSyncSettledRetriesPendingFiles(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "v1\n", 0o644)
	writes := 0
	afterRead = func(p string) {
		if writes < 2 {
			writes++
			writeFile(t, p, fmt.Sprintf("v%d-long\n", writes+1), 0o644)
		}
	}
	defer func() { afterRead = nil }()

	if err := r.syncSettled(); err != nil {
		t.Fatalf("syncSettled: %v", err)
	}
	if got := readFile(t, filepath.Join(r.Target, "envoy.yaml")); got != "v3-long\n" {
		t.Errorf("copy = %q, want v3-long", got)
	}
}

func TestSyncSettledGivesUp(t *testing.T) {
	r, _ := newRelay(t)
	path := filepath.Join(r.Source, "envoy.yaml")
	writeFile(t, path, "v\n", 0o644)
	reads := 0
	afterRead = func(p string) {
		reads++
		writeFile(t, p, strings.Repeat("v", reads+1)+"\n", 0o644)
	}
	defer func() { afterRead = nil }()

	if err := r.syncSettled(); !errors.Is(err, errPending) {
		t.Errorf("syncSettled = %v, want errPending", err)
	}
	if reads != r.settleAttempts {
		t.Errorf("read %d times, want %d", reads, r.settleAttempts)
	}
	if _, err := os.Stat(filepath.Join(r.Target, "envoy.yaml")); !os.IsNotExist(err) {
		t.Errorf("a file that never settled was copied")
	}
}

func TestSyncSettledDefaults(t *testing.T) {
	r, _ := newRelay(t)
	r.settleAttempts, r.settleDelay = 0, 0
	reads := 0
	writeFile(t, filepath.Join(r.Source, "envoy.yaml"), "v\n", 0o644)
	afterRead = func(p string) {
		reads++
		writeFile(t, p, strings.Repeat("v", reads+1)+"\n", 0o644)
	}
	defer func() { afterRead = nil }()

	start := time.Now()
	if err := r.syncSettled(); !errors.Is(err, errPending) {
		t.Errorf("syncSettled = %v, want errPending", err)
	}
	if reads != settleAttempts {
		t.Errorf("read %d times, want %d", reads, settleAttempts)
	}
	// A file being written gets about a second to settle.
	if settleAttempts*settleDelay != time.Second {
		t.Errorf("settle window = %v, want 1s", settleAttempts*settleDelay)
	}
	if d := time.Since(start); d < settleAttempts*settleDelay {
		t.Errorf("gave up after %v, want at least %v", d, settleAttempts*settleDelay)
	}
}

func TestSyncSettledReturnsOtherErrors(t *testing.T) {
	r, _ := newRelay(t)
	os.RemoveAll(r.Source)
	if err := r.syncSettled(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("syncSettled = %v, want ErrNotExist", err)
	}
}

func TestReportLogsChangesOnce(t *testing.T) {
	r, logs := newRelay(t)
	r.report(nil)
	r.report(errors.New("boom"))
	r.report(errors.New("boom"))
	r.report(nil)
	r.report(nil)
	if got, want := logs.String(), "sync failed: boom\nsync recovered\n"; got != want {
		t.Errorf("log = %q, want %q", got, want)
	}
	(&Relay{}).report(errors.New("no logger"))
}

// TestNoKeyMaterialInLogs runs every path that logs and checks that no file
// content reaches the log or an error.
func TestNoKeyMaterialInLogs(t *testing.T) {
	r, logs := newRelay(t)
	path := filepath.Join(r.Source, "sds-id-cert-and-key.yaml")
	writeFile(t, path, secret, 0o600)
	r.report(r.Sync())
	replaceFile(t, path, secret+secret)
	r.report(r.Sync())
	afterRead = func(p string) { writeFile(t, p, secret+"x", 0o600) }
	err := r.Sync()
	afterRead = nil
	r.report(err)
	os.RemoveAll(r.Source)
	r.report(r.Sync())

	if !strings.Contains(logs.String(), `updated "sds-id-cert-and-key.yaml"`) {
		t.Errorf("log = %q, want the update", logs.String())
	}
	for _, s := range []string{logs.String(), fmt.Sprint(err)} {
		if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "c2VjcmV0") {
			t.Errorf("key material in %q", s)
		}
	}
}

func TestWriteFailsWithoutTarget(t *testing.T) {
	r, _ := newRelay(t)
	os.Remove(r.Target)
	if err := r.write("envoy.yaml", &fileState{data: []byte("x"), perm: 0o644}); err == nil || !strings.Contains(err.Error(), `creating copy of "envoy.yaml"`) {
		t.Errorf("write = %v", err)
	}
}

func TestWriteFailsWhenRenameFails(t *testing.T) {
	r, _ := newRelay(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	// The rename fails because the directory that would hold the copy is
	// missing, which removing the name cannot fix.
	err := r.write("missing/envoy.yaml", &fileState{data: []byte("x"), perm: 0o644, uid: uid, gid: gid})
	if err == nil || !strings.Contains(err.Error(), `renaming copy of "missing/envoy.yaml"`) {
		t.Errorf("write = %v", err)
	}
	if n := names(t, r.Target); len(n) != 0 {
		t.Errorf("target holds %v after a failed write", n)
	}
}

func TestFileStateEqual(t *testing.T) {
	base := fileState{data: []byte("a"), perm: 0o644, uid: 1, gid: 2}
	for _, tc := range []struct {
		name  string
		other fileState
		want  bool
	}{
		{"same", base, true},
		{"data", fileState{data: []byte("b"), perm: 0o644, uid: 1, gid: 2}, false},
		{"perm", fileState{data: []byte("a"), perm: 0o600, uid: 1, gid: 2}, false},
		{"uid", fileState{data: []byte("a"), perm: 0o644, uid: 3, gid: 2}, false},
		{"gid", fileState{data: []byte("a"), perm: 0o644, uid: 1, gid: 3}, false},
	} {
		if got := base.equal(&tc.other); got != tc.want {
			t.Errorf("%s: equal = %v, want %v", tc.name, got, tc.want)
		}
	}
}
