// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsccmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestReadTempFileRewinds(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString("hello"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	got, err := readTempFile(f)
	if err != nil {
		t.Fatalf("readTempFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("readTempFile = %q, want %q", got, "hello")
	}
}

func TestReadTempFileClosedReturnsError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Close()
	if _, err := readTempFile(f); err == nil {
		t.Error("readTempFile on a closed file returned nil error")
	}
}

func TestCmdOutputCapturesBothStreams(t *testing.T) {
	cmd := exec.Command("sh", "-c", "echo out; echo err >&2")
	stdout, stderr, err := cmdOutput(cmd, false)
	if err != nil {
		t.Fatalf("cmdOutput: %v", err)
	}
	if strings.TrimSpace(string(stdout)) != "out" || strings.TrimSpace(string(stderr)) != "err" {
		t.Errorf("cmdOutput = %q, %q; want out, err", stdout, stderr)
	}
	cmd = exec.Command("sh", "-c", "echo out; echo err >&2; exit 3")
	stdout, stderr, err = cmdOutput(cmd, true)
	if err == nil {
		t.Error("cmdOutput of a failing command returned nil error")
	}
	if stderr != nil || !strings.Contains(string(stdout), "out") || !strings.Contains(string(stdout), "err") {
		t.Errorf("combined cmdOutput = %q, %q", stdout, stderr)
	}
}
