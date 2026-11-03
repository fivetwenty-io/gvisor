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

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"gvisor.dev/gvisor/runsc/boot"
)

func testEventOut() *boot.EventOut {
	ev := &boot.EventOut{ContainerUsage: map[string]uint64{"app": 1500000, "sidecar": 250000}}
	ev.Event.Type = "stats"
	ev.Event.ID = "app"
	ev.Event.Data.CPU.Usage.Total = 9000000
	return ev
}

// TestEncodeEventDefault checks that without the flag the output is the bare
// event, so existing readers of the command are unaffected.
func TestEncodeEventDefault(t *testing.T) {
	ev := testEventOut()
	var got, want bytes.Buffer
	if err := encodeEvent(&got, ev, false); err != nil {
		t.Fatalf("encodeEvent: %v", err)
	}
	if err := json.NewEncoder(&want).Encode(ev.Event); err != nil {
		t.Fatalf("encode want: %v", err)
	}
	if got.String() != want.String() {
		t.Errorf("default output = %q, want %q", got.String(), want.String())
	}
	var m map[string]any
	if err := json.Unmarshal(got.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["containerUsage"]; ok {
		t.Errorf("default output carries containerUsage: %q", got.String())
	}
}

// TestEncodeEventSentryUsage checks that the flag adds the unscaled
// per-container usage next to the event.
func TestEncodeEventSentryUsage(t *testing.T) {
	var buf bytes.Buffer
	if err := encodeEvent(&buf, testEventOut(), true); err != nil {
		t.Fatalf("encodeEvent: %v", err)
	}
	var out struct {
		Event          boot.Event        `json:"event"`
		ContainerUsage map[string]uint64 `json:"containerUsage"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ContainerUsage["app"] != 1500000 || out.ContainerUsage["sidecar"] != 250000 {
		t.Errorf("containerUsage = %v", out.ContainerUsage)
	}
	if out.Event.ID != "app" || out.Event.Data.CPU.Usage.Total != 9000000 {
		t.Errorf("event = %+v", out.Event)
	}
}
