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

package runsc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/sdsrelay"
)

// calls records the order of calls across fakes.
type calls []string

func (c *calls) add(s string) { *c = append(*c, s) }

type fakeGate struct {
	calls    *calls
	startErr error
	syncErr  error
}

func (g *fakeGate) Start(context.Context) error { g.calls.add("relay start"); return g.startErr }
func (g *fakeGate) Sync(context.Context) error  { g.calls.add("relay sync"); return g.syncErr }
func (g *fakeGate) Stop()                       { g.calls.add("relay stop") }

type fakeProcess struct {
	extension.Process
	id       string
	calls    *calls
	startErr error
}

func (p *fakeProcess) ID() string { return p.id }

func (p *fakeProcess) Start(context.Context) error {
	p.calls.add(p.id + " start")
	return p.startErr
}

func (p *fakeProcess) Delete(context.Context) error {
	p.calls.add(p.id + " delete")
	return nil
}

func (p *fakeProcess) Kill(_ context.Context, sig uint32, all bool) error {
	p.calls.add(fmt.Sprintf("%s kill %d %v", p.id, sig, all))
	return nil
}

func TestStartProcessOrder(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name     string
		init     bool
		gate     *fakeGate
		startErr error
		want     string
		wantErr  bool
	}{
		{name: "exec syncs first", gate: &fakeGate{}, want: "[relay sync p start]"},
		{name: "exec without relay", want: "[p start]"},
		{name: "exec held back on sync failure", gate: &fakeGate{syncErr: boom}, want: "[relay sync]", wantErr: true},
		{name: "exec start failure", gate: &fakeGate{}, startErr: boom, want: "[relay sync p start]", wantErr: true},
		{name: "init starts relay after itself", init: true, gate: &fakeGate{}, want: "[p start relay start]"},
		{name: "init without relay", init: true, want: "[p start]"},
		{name: "init start failure", init: true, gate: &fakeGate{}, startErr: boom, want: "[p start]", wantErr: true},
		{name: "relay start failure", init: true, gate: &fakeGate{startErr: boom}, want: "[p start relay start]", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c calls
			p := &fakeProcess{id: "p", calls: &c, startErr: tc.startErr}
			var gate relayGate
			if tc.gate != nil {
				tc.gate.calls = &c
				gate = tc.gate
			}
			err := startProcess(context.Background(), p, tc.init, gate)
			if (err != nil) != tc.wantErr {
				t.Errorf("startProcess = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, boom) {
				t.Errorf("startProcess = %v, want it to wrap the cause", err)
			}
			if got := fmt.Sprint(c); got != tc.want {
				t.Errorf("calls = %s, want %s", got, tc.want)
			}
		})
	}
}

func newTestContainer(c *calls, gate relayGate) *Container {
	return &Container{
		ID:        "app",
		processes: map[string]extension.Process{"envoy": &fakeProcess{id: "envoy", calls: c}},
		relay:     gate,
	}
}

func TestContainerGatesExecs(t *testing.T) {
	var c calls
	ct := newTestContainer(&c, &fakeGate{calls: &c})
	if _, err := ct.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy"}); err != nil {
		t.Fatal(err)
	}
	if err := ct.Kill(context.Background(), &task.KillRequest{ID: "app", ExecID: "envoy", Signal: uint32(unix.SIGTERM), All: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ct.Delete(context.Background(), &task.DeleteRequest{ID: "app", ExecID: "envoy"}); err != nil {
		t.Fatal(err)
	}
	// Signalling or deleting an exec leaves the relay running.
	if got, want := fmt.Sprint(c), "[relay sync envoy start envoy kill 15 true envoy delete]"; got != want {
		t.Errorf("calls = %s, want %s", got, want)
	}
	if _, ok := ct.processes["envoy"]; ok {
		t.Error("deleted exec is still listed")
	}
}

func TestContainerWithoutRelay(t *testing.T) {
	var c calls
	ct := newTestContainer(&c, nil)
	if _, err := ct.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy"}); err != nil {
		t.Fatal(err)
	}
	ct.StopRelay()
	if got, want := fmt.Sprint(c), "[envoy start]"; got != want {
		t.Errorf("calls = %s, want %s", got, want)
	}
}

func TestContainerStartFailsWithoutSync(t *testing.T) {
	var c calls
	ct := newTestContainer(&c, &fakeGate{calls: &c, syncErr: errors.New("relay gone")})
	if _, err := ct.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy"}); err == nil || !strings.Contains(err.Error(), "sync Envoy configuration") {
		t.Errorf("Start = %v", err)
	}
	if got, want := fmt.Sprint(c), "[relay sync]"; got != want {
		t.Errorf("calls = %s, want %s", got, want)
	}
}

func TestStopsContainer(t *testing.T) {
	for _, tc := range []struct {
		r    *task.KillRequest
		want bool
	}{
		{&task.KillRequest{Signal: uint32(unix.SIGTERM), All: true}, true},
		{&task.KillRequest{Signal: uint32(unix.SIGKILL), All: true}, true},
		{&task.KillRequest{Signal: uint32(unix.SIGTERM)}, false},
		{&task.KillRequest{Signal: uint32(unix.SIGKILL)}, false},
		{&task.KillRequest{Signal: uint32(unix.SIGHUP), All: true}, false},
		{&task.KillRequest{Signal: uint32(unix.SIGUSR1), All: true}, false},
		{&task.KillRequest{ExecID: "envoy", Signal: uint32(unix.SIGTERM), All: true}, false},
		{&task.KillRequest{ExecID: "envoy", Signal: uint32(unix.SIGKILL), All: true}, false},
	} {
		if got := stopsContainer(tc.r); got != tc.want {
			t.Errorf("stopsContainer(%v) = %v, want %v", tc.r, got, tc.want)
		}
	}
}

func TestSetSDSRelay(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	envoy := func(containerType string) *specs.Spec {
		s := &specs.Spec{
			Annotations: map[string]string{},
			Mounts: []specs.Mount{{
				Destination: sdsrelay.EnvoyConfigPath,
				Type:        "bind",
				Source:      "/var/vcap/data/rep/shared/garden/proxy_config/guid",
				Options:     []string{"bind", "rw"},
			}},
		}
		if containerType != "" {
			s.Annotations["io.kubernetes.cri.container-type"] = containerType
		}
		return s
	}

	spec := envoy("sandbox")
	relay, err := setSDSRelay(spec)
	if err != nil || !relay {
		t.Fatalf("setSDSRelay = %v, %v", relay, err)
	}
	var binary string
	for _, m := range spec.Mounts {
		if m.Destination == sdsrelay.BinaryPath {
			binary = m.Source
		}
	}
	if binary != exe {
		t.Errorf("relay binary = %q, want %q", binary, exe)
	}

	for name, spec := range map[string]*specs.Spec{
		"subcontainer": envoy("container"),
		"no Envoy":     {Annotations: map[string]string{}},
	} {
		relay, err := setSDSRelay(spec)
		if err != nil || relay {
			t.Errorf("%s: setSDSRelay = %v, %v; want false, nil", name, relay, err)
		}
	}
}
