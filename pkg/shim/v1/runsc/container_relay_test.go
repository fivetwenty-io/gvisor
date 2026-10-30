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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/console"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/anypb"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/sdsrelay"
)

func init() {
	// Init processes started by these tests report their exit here once a
	// test ends, and nothing else reads it.
	go func() {
		for range proc.ExitCh {
		}
	}()
}

// calls records the order of calls across fakes.
type calls []string

func (c *calls) add(s string) { *c = append(*c, s) }

type fakeGate struct {
	calls   *calls
	syncErr error
}

func (g *fakeGate) Start()                     { g.calls.add("relay start") }
func (g *fakeGate) Sync(context.Context) error { g.calls.add("relay sync"); return g.syncErr }
func (g *fakeGate) Stop()                      { g.calls.add("relay stop") }

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
		envoy    bool
		gate     *fakeGate
		startErr error
		want     string
		wantErr  bool
	}{
		{name: "Envoy exec syncs first", envoy: true, gate: &fakeGate{}, want: "[relay sync p start]"},
		{name: "Envoy exec without relay", envoy: true, want: "[p start]"},
		{name: "Envoy exec held back on sync failure", envoy: true, gate: &fakeGate{syncErr: boom}, want: "[relay sync]", wantErr: true},
		{name: "Envoy exec start failure", envoy: true, gate: &fakeGate{}, startErr: boom, want: "[relay sync p start]", wantErr: true},
		{name: "other exec does not sync", gate: &fakeGate{}, want: "[p start]"},
		{name: "other exec starts while sync fails", gate: &fakeGate{syncErr: boom}, want: "[p start]"},
		{name: "init starts relay after itself", init: true, gate: &fakeGate{}, want: "[p start relay start]"},
		{name: "init does not wait for a failing relay", init: true, gate: &fakeGate{syncErr: boom}, want: "[p start relay start]"},
		{name: "init without relay", init: true, want: "[p start]"},
		{name: "init start failure", init: true, gate: &fakeGate{}, startErr: boom, want: "[p start]", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c calls
			p := &fakeProcess{id: "p", calls: &c, startErr: tc.startErr}
			var gate relayGate
			if tc.gate != nil {
				tc.gate.calls = &c
				gate = tc.gate
			}
			err := startProcess(context.Background(), p, tc.init, tc.envoy, gate)
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
		ID: "app",
		processes: map[string]extension.Process{
			"envoy":  &fakeProcess{id: "envoy", calls: c},
			"health": &fakeProcess{id: "health", calls: c},
		},
		envoyExecs: map[string]bool{"envoy": true},
		relay:      gate,
	}
}

func TestContainerGatesEnvoyExecs(t *testing.T) {
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
	if ct.readsEnvoyConfig("envoy") {
		t.Error("deleted exec is still gated")
	}
}

func TestContainerDoesNotGateOtherExecs(t *testing.T) {
	var c calls
	ct := newTestContainer(&c, &fakeGate{calls: &c, syncErr: errors.New("relay gone")})
	if _, err := ct.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "health"}); err != nil {
		t.Fatalf("Start = %v", err)
	}
	if got, want := fmt.Sprint(c), "[health start]"; got != want {
		t.Errorf("calls = %s, want %s", got, want)
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
	if _, err := ct.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy"}); err == nil || !strings.Contains(err.Error(), "sync Envoy configuration: relay gone") {
		t.Errorf("Start = %v", err)
	}
	if got, want := fmt.Sprint(c), "[relay sync]"; got != want {
		t.Errorf("calls = %s, want %s", got, want)
	}
}

func TestContainerRefusesRelayedRestore(t *testing.T) {
	var c calls
	ct := newTestContainer(&c, &fakeGate{calls: &c})
	_, err := ct.Restore(context.Background(), &extension.RestoreRequest{Start: &task.StartRequest{ID: "app", ExecID: "envoy"}})
	if !errors.Is(err, errdefs.ErrNotImplemented) {
		t.Errorf("Restore = %v, want ErrNotImplemented", err)
	}
	if len(c) != 0 {
		t.Errorf("calls = %s, want none", c)
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

func processSpec(t *testing.T, args ...string) *anypb.Any {
	t.Helper()
	data, err := json.Marshal(&specs.Process{Args: args, Cwd: "/"})
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: "types.containerd.io/opencontainers/runtime-spec/1/Process", Value: data}
}

const envoyConfig = sdsrelay.EnvoyConfigPath + "/envoy.yaml"

func TestExecReadsEnvoyConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *anypb.Any
		want bool
	}{
		{"Envoy", processSpec(t, "/etc/cf-assets/envoy/envoy", "-c", envoyConfig), true},
		{"health check", processSpec(t, "/tmp/lifecycle/healthcheck", "-port=8080"), false},
		{"sshd", processSpec(t, "/tmp/lifecycle/diego-sshd", "--address=0.0.0.0:2222"), false},
		{"no spec", nil, false},
		{"undecodable spec", &anypb.Any{Value: []byte("{")}, true},
	} {
		if got := execReadsEnvoyConfig(tc.spec); got != tc.want {
			t.Errorf("%s: execReadsEnvoyConfig = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSetSDSRelay(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec := envoySpec("sandbox")
	relay, err := setSDSRelay(spec)
	if err != nil || !relay {
		t.Fatalf("setSDSRelay = %v, %v", relay, err)
	}
	if binary := relayBinary(spec); binary != exe {
		t.Errorf("relay binary = %q, want %q", binary, exe)
	}

	for name, spec := range map[string]*specs.Spec{
		"subcontainer": envoySpec("container"),
		"no Envoy":     {Annotations: map[string]string{}},
	} {
		relay, err := setSDSRelay(spec)
		if err != nil || relay {
			t.Errorf("%s: setSDSRelay = %v, %v; want false, nil", name, relay, err)
		}
	}
}

// TestSetSDSRelayWithoutExecutable checks that setSDSRelay reports why it
// could not find the shim's binary.
func TestSetSDSRelayWithoutExecutable(t *testing.T) {
	old := executable
	t.Cleanup(func() { executable = old })
	executable = func() (string, error) { return "", errors.New("no executable") }
	spec := envoySpec("sandbox")
	if relay, err := setSDSRelay(spec); relay || err == nil || !strings.Contains(err.Error(), "no executable") {
		t.Errorf("setSDSRelay = %v, %v; want the executable's error", relay, err)
	}
	if !sdsrelay.HasEnvoyConfigMount(spec) {
		t.Errorf("a failed setSDSRelay rewrote the spec")
	}
}

// envoySpec returns a spec with Diego's Envoy configuration mount, as Garden
// writes it.
func envoySpec(containerType string) *specs.Spec {
	s := &specs.Spec{
		Version:     specs.Version,
		Annotations: map[string]string{},
		Process:     &specs.Process{Args: []string{"/tmp/lifecycle/launcher"}, Cwd: "/"},
		Root:        &specs.Root{Path: "rootfs"},
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

func relayBinary(spec *specs.Spec) string {
	for _, m := range spec.Mounts {
		if m.Destination == sdsrelay.BinaryPath {
			return m.Source
		}
	}
	return ""
}

// fakeRunscScript stands in for runsc. It logs the calls that matter in
// $FAKE_RUNSC_DIR/calls. The container runs until $FAKE_RUNSC_DIR/exit
// exists, a gated sync exits with the status in $FAKE_RUNSC_DIR/sync-exit,
// and the polling relay runs until the container stops.
const fakeRunscScript = `#!/bin/sh
d="$FAKE_RUNSC_DIR"
while [ $# -gt 0 ]; do
	case "$1" in --*) shift ;; *) break ;; esac
done
cmd=$1
shift
case "$cmd" in
create)
	while [ $# -gt 1 ]; do
		[ "$1" = --pid-file ] && printf 4242 > "$2"
		shift
	done
	echo create >> "$d/calls" ;;
start)
	echo start >> "$d/calls" ;;
state)
	status=running
	[ -e "$d/exit" ] && status=stopped
	printf '{"id":"%s","pid":4242,"status":"%s"}\n' "$1" "$status" ;;
kill)
	echo "kill $*" >> "$d/calls"
	if [ "$1" = --all ]; then touch "$d/exit"; fi ;;
delete)
	echo delete >> "$d/calls" ;;
wait)
	while [ ! -e "$d/exit" ]; do sleep 0.02; done
	echo '{"exit_status":0}' ;;
exec)
	detach= process= pidfile= ipidfile=
	while [ $# -gt 1 ]; do
		case "$1" in
		--process) process=$2; shift ;;
		--detach) detach=1 ;;
		--pid-file) pidfile=$2; shift ;;
		--internal-pid-file) ipidfile=$2; shift ;;
		esac
		shift
	done
	if [ -n "$detach" ]; then
		printf 4343 > "$pidfile"
		printf 7 > "$ipidfile"
		if grep -q envoy_config "$process"; then
			echo "exec envoy" >> "$d/calls"
		else
			echo "exec other" >> "$d/calls"
		fi
		exit 0
	fi
	if grep -q -- '"--once"' "$process"; then
		echo "exec sync" >> "$d/calls"
		echo "sync failed: a source file is still being written"
		exit "$(cat "$d/sync-exit" 2>/dev/null || echo 0)"
	fi
	echo "exec poller" >> "$d/calls"
	echo "poller says hello" >&2
	while [ ! -e "$d/exit" ]; do sleep 0.02; done ;;
*)
	echo "unexpected runsc $cmd" >> "$d/calls"
	exit 1 ;;
esac
`

type fakeRunsc struct {
	dir string
}

// newFakeRunsc puts a fake runsc first on PATH.
func newFakeRunsc(t *testing.T) *fakeRunsc {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runsc"), []byte(fakeRunscScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("FAKE_RUNSC_DIR", dir)
	f := &fakeRunsc{dir: dir}
	// Let every waiting fake exit.
	t.Cleanup(f.stop)
	return f
}

func (f *fakeRunsc) stop() {
	os.WriteFile(filepath.Join(f.dir, "exit"), nil, 0o644)
}

func (f *fakeRunsc) failSyncs() {
	os.WriteFile(filepath.Join(f.dir, "sync-exit"), []byte("1"), 0o644)
}

func (f *fakeRunsc) note(s string) {
	file, err := os.OpenFile(filepath.Join(f.dir, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fmt.Fprintln(file, s)
}

func (f *fakeRunsc) calls() []string {
	data, _ := os.ReadFile(filepath.Join(f.dir, "calls"))
	return strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(data)), " ", "_"))
}

func (f *fakeRunsc) waitFor(t *testing.T, call string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !slices.Contains(f.calls(), call) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in %q", call, f.calls())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// notingGate notes each call to the container's relay among runsc's calls,
// then makes it.
type notingGate struct {
	relayGate
	f *fakeRunsc
}

func (g *notingGate) Start() { g.f.note("relay_start"); g.relayGate.Start() }
func (g *notingGate) Stop()  { g.f.note("relay_stop"); g.relayGate.Stop() }

// newContainer creates a container from spec through NewContainer, with the
// fake runsc.
func newContainer(t *testing.T, f *fakeRunsc, spec *specs.Spec) (*Container, string) {
	t.Helper()
	bundle := t.TempDir()
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := namespaces.WithNamespace(context.Background(), "test")
	c, err := NewContainer(ctx, fakePlatform{}, &ContainerConfig{ID: "app", Bundle: bundle})
	if err != nil {
		t.Fatalf("NewContainer: %v", err)
	}
	if c.relay != nil {
		t.Cleanup(c.relay.Stop)
		c.relay = &notingGate{relayGate: c.relay, f: f}
	}
	return c, bundle
}

func readSpec(t *testing.T, bundle string) *specs.Spec {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s specs.Spec
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("the container's delete unmounts its rootfs, which needs root")
	}
}

func TestNewContainerSetsUpRelay(t *testing.T) {
	f := newFakeRunsc(t)
	c, bundle := newContainer(t, f, envoySpec(""))
	if c.relay == nil {
		t.Fatal("a sandbox with Envoy's configuration has no relay")
	}
	if _, ok := c.relay.(*notingGate).relayGate.(*sdsrelay.Supervisor); !ok {
		t.Errorf("relay = %T, want a supervisor", c.relay.(*notingGate).relayGate)
	}
	// runsc reads the rewritten spec from the bundle.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if got := relayBinary(readSpec(t, bundle)); got != exe {
		t.Errorf("relay binary in the bundle's spec = %q, want %q", got, exe)
	}
	if got, want := f.calls(), []string{"create"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestNewContainerWithoutRelay(t *testing.T) {
	for name, spec := range map[string]*specs.Spec{
		"subcontainer": envoySpec("container"),
		"no Envoy":     {Version: specs.Version, Annotations: map[string]string{}, Process: &specs.Process{Args: []string{"/bin/sh"}, Cwd: "/"}, Root: &specs.Root{Path: "rootfs"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeRunsc(t)
			want, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			c, bundle := newContainer(t, f, spec)
			if c.relay != nil {
				t.Errorf("relay = %T, want none", c.relay)
			}
			got, err := os.ReadFile(filepath.Join(bundle, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("the bundle's spec was rewritten:\n%s", got)
			}
		})
	}
}

// startContainer starts init and waits for the polling relay.
func startContainer(t *testing.T, f *fakeRunsc, c *Container) {
	t.Helper()
	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.waitFor(t, "exec_poller")
}

func TestContainerStartsRelayAfterInit(t *testing.T) {
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	if got, want := f.calls(), []string{"create", "start", "relay_start", "exec_poller"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func execProcess(t *testing.T, c *Container, id string, args ...string) {
	t.Helper()
	if _, err := c.Exec(context.Background(), &task.ExecProcessRequest{ID: "app", ExecID: id, Spec: processSpec(t, args...)}); err != nil {
		t.Fatalf("Exec %s: %v", id, err)
	}
}

func TestContainerExecGate(t *testing.T) {
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	execProcess(t, c, "envoy", "/etc/cf-assets/envoy/envoy", "-c", envoyConfig)
	execProcess(t, c, "health", "/tmp/lifecycle/healthcheck", "-port=8080")
	execProcess(t, c, "sshd", "/tmp/lifecycle/diego-sshd")

	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy"}); err != nil {
		t.Fatalf("Start envoy: %v", err)
	}
	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "health"}); err != nil {
		t.Fatalf("Start health: %v", err)
	}
	if got, want := f.calls()[4:], []string{"exec_sync", "exec_envoy", "exec_other"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}

	// While a sync fails, only Envoy is held back.
	f.failSyncs()
	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "sshd"}); err != nil {
		t.Fatalf("Start sshd while syncs fail: %v", err)
	}
	execProcess(t, c, "envoy2", "/etc/cf-assets/envoy/envoy", "-c", envoyConfig)
	_, err := c.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy2"})
	if err == nil || !strings.Contains(err.Error(), "sync Envoy configuration") || !strings.Contains(err.Error(), "a source file is still being written") {
		t.Errorf("Start envoy2 = %v, want the relay's failure", err)
	}
	if got, want := f.calls()[7:], []string{"exec_other", "exec_sync"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestContainerExecReusesID(t *testing.T) {
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	execProcess(t, c, "p", "/etc/cf-assets/envoy/envoy", "-c", envoyConfig)
	if !c.readsEnvoyConfig("p") {
		t.Fatal("Envoy's exec is not gated")
	}
	c.ProcessRemove("p")
	if c.readsEnvoyConfig("p") {
		t.Error("a removed exec is still gated")
	}
	execProcess(t, c, "p", "/etc/cf-assets/envoy/envoy", "-c", envoyConfig)
	execProcess(t, c, "p", "/tmp/lifecycle/healthcheck")
	if c.readsEnvoyConfig("p") {
		t.Error("an exec that reuses Envoy's ID is gated")
	}
}

func TestContainerExecWithoutRelay(t *testing.T) {
	f := newFakeRunsc(t)
	spec := envoySpec("")
	spec.Mounts = nil
	c, _ := newContainer(t, f, spec)
	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app"}); err != nil {
		t.Fatal(err)
	}
	execProcess(t, c, "envoy", "/etc/cf-assets/envoy/envoy", "-c", envoyConfig)
	if c.readsEnvoyConfig("envoy") {
		t.Error("an exec is gated without a relay")
	}
	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "envoy"}); err != nil {
		t.Fatal(err)
	}
	if got, want := f.calls(), []string{"create", "start", "exec_envoy"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestContainerKillAllStopsRelay(t *testing.T) {
	for _, sig := range []unix.Signal{unix.SIGTERM, unix.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			f := newFakeRunsc(t)
			c, _ := newContainer(t, f, envoySpec(""))
			startContainer(t, f, c)
			if err := c.Kill(context.Background(), &task.KillRequest{ID: "app", Signal: uint32(sig), All: true}); err != nil {
				t.Fatal(err)
			}
			want := []string{"create", "start", "relay_start", "exec_poller", "relay_stop", fmt.Sprintf("kill_--all_app_%d", sig)}
			if got := f.calls(); !slices.Equal(got, want) {
				t.Errorf("calls = %q, want %q", got, want)
			}
			// The stopped relay does not hold back a start.
			f.failSyncs()
			execProcess(t, c, "envoy", "/etc/cf-assets/envoy/envoy", "-c", envoyConfig)
			if err := c.relay.Sync(context.Background()); err != nil {
				t.Errorf("Sync after the container stopped = %v", err)
			}
		})
	}
}

func TestContainerSignalLeavesRelay(t *testing.T) {
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	if err := c.Kill(context.Background(), &task.KillRequest{ID: "app", Signal: uint32(unix.SIGTERM)}); err != nil {
		t.Fatal(err)
	}
	want := []string{"create", "start", "relay_start", "exec_poller", fmt.Sprintf("kill_app_%d", unix.SIGTERM)}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestContainerDeleteStopsRelay(t *testing.T) {
	requireRoot(t)
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	f.stop()
	c.task.SetExited(0)
	if _, err := c.Delete(context.Background(), &task.DeleteRequest{ID: "app"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	want := []string{"create", "start", "relay_start", "exec_poller", "relay_stop", fmt.Sprintf("kill_--all_app_%d", unix.SIGKILL), "delete"}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// fakePlatform stands in for the console platform of a container without a
// terminal.
type fakePlatform struct{}

func (fakePlatform) CopyConsole(context.Context, console.Console, string, string, string, string, *sync.WaitGroup) (console.Console, error) {
	return nil, errors.New("no console")
}
func (fakePlatform) ShutdownConsole(context.Context, console.Console) error { return nil }
func (fakePlatform) Close() error                                           { return nil }

type fakeOOMPoller struct{}

func (fakeOOMPoller) Close() error          { return nil }
func (fakeOOMPoller) add(string, any) error { return nil }
func (fakeOOMPoller) run(context.Context)   {}
func (fakeOOMPoller) isOOM(string) bool     { return false }

func TestInitExitStopsRelay(t *testing.T) {
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	s := &runscService{
		events:     make(chan any, 128),
		containers: map[string]*Container{"app": c},
		oomPoller:  fakeOOMPoller{},
	}
	s.checkProcesses(context.Background(), proc.Exit{ID: "app", Status: 3, Timestamp: time.Now()})
	want := []string{"create", "start", "relay_start", "exec_poller", "relay_stop", fmt.Sprintf("kill_--all_app_%d", unix.SIGKILL)}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	select {
	case e := <-s.events:
		if !strings.Contains(fmt.Sprint(e), "exit_status:3") {
			t.Errorf("event = %v, want init's exit status", e)
		}
	default:
		t.Error("no exit event")
	}
}

func TestExecExitLeavesRelay(t *testing.T) {
	f := newFakeRunsc(t)
	c, _ := newContainer(t, f, envoySpec(""))
	startContainer(t, f, c)
	execProcess(t, c, "health", "/tmp/lifecycle/healthcheck")
	if _, err := c.Start(context.Background(), &task.StartRequest{ID: "app", ExecID: "health"}); err != nil {
		t.Fatal(err)
	}
	s := &runscService{
		events:     make(chan any, 128),
		containers: map[string]*Container{"app": c},
		oomPoller:  fakeOOMPoller{},
	}
	s.checkProcesses(context.Background(), proc.Exit{ID: "health", Status: 0, Timestamp: time.Now()})
	want := []string{"create", "start", "relay_start", "exec_poller", "exec_other"}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}
