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
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const shim = "/var/vcap/packages/runsc/bin/containerd-shim-runsc-v1"

// gardenSpec returns a spec with the mounts Garden gives a Diego container.
func gardenSpec(containerType string) *specs.Spec {
	spec := &specs.Spec{
		Annotations: map[string]string{},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/etc/cf-assets/envoy", Type: "bind", Source: "/var/vcap/packages/proxy", Options: []string{"bind", "ro"}},
			{Destination: "/etc/cf-assets/envoy_config", Type: "bind", Source: "/var/vcap/data/rep/shared/garden/proxy_config/guid", Options: []string{"bind", "rw"}},
			{Destination: "/tmp/app", Type: "bind", Source: "/var/app", Options: []string{"bind", "rw"}},
		},
	}
	if containerType != "" {
		spec.Annotations["io.kubernetes.cri.container-type"] = containerType
	}
	return spec
}

func TestRewriteSpec(t *testing.T) {
	for _, containerType := range []string{"", "sandbox"} {
		t.Run("type "+containerType, func(t *testing.T) {
			spec := gardenSpec(containerType)
			relay, err := RewriteSpec(spec, shim)
			if err != nil {
				t.Fatalf("RewriteSpec: %v", err)
			}
			if !relay {
				t.Fatal("RewriteSpec did not ask for the relay")
			}
			want := []specs.Mount{
				{Destination: "/proc", Type: "proc", Source: "proc"},
				{Destination: "/etc/cf-assets/envoy", Type: "bind", Source: "/var/vcap/packages/proxy", Options: []string{"bind", "ro"}},
				{Destination: "/.gvisor-sds-relay/source", Type: "bind", Source: "/var/vcap/data/rep/shared/garden/proxy_config/guid", Options: []string{"bind", "ro"}},
				{Destination: "/etc/cf-assets/envoy_config", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "noexec", "mode=0755", "uid=0", "gid=0"}},
				{Destination: "/.gvisor-sds-relay/relay", Type: "bind", Source: shim, Options: []string{"bind", "ro", "nosuid", "nodev"}},
				{Destination: "/tmp/app", Type: "bind", Source: "/var/app", Options: []string{"bind", "rw"}},
			}
			if !reflect.DeepEqual(spec.Mounts, want) {
				t.Errorf("mounts = %+v\nwant %+v", spec.Mounts, want)
			}
			if HasEnvoyConfigMount(spec) {
				t.Errorf("the rewritten spec still bind-mounts the Envoy configuration")
			}
		})
	}
}

func TestRewriteSpecIsIdempotent(t *testing.T) {
	spec := gardenSpec("sandbox")
	if _, err := RewriteSpec(spec, shim); err != nil {
		t.Fatal(err)
	}
	once := append([]specs.Mount(nil), spec.Mounts...)
	relay, err := RewriteSpec(spec, "")
	if err != nil || !relay {
		t.Fatalf("second RewriteSpec = %v, %v; want true, nil", relay, err)
	}
	if !reflect.DeepEqual(spec.Mounts, once) {
		t.Errorf("second RewriteSpec changed the mounts to %+v", spec.Mounts)
	}
}

func TestRewriteSpecLeavesOtherSpecs(t *testing.T) {
	noEnvoy := gardenSpec("sandbox")
	noEnvoy.Mounts = append(noEnvoy.Mounts[:2:2], noEnvoy.Mounts[3:]...)
	notBind := gardenSpec("sandbox")
	notBind.Mounts[2] = specs.Mount{Destination: EnvoyConfigPath, Type: "tmpfs", Source: "tmpfs"}
	for name, spec := range map[string]*specs.Spec{
		"no Envoy configuration":   noEnvoy,
		"not a bind mount":         notBind,
		"subcontainer":             gardenSpec("container"),
		"subcontainer without one": func() *specs.Spec { s := gardenSpec("container"); s.Mounts = nil; return s }(),
	} {
		t.Run(name, func(t *testing.T) {
			before := append([]specs.Mount(nil), spec.Mounts...)
			relay, err := RewriteSpec(spec, shim)
			if err != nil || relay {
				t.Errorf("RewriteSpec = %v, %v; want false, nil", relay, err)
			}
			if !reflect.DeepEqual(spec.Mounts, before) {
				t.Errorf("RewriteSpec changed the mounts to %+v", spec.Mounts)
			}
		})
	}
}

func TestRewriteSpecMatchesMountVariants(t *testing.T) {
	for name, m := range map[string]specs.Mount{
		"trailing slash":   {Destination: EnvoyConfigPath + "/", Type: "bind", Source: "/src", Options: []string{"rw"}},
		"bind option only": {Destination: EnvoyConfigPath, Type: "none", Source: "/src", Options: []string{"bind", "rw"}},
		"rbind option":     {Destination: EnvoyConfigPath, Source: "/src", Options: []string{"rbind", "ro", "nosuid"}},
		"no options":       {Destination: EnvoyConfigPath, Type: "bind", Source: "/src"},
	} {
		t.Run(name, func(t *testing.T) {
			spec := &specs.Spec{Mounts: []specs.Mount{m}}
			if !HasEnvoyConfigMount(spec) {
				t.Fatal("mount not recognized")
			}
			relay, err := RewriteSpec(spec, shim)
			if err != nil || !relay {
				t.Fatalf("RewriteSpec = %v, %v", relay, err)
			}
			if len(spec.Mounts) != 3 || spec.Mounts[0].Destination != SourcePath || spec.Mounts[1].Destination != EnvoyConfigPath || spec.Mounts[2].Destination != BinaryPath {
				t.Fatalf("mounts = %+v", spec.Mounts)
			}
			moved := spec.Mounts[0]
			if moved.Source != "/src" || moved.Type != m.Type {
				t.Errorf("moved mount = %+v", moved)
			}
			ro := 0
			for _, o := range moved.Options {
				if o == "rw" {
					t.Errorf("moved mount is still rw: %v", moved.Options)
				}
				if o == "ro" {
					ro++
				}
			}
			if ro != 1 {
				t.Errorf("moved mount options = %v, want one ro", moved.Options)
			}
		})
	}
}

func TestRewriteSpecNeedsAbsoluteBinary(t *testing.T) {
	spec := gardenSpec("sandbox")
	before := append([]specs.Mount(nil), spec.Mounts...)
	if _, err := RewriteSpec(spec, "containerd-shim-runsc-v1"); err == nil {
		t.Error("RewriteSpec accepted a relative binary path")
	}
	if !reflect.DeepEqual(spec.Mounts, before) {
		t.Errorf("a failed RewriteSpec changed the mounts")
	}
}

func TestRewriteSpecDoesNotAliasOptions(t *testing.T) {
	spec := gardenSpec("sandbox")
	options := spec.Mounts[2].Options
	if _, err := RewriteSpec(spec, shim); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options, []string{"bind", "rw"}) {
		t.Errorf("RewriteSpec changed the original options to %v", options)
	}
}

func TestProcess(t *testing.T) {
	p := Process()
	if want := []string{BinaryPath, Subcommand, "--source", SourcePath, "--target", EnvoyConfigPath}; !reflect.DeepEqual(p.Args, want) {
		t.Errorf("args = %v, want %v", p.Args, want)
	}
	if p.User.UID != 0 || p.User.GID != 0 || len(p.User.AdditionalGids) != 0 {
		t.Errorf("user = %+v, want root without supplementary groups", p.User)
	}
	if !p.NoNewPrivileges {
		t.Error("NoNewPrivileges is off")
	}
	if p.Terminal {
		t.Error("the relay has a terminal")
	}
	if p.Cwd != "/" {
		t.Errorf("cwd = %q", p.Cwd)
	}
	caps := []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH"}
	c := p.Capabilities
	if c == nil || !reflect.DeepEqual(c.Bounding, caps) || !reflect.DeepEqual(c.Effective, caps) || !reflect.DeepEqual(c.Permitted, caps) || len(c.Inheritable) != 0 || len(c.Ambient) != 0 {
		t.Errorf("capabilities = %+v, want only %v", c, caps)
	}
	if !reflect.DeepEqual(p.Env, []string{"GOMAXPROCS=1"}) {
		t.Errorf("env = %v", p.Env)
	}

	// Extra arguments follow the fixed ones, and never change a later
	// process's arguments or environment.
	once := Process(OnceFlag)
	if want := []string{BinaryPath, Subcommand, "--source", SourcePath, "--target", EnvoyConfigPath, "--once"}; !reflect.DeepEqual(once.Args, want) {
		t.Errorf("args = %v, want %v", once.Args, want)
	}
	once.Env[0] = "changed"
	if p := Process(); len(p.Args) != 6 || p.Env[0] != "GOMAXPROCS=1" {
		t.Errorf("Process() = %v %v after a change to an earlier result", p.Args, p.Env)
	}
}

func TestReadsEnvoyConfig(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		// Diego's Envoy command.
		{[]string{"sh", "-c", "trap 'kill -9 0' TERM; /etc/cf-assets/envoy/envoy -c /etc/cf-assets/envoy_config/envoy.yaml --drain-time-s 900 --log-level critical& pid=$!; wait $pid"}, true},
		{[]string{"/etc/cf-assets/envoy/envoy", "-c", "/etc/cf-assets/envoy_config/envoy.yaml"}, true},
		{[]string{"cat", "/etc/cf-assets/envoy_config"}, true},
		// The app, health checks, sshd, and Garden's streams.
		{[]string{"/tmp/lifecycle/launcher", "app", "bundle exec rackup", ""}, false},
		{[]string{"/etc/cf-assets/healthcheck/healthcheck", "-port=8080", "-timeout=1000ms"}, false},
		{[]string{"/tmp/lifecycle/diego-sshd", "--allowedKeyExchanges=", "--address=0.0.0.0:2222"}, false},
		{[]string{"tar", "-x", "-C", "/home/vcap"}, false},
		{[]string{"/etc/cf-assets/envoy/envoy", "--version"}, false},
		{nil, false},
	} {
		if got := ReadsEnvoyConfig(tc.args); got != tc.want {
			t.Errorf("ReadsEnvoyConfig(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
