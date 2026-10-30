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

// Package sdsrelay keeps Envoy's SDS files reloadable inside a sandbox.
//
// Cloud Foundry's Diego bind-mounts a host directory of Envoy configuration
// into each container and replaces the SDS files in it with a rename on the
// host. The Sentry raises inotify events only for operations it performs
// itself, so Envoy's watch on the bind mount never fires and Envoy keeps
// serving its first certificates. The shim therefore moves the bind mount to a
// hidden path, puts a sandbox tmpfs at the original path, and runs a relay
// inside the sandbox that mirrors the hidden directory into the tmpfs with a
// rename the Sentry performs, which raises IN_MOVED_TO for Envoy.
package sdsrelay

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

const (
	// Subcommand selects the relay when the shim binary runs in a sandbox.
	Subcommand = "sds-relay"

	// EnvoyConfigPath is where Diego mounts a container's Envoy configuration.
	EnvoyConfigPath = "/etc/cf-assets/envoy_config"

	// relayDir holds the relay's own mounts inside the container.
	relayDir = "/.gvisor-sds-relay"

	// SourcePath is where the shim moves Diego's bind mount.
	SourcePath = relayDir + "/source"

	// BinaryPath is where the shim mounts its own binary to run the relay.
	BinaryPath = relayDir + "/relay"
)

// relayCapabilities lets the relay give each copy the owner of its source
// file, and read a source file whatever its mode, as Envoy can. The relay
// gets no other capability.
var relayCapabilities = []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH"}

// relayEnv keeps the relay to one thread that runs Go code. The relay runs in
// the app's sandbox and counts against the app's memory limit. Its heap holds
// only a few small files, so GOGC and GOMEMLIMIT do not make it smaller: with
// GOGC=25 and GOMEMLIMIT=4MiB, a relay in a gVisor sandbox took 1.2 MB more
// than with GOMAXPROCS=1 alone.
var relayEnv = []string{"GOMAXPROCS=1"}

// Process returns the process the shim executes in the sandbox to run the
// relay, with extra appended to its arguments.
func Process(extra ...string) specs.Process {
	return specs.Process{
		Args: append([]string{BinaryPath, Subcommand, "--source", SourcePath, "--target", EnvoyConfigPath}, extra...),
		Env:  slices.Clone(relayEnv),
		Cwd:  "/",
		User: specs.User{UID: 0, GID: 0},
		Capabilities: &specs.LinuxCapabilities{
			Bounding:  relayCapabilities,
			Effective: relayCapabilities,
			Permitted: relayCapabilities,
		},
		NoNewPrivileges: true,
	}
}

// ReadsEnvoyConfig reports whether a process with args reads Diego's Envoy
// configuration. Diego always starts Envoy with the path of its bootstrap in
// that directory, and no other process Diego starts names it.
func ReadsEnvoyConfig(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, EnvoyConfigPath) {
			return true
		}
	}
	return false
}

// HasEnvoyConfigMount reports whether spec bind-mounts Diego's Envoy
// configuration.
func HasEnvoyConfigMount(spec *specs.Spec) bool {
	return envoyConfigMount(spec) >= 0
}

// envoyConfigMount returns the index of the bind mount at EnvoyConfigPath, or
// -1 when there is none.
func envoyConfigMount(spec *specs.Spec) int {
	for i, m := range spec.Mounts {
		if filepath.Clean(m.Destination) == EnvoyConfigPath && isBind(m) {
			return i
		}
	}
	return -1
}

// RewriteSpec prepares a sandbox container's spec for the relay. It moves the
// bind mount at EnvoyConfigPath to SourcePath, read-only, puts a tmpfs at
// EnvoyConfigPath, and mounts binary read-only at BinaryPath. It returns true
// when the container needs the relay, and leaves a spec that has no such bind
// mount, or that is not the sandbox's root container, unchanged.
func RewriteSpec(spec *specs.Spec, binary string) (bool, error) {
	if !utils.IsSandbox(spec) {
		return false, nil
	}
	for _, m := range spec.Mounts {
		if filepath.Clean(m.Destination) == SourcePath {
			// The spec was already rewritten.
			return true, nil
		}
	}
	i := envoyConfigMount(spec)
	if i < 0 {
		return false, nil
	}
	if !filepath.IsAbs(binary) {
		return false, fmt.Errorf("relay binary path %q is not absolute", binary)
	}

	source := spec.Mounts[i]
	source.Destination = SourcePath
	source.Options = readOnly(source.Options)
	mounts := []specs.Mount{
		source,
		{
			Destination: EnvoyConfigPath,
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "nodev", "noexec", "mode=0755", "uid=0", "gid=0"},
		},
		{
			Destination: BinaryPath,
			Type:        "bind",
			Source:      binary,
			Options:     []string{"bind", "ro", "nosuid", "nodev"},
		},
	}
	spec.Mounts = slices.Concat(spec.Mounts[:i], mounts, spec.Mounts[i+1:])
	return true, nil
}

func isBind(m specs.Mount) bool {
	if m.Type == "bind" {
		return true
	}
	for _, o := range m.Options {
		if o == "bind" || o == "rbind" {
			return true
		}
	}
	return false
}

// readOnly returns options with any "rw" replaced by a single "ro".
func readOnly(options []string) []string {
	out := make([]string, 0, len(options)+1)
	for _, o := range options {
		if o != "rw" && o != "ro" {
			out = append(out, o)
		}
	}
	return append(out, "ro")
}
