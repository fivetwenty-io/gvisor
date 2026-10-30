// Copyright 2020 The gVisor Authors.
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

// Binary containerd-shim-runsc-v1 is the v2 containerd shim (implementing the formal v1 API).
package main

import (
	"os"

	"gvisor.dev/gvisor/pkg/shim/v1/sdsrelay"
	"gvisor.dev/gvisor/shim/v1/cli"
)

func main() {
	// The shim mounts its own binary into sandboxes that need the SDS relay
	// and runs it there with this subcommand.
	if len(os.Args) > 1 && os.Args[1] == sdsrelay.Subcommand {
		os.Exit(sdsrelay.Main(os.Args[2:]))
	}
	cli.Main()
}
