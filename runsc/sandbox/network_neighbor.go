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

package sandbox

import (
	"net"
	"sort"

	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/runsc/boot"
)

// liveNeighborStates are the dynamic neighbor states whose link-layer address
// is worth copying into the sandbox, for gateways and peers only.
const liveNeighborStates = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE

// isIPv6LinkLocal returns true for fe80::/10 addresses. Connecting to one
// requires a scope id, which a plain UDPAddr without Zone does not carry.
func isIPv6LinkLocal(ip net.IP) bool {
	return ip.To4() == nil && ip.IsLinkLocalUnicast()
}

// gatewayIPs returns the distinct, specified gateway addresses used by routes
// and the default routes, sorted by their string form.
func gatewayIPs(routes []boot.Route, defaults ...*boot.Route) []net.IP {
	seen := map[string]net.IP{}
	add := func(gw net.IP) {
		if len(gw) == 0 || gw.IsUnspecified() {
			return
		}
		seen[gw.String()] = gw
	}
	for _, r := range routes {
		add(r.Gateway)
	}
	for _, r := range defaults {
		if r != nil {
			add(r.Gateway)
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ips := make([]net.IP, 0, len(keys))
	for _, k := range keys {
		ips = append(ips, seen[k])
	}
	return ips
}

// peerIPs returns the distinct point-to-point peer addresses of addrs.
func peerIPs(addrs []netlink.Addr) []net.IP {
	seen := map[string]bool{}
	var ips []net.IP
	for _, a := range addrs {
		if a.Peer == nil || len(a.Peer.IP) == 0 || seen[a.Peer.IP.String()] {
			continue
		}
		seen[a.Peer.IP.String()] = true
		ips = append(ips, a.Peer.IP)
	}
	return ips
}

// hasLinkAddr returns true if dump has an entry for ip with a link-layer
// address.
func hasLinkAddr(dump []netlink.Neigh, ip net.IP) bool {
	for _, n := range dump {
		if n.IP != nil && n.IP.Equal(ip) && len(n.HardwareAddr) > 0 {
			return true
		}
	}
	return false
}

// missingNeighbors returns the members of ips that have no entry with a
// link-layer address in dump.
func missingNeighbors(dump []netlink.Neigh, ips []net.IP) []net.IP {
	var missing []net.IP
	for _, ip := range ips {
		if !hasLinkAddr(dump, ip) {
			missing = append(missing, ip)
		}
	}
	return missing
}

// selectNeighbors returns the neighbors to copy into the sandbox. Static
// (PERMANENT) entries are always copied. Dynamic entries in a live state are
// copied only when their IP is in targets, because the sandbox treats every
// copied entry as static and never re-probes it. Entries without a link-layer
// address are skipped.
func selectNeighbors(dump []netlink.Neigh, targets []net.IP) []boot.Neighbor {
	isTarget := func(ip net.IP) bool {
		for _, t := range targets {
			if t.Equal(ip) {
				return true
			}
		}
		return false
	}
	var neighbors []boot.Neighbor
	for _, n := range dump {
		if len(n.HardwareAddr) == 0 {
			continue
		}
		switch {
		case n.State == netlink.NUD_PERMANENT:
		case n.State&liveNeighborStates != 0 && isTarget(n.IP):
		default:
			continue
		}
		// No flags are copied because Stack.AddStaticNeighbor does not support flags right now.
		neighbors = append(neighbors, boot.Neighbor{IP: n.IP, HardwareAddr: n.HardwareAddr})
	}
	return neighbors
}
