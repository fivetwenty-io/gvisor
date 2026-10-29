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
	"testing"

	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/runsc/boot"
)

func TestIsIPv6LinkLocal(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"fe80::1", true},
		{"febf::1", true},
		{"fec0::1", false},
		{"2001:db8::1", false},
		{"::1", false},
		{"169.254.0.1", false},
		{"10.0.0.1", false},
	} {
		if got := isIPv6LinkLocal(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("isIPv6LinkLocal(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestGatewayIPs(t *testing.T) {
	gw4 := net.ParseIP("169.254.0.1")
	gw6 := net.ParseIP("fe80::1")
	routes := []boot.Route{
		{Gateway: gw4},
		{Gateway: nil},
		{Gateway: net.IPv4zero},
		{Gateway: net.ParseIP("169.254.0.1")},
		{Gateway: gw6},
	}
	def4 := &boot.Route{Gateway: gw4}
	got := gatewayIPs(routes, def4, nil, &boot.Route{Gateway: net.ParseIP("10.0.0.1")})
	want := []string{"10.0.0.1", "169.254.0.1", "fe80::1"}
	if len(got) != len(want) {
		t.Fatalf("gatewayIPs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("gatewayIPs()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
	if got := gatewayIPs(nil); len(got) != 0 {
		t.Errorf("gatewayIPs(nil) = %v, want empty", got)
	}
}

func TestPeerIPs(t *testing.T) {
	_, local, _ := net.ParseCIDR("10.255.233.5/32")
	_, peer, _ := net.ParseCIDR("169.254.0.1/32")
	addrs := []netlink.Addr{
		{IPNet: local, Peer: peer},
		{IPNet: local},
		{IPNet: local, Peer: peer},
	}
	got := peerIPs(addrs)
	if len(got) != 1 || !got[0].Equal(net.ParseIP("169.254.0.1")) {
		t.Errorf("peerIPs() = %v, want [169.254.0.1]", got)
	}
	if got := peerIPs(nil); len(got) != 0 {
		t.Errorf("peerIPs(nil) = %v, want empty", got)
	}
}

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestMissingNeighbors(t *testing.T) {
	dump := []netlink.Neigh{
		{IP: net.ParseIP("169.254.0.1"), HardwareAddr: mac("aa:bb:cc:dd:ee:01"), State: netlink.NUD_STALE},
		{IP: net.ParseIP("10.0.0.1"), State: netlink.NUD_INCOMPLETE},
	}
	got := missingNeighbors(dump, []net.IP{net.ParseIP("169.254.0.1"), net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")})
	if len(got) != 2 || got[0].String() != "10.0.0.1" || got[1].String() != "10.0.0.2" {
		t.Errorf("missingNeighbors() = %v, want [10.0.0.1 10.0.0.2]", got)
	}
}

func TestSelectNeighbors(t *testing.T) {
	gw := net.ParseIP("169.254.0.1")
	dump := []netlink.Neigh{
		{IP: gw, HardwareAddr: mac("aa:bb:cc:dd:ee:01"), State: netlink.NUD_REACHABLE},
		{IP: net.ParseIP("10.0.0.7"), HardwareAddr: mac("aa:bb:cc:dd:ee:02"), State: netlink.NUD_PERMANENT},
		{IP: net.ParseIP("10.0.0.8"), HardwareAddr: mac("aa:bb:cc:dd:ee:03"), State: netlink.NUD_STALE},
		{IP: net.ParseIP("10.0.0.9"), HardwareAddr: mac("aa:bb:cc:dd:ee:04"), State: netlink.NUD_REACHABLE},
		{IP: net.ParseIP("10.0.0.10"), State: netlink.NUD_PERMANENT},
		{IP: net.ParseIP("10.0.0.1"), HardwareAddr: mac("aa:bb:cc:dd:ee:05"), State: netlink.NUD_FAILED},
	}
	got := selectNeighbors(dump, []net.IP{gw, net.ParseIP("10.0.0.1")})
	want := map[string]string{
		"169.254.0.1": "aa:bb:cc:dd:ee:01", // gateway, live state
		"10.0.0.7":    "aa:bb:cc:dd:ee:02", // static entry, always copied
	}
	if len(got) != len(want) {
		t.Fatalf("selectNeighbors() = %+v, want %v", got, want)
	}
	for _, n := range got {
		if m, ok := want[n.IP.String()]; !ok || m != n.HardwareAddr.String() {
			t.Errorf("unexpected neighbor %v %v", n.IP, n.HardwareAddr)
		}
	}
}
