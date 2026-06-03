package udpext

import (
	"log/slog"
	"net"
	"strings"
	"testing"
)

// newTestManager builds a manager with explicit guards/caps, bypassing the
// env-derived ones. Empty allow strings yield deny-all-private (send) and
// deny-wildcard (bind) guards so the block paths can be exercised. Tests that
// want the production defaults pass defaultSendAllow / defaultBindAllow.
func newTestManager(sendAllow, bindAllow string, perCell, total int) *udpManager {
	return &udpManager{
		logger:     slog.Default(),
		sendGuard:  newEgressGuard(sendAllow),
		bindGuard:  newEgressGuard(bindAllow),
		maxPerCell: perCell,
		maxTotal:   total,
		sockets:    map[uint64]*udpSocket{},
		perCell:    map[string]int{},
	}
}

func TestIPBlocked_Ranges(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"169.254.169.254", // cloud metadata (link-local)
		"10.1.2.3",        // RFC-1918
		"172.16.0.1",      // RFC-1918
		"192.168.1.1",     // RFC-1918
		"fc00::1",         // ULA
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
	}
	for _, s := range blocked {
		if !ipBlocked(net.ParseIP(s)) {
			t.Errorf("ipBlocked(%s) = false, want true", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range public {
		if ipBlocked(net.ParseIP(s)) {
			t.Errorf("ipBlocked(%s) = true, want false (public)", s)
		}
	}
}

// TestSend_BlocksInternal confirms a default (no-allowlist) manager refuses
// to send to loopback / metadata / RFC-1918 destinations — the SSRF /
// amplification class. We open a real loopback socket to send FROM (it is
// the destination that is guarded, not the source).
func TestSend_BlocksInternal(t *testing.T) {
	m := newTestManager("", "", 64, 512)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	m.sockets[1] = &udpSocket{id: 1, cellID: "c1", conn: conn}

	for _, dst := range []string{"127.0.0.1:9", "169.254.169.254:80", "10.0.0.1:53", "[::1]:9"} {
		_, err := m.send("c1", udpSendRequest{SocketID: 1, DstAddr: dst, Payload: []byte("x")})
		if err == nil {
			t.Errorf("send to %q: expected egress block, got nil", dst)
		} else if !strings.Contains(err.Error(), "blocked") {
			t.Errorf("send to %q: expected blocked error, got %v", dst, err)
		}
	}
}

// TestSend_AllowlistPermitsInternal confirms an explicit CIDR allowlist lets
// a genuinely-needed internal destination through (the datagram actually
// lands on a second loopback socket).
func TestSend_AllowlistPermitsInternal(t *testing.T) {
	m := newTestManager("127.0.0.0/8", "", 64, 512)
	src, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen src: %v", err)
	}
	defer src.Close()
	dst, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen dst: %v", err)
	}
	defer dst.Close()

	m.sockets[1] = &udpSocket{id: 1, cellID: "c1", conn: src}
	n, err := m.send("c1", udpSendRequest{SocketID: 1, DstAddr: dst.LocalAddr().String(), Payload: []byte("hi")})
	if err != nil {
		t.Fatalf("allowlisted send should succeed, got %v", err)
	}
	if n != 2 {
		t.Errorf("bytes sent = %d, want 2", n)
	}
}

// TestSend_DefaultsPermitPrivateBackendsButBlockOwnHost confirms the
// production default send allowlist (defaultSendAllow) lets the Peel relay
// forward to RFC-1918 game-server backends, while loopback / link-local
// metadata / multicast destinations stay blocked (the reflection / own-host
// class the guard exists to stop).
func TestSend_DefaultsPermitPrivateBackendsButBlockOwnHost(t *testing.T) {
	m := newTestManager(defaultSendAllow, defaultBindAllow, 64, 512)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	m.sockets[1] = &udpSocket{id: 1, cellID: "c1", conn: conn}

	// RFC-1918 backends (the relay's real forward targets) must pass the
	// guard. The OS may still fail the actual WriteToUDP if the private
	// network is unreachable from the test host — that is a "write udp:"
	// error, NOT an egress block. We assert only that the guard admitted the
	// destination (no "blocked" error).
	for _, dst := range []string{"10.99.0.10:5520", "172.16.0.1:5521", "192.168.1.50:5520"} {
		_, err := m.send("c1", udpSendRequest{SocketID: 1, DstAddr: dst, Payload: []byte("x")})
		if err != nil && strings.Contains(err.Error(), "blocked") {
			t.Errorf("send to private backend %q should pass guard under defaults, got blocked: %v", dst, err)
		}
	}
	// Own-host / reflection class stays blocked even under defaults.
	for _, dst := range []string{"127.0.0.1:9", "169.254.169.254:80", "224.0.0.1:9"} {
		_, err := m.send("c1", udpSendRequest{SocketID: 1, DstAddr: dst, Payload: []byte("x")})
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Errorf("send to %q: expected egress block under defaults, got %v", dst, err)
		}
	}
}

// TestListen_BlocksWildcardBind confirms binding a FIXED public/wildcard port
// is refused when the bind allowlist is empty — the all-interface exposure
// class. Fixed ports (not :0) are used because a kernel-assigned ephemeral
// (port-0) bind is a transient client socket and is always permitted.
func TestListen_BlocksWildcardBind(t *testing.T) {
	m := newTestManager("", "", 64, 512)
	for _, addr := range []string{"0.0.0.0:5520", ":5520", "[::]:5520"} {
		_, err := m.listen("c1", udpListenRequest{Addr: addr})
		if err == nil {
			t.Errorf("bind %q: expected bind block, got nil", addr)
		} else if !strings.Contains(err.Error(), "bind guard") {
			t.Errorf("bind %q: expected bind-guard error, got %v", addr, err)
		}
	}
}

// TestListen_PermitsEphemeralBind confirms a port-0 (kernel-assigned
// ephemeral) bind is always allowed regardless of IP, even with an empty
// allowlist. This is the Peel relay's per-player outbound-socket path
// (udp.Listen("")), and a resolver's :0 probe socket — transient client
// sockets, not exposed listeners.
func TestListen_PermitsEphemeralBind(t *testing.T) {
	m := newTestManager("", "", 64, 512)
	for _, addr := range []string{"", ":0", "0.0.0.0:0", "[::]:0"} {
		id, err := m.listen("c1", udpListenRequest{Addr: addr})
		if err != nil {
			t.Fatalf("ephemeral bind %q should succeed, got %v", addr, err)
		}
		_ = m.close("c1", udpCloseRequest{SocketID: id})
	}
}

// TestListen_PeelInboundBindWithDefaults confirms the Peel relay's configured
// public inbound listener (":5520", the production listen_addr → nil-IP
// fixed-port wildcard bind) is admitted under the production default bind
// allowlist. This is the regression the fix restores: a relay MEANT to be
// reachable must be able to bind its player-facing port.
func TestListen_PeelInboundBindWithDefaults(t *testing.T) {
	m := newTestManager(defaultSendAllow, defaultBindAllow, 64, 512)
	for _, addr := range []string{":5520", "0.0.0.0:5520", "[::]:5520"} {
		id, err := m.listen("c1", udpListenRequest{Addr: addr})
		if err != nil {
			t.Fatalf("relay inbound bind %q should succeed under defaults, got %v", addr, err)
		}
		_ = m.close("c1", udpCloseRequest{SocketID: id})
	}
}

// TestListen_PermitsLoopbackBind confirms a loopback bind is always allowed.
func TestListen_PermitsLoopbackBind(t *testing.T) {
	m := newTestManager("", "", 64, 512)
	id, err := m.listen("c1", udpListenRequest{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("loopback bind should succeed, got %v", err)
	}
	if err := m.close("c1", udpCloseRequest{SocketID: id}); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestListen_BindAllowlist confirms UDP_BIND_ALLOW lets a FIXED-port wildcard
// bind through when explicitly permitted (a fixed port, so the always-allow
// ephemeral path is not what is being exercised).
func TestListen_BindAllowlist(t *testing.T) {
	m := newTestManager("", "0.0.0.0", 64, 512)
	id, err := m.listen("c1", udpListenRequest{Addr: "0.0.0.0:5520"})
	if err != nil {
		t.Fatalf("allowlisted wildcard bind should succeed, got %v", err)
	}
	_ = m.close("c1", udpCloseRequest{SocketID: id})
}

// TestSocketCap_PerCell confirms a single cell cannot exceed its per-cell
// socket cap, and that closing a socket frees a slot.
func TestSocketCap_PerCell(t *testing.T) {
	m := newTestManager("", "", 2, 512)
	var ids []uint64
	for i := 0; i < 2; i++ {
		id, err := m.listen("c1", udpListenRequest{Addr: "127.0.0.1:0"})
		if err != nil {
			t.Fatalf("listen %d should succeed, got %v", i, err)
		}
		ids = append(ids, id)
	}
	if _, err := m.listen("c1", udpListenRequest{Addr: "127.0.0.1:0"}); err == nil {
		t.Fatal("expected per-cell cap to reject the 3rd socket, got nil")
	}
	// A different cell still has headroom (global cap not hit).
	if id, err := m.listen("c2", udpListenRequest{Addr: "127.0.0.1:0"}); err != nil {
		t.Fatalf("other cell should not be blocked by c1's cap, got %v", err)
	} else {
		_ = m.close("c2", udpCloseRequest{SocketID: id})
	}
	// Free one of c1's slots → a new listen succeeds.
	if err := m.close("c1", udpCloseRequest{SocketID: ids[0]}); err != nil {
		t.Fatalf("close: %v", err)
	}
	id, err := m.listen("c1", udpListenRequest{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("listen after close should succeed, got %v", err)
	}
	_ = m.close("c1", udpCloseRequest{SocketID: id})
	_ = m.close("c1", udpCloseRequest{SocketID: ids[1]})
}

// TestSocketCap_Global confirms the global cap is enforced across cells.
func TestSocketCap_Global(t *testing.T) {
	m := newTestManager("", "", 64, 1)
	id, err := m.listen("c1", udpListenRequest{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("first listen should succeed, got %v", err)
	}
	if _, err := m.listen("c2", udpListenRequest{Addr: "127.0.0.1:0"}); err == nil {
		t.Fatal("expected global cap to reject the 2nd socket, got nil")
	}
	_ = m.close("c1", udpCloseRequest{SocketID: id})
}

// TestBufferSize_Clamped confirms an oversized cell-requested read buffer is
// clamped to defaultReadBuffer (no panic / no honoring of the huge value).
func TestBufferSize_Clamped(t *testing.T) {
	m := newTestManager("", "", 64, 512)
	id, err := m.listen("c1", udpListenRequest{Addr: "127.0.0.1:0", BufferSize: 1 << 30})
	if err != nil {
		t.Fatalf("listen with oversized buffer should still succeed (clamped), got %v", err)
	}
	_ = m.close("c1", udpCloseRequest{SocketID: id})
}
