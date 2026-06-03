package udpext

import (
	"log/slog"
	"net"
	"strings"
	"testing"
)

// newTestManager builds a manager with explicit guards/caps, bypassing the
// env-derived ones. Empty allow strings yield deny-all-private (send) and
// loopback-only (bind) guards so the block paths can be exercised.
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

// TestListen_BlocksWildcardBind confirms binding 0.0.0.0 / :: is refused by
// default — the all-interface exposure class.
func TestListen_BlocksWildcardBind(t *testing.T) {
	m := newTestManager("", "", 64, 512)
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0"} {
		_, err := m.listen("c1", udpListenRequest{Addr: addr})
		if err == nil {
			t.Errorf("bind %q: expected bind block, got nil", addr)
		} else if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("bind %q: expected bind-guard error, got %v", addr, err)
		}
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

// TestListen_BindAllowlist confirms UDP_BIND_ALLOW lets a wildcard bind
// through when explicitly permitted.
func TestListen_BindAllowlist(t *testing.T) {
	m := newTestManager("", "0.0.0.0", 64, 512)
	id, err := m.listen("c1", udpListenRequest{Addr: "0.0.0.0:0"})
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
