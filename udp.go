// Package udpext is Pulp's UDP transport extension. It registers a single
// capability, network.udp, giving cells the ability to open UDP sockets,
// send datagrams, and receive packets via the step event loop.
//
// The extension maintains one *net.UDPConn per logical socket plus a
// bounded per-socket ring buffer for inbound packets. A reader goroutine
// pushes received datagrams into the ring (drop-oldest on overflow) and
// Poll drains packets round-robin across sockets, surfacing each as a
// udp.packet StepEvent.
//
// Deployment:
//
//	import _ "github.com/BananaLabs-OSS/Pulp-ext-udp"
//
// Host imports exposed (all msgpack request/response):
//
//	udp_listen(req, resp)  — bind a UDP socket, return monotonic socket_id
//	udp_send(req, resp)    — send a datagram on a socket
//	udp_close(req)         — close a socket and stop its reader
package udpext

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

// ---------------------------------------------------------------------
// Constants & exported event kinds
// ---------------------------------------------------------------------

// EventUDPPacket is the StepEvent kind for an inbound UDP datagram.
const EventUDPPacket = "udp.packet"

const (
	defaultRingSize   = 1024
	defaultReadBuffer = 256 * 1024
	maxDatagramSize   = 65535
)

// ---------------------------------------------------------------------
// init — register the network.udp capability
// ---------------------------------------------------------------------

func init() {
	ext.Register(ext.Capability{
		Name:           "network.udp",
		Register:       udpRegister,
		Stub:           udpStub,
		Setup:          udpSetup,
		Teardown:       udpTeardown,
		Poll:           udpPoll,
		TeardownCell: udpTeardownCell,
	})
}

// ---------------------------------------------------------------------
// Wire types (msgpack request / response)
// ---------------------------------------------------------------------

type udpListenRequest struct {
	Addr       string `msgpack:"addr"`
	BufferSize int    `msgpack:"buffer_size,omitempty"`
}

type udpListenResponse struct {
	SocketID uint64 `msgpack:"socket_id"`
}

type udpSendRequest struct {
	SocketID uint64 `msgpack:"socket_id"`
	DstAddr  string `msgpack:"dst_addr"`
	Payload  []byte `msgpack:"payload"`
}

type udpSendResponse struct {
	BytesSent int `msgpack:"bytes_sent"`
}

type udpCloseRequest struct {
	SocketID uint64 `msgpack:"socket_id"`
}

// UDPPacket is the decoded payload for an EventUDPPacket StepEvent.
type UDPPacket struct {
	SocketID   uint64 `msgpack:"socket_id"`
	SrcAddr    string `msgpack:"src_addr"`
	Payload    []byte `msgpack:"payload"`
	ReceivedAt int64  `msgpack:"received_at"`
}

// ---------------------------------------------------------------------
// Packet ring buffer — bounded per-socket, drop-oldest on overflow
// ---------------------------------------------------------------------

type packetRing struct {
	mu      sync.Mutex
	buf     []UDPPacket
	head    int // read index
	tail    int // write index
	size    int // number of occupied slots
	cap     int
	dropped atomic.Uint64
}

func newPacketRing(capacity int) *packetRing {
	if capacity <= 0 {
		capacity = defaultRingSize
	}
	return &packetRing{
		buf: make([]UDPPacket, capacity),
		cap: capacity,
	}
}

// push appends pkt to the ring, dropping the oldest entry (and bumping the
// dropped counter) if the ring is full.
func (r *packetRing) push(pkt UDPPacket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == r.cap {
		// Drop oldest — advance head.
		r.head = (r.head + 1) % r.cap
		r.size--
		r.dropped.Add(1)
	}
	r.buf[r.tail] = pkt
	r.tail = (r.tail + 1) % r.cap
	r.size++
}

// pop returns the oldest packet if any, or (UDPPacket{}, false).
func (r *packetRing) pop() (UDPPacket, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == 0 {
		return UDPPacket{}, false
	}
	pkt := r.buf[r.head]
	r.buf[r.head] = UDPPacket{}
	r.head = (r.head + 1) % r.cap
	r.size--
	return pkt, true
}

func (r *packetRing) droppedCount() uint64 {
	return r.dropped.Load()
}

// ---------------------------------------------------------------------
// Socket — one UDP listener + reader goroutine + ring
// ---------------------------------------------------------------------

type udpSocket struct {
	id       uint64
	cellID string
	conn     *net.UDPConn
	addr     string
	ring     *packetRing
	cancel   context.CancelFunc
}

// ---------------------------------------------------------------------
// Manager — shared state across the capability's lifecycle
// ---------------------------------------------------------------------

type udpManager struct {
	logger *slog.Logger

	mu      sync.Mutex
	sockets map[uint64]*udpSocket
	order   []uint64 // stable iteration order for Poll round-robin
	nextID  atomic.Uint64
	pollIdx int // rotating start index for Poll fairness
}

func newUDPManager(logger *slog.Logger) *udpManager {
	return &udpManager{
		logger:  logger,
		sockets: map[uint64]*udpSocket{},
	}
}

var manager *udpManager

// listen binds a new UDP socket owned by cellID and spawns its reader
// goroutine. cellID is the manifest name of the cell that called
// udp_listen; every subsequent udp_send / udp_close / Poll operation is
// gated on socket ownership.
func (m *udpManager) listen(cellID string, req udpListenRequest) (uint64, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", req.Addr)
	if err != nil {
		return 0, fmt.Errorf("resolve %q: %w", req.Addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return 0, fmt.Errorf("listen %q: %w", req.Addr, err)
	}

	bufSize := req.BufferSize
	if bufSize <= 0 {
		bufSize = defaultReadBuffer
	}
	if err := conn.SetReadBuffer(bufSize); err != nil {
		m.logger.Warn("udp set read buffer failed", "addr", req.Addr, "size", bufSize, "err", err)
	}

	id := m.nextID.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	sock := &udpSocket{
		id:       id,
		cellID: cellID,
		conn:     conn,
		addr:     req.Addr,
		ring:     newPacketRing(defaultRingSize),
		cancel:   cancel,
	}

	m.mu.Lock()
	m.sockets[id] = sock
	m.order = append(m.order, id)
	m.mu.Unlock()

	go m.readLoop(ctx, sock)

	m.logger.Info("udp socket listening", "id", id, "cell", cellID, "addr", req.Addr, "buffer_size", bufSize)
	return id, nil
}

// ErrNotYourSocket is returned when a cell tries to send or close a
// socket owned by a different cell. Surfaced as error code 11 at the
// host boundary.
var ErrNotYourSocket = fmt.Errorf("socket not owned by caller cell")

// send writes a datagram on the given socket. Rejects cross-cell access.
func (m *udpManager) send(cellID string, req udpSendRequest) (int, error) {
	m.mu.Lock()
	sock, ok := m.sockets[req.SocketID]
	m.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("no such socket id %d", req.SocketID)
	}
	if sock.cellID != cellID {
		return 0, ErrNotYourSocket
	}
	dst, err := net.ResolveUDPAddr("udp", req.DstAddr)
	if err != nil {
		return 0, fmt.Errorf("resolve dst %q: %w", req.DstAddr, err)
	}
	n, err := sock.conn.WriteToUDP(req.Payload, dst)
	if err != nil {
		return 0, fmt.Errorf("write udp: %w", err)
	}
	return n, nil
}

// close tears down a single socket. Rejects cross-cell access.
func (m *udpManager) close(cellID string, req udpCloseRequest) error {
	m.mu.Lock()
	sock, ok := m.sockets[req.SocketID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("no such socket id %d", req.SocketID)
	}
	if sock.cellID != cellID {
		m.mu.Unlock()
		return ErrNotYourSocket
	}
	delete(m.sockets, req.SocketID)
	for i, id := range m.order {
		if id == req.SocketID {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	sock.cancel()
	if err := sock.conn.Close(); err != nil {
		return fmt.Errorf("close udp: %w", err)
	}
	dropped := sock.ring.droppedCount()
	if dropped > 0 {
		m.logger.Info("udp socket closed", "id", sock.id, "cell", sock.cellID, "addr", sock.addr, "dropped", dropped)
	} else {
		m.logger.Info("udp socket closed", "id", sock.id, "cell", sock.cellID, "addr", sock.addr)
	}
	return nil
}

// closeCell tears down every socket owned by cellID. Returns the
// count of sockets closed. Used by TeardownCell for graceful
// per-cell shutdown.
func (m *udpManager) closeCell(cellID string) int {
	m.mu.Lock()
	victims := make([]*udpSocket, 0)
	for id, s := range m.sockets {
		if s.cellID == cellID {
			victims = append(victims, s)
			delete(m.sockets, id)
		}
	}
	// Rebuild order without victim IDs.
	if len(victims) > 0 {
		kept := m.order[:0]
		for _, id := range m.order {
			if _, stillThere := m.sockets[id]; stillThere {
				kept = append(kept, id)
			}
		}
		m.order = kept
	}
	m.mu.Unlock()

	for _, s := range victims {
		s.cancel()
		_ = s.conn.Close()
	}
	return len(victims)
}

// readLoop reads datagrams from sock.conn until ctx is cancelled or the
// connection is closed, pushing each packet into the socket's ring.
func (m *udpManager) readLoop(ctx context.Context, sock *udpSocket) {
	buf := make([]byte, maxDatagramSize)
	for {
		if ctx.Err() != nil {
			return
		}
		// Short read deadline so we can notice cancellation promptly
		// without relying solely on Close() to unblock.
		_ = sock.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := sock.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Conn closed or fatal — exit the loop.
			if ctx.Err() == nil {
				m.logger.Debug("udp read loop exiting", "id", sock.id, "err", err)
			}
			return
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		pkt := UDPPacket{
			SocketID:   sock.id,
			SrcAddr:    src.String(),
			Payload:    payload,
			ReceivedAt: time.Now().UnixNano(),
		}
		sock.ring.push(pkt)
	}
}

// poll returns the next pending packet across sockets, round-robin. The
// start index rotates on each successful poll so busy sockets cannot
// starve quiet ones.
func (m *udpManager) poll() (ext.StepEvent, bool) {
	m.mu.Lock()
	if len(m.order) == 0 {
		m.mu.Unlock()
		return ext.StepEvent{}, false
	}
	// Snapshot the current socket order and starting offset, then drop
	// the lock before touching each ring (which takes its own lock).
	order := make([]uint64, len(m.order))
	copy(order, m.order)
	start := m.pollIdx % len(order)
	m.mu.Unlock()

	for i := 0; i < len(order); i++ {
		idx := (start + i) % len(order)
		id := order[idx]

		m.mu.Lock()
		sock, ok := m.sockets[id]
		m.mu.Unlock()
		if !ok {
			continue
		}

		pkt, has := sock.ring.pop()
		if !has {
			continue
		}

		payload, err := msgpack.Marshal(pkt)
		if err != nil {
			m.logger.Error("encode udp packet", "err", err, "socket_id", id)
			continue
		}

		m.mu.Lock()
		m.pollIdx = (idx + 1) % len(order)
		m.mu.Unlock()

		return ext.StepEvent{
			Kind:     EventUDPPacket,
			Payload:  payload,
			CellID: sock.cellID,
		}, true
	}
	return ext.StepEvent{}, false
}

// shutdown closes every socket and stops every reader goroutine.
func (m *udpManager) shutdown() {
	m.mu.Lock()
	socks := make([]*udpSocket, 0, len(m.sockets))
	for _, s := range m.sockets {
		socks = append(socks, s)
	}
	m.sockets = map[uint64]*udpSocket{}
	m.order = nil
	m.mu.Unlock()

	for _, s := range socks {
		s.cancel()
		_ = s.conn.Close()
	}
}

// ---------------------------------------------------------------------
// Capability lifecycle
// ---------------------------------------------------------------------

func udpSetup(env ext.SetupEnv) error {
	logger := env.Logger
	if logger == nil {
		logger = slog.Default()
	}
	manager = newUDPManager(logger)
	return nil
}

func udpTeardown(_ context.Context) error {
	if manager != nil {
		manager.shutdown()
	}
	return nil
}

// udpTeardownCell closes only the sockets owned by cellID. Other
// cells' sockets keep running. Safe to call with a cell name that
// owns no sockets.
func udpTeardownCell(_ context.Context, cellID string) error {
	if manager == nil {
		return nil
	}
	closed := manager.closeCell(cellID)
	if closed > 0 {
		manager.logger.Info("udp teardown cell", "cell", cellID, "sockets_closed", closed)
	}
	return nil
}

func udpPoll() (ext.StepEvent, bool) {
	if manager == nil {
		return ext.StepEvent{}, false
	}
	return manager.poll()
}

// ---------------------------------------------------------------------
// Host imports — network.udp
// ---------------------------------------------------------------------

func udpRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	// Capture the calling cell's name at Register time. Each cell
	// that declares network.udp gets its own closure set with its own
	// cellID baked in — cross-cell socket access is rejected on
	// every host-function call.
	cellID := cell.Name()

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
			if manager == nil {
				return 10
			}
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var req udpListenRequest
			if err := msgpack.Unmarshal(data, &req); err != nil {
				return 3
			}
			id, err := manager.listen(cellID, req)
			if err != nil {
				manager.logger.Error("udp_listen failed", "err", err, "cell", cellID, "addr", req.Addr)
				return 4
			}
			return writeMsgpackResponse(ctx, m, udpListenResponse{SocketID: id}, respPtrOut, respLenOut)
		}).
		Export("udp_listen")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
			if manager == nil {
				return 10
			}
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var req udpSendRequest
			if err := msgpack.Unmarshal(data, &req); err != nil {
				return 3
			}
			n, err := manager.send(cellID, req)
			if err != nil {
				if err == ErrNotYourSocket {
					manager.logger.Warn("udp_send cross-cell rejected", "cell", cellID, "socket_id", req.SocketID)
					return 11
				}
				manager.logger.Error("udp_send failed", "err", err, "cell", cellID, "socket_id", req.SocketID, "dst", req.DstAddr)
				return 4
			}
			return writeMsgpackResponse(ctx, m, udpSendResponse{BytesSent: n}, respPtrOut, respLenOut)
		}).
		Export("udp_send")

	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if manager == nil {
				return 10
			}
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var req udpCloseRequest
			if err := msgpack.Unmarshal(data, &req); err != nil {
				return 3
			}
			if err := manager.close(cellID, req); err != nil {
				if err == ErrNotYourSocket {
					manager.logger.Warn("udp_close cross-cell rejected", "cell", cellID, "socket_id", req.SocketID)
					return 11
				}
				manager.logger.Error("udp_close failed", "err", err, "cell", cellID, "socket_id", req.SocketID)
				return 4
			}
			return 0
		}).
		Export("udp_close")

	return nil
}

func udpStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	nop4 := func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }
	nop2 := func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }
	b.NewFunctionBuilder().WithFunc(nop4).Export("udp_listen")
	b.NewFunctionBuilder().WithFunc(nop4).Export("udp_send")
	b.NewFunctionBuilder().WithFunc(nop2).Export("udp_close")
	return nil
}

// ---------------------------------------------------------------------
// Shared helper — writes a msgpack-encoded value into cell memory via
// the cell's exported pulp_alloc function. Mirrors the pattern used in
// Pulp-ext-docker and Pulp-ext-http.
// ---------------------------------------------------------------------

func writeMsgpackResponse(ctx context.Context, m api.Module, v any, respPtrOut, respLenOut uint32) uint32 {
	encoded, err := msgpack.Marshal(v)
	if err != nil {
		return 5
	}
	allocFn := m.ExportedFunction("pulp_alloc")
	if allocFn == nil {
		return 7
	}
	var ptr uint32
	if len(encoded) > 0 {
		res, err := allocFn.Call(ctx, uint64(len(encoded)))
		if err != nil || len(res) == 0 {
			return 7
		}
		ptr = uint32(res[0])
		if ptr == 0 {
			return 7
		}
		if !m.Memory().Write(ptr, encoded) {
			return 8
		}
	}
	if !m.Memory().WriteUint32Le(respPtrOut, ptr) {
		return 8
	}
	if !m.Memory().WriteUint32Le(respLenOut, uint32(len(encoded))) {
		return 8
	}
	return 0
}
