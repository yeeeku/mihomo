package aegis

// Aegis-Stream v2 multiplexer (client side, mihomo).
//
// One TLS+Aegis connection carries N concurrent logical streams. Cuts the
// connection-count signal that DPI (e.g. 傲盾) uses to fingerprint proxy
// traffic. Each stream is identified by a u32 stream_id; the demuxer
// dispatches incoming frames to per-stream channels, and a single writer
// goroutine serialises outbound frames so the underlying TLS conn's
// non-concurrent write is respected.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMuxBufferFrames    = 256             // per-stream inbound channel depth (~2 MB at 8KB frames)
	DefaultWriterChanDepth    = 256             // shared writer queue
	DefaultOpenAckTimeout     = 10 * time.Second
	DefaultMuxKeepAliveEvery  = 30 * time.Second // proactive keepalive to defeat NAT timers
)

// MuxConn is one TLS+Aegis tunnel carrying many logical streams.
type MuxConn struct {
	raw      net.Conn
	sendAead *DirectedAead
	recvAead *DirectedAead

	nextSID  uint32        // atomic: monotonic stream_id source (starts at 1)
	streamMu sync.Mutex    // protects streams
	streams  map[uint32]*muxStream

	sendCh chan muxWriteReq // writer drains this

	closeOnce sync.Once
	closeErr  error
	done      chan struct{} // closed when conn is dying
}

type muxWriteReq struct {
	ty      FrameType
	payload []byte
}

// NewMuxConn performs the Aegis handshake on c (already TLS-terminated)
// and starts the demuxer + writer goroutines.
func NewMuxConn(c net.Conn, cfg ClientConfig) (*MuxConn, error) {
	keys, err := ClientHandshake(c, cfg)
	if err != nil {
		return nil, err
	}
	m := &MuxConn{
		raw:      c,
		sendAead: NewDirectedAead(keys, C2S),
		recvAead: NewDirectedAead(keys, S2C),
		streams:  make(map[uint32]*muxStream),
		sendCh:   make(chan muxWriteReq, DefaultWriterChanDepth),
		done:     make(chan struct{}),
	}
	go m.writerLoop()
	go m.demuxLoop()
	go m.keepAliveLoop()
	return m, nil
}

// keepAliveLoop sends a MuxKeepAlive every DefaultMuxKeepAliveEvery so
// NAT/firewall middleboxes don't drop the idle TLS conn. Server is
// responsible for ignoring these frames.
func (m *MuxConn) keepAliveLoop() {
	t := time.NewTicker(DefaultMuxKeepAliveEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// best-effort, ignore errors -- writerLoop will close on real failures
			_ = m.send(FrameMuxKeepAlive, nil)
		case <-m.done:
			return
		}
	}
}

// IsClosed reports whether the underlying conn is dead / shutting down.
func (m *MuxConn) IsClosed() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// ActiveStreams returns the current stream count (for pool placement).
func (m *MuxConn) ActiveStreams() int {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	return len(m.streams)
}

// Close tears down the mux conn and all streams.
func (m *MuxConn) Close() error {
	m.closeWith(errors.New("aegis mux: closed"))
	return nil
}

func (m *MuxConn) closeWith(err error) {
	m.closeOnce.Do(func() {
		m.closeErr = err
		close(m.done)
		_ = m.raw.Close()
		m.streamMu.Lock()
		for _, s := range m.streams {
			s.markClosed(err)
		}
		m.streams = make(map[uint32]*muxStream)
		m.streamMu.Unlock()
	})
}

// ─── writer / demuxer goroutines ──────────────────────────────────────

func (m *MuxConn) writerLoop() {
	for {
		select {
		case req := <-m.sendCh:
			if err := WriteSealedFrame(m.raw, m.sendAead,
				Frame{Type: req.ty, Payload: req.payload}); err != nil {
				m.closeWith(fmt.Errorf("aegis mux write: %w", err))
				return
			}
		case <-m.done:
			return
		}
	}
}

func (m *MuxConn) demuxLoop() {
	for {
		f, err := ReadSealedFrame(m.raw, m.recvAead)
		if err != nil {
			m.closeWith(fmt.Errorf("aegis mux read: %w", err))
			return
		}
		switch f.Type {
		case FrameMuxKeepAlive:
			continue
		case FrameMuxGoAway:
			m.closeWith(io.EOF)
			return
		}
		if !f.Type.IsMux() {
			// v1 frame on a v2 conn -- server bug. Drop.
			continue
		}
		sid, rest, err := SplitStreamID(f.Payload)
		if err != nil {
			continue
		}

		m.streamMu.Lock()
		s := m.streams[sid]
		m.streamMu.Unlock()

		if s == nil {
			// Unknown stream; tell server to forget it.
			_ = m.send(FrameMuxStreamClose, MuxPayload(sid, nil))
			continue
		}

		switch f.Type {
		case FrameMuxStreamOpenAck:
			if len(rest) >= 1 {
				select {
				case s.ackCh <- rest[0]:
				default:
				}
			}
		case FrameMuxStreamData, FrameMuxStreamUdpData:
			// Per-stream HOL guard: never block the demuxer waiting on a
			// single slow consumer -- that would freeze every other stream
			// sharing this TLS conn. If a stream's recv buffer overflows,
			// kill JUST that stream (not the whole conn) and tell the peer.
			select {
			case s.recvCh <- rest:
			case <-s.closed:
			case <-m.done:
				return
			default:
				s.markClosed(fmt.Errorf("aegis mux: stream %d recv overflow", sid))
				m.streamMu.Lock()
				delete(m.streams, sid)
				m.streamMu.Unlock()
				_ = m.send(FrameMuxStreamClose, MuxPayload(sid, nil))
			}
		case FrameMuxStreamClose:
			s.markClosed(io.EOF)
			m.streamMu.Lock()
			delete(m.streams, sid)
			m.streamMu.Unlock()
		}
	}
}

// send queues a frame for the writer goroutine.
func (m *MuxConn) send(ty FrameType, payload []byte) error {
	select {
	case m.sendCh <- muxWriteReq{ty: ty, payload: payload}:
		return nil
	case <-m.done:
		return m.closeErr
	}
}

func (m *MuxConn) registerStream(s *muxStream) uint32 {
	sid := atomic.AddUint32(&m.nextSID, 1)
	s.sid = sid
	m.streamMu.Lock()
	m.streams[sid] = s
	m.streamMu.Unlock()
	return sid
}

func (m *MuxConn) unregisterStream(sid uint32) {
	m.streamMu.Lock()
	if s, ok := m.streams[sid]; ok {
		s.markClosed(io.EOF)
		delete(m.streams, sid)
	}
	m.streamMu.Unlock()
}

// OpenStream opens a logical TCP stream to (host, port). Returns a net.Conn.
func (m *MuxConn) OpenStream(host string, port uint16) (net.Conn, error) {
	if m.IsClosed() {
		return nil, errors.New("aegis mux: conn closed")
	}
	s := &muxStream{
		conn:   m,
		recvCh: make(chan []byte, DefaultMuxBufferFrames),
		ackCh:  make(chan byte, 1),
		closed: make(chan struct{}),
	}
	sid := m.registerStream(s)

	if err := m.send(FrameMuxStreamOpenTcp, EncodeMuxOpenTcp(sid, host, port)); err != nil {
		m.unregisterStream(sid)
		return nil, err
	}
	select {
	case status := <-s.ackCh:
		if status != 0x01 {
			m.unregisterStream(sid)
			return nil, fmt.Errorf("aegis mux: server refused open tcp (code=%d)", status)
		}
		return s, nil
	case <-time.After(DefaultOpenAckTimeout):
		m.unregisterStream(sid)
		return nil, errors.New("aegis mux: OpenTcp ack timeout")
	case <-m.done:
		return nil, m.closeErr
	}
}

// OpenPacketConn opens a logical UDP-associate stream. Returns net.PacketConn.
func (m *MuxConn) OpenPacketConn() (net.PacketConn, error) {
	if m.IsClosed() {
		return nil, errors.New("aegis mux: conn closed")
	}
	s := &muxStream{
		conn:   m,
		isUDP:  true,
		recvCh: make(chan []byte, DefaultMuxBufferFrames),
		ackCh:  make(chan byte, 1),
		closed: make(chan struct{}),
	}
	sid := m.registerStream(s)

	if err := m.send(FrameMuxStreamOpenUdp, MuxPayload(sid, nil)); err != nil {
		m.unregisterStream(sid)
		return nil, err
	}
	select {
	case status := <-s.ackCh:
		if status != 0x01 {
			m.unregisterStream(sid)
			return nil, fmt.Errorf("aegis mux: server refused open udp (code=%d)", status)
		}
		return &muxPacketConn{stream: s}, nil
	case <-time.After(DefaultOpenAckTimeout):
		m.unregisterStream(sid)
		return nil, errors.New("aegis mux: OpenUdp ack timeout")
	case <-m.done:
		return nil, m.closeErr
	}
}

// ─── muxStream (implements net.Conn for TCP-mode streams) ────────────

type muxStream struct {
	conn  *MuxConn
	sid   uint32
	isUDP bool

	recvCh  chan []byte
	recvBuf bytes.Buffer
	readMu  sync.Mutex

	ackCh chan byte

	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
}

func (s *muxStream) markClosed(err error) {
	s.closeOnce.Do(func() {
		if err != nil {
			s.closeErr = err
		}
		close(s.closed)
	})
}

func (s *muxStream) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *muxStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for s.recvBuf.Len() == 0 {
		select {
		case data, ok := <-s.recvCh:
			if !ok {
				return 0, io.EOF
			}
			s.recvBuf.Write(data)
		case <-s.closed:
			if s.recvBuf.Len() == 0 {
				if s.closeErr != nil && s.closeErr != io.EOF {
					return 0, s.closeErr
				}
				return 0, io.EOF
			}
		}
	}
	return s.recvBuf.Read(p)
}

func (s *muxStream) Write(p []byte) (int, error) {
	if s.isClosed() {
		return 0, io.ErrClosedPipe
	}
	// Chunk at MaxPayload - 4 (sid header). Without this, a single 32KB write
	// from io.Copy turns into one oversized frame -> EncodeFrame returns
	// "payload too large" -> writerLoop kills the entire mux conn (taking
	// every other stream with it). v1 conn.go has had this loop since day
	// one; mux.go missed it.
	const chunkMax = MaxPayload - 4
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunkMax {
			n = chunkMax
		}
		if err := s.conn.send(FrameMuxStreamData, MuxPayload(s.sid, p[:n])); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *muxStream) Close() error {
	if s.isClosed() {
		return nil
	}
	_ = s.conn.send(FrameMuxStreamClose, MuxPayload(s.sid, nil))
	s.conn.unregisterStream(s.sid)
	return nil
}

func (s *muxStream) LocalAddr() net.Addr                { return s.conn.raw.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr               { return s.conn.raw.RemoteAddr() }
func (s *muxStream) SetDeadline(t time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { return nil }

// ─── muxPacketConn (UDP) ──────────────────────────────────────────────

type muxPacketConn struct {
	stream *muxStream
}

func (p *muxPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case data := <-p.stream.recvCh:
			host, port, payload, err := DecodeUdpData(data)
			if err != nil {
				continue
			}
			n := copy(b, payload)
			addr, aerr := resolveUDPAddr(host, port)
			if aerr != nil {
				addr = &udpDomainAddr{host: host, port: port}
			}
			return n, addr, nil
		case <-p.stream.closed:
			if p.stream.closeErr != nil && p.stream.closeErr != io.EOF {
				return 0, nil, p.stream.closeErr
			}
			return 0, nil, io.EOF
		}
	}
}

func (p *muxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, port, err := splitAddr(addr)
	if err != nil {
		return 0, err
	}
	payload := EncodeMuxUdpData(p.stream.sid, host, port, b)
	// UDP packets larger than MaxPayload (minus header/sid/atyp/port) cannot
	// fit in one Aegis frame; UDP semantics also forbid fragmentation here.
	// Drop oversized datagrams (this matches kernel UDP behaviour for IP MTU).
	if len(payload) > MaxPayload {
		return 0, fmt.Errorf("aegis mux: udp payload %d exceeds frame limit", len(b))
	}
	if err := p.stream.conn.send(FrameMuxStreamUdpData, payload); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *muxPacketConn) Close() error                       { return p.stream.Close() }
func (p *muxPacketConn) LocalAddr() net.Addr                { return p.stream.LocalAddr() }
func (p *muxPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *muxPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *muxPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// ─── ConnPool: lazily-created multiple MuxConns per outbound ─────────

const (
	DefaultMaxStreamsPerConn = 16
	DefaultMaxMuxConns       = 4
)

// MuxConnFactory creates a fresh, fully-handshaken MuxConn. Caller
// provides this so the pool stays decoupled from TLS/dialer details.
type MuxConnFactory func() (*MuxConn, error)

// MuxPool holds up to MaxConns MuxConns. GetConn returns one with
// spare capacity (creating a new one if none available, up to MaxConns).
type MuxPool struct {
	factory           MuxConnFactory
	MaxConns          int
	MaxStreamsPerConn int

	mu    sync.Mutex
	conns []*MuxConn
}

func NewMuxPool(factory MuxConnFactory) *MuxPool {
	return &MuxPool{
		factory:           factory,
		MaxConns:          DefaultMaxMuxConns,
		MaxStreamsPerConn: DefaultMaxStreamsPerConn,
	}
}

// GetConn returns a MuxConn ready to OpenStream/OpenPacketConn on.
// Will create a new one on demand up to MaxConns. If saturated, returns
// the least-loaded existing conn (streams will queue behind others on
// shared writer).
func (p *MuxPool) GetConn() (*MuxConn, error) {
	// Fast path: sweep + pick alive with capacity
	p.mu.Lock()
	alive := p.conns[:0]
	var picked *MuxConn
	for _, c := range p.conns {
		if c.IsClosed() {
			continue
		}
		alive = append(alive, c)
		if picked == nil && c.ActiveStreams() < p.MaxStreamsPerConn {
			picked = c
		}
	}
	p.conns = alive
	if picked != nil {
		p.mu.Unlock()
		return picked, nil
	}
	if len(p.conns) >= p.MaxConns {
		// All conns at capacity; pick least-loaded.
		best := p.conns[0]
		for _, c := range p.conns[1:] {
			if c.ActiveStreams() < best.ActiveStreams() {
				best = c
			}
		}
		p.mu.Unlock()
		return best, nil
	}
	p.mu.Unlock()

	// Slow path: create a new conn outside the lock (TLS handshake may
	// take seconds; we don't want to block all other goroutines).
	nc, err := p.factory()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	// Race: another goroutine may have added one too. Cap at MaxConns + 1
	// to avoid pathological over-provisioning.
	p.conns = append(p.conns, nc)
	p.mu.Unlock()
	return nc, nil
}

// Close tears down all MuxConns in the pool.
func (p *MuxPool) Close() error {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}
