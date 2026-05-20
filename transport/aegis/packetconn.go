package aegis

// PacketConn: UDP-over-TCP on top of an Aegis stream.
//
// After a UdpAssociate handshake, every Write/Read on this conn is
// encoded as a FrameUdpData carrying the SOCKS5-style (atyp, addr, port,
// payload) tuple. This implements net.PacketConn so the standard mihomo
// outbound machinery (newPacketConn) can wrap it.

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PacketConn wraps a TLS-terminated net.Conn into a net.PacketConn,
// using Aegis UDP-over-TCP frames.
type PacketConn struct {
	raw      net.Conn
	sendAead *DirectedAead
	recvAead *DirectedAead

	writeMu sync.Mutex
	readMu  sync.Mutex
	closed  bool
}

// OpenUDP performs the Aegis handshake on `c` (already TLS-terminated),
// sends a FrameUdpAssociate, waits for FrameConnectAck, and returns a
// PacketConn ready for ReadFrom / WriteTo.
func OpenUDP(c net.Conn, cfg ClientConfig) (*PacketConn, error) {
	keys, err := ClientHandshake(c, cfg)
	if err != nil {
		return nil, err
	}
	pc := &PacketConn{
		raw:      c,
		sendAead: NewDirectedAead(keys, C2S),
		recvAead: NewDirectedAead(keys, S2C),
	}

	if err := WriteSealedFrame(c, pc.sendAead, Frame{Type: FrameUdpAssociate}); err != nil {
		c.Close()
		return nil, fmt.Errorf("aegis: send udp-associate: %w", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := ReadSealedFrame(c, pc.recvAead)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("aegis: read udp-associate ack: %w", err)
	}
	if f.Type != FrameConnectAck {
		c.Close()
		return nil, fmt.Errorf("aegis: expected ConnectAck for udp-associate, got type=%d", f.Type)
	}
	if len(f.Payload) < 1 || f.Payload[0] != 0x01 {
		c.Close()
		code := -1
		if len(f.Payload) >= 1 {
			code = int(f.Payload[0])
		}
		return nil, fmt.Errorf("aegis: server refused udp-associate (code=%d)", code)
	}
	return pc, nil
}

// ReadFrom blocks until one Aegis UdpData frame arrives, then surfaces it
// as a single net.PacketConn datagram.
func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	for {
		if p.closed {
			return 0, nil, net.ErrClosed
		}
		f, err := ReadSealedFrame(p.raw, p.recvAead)
		if err != nil {
			return 0, nil, err
		}
		switch f.Type {
		case FrameUdpData:
			host, port, payload, derr := DecodeUdpData(f.Payload)
			if derr != nil {
				return 0, nil, derr
			}
			n := copy(b, payload)
			addr, aerr := resolveUDPAddr(host, port)
			if aerr != nil {
				// Surface a synthetic addr if the source isn't a literal IP.
				addr = &udpDomainAddr{host: host, port: port}
			}
			return n, addr, nil
		case FrameKeepAlive:
			continue
		case FrameClose:
			return 0, nil, errors.New("aegis: peer closed udp stream")
		default:
			return 0, nil, fmt.Errorf("aegis: unexpected frame type=%d in udp stream", f.Type)
		}
	}
}

// WriteTo sends one UDP datagram to (host, port) by wrapping it in a
// FrameUdpData. addr may be a *net.UDPAddr (IP literal) or any net.Addr
// whose String() is "host:port".
func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}

	host, port, err := splitAddr(addr)
	if err != nil {
		return 0, err
	}
	payload := EncodeUdpData(host, port, b)
	if err := WriteSealedFrame(p.raw, p.sendAead, Frame{
		Type:    FrameUdpData,
		Payload: payload,
	}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close ends the UDP stream + closes the underlying connection.
func (p *PacketConn) Close() error {
	p.writeMu.Lock()
	p.closed = true
	_ = WriteSealedFrame(p.raw, p.sendAead, Frame{Type: FrameClose})
	p.writeMu.Unlock()
	return p.raw.Close()
}

func (p *PacketConn) LocalAddr() net.Addr                { return p.raw.LocalAddr() }
func (p *PacketConn) SetDeadline(t time.Time) error      { return p.raw.SetDeadline(t) }
func (p *PacketConn) SetReadDeadline(t time.Time) error  { return p.raw.SetReadDeadline(t) }
func (p *PacketConn) SetWriteDeadline(t time.Time) error { return p.raw.SetWriteDeadline(t) }

// ── helpers ──────────────────────────────────────────────────────────────

// udpDomainAddr is a synthetic net.Addr used when the remote host arrives
// as an FQDN rather than an IP literal. It implements net.Addr so it can
// be surfaced from ReadFrom without a DNS lookup.
type udpDomainAddr struct {
	host string
	port uint16
}

func (a *udpDomainAddr) Network() string { return "udp" }
func (a *udpDomainAddr) String() string {
	return net.JoinHostPort(a.host, fmt.Sprintf("%d", a.port))
}

func resolveUDPAddr(host string, port uint16) (net.Addr, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("not an IP literal")
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func splitAddr(addr net.Addr) (string, uint16, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String(), uint16(a.Port), nil
	case *udpDomainAddr:
		return a.host, a.port, nil
	}
	s := addr.String()
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("aegis: bad addr %q: %w", s, err)
	}
	port64, perr := strconv.ParseUint(portStr, 10, 16)
	if perr != nil {
		return "", 0, fmt.Errorf("aegis: bad port in %q", s)
	}
	if port64 == 0 {
		return "", 0, errors.New("aegis: zero port")
	}
	host = strings.Trim(host, "[]") // strip brackets for IPv6 literal
	return host, uint16(port64), nil
}
