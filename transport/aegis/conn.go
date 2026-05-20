package aegis

// Conn wraps a TLS-terminated net.Conn into a stream-oriented Aegis pipe.
// Read/Write surface looks like ordinary net.Conn from the caller's view;
// internally each Write becomes a sealed Data frame and Read drains frames
// into an internal buffer.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Conn is an Aegis stream layered on top of an existing net.Conn (typically
// a *tls.Conn). The first frames exchanged are Connect / ConnectAck; after
// that Read/Write transport arbitrary Data frames.
type Conn struct {
	raw     net.Conn
	sendAead *DirectedAead
	recvAead *DirectedAead

	writeMu sync.Mutex
	readMu  sync.Mutex

	readBuf bytes.Buffer // pending decoded payload bytes
	closed  bool
}

// Open performs the full handshake on the supplied net.Conn (already TLS-
// terminated), then sends a Connect frame for the requested target and
// waits for ConnectAck. On success, returns a *Conn ready for I/O.
func Open(c net.Conn, cfg ClientConfig, targetHost string, targetPort uint16) (*Conn, error) {
	keys, err := ClientHandshake(c, cfg)
	if err != nil {
		return nil, err
	}
	ac := &Conn{
		raw:      c,
		sendAead: NewDirectedAead(keys, C2S),
		recvAead: NewDirectedAead(keys, S2C),
	}

	// Send Connect frame.
	if err := WriteSealedFrame(c, ac.sendAead, Frame{
		Type:    FrameConnect,
		Payload: EncodeConnect(targetHost, targetPort),
	}); err != nil {
		c.Close()
		return nil, fmt.Errorf("aegis: send connect: %w", err)
	}

	// Wait for ConnectAck.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := ReadSealedFrame(c, ac.recvAead)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("aegis: read connect ack: %w", err)
	}
	if f.Type != FrameConnectAck {
		c.Close()
		return nil, fmt.Errorf("aegis: expected ConnectAck, got type=%d", f.Type)
	}
	if len(f.Payload) < 1 || f.Payload[0] != 0x01 {
		c.Close()
		code := -1
		if len(f.Payload) >= 1 {
			code = int(f.Payload[0])
		}
		return nil, fmt.Errorf("aegis: server refused connect (code=%d)", code)
	}
	return ac, nil
}

// Read drains decoded payload bytes from the next Data frame(s).
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readBuf.Len() == 0 {
		if c.closed {
			return 0, net.ErrClosed
		}
		f, err := ReadSealedFrame(c.raw, c.recvAead)
		if err != nil {
			return 0, err
		}
		switch f.Type {
		case FrameData:
			c.readBuf.Write(f.Payload)
		case FrameKeepAlive:
			// ignore
		case FrameClose:
			return 0, errors.New("aegis: peer closed stream")
		case FrameConnect, FrameConnectAck:
			return 0, fmt.Errorf("aegis: unexpected control frame type=%d mid-stream", f.Type)
		default:
			return 0, fmt.Errorf("aegis: unknown frame type=%d", f.Type)
		}
	}
	return c.readBuf.Read(p)
}

// Write sends p as one or more Data frames (chunked at MaxPayload).
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := WriteSealedFrame(c.raw, c.sendAead, Frame{
			Type:    FrameData,
			Payload: p[:n],
		}); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close gracefully signals end-of-stream + closes the underlying connection.
func (c *Conn) Close() error {
	c.writeMu.Lock()
	c.closed = true
	// Best-effort Close frame; ignore errors.
	_ = WriteSealedFrame(c.raw, c.sendAead, Frame{Type: FrameClose})
	c.writeMu.Unlock()
	return c.raw.Close()
}

// Standard net.Conn passthroughs.
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
