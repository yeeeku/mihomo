package aegis

// Aegis-Stream frame format. Mirrors src/frame.rs + src/crypto/aead.rs.
//
// Plaintext layout:
//   +------+---------------+---------------+----------+----------+
//   | type | payload_len   | padding_len   | payload  | padding  |
//   | u8   | u16 BE        | u16 BE        | N bytes  | M bytes  |
//   +------+---------------+---------------+----------+----------+
//
// Wire layout (after AEAD seal):
//   +-------------------+-----------------------------+
//   | ct_len (BE u16)   | ciphertext + 16-byte tag    |
//   +-------------------+-----------------------------+

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand"
	"net"

	"github.com/metacubex/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

type FrameType byte

const (
	// v1 (single-stream)
	FrameData         FrameType = 0x01
	FrameKeepAlive    FrameType = 0x02
	FrameClose        FrameType = 0x03
	FrameConnect      FrameType = 0x04
	FrameConnectAck   FrameType = 0x05
	FrameUdpAssociate FrameType = 0x06
	FrameUdpData      FrameType = 0x07

	// v2 (mux: many logical streams per TLS+Aegis conn).
	// For all Mux* frame types, the FIRST 4 BYTES of payload = stream_id (u32 BE).
	FrameMuxStreamOpenTcp FrameType = 0x10 // c→s [sid][atyp,addr,port]
	FrameMuxStreamOpenAck FrameType = 0x11 // s→c [sid][status]
	FrameMuxStreamData    FrameType = 0x12 // ↔   [sid][bytes]
	FrameMuxStreamClose   FrameType = 0x13 // ↔   [sid]
	FrameMuxStreamOpenUdp FrameType = 0x14 // c→s [sid]
	FrameMuxStreamUdpData FrameType = 0x15 // ↔   [sid][atyp,addr,port][udp_data]
	FrameMuxKeepAlive     FrameType = 0x16 // (sid=0, empty payload)
	FrameMuxGoAway        FrameType = 0x17 // (sid=0, empty payload)
)

const (
	HeaderLen  = 5
	TagLen     = 16
	MinPad     = 1
	MaxPad     = 512
	MaxPayload = 16 * 1024
	MaxFramePT = HeaderLen + MaxPayload + MaxPad
	MaxFrameCT = MaxFramePT + TagLen
)

// Frame is the decoded plaintext content of one Aegis frame.
type Frame struct {
	Type    FrameType
	Payload []byte
}

// Direction labels which side of the bytestream this AEAD is for.
type Direction int

const (
	C2S Direction = iota // client→server
	S2C                  // server→client
)

// Per-direction AAD strings (matches Rust constants).
var (
	AADc2s = []byte("aegis/c2s")
	AADs2c = []byte("aegis/s2c")
)

// DirectedAead wraps ChaCha20-Poly1305 with a monotonic per-direction nonce
// constructed from a Blake3-derived IV prefix XORed with the counter.
type DirectedAead struct {
	aead     cipher.AEAD
	ivPrefix [12]byte
	counter  uint64
	aad      []byte
}

// NewDirectedAead constructs an AEAD bound to one direction of the stream.
func NewDirectedAead(keys SessionKeys, dir Direction) *DirectedAead {
	var key []byte
	var label string
	var aad []byte
	switch dir {
	case C2S:
		key, label, aad = keys.KeyC2S[:], "aegis-stream/v1/iv_c2s", AADc2s
	case S2C:
		key, label, aad = keys.KeyS2C[:], "aegis-stream/v1/iv_s2c", AADs2c
	default:
		panic("aegis: unknown Direction")
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		// 32-byte keys cannot fail; impossible state
		panic("aegis: chacha20poly1305.New: " + err.Error())
	}
	d := &DirectedAead{aead: c, aad: aad}
	var iv [32]byte
	blake3.DeriveKey(iv[:], label, key)
	copy(d.ivPrefix[:], iv[:12])
	return d
}

func (d *DirectedAead) nextNonce() [12]byte {
	var n [12]byte
	copy(n[:], d.ivPrefix[:])
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], d.counter)
	for i := 0; i < 8; i++ {
		n[4+i] ^= ctr[i]
	}
	d.counter++
	return n
}

// Seal returns ciphertext+tag for the given plaintext.
func (d *DirectedAead) Seal(plaintext []byte) []byte {
	nonce := d.nextNonce()
	return d.aead.Seal(nil, nonce[:], plaintext, d.aad)
}

// Open decrypts ciphertext+tag and returns plaintext.
func (d *DirectedAead) Open(ciphertext []byte) ([]byte, error) {
	nonce := d.nextNonce()
	return d.aead.Open(nil, nonce[:], ciphertext, d.aad)
}

// EncodeFrame produces the plaintext byte representation of a frame
// (type, lens, payload, padding). Padding is random 1..=512 bytes.
func EncodeFrame(ty FrameType, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, errors.New("aegis: payload too large")
	}
	padLen := MinPad + mathrand.Intn(MaxPad-MinPad+1)
	buf := make([]byte, HeaderLen+len(payload)+padLen)
	buf[0] = byte(ty)
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	binary.BigEndian.PutUint16(buf[3:5], uint16(padLen))
	copy(buf[5:5+len(payload)], payload)
	if _, err := rand.Read(buf[5+len(payload):]); err != nil {
		return nil, err
	}
	return buf, nil
}

// DecodeFrame parses an Aegis plaintext frame.
func DecodeFrame(buf []byte) (Frame, error) {
	if len(buf) < HeaderLen {
		return Frame{}, errors.New("aegis: short frame")
	}
	ty := FrameType(buf[0])
	payloadLen := int(binary.BigEndian.Uint16(buf[1:3]))
	padLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if padLen < MinPad || padLen > MaxPad {
		return Frame{}, errors.New("aegis: bad padding length")
	}
	if len(buf) < HeaderLen+payloadLen+padLen {
		return Frame{}, errors.New("aegis: truncated frame")
	}
	return Frame{
		Type:    ty,
		Payload: append([]byte(nil), buf[HeaderLen:HeaderLen+payloadLen]...),
	}, nil
}

// WriteSealedFrame: seal + length-prefixed write.
func WriteSealedFrame(w io.Writer, aead *DirectedAead, f Frame) error {
	pt, err := EncodeFrame(f.Type, f.Payload)
	if err != nil {
		return err
	}
	ct := aead.Seal(pt)
	if len(ct) > 0xFFFF {
		return errors.New("aegis: ciphertext > u16 max")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(ct)
	return err
}

// ReadSealedFrame: read length, ciphertext, AEAD-open, decode plaintext.
func ReadSealedFrame(r io.Reader, aead *DirectedAead) (Frame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < TagLen || n > MaxFrameCT {
		return Frame{}, errors.New("aegis: ciphertext length out of range")
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(r, ct); err != nil {
		return Frame{}, err
	}
	pt, err := aead.Open(ct)
	if err != nil {
		return Frame{}, err
	}
	return DecodeFrame(pt)
}

// EncodeConnect builds the payload of a FrameConnect:
//
//	atyp(1) | addr | port(u16 BE)
//	atyp = 1 ipv4 (4 bytes)
//	atyp = 3 domain (1-byte length + bytes)
//	atyp = 4 ipv6 (16 bytes)
func EncodeConnect(host string, port uint16) []byte {
	out := make([]byte, 0, 2+len(host)+2)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 1)
			out = append(out, v4...)
		} else {
			out = append(out, 4)
			out = append(out, ip.To16()...)
		}
	} else {
		n := len(host)
		if n > 255 {
			n = 255
		}
		out = append(out, 3, byte(n))
		out = append(out, host[:n]...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	out = append(out, p[:]...)
	return out
}

// EncodeUdpData builds the payload of a FrameUdpData:
//
//	atyp(1) | addr | port(u16 BE) | udp_payload
//
// Same atyp encoding as EncodeConnect; trailing bytes are the raw UDP datagram.
func EncodeUdpData(host string, port uint16, payload []byte) []byte {
	header := EncodeConnect(host, port)
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out
}

// DecodeUdpData parses a FrameUdpData payload back into (host, port, udp_payload).
func DecodeUdpData(buf []byte) (string, uint16, []byte, error) {
	if len(buf) < 1 {
		return "", 0, nil, errors.New("aegis: empty UdpData payload")
	}
	atyp := buf[0]
	var (
		host    string
		off     int
	)
	switch atyp {
	case 1:
		if len(buf) < 1+4+2 {
			return "", 0, nil, errors.New("aegis: short v4 UdpData")
		}
		host = net.IP(buf[1:5]).String()
		off = 1 + 4
	case 3:
		if len(buf) < 2 {
			return "", 0, nil, errors.New("aegis: short domain UdpData")
		}
		n := int(buf[1])
		if len(buf) < 2+n+2 {
			return "", 0, nil, errors.New("aegis: short domain UdpData")
		}
		host = string(buf[2 : 2+n])
		off = 2 + n
	case 4:
		if len(buf) < 1+16+2 {
			return "", 0, nil, errors.New("aegis: short v6 UdpData")
		}
		host = net.IP(buf[1:17]).String()
		off = 1 + 16
	default:
		return "", 0, nil, errors.New("aegis: bad atyp in UdpData")
	}
	if len(buf) < off+2 {
		return "", 0, nil, errors.New("aegis: missing port in UdpData")
	}
	port := binary.BigEndian.Uint16(buf[off : off+2])
	off += 2
	return host, port, buf[off:], nil
}

// ── v2 mux helpers ─────────────────────────────────────────────────────

// IsMux reports whether the frame type belongs to the v2 mux protocol
// (first 4 bytes of payload = stream_id).
func (t FrameType) IsMux() bool {
	switch t {
	case FrameMuxStreamOpenTcp, FrameMuxStreamOpenAck, FrameMuxStreamData,
		FrameMuxStreamClose, FrameMuxStreamOpenUdp, FrameMuxStreamUdpData,
		FrameMuxKeepAlive, FrameMuxGoAway:
		return true
	}
	return false
}

// MuxPayload builds a mux frame payload: 4-byte stream_id followed by tail.
func MuxPayload(streamID uint32, tail []byte) []byte {
	out := make([]byte, 4+len(tail))
	binary.BigEndian.PutUint32(out[:4], streamID)
	copy(out[4:], tail)
	return out
}

// SplitStreamID pulls a 4-byte stream_id off the front of a mux payload.
func SplitStreamID(buf []byte) (uint32, []byte, error) {
	if len(buf) < 4 {
		return 0, nil, errors.New("aegis: mux frame missing stream_id")
	}
	return binary.BigEndian.Uint32(buf[:4]), buf[4:], nil
}

// EncodeMuxOpenTcp builds an OpenTcp payload: [sid][atyp,addr,port].
func EncodeMuxOpenTcp(streamID uint32, host string, port uint16) []byte {
	return MuxPayload(streamID, EncodeConnect(host, port))
}

// EncodeMuxOpenAck: [sid][status:u8].
func EncodeMuxOpenAck(streamID uint32, status byte) []byte {
	out := make([]byte, 5)
	binary.BigEndian.PutUint32(out[:4], streamID)
	out[4] = status
	return out
}

// EncodeMuxUdpData: [sid][atyp,addr,port][udp_data].
func EncodeMuxUdpData(streamID uint32, host string, port uint16, data []byte) []byte {
	return MuxPayload(streamID, EncodeUdpData(host, port, data))
}

// DecodeMuxUdpData: -> (sid, host, port, data).
func DecodeMuxUdpData(buf []byte) (uint32, string, uint16, []byte, error) {
	sid, rest, err := SplitStreamID(buf)
	if err != nil {
		return 0, "", 0, nil, err
	}
	host, port, data, err := DecodeUdpData(rest)
	return sid, host, port, data, err
}
