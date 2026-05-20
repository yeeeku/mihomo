package outbound

// Aegis-Stream outbound adapter for mihomo.
//
// Layered (outermost -> innermost):
//   TCP -> TLS 1.3 -> HTTP/1.1 Upgrade (disguised) -> Aegis frames
//
// Configuration (YAML):
//   - name: my-aegis-node
//     type: aegis
//     server: cdn.example.com
//     port: 8443
//     password: 8b76e3f0-a65d-4c2b-9e7a-1f4d3a02f9b5
//     server-pubkey-b64: 6jhU7m...........=     # 44-char base64 of 32-byte X25519 pub
//     sni: cdn.example.com                       # TLS SNI
//     host: cdn.example.com                      # HTTP Host header (disguise)
//     path: /chat                                # HTTP path (disguise)
//     skip-cert-verify: false
//     client-fingerprint: chrome                 # uTLS fingerprint: chrome|firefox|safari|ios|edge|random|...
//     udp: false                                 # UDP not supported in v1

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/aegis"
)

type Aegis struct {
	*Base
	option    *AegisOption
	serverPub [32]byte
}

type AegisOption struct {
	BasicOption
	Name              string `proxy:"name"`
	Server            string `proxy:"server"`
	Port              int    `proxy:"port"`
	Password          string `proxy:"password"`
	ServerPubkeyB64   string `proxy:"server-pubkey-b64"`
	SNI               string `proxy:"sni,omitempty"`
	Host              string `proxy:"host,omitempty"`
	Path              string `proxy:"path,omitempty"`
	SkipCertVerify    bool   `proxy:"skip-cert-verify,omitempty"`
	ClientFingerprint string `proxy:"client-fingerprint,omitempty"`
	UDP               bool   `proxy:"udp,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter -- wraps the raw dialed TCP
// connection in TLS, runs the Aegis handshake, sends a Connect frame
// targeting metadata's destination.
func (a *Aegis) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	sni := a.option.SNI
	if sni == "" {
		sni = a.option.Server
	}
	tlsCfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: a.option.SkipCertVerify,
	}

	// TLS with optional uTLS fingerprint. When client-fingerprint is set
	// (e.g. "chrome", "firefox", "safari", "ios", "random"), use uTLS so
	// the ClientHello mimics a real browser; otherwise fall back to the
	// stdlib crypto/tls.
	var tlsConn net.Conn
	if fp, ok := tlsC.GetFingerprint(a.option.ClientFingerprint); ok {
		uConn := tlsC.UClient(c, tlsC.UConfig(tlsCfg), fp)
		// Pin the ALPN to http/1.1 inside the uTLS extensions so the
		// Sec-WebSocket-Protocol carrier handshake we send next is
		// consistent with what a real browser would advertise.
		if err := tlsC.BuildWebsocketHandshakeState(uConn); err != nil {
			return nil, fmt.Errorf("aegis: build utls handshake state: %w", err)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("aegis: utls handshake: %w", err)
		}
		tlsConn = uConn
	} else {
		stdTLS := tls.Client(c, tlsCfg)
		if err := stdTLS.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("aegis: tls handshake: %w", err)
		}
		tlsConn = stdTLS
	}

	ephSk, _, err := aegis.GenerateEphemeralKeypair()
	if err != nil {
		return nil, fmt.Errorf("aegis: gen ephemeral: %w", err)
	}
	host := a.option.Host
	if host == "" {
		host = sni
	}
	path := a.option.Path
	if path == "" {
		path = "/"
	}
	cfg := aegis.ClientConfig{
		EphSk:      ephSk,
		ServerPub:  a.serverPub,
		UserSecret: aegis.DeriveUserSecret(a.option.Password),
		Host:       host,
		Path:       path,
	}

	targetHost, targetPort, err := metadataAddr(metadata)
	if err != nil {
		return nil, err
	}

	ac, err := aegis.Open(tlsConn, cfg, targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	return ac, nil
}

// DialContext implements C.ProxyAdapter.
func (a *Aegis) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := a.dialer.DialContext(ctx, "tcp", a.addr)
	if err != nil {
		return nil, fmt.Errorf("aegis dial %s: %w", a.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	streamed, err := a.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(streamed, a), nil
}

// ListenPacketContext: UDP not supported in v1.
func (a *Aegis) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("aegis: UDP not supported (v1)")
}

// SupportUOT implements C.ProxyAdapter (no UDP-over-TCP for now).
func (a *Aegis) SupportUOT() bool { return false }

// ProxyInfo implements C.ProxyAdapter.
func (a *Aegis) ProxyInfo() C.ProxyInfo {
	info := a.Base.ProxyInfo()
	info.DialerProxy = a.option.DialerProxy
	return info
}

// NewAegis constructs an Aegis adapter from validated options.
func NewAegis(option AegisOption) (*Aegis, error) {
	if option.Password == "" {
		return nil, errors.New("aegis: empty password")
	}
	if option.ServerPubkeyB64 == "" {
		return nil, errors.New("aegis: missing server-pubkey-b64")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(option.ServerPubkeyB64)
	if err != nil {
		return nil, fmt.Errorf("aegis: bad server-pubkey-b64: %w", err)
	}
	if len(pubBytes) != 32 {
		return nil, fmt.Errorf("aegis: server pubkey must decode to 32 bytes, got %d", len(pubBytes))
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	a := &Aegis{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Aegis,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	copy(a.serverPub[:], pubBytes)
	a.dialer = option.NewDialer(a.DialOptions())
	return a, nil
}

// metadataAddr extracts (host, port) from mihomo's C.Metadata.
func metadataAddr(m *C.Metadata) (string, uint16, error) {
	host := m.Host
	if host == "" {
		if m.DstIP.IsValid() {
			host = m.DstIP.String()
		}
	}
	if host == "" {
		return "", 0, errors.New("aegis: empty target host")
	}
	if m.DstPort == 0 {
		return "", 0, errors.New("aegis: empty target port")
	}
	return host, m.DstPort, nil
}
