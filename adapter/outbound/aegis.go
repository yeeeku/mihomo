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
//     udp: true                                  # UDP-over-TCP via separate Aegis stream per UDP session

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

// StreamConnContext implements C.ProxyAdapter -- TCP stream path.
// Wraps the raw dialed TCP connection in TLS, runs the Aegis handshake,
// sends a Connect frame for metadata's destination.
func (a *Aegis) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	tlsConn, err := a.handshakeTLS(ctx, c)
	if err != nil {
		return nil, err
	}

	cfg, err := a.buildAegisClientConfig()
	if err != nil {
		return nil, err
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

// handshakeTLS wraps `c` in TLS (optionally uTLS). Used by both the TCP
// (StreamConnContext) and UDP (ListenPacketContext) paths so they share
// the same fingerprint masquerade.
func (a *Aegis) handshakeTLS(ctx context.Context, c net.Conn) (net.Conn, error) {
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

	if fp, ok := tlsC.GetFingerprint(a.option.ClientFingerprint); ok {
		uConn := tlsC.UClient(c, tlsC.UConfig(tlsCfg), fp)
		if err := tlsC.BuildWebsocketHandshakeState(uConn); err != nil {
			return nil, fmt.Errorf("aegis: build utls handshake state: %w", err)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("aegis: utls handshake: %w", err)
		}
		return uConn, nil
	}
	stdTLS := tls.Client(c, tlsCfg)
	if err := stdTLS.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("aegis: tls handshake: %w", err)
	}
	return stdTLS, nil
}

// buildAegisClientConfig generates a fresh ephemeral keypair and bundles
// it with the static per-node config into an aegis.ClientConfig.
func (a *Aegis) buildAegisClientConfig() (aegis.ClientConfig, error) {
	ephSk, _, err := aegis.GenerateEphemeralKeypair()
	if err != nil {
		return aegis.ClientConfig{}, fmt.Errorf("aegis: gen ephemeral: %w", err)
	}
	host := a.option.Host
	if host == "" {
		host = a.option.SNI
		if host == "" {
			host = a.option.Server
		}
	}
	path := a.option.Path
	if path == "" {
		path = "/"
	}
	return aegis.ClientConfig{
		EphSk:      ephSk,
		ServerPub:  a.serverPub,
		UserSecret: aegis.DeriveUserSecret(a.option.Password),
		Host:       host,
		Path:       path,
	}, nil
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

// ListenPacketContext implements C.ProxyAdapter: UDP-over-TCP tunnel.
// Opens a fresh TCP + TLS + Aegis handshake, sends a UdpAssociate frame
// (instead of Connect), then returns a net.PacketConn that wraps every
// Write/Read in a FrameUdpData carrying (host, port, payload).
func (a *Aegis) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	c, err := a.dialer.DialContext(ctx, "tcp", a.addr)
	if err != nil {
		return nil, fmt.Errorf("aegis udp dial %s: %w", a.addr, err)
	}

	tlsConn, err := a.handshakeTLS(ctx, c)
	if err != nil {
		c.Close()
		return nil, err
	}

	cfg, err := a.buildAegisClientConfig()
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	pc, err := aegis.OpenUDP(tlsConn, cfg)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return newPacketConn(pc, a), nil
}

// SupportUOT implements C.ProxyAdapter -- yes, UDP rides UoT frames.
func (a *Aegis) SupportUOT() bool { return true }

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
