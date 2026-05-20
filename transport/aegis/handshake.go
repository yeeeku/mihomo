package aegis

// Client-side handshake: build the disguised HTTP/1.1 Upgrade request,
// write it onto the TLS connection, read the server's 101 response.
// Mirrors src/client/connect.rs in the Rust reference.

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ClientConfig is the per-connection configuration handed to ClientHandshake.
type ClientConfig struct {
	// X25519 ephemeral secret key (32 bytes) — generated fresh per connection.
	EphSk [32]byte
	// Server's static X25519 public key (44 char base64 → 32 bytes).
	ServerPub [32]byte
	// Per-user secret derived from V2Board password via DeriveUserSecret.
	UserSecret UserSecret
	// Host header to send in the disguised request (must match panel's
	// node host_header config).
	Host string
	// HTTP path to send.
	Path string
	// User-Agent string (Chrome default if empty).
	UserAgent string
}

// ClientHandshake performs the Aegis handshake on an already-established
// TLS connection (caller dials TCP + completes TLS first). Returns:
//   - keys: session keys derived from the handshake (caller uses these to
//     construct the directed AEADs)
//   - first server response bytes after \r\n\r\n (rarely useful, returned
//     for diagnostics)
func ClientHandshake(c net.Conn, cfg ClientConfig) (keys SessionKeys, err error) {
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	}

	tsUnix := time.Now().Unix()
	blob, sessionKeys, err := BuildHandshakeBlob(
		&cfg.EphSk, &cfg.ServerPub, cfg.UserSecret,
		cfg.Host, cfg.Path, tsUnix,
	)
	if err != nil {
		return keys, fmt.Errorf("aegis: build handshake blob: %w", err)
	}
	keys = sessionKeys

	// Header carrier split:
	//   Sec-WebSocket-Key      = base64-std(nonce[16])           → 24 chars
	//   Sec-WebSocket-Protocol = "aegis." + base64url-no-pad(rest52)
	//     rest52 = pubkey32 || ts8 || fp4 || mac8
	nonceB64 := base64.StdEncoding.EncodeToString(blob[32:48])
	rest := make([]byte, 0, 52)
	rest = append(rest, blob[0:32]...)  // pubkey
	rest = append(rest, blob[48:56]...) // ts
	rest = append(rest, blob[56:60]...) // fp
	rest = append(rest, blob[60:68]...) // mac
	protoB64 := base64.RawURLEncoding.EncodeToString(rest)

	req := strings.Join([]string{
		"GET " + cfg.Path + " HTTP/1.1",
		"Host: " + cfg.Host,
		"User-Agent: " + cfg.UserAgent,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: " + nonceB64,
		"Sec-WebSocket-Protocol: aegis." + protoB64,
		"Pragma: no-cache",
		"Cache-Control: no-cache",
		"", "",
	}, "\r\n")

	if _, err = c.Write([]byte(req)); err != nil {
		return keys, fmt.Errorf("aegis: write handshake: %w", err)
	}

	// Read response until \r\n\r\n.
	if err = readResponse(c); err != nil {
		return keys, err
	}
	return keys, nil
}

// readResponse reads bytes from c until it finds \r\n\r\n, then verifies the
// status line starts with "HTTP/1.1 101". Bounded at 4KiB to avoid runaway.
func readResponse(c net.Conn) error {
	br := bufio.NewReaderSize(c, 4096)
	const maxHeaderBytes = 4096
	var buf []byte
	for len(buf) < maxHeaderBytes {
		b, err := br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("aegis: eof before handshake response")
			}
			return fmt.Errorf("aegis: read handshake response: %w", err)
		}
		buf = append(buf, b)
		if n := len(buf); n >= 4 &&
			buf[n-4] == '\r' && buf[n-3] == '\n' &&
			buf[n-2] == '\r' && buf[n-1] == '\n' {
			break
		}
	}
	if len(buf) >= maxHeaderBytes {
		return errors.New("aegis: handshake response too large")
	}
	resp := string(buf)
	if !strings.HasPrefix(resp, "HTTP/1.1 101") &&
		!strings.HasPrefix(resp, "HTTP/1.0 101") {
		// 401 means auth failed → server fell back to nginx / external TLS
		return fmt.Errorf("aegis: server did not switch protocols, response prefix: %q",
			firstLine(resp))
	}
	// If the bufio reader has any extra data (server sent the first
	// frame in the same TCP segment as the response), it would be inside
	// br's internal buffer. We don't currently support 0-RTT data on the
	// server side, but to be safe we drain it back into c. Skip for now —
	// reference Rust client doesn't either.
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		return s[:i]
	}
	return s
}
