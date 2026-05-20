// Package aegis implements the Aegis-Stream client-side wire protocol.
//
// Layered (outermost → innermost):
//   TCP
//   └── TLS 1.3 (client-side, normal cert verification or skip)
//       └── HTTP/1.1 Upgrade: websocket  (disguised handshake; X25519
//           ephemeral key + per-user fingerprint + nonce + MAC are split
//           across Sec-WebSocket-Key + Sec-WebSocket-Protocol)
//           └── Aegis Frames (ChaCha20-Poly1305 sealed; random padding;
//               first c→s frame is Connect with SOCKS5-style target,
//               first s→c frame is ConnectAck)
//
// This file: X25519 key exchange + Blake3-keyed KDF + 64-bit handshake blob.
// Mirrors src/crypto/kx.rs in the Rust reference implementation.
package aegis

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
	"lukechampine.com/blake3"
)

// BlobLen is the on-wire handshake blob:
//   client_eph_pub(32) || nonce(16) || ts_be(8) || user_fp(4) || mac(8) = 68
const BlobLen = 32 + 16 + 8 + 4 + 8

// SessionKeys derived from ECDH + nonce + K_user.
type SessionKeys struct {
	KeyC2S [32]byte // client→server payload AEAD
	KeyS2C [32]byte // server→client payload AEAD
	MacKey [32]byte // handshake MAC + future re-keys
}

// UserSecret = blake3::derive_key("aegis-stream/v1/user_secret", utf8(password))
// — the per-user 32-byte secret. Matches the Rust UserSecret type.
type UserSecret [32]byte

// DeriveUserSecret converts a V2Board password (typically a UUID) into a
// stable 32-byte secret via Blake3's KDF mode.
func DeriveUserSecret(password string) UserSecret {
	var out UserSecret
	blake3.DeriveKey(out[:], "aegis-stream/v1/user_secret", []byte(password))
	return out
}

// Fingerprint returns the 4-byte fingerprint server uses to look up the user.
func (u UserSecret) Fingerprint() [4]byte {
	var full [32]byte
	blake3.DeriveKey(full[:], "aegis-stream/v1/user_fp", u[:])
	var fp [4]byte
	copy(fp[:], full[:4])
	return fp
}

// RandomNonce returns a fresh 16-byte handshake nonce.
func RandomNonce() ([16]byte, error) {
	var n [16]byte
	_, err := rand.Read(n[:])
	return n, err
}

// BuildHandshakeBlob is the client-side handshake construction.
// Returns the 68-byte blob and the derived session keys.
//
// host/path must match exactly what the client will send in the HTTP request
// (used to bind the MAC to the disguise headers).
func BuildHandshakeBlob(
	clientEphSk *[32]byte,
	serverStaticPub *[32]byte,
	userSecret UserSecret,
	host, path string,
	tsUnix int64,
) (blob [BlobLen]byte, keys SessionKeys, err error) {
	nonce, err := RandomNonce()
	if err != nil {
		return blob, keys, err
	}

	// X25519: shared = curve25519(client_eph_sk, server_static_pub)
	shared, err := curve25519.X25519(clientEphSk[:], serverStaticPub[:])
	if err != nil {
		return blob, keys, err
	}

	// Derive client public key from ephemeral secret.
	clientPub, err := curve25519.X25519(clientEphSk[:], curve25519.Basepoint)
	if err != nil {
		return blob, keys, err
	}

	keys = deriveKeys(shared, nonce[:], userSecret[:])
	fp := userSecret.Fingerprint()

	// Layout
	copy(blob[0:32], clientPub)
	copy(blob[32:48], nonce[:])
	binary.BigEndian.PutUint64(blob[48:56], uint64(tsUnix))
	copy(blob[56:60], fp[:])
	mac := macHandshake(keys.MacKey, host, path, tsUnix, clientPub, nonce[:], fp[:])
	copy(blob[60:68], mac[:])
	return blob, keys, nil
}

// deriveKeys: shared || nonce || K_user → 3 separate 32B keys via Blake3 KDF.
func deriveKeys(shared, nonce, userSecret []byte) SessionKeys {
	ikm := make([]byte, 0, 32+16+32)
	ikm = append(ikm, shared...)
	ikm = append(ikm, nonce...)
	ikm = append(ikm, userSecret...)

	var keys SessionKeys
	blake3.DeriveKey(keys.KeyC2S[:], "aegis-stream/v1/key_c2s", ikm)
	blake3.DeriveKey(keys.KeyS2C[:], "aegis-stream/v1/key_s2c", ikm)
	blake3.DeriveKey(keys.MacKey[:], "aegis-stream/v1/mac", ikm)
	return keys
}

// macHandshake is the 8-byte truncated keyed Blake3 over (request-line ||
// host || ts_be || pubkey || nonce || user_fp). Bytes match the Rust impl.
func macHandshake(macKey [32]byte, host, path string, ts int64, pubKey, nonce, fp []byte) [8]byte {
	h := blake3.New(32, macKey[:])
	h.Write([]byte("GET "))
	h.Write([]byte(path))
	h.Write([]byte(" HTTP/1.1\nHost: "))
	h.Write([]byte(host))
	h.Write([]byte("\nTS: "))
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))
	h.Write(tsBuf[:])
	h.Write([]byte("\nPK: "))
	h.Write(pubKey)
	h.Write([]byte("\nN: "))
	h.Write(nonce)
	h.Write([]byte("\nFP: "))
	h.Write(fp)
	full := h.Sum(nil)
	var mac [8]byte
	copy(mac[:], full[:8])
	return mac
}

// GenerateEphemeralKeypair returns a fresh client-side X25519 keypair.
func GenerateEphemeralKeypair() (sk, pk [32]byte, err error) {
	if _, err = rand.Read(sk[:]); err != nil {
		return
	}
	// Per RFC 7748 clamp the secret.
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pkSlice, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	copy(pk[:], pkSlice)
	return
}

// ConstantTimeEqMac8 — constant-time comparison for the 8-byte MAC.
func ConstantTimeEqMac8(a, b [8]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// errors exported for callers
var (
	ErrBadBlobLen = errors.New("aegis: handshake blob wrong length")
	ErrBadMAC     = errors.New("aegis: handshake MAC mismatch")
)
