// Package vpn manages the WireGuard tunnel that carries a household's
// filtering out of the house.
//
// This is the feature that makes the product follow you: a phone on mobile
// data resolves through this node, so the ad blocking, the malware filtering
// and the per-device policy do not stop at the front door. It also gives a
// roaming device a fixed address inside the tunnel, which is a far better
// handle for policy than a LAN address that changes with every lease.
package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the size of a WireGuard key in bytes.
const KeyLen = 32

// Key is a WireGuard key in its wire format.
type Key [KeyLen]byte

// String returns the base64 encoding WireGuard configuration files use.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// GeneratePrivateKey creates a private key.
//
// The clamping is part of Curve25519, not decoration: without it a private key
// is not a valid scalar and the handshake produces a shared secret neither side
// can reproduce.
func GeneratePrivateKey() (key Key, err error) {
	if _, err = rand.Read(key[:]); err != nil {
		return Key{}, fmt.Errorf("generating key: %w", err)
	}

	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// GeneratePresharedKey creates a symmetric key.
//
// It is layered on top of the handshake and is the reason a recorded session
// stays unreadable even if Curve25519 is broken later.
func GeneratePresharedKey() (key Key, err error) {
	if _, err = rand.Read(key[:]); err != nil {
		return Key{}, fmt.Errorf("generating preshared key: %w", err)
	}

	return key, nil
}

// PublicKey derives the public key for a private one.
func PublicKey(private Key) (public Key, err error) {
	derived, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, fmt.Errorf("deriving public key: %w", err)
	}

	copy(public[:], derived)

	return public, nil
}

// KeyPair is a private key and the public key derived from it.
type KeyPair struct {
	Private Key
	Public  Key
}

// GenerateKeyPair creates a keypair.
func GenerateKeyPair() (pair KeyPair, err error) {
	private, err := GeneratePrivateKey()
	if err != nil {
		return KeyPair{}, err
	}

	public, err := PublicKey(private)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{Private: private, Public: public}, nil
}

// ParseKey reads a base64-encoded key.
func ParseKey(encoded string) (key Key, err error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Key{}, fmt.Errorf("decoding key: %w", err)
	}

	if len(raw) != KeyLen {
		return Key{}, fmt.Errorf("key is %d bytes, want %d", len(raw), KeyLen)
	}

	copy(key[:], raw)

	return key, nil
}
