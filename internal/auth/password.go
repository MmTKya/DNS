// Package auth handles who may administer the node.
//
// Passwords are hashed with argon2id, sessions are server-side and their
// tokens are stored hashed, and TOTP is available as a second factor.  The
// panel is same-origin, so sessions are plain cookies rather than JWTs: a
// bearer token in browser storage buys nothing here and gives up the ability
// to revoke a login.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters.
//
// These follow the OWASP minimum for argon2id (19 MiB, two passes).  The
// memory cost is what makes a stolen hash expensive to attack, and it is also
// what has to fit on a Raspberry Pi during a login, so it is not raised
// further.
const (
	argonMemory  = 19 * 1024 // KiB
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrInvalidHash means the stored string is not a hash this code wrote.
var ErrInvalidHash = errors.New("password hash is malformed")

// HashPassword returns an encoded argon2id hash.
//
// The encoding carries its own parameters, so raising the cost later does not
// invalidate existing passwords: old hashes keep verifying with the parameters
// they were made with.
func HashPassword(password string) (encoded string, err error) {
	salt := make([]byte, argonSaltLen)
	if _, err = rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches the encoded hash.
func VerifyPassword(password, encoded string) (ok bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}

	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}

	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))

	// Constant time: a timing difference here leaks how much of the hash
	// matched, which is enough to attack it byte by byte.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// randomToken returns a URL-safe random string with n bytes of entropy.
func randomToken(n int) (token string, err error) {
	buf := make([]byte, n)
	if _, err = rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
