// Package portal is the customer portal's domain logic (ADR 0105): customer
// accounts and passwords, sessions, gateway keys and their synchronisation into
// CPA's access.api-keys. Storage belongs to internal/repository and HTTP to
// internal/api; this package holds the rules between them.
package portal

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// KeyPrefix starts every customer key, so a key is recognisable in a client's
// configuration and the secret scanners can match it.
const KeyPrefix = "sk-omc-"

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// PasswordIterations is the PBKDF2-SHA256 work factor for new hashes (OWASP's
// 2023 recommendation). The count is stored in each hash, so raising it later
// leaves existing hashes verifiable. Tests lower it.
var PasswordIterations = 600_000

const passwordScheme = "pbkdf2-sha256"

var errMalformedHash = errors.New("malformed password hash")

func randomBase62(length int) (string, error) {
	var builder strings.Builder
	builder.Grow(length)
	limit := big.NewInt(int64(len(base62Alphabet)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generate random text: %w", err)
		}
		builder.WriteByte(base62Alphabet[n.Int64()])
	}
	return builder.String(), nil
}

// NewKeySecret returns a fresh customer key: the prefix and 40 base62
// characters (about 238 bits).
func NewKeySecret() (string, error) {
	body, err := randomBase62(40)
	if err != nil {
		return "", err
	}
	return KeyPrefix + body, nil
}

// KeyDisplayParts is what the portal keeps of a key besides its fingerprint:
// the recognisable head and the last four characters.
func KeyDisplayParts(secret string) (prefix, last4 string) {
	body := strings.TrimPrefix(secret, KeyPrefix)
	head := body
	if len(head) > 4 {
		head = head[:4]
	}
	tail := body
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return KeyPrefix + head, tail
}

// NewInviteCode returns a fresh invite code.
func NewInviteCode() (string, error) {
	body, err := randomBase62(20)
	if err != nil {
		return "", err
	}
	return "omc-inv-" + body, nil
}

// NewSessionToken returns a fresh opaque cookie value.
func NewSessionToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// HashToken is the stored identity of a session token or invite code. These
// are high-entropy random values, so an unkeyed SHA-256 is enough: there is
// nothing to guess.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// HashPassword derives a storable hash in the form
// pbkdf2-sha256$<iterations>$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, PasswordIterations, 32)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return strings.Join([]string{
		passwordScheme,
		strconv.Itoa(PasswordIterations),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	}, "$"), nil
}

// VerifyPassword reports whether password matches a stored hash.
func VerifyPassword(stored, password string) bool {
	ok, err := verifyPassword(stored, password)
	return err == nil && ok
}

func verifyPassword(stored, password string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return false, errMalformedHash
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > 10_000_000 {
		return false, errMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, errMalformedHash
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) == 0 {
		return false, errMalformedHash
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(derived, expected) == 1, nil
}

// dummyHash is verified against when a username does not exist, so a failed
// sign-in takes the same time whether or not the account exists.
var dummyHash = func() string {
	hash, err := HashPassword("omc-portal-timing-equaliser")
	if err != nil {
		return passwordScheme + "$1$AAAA$AAAA"
	}
	return hash
}
