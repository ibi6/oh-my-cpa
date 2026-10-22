package portal

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Validation errors carry a stable code the API maps to a response.
var (
	ErrInvalidUsername    = errors.New("invalid_username")
	ErrInvalidPassword    = errors.New("invalid_password")
	ErrInvalidDisplayName = errors.New("invalid_display_name")
	ErrInvalidKeyName     = errors.New("invalid_key_name")
	ErrInvalidExpiry      = errors.New("invalid_expiry")
	ErrInvalidNote        = errors.New("invalid_note")
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$`)

// NormalizeUsername trims and validates a sign-in name: 3-32 characters of
// letters, digits, '_', '.', '-', starting with a letter or digit. Usernames
// compare case-insensitively.
func NormalizeUsername(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if !usernamePattern.MatchString(value) {
		return "", ErrInvalidUsername
	}
	return value, nil
}

// ValidatePassword requires 8 to 128 characters.
func ValidatePassword(password string) error {
	count := utf8.RuneCountInString(password)
	if count < 8 || count > 128 || !utf8.ValidString(password) {
		return ErrInvalidPassword
	}
	return nil
}

func normalizeText(raw string, limit int, err error) (string, error) {
	value := strings.TrimSpace(raw)
	if utf8.RuneCountInString(value) > limit || !utf8.ValidString(value) {
		return "", err
	}
	for _, char := range value {
		if unicode.IsControl(char) || isBidiControl(char) {
			return "", err
		}
	}
	return value, nil
}

func isBidiControl(char rune) bool {
	return (char >= 0x202A && char <= 0x202E) || (char >= 0x2066 && char <= 0x2069) || char == 0x200E || char == 0x200F
}

// NormalizeDisplayName allows up to 64 printable characters; empty is allowed.
func NormalizeDisplayName(raw string) (string, error) {
	return normalizeText(raw, 64, ErrInvalidDisplayName)
}

// NormalizeNote allows up to 500 printable characters for the operator's note.
func NormalizeNote(raw string) (string, error) {
	return normalizeText(raw, 500, ErrInvalidNote)
}

// NormalizeKeyName requires 1 to 48 printable characters.
func NormalizeKeyName(raw string) (string, error) {
	value, err := normalizeText(raw, 48, ErrInvalidKeyName)
	if err != nil || value == "" {
		return "", ErrInvalidKeyName
	}
	return value, nil
}
