package twofa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"io"
	"time"

	"github.com/go-make-bytes/redmine-gateway/internal/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/pbkdf2"
)

// TOTPService handles TOTP generation, validation, and encryption
type TOTPService struct {
	config *config.Config
}

// NewTOTPService creates a new TOTP service instance
func NewTOTPService(cfg *config.Config) *TOTPService {
	return &TOTPService{
		config: cfg,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (s *TOTPService) GenerateSecret(accountName string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.TwoFactor.TOTP.Issuer,
		AccountName: accountName,
		Period:      uint(s.config.TwoFactor.TOTP.Period),
		Digits:      otp.Digits(s.config.TwoFactor.TOTP.Digits),
		Algorithm:   otp.AlgorithmSHA1, // Standard TOTP uses SHA1
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key, nil
}

// GenerateQRCodeURL generates a QR code as a base64-encoded PNG data URL
func (s *TOTPService) GenerateQRCodeURL(key *otp.Key) (string, error) {
	// Convert the key to an image (200x200 pixels)
	img, err := key.Image(200, 200)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code image: %w", err)
	}

	// Encode as PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("failed to encode QR code as PNG: %w", err)
	}

	// Convert to base64 data URL
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	dataURL := "data:image/png;base64," + b64

	return dataURL, nil
}

// ValidateCode validates a TOTP code with time drift support
func (s *TOTPService) ValidateCode(secret, code string) bool {
	// totp.Validate handles time drift automatically (±1 period by default)
	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    uint(s.config.TwoFactor.TOTP.Period),
			Skew:      1, // Allow ±1 time period (30s skew)
			Digits:    otp.Digits(s.config.TwoFactor.TOTP.Digits),
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return err == nil && valid
}

// getCurrentTime returns current time (wrapper for testing)
func (s *TOTPService) getCurrentTime() time.Time {
	return time.Now()
}

// EncryptSecret encrypts a TOTP secret using AES-256-CBC (Redmine compatible)
// If REDMINE_SECRET_KEY_BASE is not configured, returns the secret as plain text (like Redmine 6.x)
func (s *TOTPService) EncryptSecret(secret string) (string, error) {
	// If no secret key base is configured, store as plain text (Redmine 6.x behavior)
	if s.config.Redmine.SecretKeyBase == "" {
		return secret, nil
	}

	// Derive encryption key using PBKDF2 (matching Rails' key derivation)
	// Rails uses 65536 iterations for PBKDF2-SHA256
	salt := []byte("encrypted attribute") // Rails default salt
	key := pbkdf2.Key([]byte(s.config.Redmine.SecretKeyBase), salt, 65536, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// PKCS#7 padding
	plaintext := []byte(secret)
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt using CBC mode
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// Prepend IV to ciphertext and encode as base64
	result := append(iv, ciphertext...)
	encoded := base64.StdEncoding.EncodeToString(result)

	return encoded, nil
}

// DecryptSecret decrypts a TOTP secret using AES-256-CBC (Redmine compatible)
// If the secret is already in plain text (base32 format), it returns it as-is
func (s *TOTPService) DecryptSecret(encrypted string) (string, error) {
	// Check if the secret is already in plain text (base32 format used by TOTP)
	// Base32 secrets are typically 16-32 characters, all uppercase alphanumeric
	if isBase32Secret(encrypted) {
		return encrypted, nil
	}

	// If not base32, try to decrypt (for older encrypted versions)
	if s.config.Redmine.SecretKeyBase == "" {
		// If no secret key is configured but we have a base32-looking string,
		// assume it's plain text
		return encrypted, nil
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		// If base64 decode fails, it might be plain text
		if isBase32Secret(encrypted) {
			return encrypted, nil
		}
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Extract IV (first 16 bytes)
	if len(data) < aes.BlockSize {
		return "", errors.New("encrypted data too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	// Derive decryption key (same as encryption)
	salt := []byte("encrypted attribute")
	key := pbkdf2.Key([]byte(s.config.Redmine.SecretKeyBase), salt, 65536, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt using CBC mode
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of block size")
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return "", errors.New("invalid padding")
	}
	// Verify all padding bytes are correct
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return "", errors.New("invalid padding bytes")
		}
	}
	plaintext = plaintext[:len(plaintext)-padding]

	return string(plaintext), nil
}

// isBase32Secret checks if a string looks like a base32-encoded TOTP secret
func isBase32Secret(s string) bool {
	// TOTP secrets are typically 16-32 characters
	if len(s) < 16 || len(s) > 128 {
		return false
	}

	// Base32 alphabet is A-Z and 2-7 (uppercase)
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=') {
			return false
		}
	}

	return true
}
