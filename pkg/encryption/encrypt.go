package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"io"
)

// EncryptBlob encrypts data using hybrid RSA+AES encryption.
// The function uses RSA to encrypt an AES session key, then uses AES-GCM
// to encrypt the actual data. The result format is compatible with the Python cryptum library.
const maxDataSize = 1024 * 512 // 512KB max size

// For testing purposes
var (
	newEncryptCipher = aes.NewCipher
	newEncryptGCM    = cipher.NewGCM
	readFull         = io.ReadFull
	encryptOAEP      = rsa.EncryptOAEP
	randReader       = rand.Reader
)

func EncryptBlob(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key is required")
	}
	if data == nil {
		return nil, errors.New("data is required")
	}
	if len(data) == 0 {
		return nil, errors.New("data cannot be empty")
	}
	if len(data) > maxDataSize {
		return nil, errors.New("data too large")
	}

	// Generate random AES session key
	sessionKey := make([]byte, 32) // AES-256
	if _, err := readFull(randReader, sessionKey); err != nil {
		return nil, err
	}

	// Encrypt session key with RSA
	hash := sha512.New()
	encryptedSessionKey, err := encryptOAEP(hash, randReader, publicKey, sessionKey, nil)
	if err != nil {
		return nil, err
	}

	if len(encryptedSessionKey) != 512 {
		return nil, errors.New("invalid session key size")
	}

	// Create AES cipher
	block, err := newEncryptCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := newEncryptGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := readFull(randReader, nonce); err != nil {
		return nil, errors.New("failed to generate nonce")
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	if ciphertext == nil {
		return nil, errors.New("encryption failed")
	}

	// Format: [encrypted_session_key(512)][nonce(12)][ciphertext][tag(16)]
	// This matches the Python cryptum format
	totalSize := 512 + len(nonce) + len(ciphertext)
	if totalSize <= 512+len(nonce) {
		return nil, errors.New("invalid ciphertext size")
	}

	result := make([]byte, 0, totalSize)
	result = append(result, encryptedSessionKey...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// EncryptString is a convenience function that encrypts a string using hybrid RSA+AES encryption.
func EncryptString(data string, publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key is required")
	}
	return EncryptBlob([]byte(data), publicKey)
}
