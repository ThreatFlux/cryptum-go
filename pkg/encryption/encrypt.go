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
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, err
	}

	// Encrypt session key with RSA
	hash := sha512.New()
	encryptedSessionKey, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, sessionKey, nil)
	if err != nil {
		return nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Format: [encrypted_session_key(512)][nonce(12)][ciphertext][tag(16)]
	// This matches the Python cryptum format
	result := make([]byte, 0, 512+len(nonce)+len(ciphertext))
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
