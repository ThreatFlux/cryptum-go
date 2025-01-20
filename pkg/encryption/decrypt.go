package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
)

var (
	// ErrInvalidData indicates that the encrypted data is not in the expected format
	ErrInvalidData = errors.New("invalid encrypted data format")
	// ErrDecryptionFailed indicates a failure during the decryption process
	ErrDecryptionFailed = errors.New("decryption failed")
)

// DecryptBlob decrypts data that was encrypted using hybrid RSA+AES encryption.
// The data format must match the Python cryptum library:
// [encrypted_session_key(512)][nonce(12)][ciphertext][tag(16)]
func DecryptBlob(encryptedData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if len(encryptedData) < 512+12+16 { // Minimum length check
		return nil, ErrInvalidData
	}

	// Extract components
	encryptedSessionKey := encryptedData[:512]
	nonce := encryptedData[512:524]   // 12 bytes for GCM nonce
	ciphertext := encryptedData[524:] // Remaining data includes ciphertext and tag

	// Decrypt session key
	hash := sha512.New()
	sessionKey, err := rsa.DecryptOAEP(hash, nil, privateKey, encryptedSessionKey, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
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

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptToString is a convenience function that decrypts data and returns it as a string.
func DecryptToString(encryptedData []byte, privateKey *rsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is required")
	}

	decrypted, err := DecryptBlob(encryptedData, privateKey)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
