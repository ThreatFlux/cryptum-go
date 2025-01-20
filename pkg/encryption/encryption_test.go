package encryption

import (
	"bytes"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check that keys are not empty and are base64 encoded
	if len(privateKey) == 0 || !isBase64(privateKey) {
		t.Error("Invalid private key format")
	}
	if len(publicKey) == 0 || !isBase64(publicKey) {
		t.Error("Invalid public key format")
	}

	// Test key parsing
	privKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	pubKey, err := ParsePublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Verify key pair matches
	if !bytes.Equal(pubKey.N.Bytes(), privKey.PublicKey.N.Bytes()) {
		t.Error("Public key does not match private key")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	// Generate test keys
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	privKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	pubKey, err := ParsePublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty string",
			data: []byte(""),
		},
		{
			name: "Short string",
			data: []byte("Hello, World!"),
		},
		{
			name: "Long string",
			data: []byte(strings.Repeat("Long message for testing. ", 100)),
		},
		{
			name: "Binary data",
			data: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := EncryptBlob(tc.data, pubKey)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify format
			if len(encrypted) < 512+12+16 { // RSA(512) + Nonce(12) + Min tag size(16)
				t.Error("Encrypted data too short")
			}

			// Decrypt
			decrypted, err := DecryptBlob(encrypted, privKey)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Compare
			if !bytes.Equal(tc.data, decrypted) {
				t.Error("Decrypted data does not match original")
			}
		})
	}
}

func TestEncryptionErrors(t *testing.T) {
	_, publicKey, _ := GenerateKeyPair()
	pubKey, _ := ParsePublicKey(publicKey)

	testCases := []struct {
		name    string
		data    []byte
		key     *rsa.PublicKey
		wantErr bool
	}{
		{
			name:    "Nil data",
			data:    nil,
			key:     pubKey,
			wantErr: false, // nil data is valid, just encrypts empty bytes
		},
		{
			name:    "Nil key",
			data:    []byte("test"),
			key:     nil,
			wantErr: true,
		},
		{
			name:    "Valid input",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EncryptBlob(tc.data, tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("EncryptBlob() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecryptionErrors(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	privKey, _ := ParsePrivateKey(privateKey)

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty data",
			data: []byte{},
		},
		{
			name: "Short data",
			data: []byte("too short"),
		},
		{
			name: "Invalid format",
			data: make([]byte, 600), // Right size, wrong content
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecryptBlob(tc.data, privKey)
			if err == nil {
				t.Error("Expected error for invalid data")
			}
		})
	}
}

// Helper function to check if a string is base64 encoded
func isBase64(s string) bool {
	return len(s)%4 == 0 && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=") == ""
}
