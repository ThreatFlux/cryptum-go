package encryption

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type errorReader struct {
	readCount int
	failAfter int
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	r.readCount++
	if r.readCount > r.failAfter {
		return 0, errors.New("simulated read error")
	}
	return rand.Read(p)
}

func TestKeyGeneration(t *testing.T) {
	// Save original rand.Reader
	oldReader := rand.Reader
	defer func() { rand.Reader = oldReader }()

	// Test key generation failure
	t.Run("Generation failure", func(t *testing.T) {
		rand.Reader = &errorReader{failAfter: 0}
		_, _, err := GenerateKeyPair()
		if err == nil {
			t.Error("Expected error when random number generator fails")
		}
	})

	// Reset reader for successful tests
	rand.Reader = oldReader

	// Test multiple key generations to ensure consistency
	for i := 0; i < 5; i++ {
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

		// Decode base64 keys
		privBytes, err := base64.StdEncoding.DecodeString(privateKey)
		if err != nil {
			t.Errorf("Failed to decode private key: %v", err)
		}
		pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
		if err != nil {
			t.Errorf("Failed to decode public key: %v", err)
		}

		// Convert to string for checking format
		privStr := string(privBytes)
		pubStr := string(pubBytes)

		// Verify key format - PEM encoded keys
		if !strings.Contains(privStr, "-----BEGIN RSA PRIVATE KEY-----") {
			t.Errorf("Private key has incorrect format: %s", privStr)
		}
		if !strings.Contains(privStr, "-----END RSA PRIVATE KEY-----") {
			t.Errorf("Private key missing end marker: %s", privStr)
		}
		if !strings.Contains(pubStr, "-----BEGIN RSA PUBLIC KEY-----") {
			t.Errorf("Public key has incorrect format: %s", pubStr)
		}
		if !strings.Contains(pubStr, "-----END RSA PUBLIC KEY-----") {
			t.Errorf("Public key missing end marker: %s", pubStr)
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

		// Test key size
		if privKey.Size() != 512 {
			t.Errorf("Private key has wrong size: got %d, want 512", privKey.Size())
		}
		if pubKey.Size() != 512 {
			t.Errorf("Public key has wrong size: got %d, want 512", pubKey.Size())
		}
	}
}

func TestKeyParsingErrors(t *testing.T) {
	testCases := []struct {
		name        string
		private     string
		public      string
		wantPrivErr bool
		wantPubErr  bool
	}{
		{
			name:        "Empty keys",
			private:     "",
			public:      "",
			wantPrivErr: true,
			wantPubErr:  true,
		},
		{
			name:        "Invalid base64",
			private:     "not-base64!",
			public:      "also-not-base64!",
			wantPrivErr: true,
			wantPubErr:  true,
		},
		{
			name:        "Invalid key data",
			private:     "SGVsbG8sIFdvcmxkIQ==", // "Hello, World!" in base64
			public:      "SGVsbG8sIFdvcmxkIQ==",
			wantPrivErr: true,
			wantPubErr:  true,
		},
		{
			name:        "Invalid PEM format",
			private:     "LS0tLS1CRUdJTiBJTlZBTElEIEtFWS0tLS0tCg==",
			public:      "LS0tLS1CRUdJTiBJTlZBTElEIEtFWS0tLS0tCg==",
			wantPrivErr: true,
			wantPubErr:  true,
		},
		{
			name:        "Malformed base64",
			private:     "SGVsbG8=====",
			public:      "V29ybGQ=====",
			wantPrivErr: true,
			wantPubErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrivateKey(tc.private)
			if (err != nil) != tc.wantPrivErr {
				t.Errorf("ParsePrivateKey() error = %v, wantErr %v", err, tc.wantPrivErr)
			}

			_, err = ParsePublicKey(tc.public)
			if (err != nil) != tc.wantPubErr {
				t.Errorf("ParsePublicKey() error = %v, wantErr %v", err, tc.wantPubErr)
			}
		})
	}
}

func TestEncryptionDecryption(t *testing.T) {
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
		{
			name: "Maximum size",
			data: bytes.Repeat([]byte("a"), maxDataSize),
		},
		{
			name: "Single byte",
			data: []byte{1},
		},
		{
			name: "UTF-8 characters",
			data: []byte("Hello, 世界! ¡Hola, мир! 👋🌍"),
		},
		{
			name: "Special characters",
			data: []byte("!@#$%^&*()_+-=[]{}|;:,.<>?"),
		},
		{
			name: "Mixed content",
			data: bytes.Join([][]byte{
				[]byte("Regular text"),
				{0, 1, 2, 3},
				[]byte("🌟 Unicode"),
				{255, 254, 253},
			}, []byte(" ")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test blob encryption/decryption
			encrypted, err := EncryptBlob(tc.data, pubKey)
			if err != nil {
				t.Fatalf("EncryptBlob failed: %v", err)
			}

			decrypted, err := DecryptBlob(encrypted, privKey)
			if err != nil {
				t.Fatalf("DecryptBlob failed: %v", err)
			}

			if !bytes.Equal(tc.data, decrypted) {
				t.Error("Decrypted blob does not match original")
			}

			// Test string encryption/decryption
			if tc.name != "Binary data" {
				encryptedStr, err := EncryptString(string(tc.data), pubKey)
				if err != nil {
					t.Fatalf("EncryptString failed: %v", err)
				}

				decryptedStr, err := DecryptToString(encryptedStr, privKey)
				if err != nil {
					t.Fatalf("DecryptToString failed: %v", err)
				}

				if decryptedStr != string(tc.data) {
					t.Error("Decrypted string does not match original")
				}
			}
		})
	}
}

func TestEncryptionErrors(t *testing.T) {
	_, publicKey, _ := GenerateKeyPair()
	pubKey, _ := ParsePublicKey(publicKey)

	// Save original rand.Reader
	oldReader := rand.Reader
	defer func() { rand.Reader = oldReader }()

	testCases := []struct {
		name    string
		data    []byte
		key     *rsa.PublicKey
		wantErr bool
		setup   func()
	}{
		{
			name:    "Nil data",
			data:    nil,
			key:     pubKey,
			wantErr: true,
		},
		{
			name:    "Empty data",
			data:    []byte{},
			key:     pubKey,
			wantErr: true,
		},
		{
			name:    "Nil key",
			data:    []byte("test"),
			key:     nil,
			wantErr: true,
		},
		{
			name:    "Data too large",
			data:    bytes.Repeat([]byte("a"), maxDataSize+1),
			key:     pubKey,
			wantErr: true,
		},
		{
			name:    "Session key generation failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				rand.Reader = &errorReader{failAfter: 0}
			},
		},
		{
			name:    "Nonce generation failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				rand.Reader = &errorReader{failAfter: 1}
			},
		},
		{
			name:    "RSA encryption failure",
			data:    []byte("test"),
			key:     &rsa.PublicKey{N: nil, E: 0}, // Invalid public key
			wantErr: true,
		},
		{
			name:    "Maximum allowed size",
			data:    bytes.Repeat([]byte("a"), maxDataSize),
			key:     pubKey,
			wantErr: false,
		},
		{
			name:    "Near maximum size",
			data:    bytes.Repeat([]byte("a"), maxDataSize-1),
			key:     pubKey,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			_, err := EncryptBlob(tc.data, tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("EncryptBlob() error = %v, wantErr %v", err, tc.wantErr)
			}
			// Reset reader after each test
			rand.Reader = oldReader
		})
	}
}

func TestDecryptionErrors(t *testing.T) {
	privateKey, publicKey, _ := GenerateKeyPair()
	privKey, _ := ParsePrivateKey(privateKey)
	pubKey, _ := ParsePublicKey(publicKey)

	// Create valid encrypted data for testing
	validData := []byte("test data for decryption")
	encryptedData, _ := EncryptBlob(validData, pubKey)

	// Corrupt the session key but keep valid format
	corruptedData := make([]byte, len(encryptedData))
	copy(corruptedData, encryptedData)
	copy(corruptedData[:32], bytes.Repeat([]byte{0xFF}, 32)) // Corrupt the session key

	testCases := []struct {
		name    string
		data    []byte
		key     *rsa.PrivateKey
		wantErr bool
	}{
		{
			name:    "Empty data",
			data:    []byte{},
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Short data",
			data:    []byte("too short"),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid format",
			data:    make([]byte, 600), // Right size, wrong content
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Nil key",
			data:    make([]byte, 600),
			key:     nil,
			wantErr: true,
		},
		{
			name:    "Invalid session key",
			data:    bytes.Repeat([]byte{1}, 512+12+16), // Invalid encrypted session key
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid nonce size",
			data:    bytes.Repeat([]byte{1}, 512+8), // Wrong nonce size
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid ciphertext size",
			data:    bytes.Repeat([]byte{1}, 512+12), // No ciphertext
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Corrupted data",
			data:    bytes.Repeat([]byte{0xFF}, 512+12+32), // All invalid bytes
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid AES key",
			data:    corruptedData, // Valid format but corrupted session key
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid GCM tag",
			data:    append(encryptedData, []byte{1, 2, 3}...), // Append invalid GCM tag
			key:     privKey,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecryptBlob(tc.data, tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("DecryptBlob() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestStringEncryption(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	privKey, err := ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := ParsePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "Simple string",
			input:   "Hello, World!",
			wantErr: false,
		},
		{
			name:    "Long string",
			input:   strings.Repeat("Long message for testing. ", 50),
			wantErr: false,
		},
		{
			name:    "Special characters",
			input:   "!@#$%^&*()_+-=[]{}|;:,.<>?",
			wantErr: false,
		},
		{
			name:    "Unicode characters",
			input:   "Hello, 世界! ¡Hola, мир! 👋🌍",
			wantErr: false,
		},
		{
			name:    "Maximum size string",
			input:   strings.Repeat("a", maxDataSize),
			wantErr: false,
		},
		{
			name:    "Too large string",
			input:   strings.Repeat("a", maxDataSize+1),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test encryption
			encrypted, err := EncryptString(tc.input, pubKey)
			if (err != nil) != tc.wantErr {
				t.Errorf("EncryptString() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr {
				return
			}

			// Test decryption
			decrypted, err := DecryptToString(encrypted, privKey)
			if err != nil {
				t.Errorf("DecryptToString() error = %v", err)
				return
			}

			// Compare
			if decrypted != tc.input {
				t.Errorf("DecryptToString() = %v, want %v", decrypted, tc.input)
			}
		})
	}
}

// Helper function to check if a string is base64 encoded
func isBase64(s string) bool {
	return len(s)%4 == 0 && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=") == ""
}
