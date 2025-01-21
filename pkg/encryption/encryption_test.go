package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/threatflux/cryptum-go/internal/testutil"
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

// Mock AEAD for testing GCM errors
type mockAEAD struct {
	err       error
	sealError bool
}

func (m *mockAEAD) NonceSize() int { return 12 }
func (m *mockAEAD) Overhead() int  { return 16 }
func (m *mockAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if m.sealError {
		return nil
	}
	if m.err != nil {
		return nil
	}
	// Simulate real GCM behavior by appending tag
	result := append(dst, plaintext...)
	return append(result, bytes.Repeat([]byte{0}, 16)...)
}
func (m *mockAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Remove simulated tag
	return append(dst, ciphertext[:len(ciphertext)-16]...), nil
}

// Mock Block for testing GCM errors
type mockBlock struct {
	cipher.Block
	gcmErr error
}

func (m *mockBlock) BlockSize() int { return 16 }

func newMockGCM(b cipher.Block) (cipher.AEAD, error) {
	if mb, ok := b.(*mockBlock); ok && mb.gcmErr != nil {
		return nil, mb.gcmErr
	}
	return &mockAEAD{}, nil
}

func newMockGCMWithOpenError(b cipher.Block) (cipher.AEAD, error) {
	return &mockAEAD{err: errors.New("mock Open error")}, nil
}

func newMockGCMWithSealError(b cipher.Block) (cipher.AEAD, error) {
	return &mockAEAD{sealError: true}, nil
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
		if len(privateKey) == 0 || !testutil.IsBase64(privateKey) {
			t.Error("Invalid private key format")
		}
		if len(publicKey) == 0 || !testutil.IsBase64(publicKey) {
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
		if !bytes.Contains(privBytes, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
			t.Errorf("Private key has incorrect format: %s", privStr)
		}
		if !bytes.Contains(privBytes, []byte("-----END RSA PRIVATE KEY-----")) {
			t.Errorf("Private key missing end marker: %s", privStr)
		}
		if !bytes.Contains(pubBytes, []byte("-----BEGIN RSA PUBLIC KEY-----")) {
			t.Errorf("Public key has incorrect format: %s", pubStr)
		}
		if !bytes.Contains(pubBytes, []byte("-----END RSA PUBLIC KEY-----")) {
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
			private:     testutil.TestData.InvalidBase64,
			public:      testutil.TestData.InvalidBase64,
			wantPrivErr: true,
			wantPubErr:  true,
		},
		{
			name:        "Invalid key data",
			private:     base64.StdEncoding.EncodeToString([]byte("Hello, World!")),
			public:      base64.StdEncoding.EncodeToString([]byte("Hello, World!")),
			wantPrivErr: true,
			wantPubErr:  true,
		},
		{
			name: "Valid PEM format but invalid key data",
			private: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("invalid key data"),
			})),
			public: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: []byte("invalid key data"),
			})),
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
			data: []byte(testutil.TestData.ShortMessage),
		},
		{
			name: "Long string",
			data: []byte(testutil.TestData.LongMessage),
		},
		{
			name: "Binary data",
			data: testutil.TestData.BinaryData,
		},
		{
			name: "Maximum size",
			data: testutil.TestData.MaxSizeData,
		},
		{
			name: "Single byte",
			data: []byte{1},
		},
		{
			name: "UTF-8 characters",
			data: []byte(testutil.TestData.UnicodeChars),
		},
		{
			name: "Special characters",
			data: []byte(testutil.TestData.SpecialChars),
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

	// Save original functions
	oldNewCipher := newEncryptCipher
	oldNewGCM := newEncryptGCM
	oldReader := rand.Reader
	defer func() {
		newEncryptCipher = oldNewCipher
		newEncryptGCM = oldNewGCM
		rand.Reader = oldReader
	}()

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
			name:    "AES cipher creation failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				newEncryptCipher = func(key []byte) (cipher.Block, error) {
					return nil, errors.New("mock cipher error")
				}
			},
		},
		{
			name:    "GCM creation failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				newEncryptGCM = func(block cipher.Block) (cipher.AEAD, error) {
					return nil, errors.New("mock GCM error")
				}
			},
		},
		{
			name:    "GCM seal failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				newEncryptGCM = newMockGCMWithSealError
			},
		},
		{
			name:    "Nonce generation failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				// First ReadFull is for session key, second is for nonce
				rand.Reader = &errorReader{failAfter: 1}
			},
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
		})
	}
}

func TestDecryptionErrors(t *testing.T) {
	privateKey, publicKey, _ := GenerateKeyPair()
	privKey, _ := ParsePrivateKey(privateKey)
	pubKey, _ := ParsePublicKey(publicKey)

	// Save original functions
	oldNewCipher := newCipher
	oldNewGCM := newGCM
	defer func() {
		newCipher = oldNewCipher
		newGCM = oldNewGCM
	}()

	// Create valid encrypted data for testing
	validData := []byte("test data for decryption")
	encryptedData, _ := EncryptBlob(validData, pubKey)

	// Create corrupted data
	corruptedData := make([]byte, len(encryptedData))
	copy(corruptedData, encryptedData)
	copy(corruptedData[:32], bytes.Repeat([]byte{0xFF}, 32))

	testCases := []struct {
		name    string
		data    []byte
		key     *rsa.PrivateKey
		wantErr bool
		setup   func()
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
			data:    make([]byte, 600),
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
			data:    bytes.Repeat([]byte{1}, 512+12+16),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid nonce size",
			data:    bytes.Repeat([]byte{1}, 512+8),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Invalid ciphertext size",
			data:    bytes.Repeat([]byte{1}, 512+12),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Corrupted data",
			data:    bytes.Repeat([]byte{0xFF}, 512+12+32),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "AES cipher creation failure",
			data:    encryptedData,
			key:     privKey,
			wantErr: true,
			setup: func() {
				newCipher = func(key []byte) (cipher.Block, error) {
					return nil, errors.New("mock cipher error")
				}
			},
		},
		{
			name:    "GCM creation failure",
			data:    encryptedData,
			key:     privKey,
			wantErr: true,
			setup: func() {
				newCipher = func(key []byte) (cipher.Block, error) {
					return &mockBlock{gcmErr: errors.New("mock GCM error")}, nil
				}
				newGCM = newMockGCM
			},
		},
		{
			name:    "GCM open failure",
			data:    encryptedData,
			key:     privKey,
			wantErr: true,
			setup: func() {
				newGCM = newMockGCMWithOpenError
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
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
			input:   testutil.TestData.ShortMessage,
			wantErr: false,
		},
		{
			name:    "Long string",
			input:   testutil.TestData.LongMessage,
			wantErr: false,
		},
		{
			name:    "Special characters",
			input:   testutil.TestData.SpecialChars,
			wantErr: false,
		},
		{
			name:    "Unicode characters",
			input:   testutil.TestData.UnicodeChars,
			wantErr: false,
		},
		{
			name:    "Maximum size string",
			input:   string(testutil.TestData.MaxSizeData),
			wantErr: false,
		},
		{
			name:    "Too large string",
			input:   string(bytes.Repeat([]byte("a"), maxDataSize+1)),
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
