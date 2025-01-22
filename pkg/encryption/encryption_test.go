package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"hash"
	"io"
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

// Mock block cipher for testing
type mockBlock struct {
	cipher.Block
}

func (m *mockBlock) BlockSize() int { return 16 }

// Mock AEAD for testing GCM errors
type mockAEAD struct {
	err          error
	sealError    bool
	nilOutput    bool
	emptyOutput  bool
	customOutput []byte
}

func (m *mockAEAD) NonceSize() int { return 12 }
func (m *mockAEAD) Overhead() int  { return 16 }
func (m *mockAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if m.sealError {
		return nil
	}
	if m.nilOutput {
		return nil
	}
	if m.emptyOutput {
		return make([]byte, 0)
	}
	if m.customOutput != nil {
		return m.customOutput
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

func TestEncryptionErrors(t *testing.T) {
	_, publicKey, _ := GenerateKeyPair()
	pubKey, _ := ParsePublicKey(publicKey)

	// Save original functions and reader
	oldNewCipher := newEncryptCipher
	oldNewGCM := newEncryptGCM
	oldReader := randReader
	oldReadFull := readFull
	oldEncryptOAEP := encryptOAEP

	// Ensure cleanup after each test
	defer func() {
		newEncryptCipher = oldNewCipher
		newEncryptGCM = oldNewGCM
		randReader = oldReader
		readFull = oldReadFull
		encryptOAEP = oldEncryptOAEP
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
				randReader = &errorReader{failAfter: 0}
			},
		},
		{
			name:    "RSA encryption failure",
			data:    []byte("test"),
			key:     &rsa.PublicKey{N: nil, E: 0}, // Invalid public key
			wantErr: true,
		},
		{
			name:    "Invalid session key size",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				encryptOAEP = func(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
					return make([]byte, 256), nil // Return shorter key
				}
			},
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
			name:    "Nonce generation failure",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				readFull = func(r io.Reader, buf []byte) (n int, err error) {
					if len(buf) == 12 { // nonce generation
						return 0, errors.New("mock nonce error")
					}
					return oldReadFull(r, buf)
				}
			},
		},
		{
			name:    "GCM seal returns nil",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				newEncryptGCM = func(block cipher.Block) (cipher.AEAD, error) {
					return &mockAEAD{nilOutput: true}, nil
				}
			},
		},
		{
			name:    "GCM seal returns empty output",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				newEncryptGCM = func(block cipher.Block) (cipher.AEAD, error) {
					return &mockAEAD{emptyOutput: true}, nil
				}
			},
		},
		{
			name:    "GCM seal returns nil with error",
			data:    []byte("test"),
			key:     pubKey,
			wantErr: true,
			setup: func() {
				newEncryptGCM = func(block cipher.Block) (cipher.AEAD, error) {
					return &mockAEAD{err: errors.New("mock seal error")}, nil
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset to original state
			newEncryptCipher = oldNewCipher
			newEncryptGCM = oldNewGCM
			randReader = oldReader
			readFull = oldReadFull
			encryptOAEP = oldEncryptOAEP

			// Apply test-specific setup
			if tc.setup != nil {
				tc.setup()
			}

			// Run test
			result, err := EncryptBlob(tc.data, tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("EncryptBlob() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			// Additional verification for successful cases
			if err == nil {
				// Verify the format of the result
				if len(result) <= 512+12 { // 512 for RSA key + 12 for nonce
					t.Error("Result too short for valid encryption")
				}

				// Verify result structure
				if len(result) < 512 {
					t.Error("Result missing encrypted session key")
				} else if len(result) < 512+12 {
					t.Error("Result missing nonce")
				} else if len(result) <= 512+12 {
					t.Error("Result missing ciphertext")
				}
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
				newGCM = func(block cipher.Block) (cipher.AEAD, error) {
					return nil, errors.New("mock GCM error")
				}
			},
		},
		{
			name:    "GCM open failure",
			data:    encryptedData,
			key:     privKey,
			wantErr: true,
			setup: func() {
				newGCM = func(block cipher.Block) (cipher.AEAD, error) {
					return &mockAEAD{err: errors.New("mock open error")}, nil
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset to original state
			newCipher = oldNewCipher
			newGCM = oldNewGCM

			// Apply test-specific setup
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
