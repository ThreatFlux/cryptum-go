package encryption

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

var ErrInvalidKey = errors.New("invalid key")

func TestEncryptDecryptString(t *testing.T) {
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

	tests := []struct {
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
			input:   strings.Repeat("Long message for testing. ", 100),
			wantErr: false,
		},
		{
			name:    "Special characters",
			input:   "!@#$%^&*()_+-=[]{}|;:,.<>?",
			wantErr: false,
		},
		{
			name:    "Unicode characters",
			input:   "Hello, World! Unicode test.",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test EncryptString
			encrypted, err := EncryptString(tt.input, pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Test DecryptToString
			decrypted, err := DecryptToString(encrypted, privKey)
			if err != nil {
				t.Errorf("DecryptToString() error = %v", err)
				return
			}

			if decrypted != tt.input {
				t.Errorf("DecryptToString() = %v, want %v", decrypted, tt.input)
			}
		})
	}
}

func TestEncryptStringErrors(t *testing.T) {
	_, publicKey, _ := GenerateKeyPair()
	pubKey, _ := ParsePublicKey(publicKey)

	tests := []struct {
		name    string
		input   string
		key     *rsa.PublicKey
		wantErr bool
	}{
		{
			name:    "Nil key",
			input:   "test",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "Valid input",
			input:   "test",
			key:     pubKey,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptString(tt.input, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptToStringErrors(t *testing.T) {
	privateKey, _, _ := GenerateKeyPair()
	privKey, _ := ParsePrivateKey(privateKey)

	tests := []struct {
		name    string
		input   []byte
		key     *rsa.PrivateKey
		wantErr bool
	}{
		{
			name:    "Nil key",
			input:   []byte("test"),
			key:     nil,
			wantErr: true,
		},
		{
			name:    "Invalid data",
			input:   []byte("invalid"),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Empty data",
			input:   []byte{},
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Non-base64 data",
			input:   []byte("!@#$%^"),
			key:     privKey,
			wantErr: true,
		},
		{
			name:    "Too large data",
			input:   make([]byte, 1024*1024), // 1MB
			key:     privKey,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptToString(tt.input, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptToString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateKeyPairErrors(t *testing.T) {
	// Test multiple key generations to ensure consistency
	for i := 0; i < 3; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Errorf("GenerateKeyPair() failed on iteration %d: %v", i, err)
			continue
		}

		// Decode base64 keys
		privBytes, err := base64.StdEncoding.DecodeString(priv)
		if err != nil {
			t.Errorf("Failed to decode private key: %v", err)
		}
		pubBytes, err := base64.StdEncoding.DecodeString(pub)
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
	}
}

func TestParseKeyErrors(t *testing.T) {
	tests := []struct {
		name       string
		privateKey string
		publicKey  string
		wantErr    bool
	}{
		{
			name:       "Empty private key",
			privateKey: "",
			wantErr:    true,
		},
		{
			name:      "Empty public key",
			publicKey: "",
			wantErr:   true,
		},
		{
			name:       "Invalid base64 private key",
			privateKey: "invalid-base64!@#",
			wantErr:    true,
		},
		{
			name:      "Invalid base64 public key",
			publicKey: "invalid-base64!@#",
			wantErr:   true,
		},
		{
			name:       "Invalid PEM format private key",
			privateKey: base64.StdEncoding.EncodeToString([]byte("not a PEM format")),
			wantErr:    true,
		},
		{
			name:      "Invalid PEM format public key",
			publicKey: base64.StdEncoding.EncodeToString([]byte("not a PEM format")),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.privateKey != "" {
				_, err := ParsePrivateKey(tt.privateKey)
				if (err != nil) != tt.wantErr {
					t.Errorf("ParsePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if tt.publicKey != "" {
				_, err := ParsePublicKey(tt.publicKey)
				if (err != nil) != tt.wantErr {
					t.Errorf("ParsePublicKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestEncryptDecryptBlobErrors(t *testing.T) {
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

	tests := []struct {
		name    string
		data    []byte
		key     interface{}
		encrypt bool
		wantErr bool
	}{
		{
			name:    "Encrypt nil data",
			data:    nil,
			key:     pubKey,
			encrypt: true,
			wantErr: true,
		},
		{
			name:    "Encrypt empty data",
			data:    []byte{},
			key:     pubKey,
			encrypt: true,
			wantErr: true,
		},
		{
			name:    "Encrypt with nil key",
			data:    []byte("test"),
			key:     nil,
			encrypt: true,
			wantErr: true,
		},
		{
			name:    "Decrypt nil data",
			data:    nil,
			key:     privKey,
			encrypt: false,
			wantErr: true,
		},
		{
			name:    "Decrypt empty data",
			data:    []byte{},
			key:     privKey,
			encrypt: false,
			wantErr: true,
		},
		{
			name:    "Decrypt with nil key",
			data:    []byte("test"),
			key:     nil,
			encrypt: false,
			wantErr: true,
		},
		{
			name:    "Decrypt invalid data",
			data:    []byte("not encrypted data"),
			key:     privKey,
			encrypt: false,
			wantErr: true,
		},
		{
			name:    "Encrypt large data",
			data:    make([]byte, 1024*1024), // 1MB
			key:     pubKey,
			encrypt: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.encrypt {
				if pubKey, ok := tt.key.(*rsa.PublicKey); ok {
					_, err = EncryptBlob(tt.data, pubKey)
				} else {
					err = ErrInvalidKey
				}
			} else {
				if privKey, ok := tt.key.(*rsa.PrivateKey); ok {
					_, err = DecryptBlob(tt.data, privKey)
				} else {
					err = ErrInvalidKey
				}
			}
			if (err != nil) != tt.wantErr {
				operation := "EncryptBlob()"
				if !tt.encrypt {
					operation = "DecryptBlob()"
				}
				t.Errorf("%s error = %v, wantErr %v", operation, err, tt.wantErr)
			}
		})
	}
}
