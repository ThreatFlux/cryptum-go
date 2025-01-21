package encryption

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	// Save original rand.Reader
	oldReader := rand.Reader
	defer func() { rand.Reader = oldReader }()

	// Test key generation failure
	t.Run("Generation failure", func(t *testing.T) {
		rand.Reader = &errorReader{failAfter: 0}
		priv, pub, err := GenerateKeyPair()
		if err == nil {
			t.Error("Expected error when random number generator fails")
		}
		if priv != "" || pub != "" {
			t.Error("Expected empty strings on error")
		}
	})

	// Test successful key generation
	t.Run("Successful generation", func(t *testing.T) {
		rand.Reader = oldReader
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Verify private key format
		privBytes, err := base64.URLEncoding.DecodeString(priv)
		if err != nil {
			t.Errorf("Failed to decode private key base64: %v", err)
		}
		privBlock, _ := pem.Decode(privBytes)
		if privBlock == nil {
			t.Error("Failed to decode private key PEM")
		} else {
			if privBlock.Type != "RSA PRIVATE KEY" {
				t.Errorf("Wrong private key type: got %s, want RSA PRIVATE KEY", privBlock.Type)
			}
			if _, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes); err != nil {
				t.Errorf("Failed to parse private key: %v", err)
			}
		}

		// Verify public key format
		pubBytes, err := base64.URLEncoding.DecodeString(pub)
		if err != nil {
			t.Errorf("Failed to decode public key base64: %v", err)
		}
		pubBlock, _ := pem.Decode(pubBytes)
		if pubBlock == nil {
			t.Error("Failed to decode public key PEM")
		} else {
			if pubBlock.Type != "RSA PUBLIC KEY" {
				t.Errorf("Wrong public key type: got %s, want RSA PUBLIC KEY", pubBlock.Type)
			}
			if _, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes); err != nil {
				t.Errorf("Failed to parse public key: %v", err)
			}
		}
	})
}

func TestParsePrivateKey(t *testing.T) {
	// Generate a valid key for testing
	validPriv, _, _ := GenerateKeyPair()

	// Create an invalid PEM block
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("invalid key data"),
	})
	invalidPEMBase64 := base64.URLEncoding.EncodeToString(invalidPEM)

	testCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Valid key",
			input:   validPriv,
			wantErr: false,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "Invalid base64",
			input:   "not-base64!",
			wantErr: true,
		},
		{
			name:    "Invalid PEM block",
			input:   base64.URLEncoding.EncodeToString([]byte("not a PEM block")),
			wantErr: true,
		},
		{
			name:    "Invalid key data",
			input:   invalidPEMBase64,
			wantErr: true,
		},
		{
			name:    "Malformed base64",
			input:   "SGVsbG8=====",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParsePrivateKey(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParsePrivateKey() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && key == nil {
				t.Error("Expected valid key, got nil")
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	// Generate a valid key for testing
	_, validPub, _ := GenerateKeyPair()

	// Create an invalid PEM block
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: []byte("invalid key data"),
	})
	invalidPEMBase64 := base64.URLEncoding.EncodeToString(invalidPEM)

	testCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Valid key",
			input:   validPub,
			wantErr: false,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "Invalid base64",
			input:   "not-base64!",
			wantErr: true,
		},
		{
			name:    "Invalid PEM block",
			input:   base64.URLEncoding.EncodeToString([]byte("not a PEM block")),
			wantErr: true,
		},
		{
			name:    "Invalid key data",
			input:   invalidPEMBase64,
			wantErr: true,
		},
		{
			name:    "Malformed base64",
			input:   "SGVsbG8=====",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParsePublicKey(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParsePublicKey() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && key == nil {
				t.Error("Expected valid key, got nil")
			}
		})
	}
}
