package e2e

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEndToEnd(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptum-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Build the CLI tool
	buildCmd := exec.Command("go", "build", "-o", filepath.Join(tmpDir, "cryptum"), "../../cmd/cryptum")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build CLI: %v\n%s", err, out)
	}

	cryptumBin := filepath.Join(tmpDir, "cryptum")

	tests := []struct {
		name     string
		testFunc func(*testing.T, string, string)
	}{
		{"TestKeyGeneration", testKeyGeneration},
		{"TestEncryptDecryptFile", testEncryptDecryptFile},
		{"TestEncryptDecryptStdin", testEncryptDecryptStdin},
		{"TestInvalidInputs", testInvalidInputs},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t, cryptumBin, tmpDir)
		})
	}
}

func testKeyGeneration(t *testing.T, cryptumBin, tmpDir string) {
	keyPrefix := filepath.Join(tmpDir, "test_keys")
	cmd := exec.Command(cryptumBin, "-generate", "-output", keyPrefix)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Key generation failed: %v\n%s", err, out)
	}

	// Verify key files exist and are base64 encoded
	privateKey, err := os.ReadFile(keyPrefix + ".private")
	if err != nil {
		t.Fatal("Failed to read private key:", err)
	}
	if !isBase64(string(privateKey)) {
		t.Error("Private key is not base64 encoded")
	}

	publicKey, err := os.ReadFile(keyPrefix + ".public")
	if err != nil {
		t.Fatal("Failed to read public key:", err)
	}
	if !isBase64(string(publicKey)) {
		t.Error("Public key is not base64 encoded")
	}
}

func testEncryptDecryptFile(t *testing.T, cryptumBin, tmpDir string) {
	// Generate keys
	keyPrefix := filepath.Join(tmpDir, "test_keys")
	exec.Command(cryptumBin, "-generate", "-output", keyPrefix).Run()

	// Create test message
	message := "Hello, this is a test message!"
	messageFile := filepath.Join(tmpDir, "message.txt")
	if err := os.WriteFile(messageFile, []byte(message), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt
	encryptedFile := filepath.Join(tmpDir, "encrypted.txt")
	cmd := exec.Command(cryptumBin,
		"-encrypt",
		"-public-key", keyPrefix+".public",
		"-input", messageFile,
		"-output", encryptedFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Encryption failed: %v\n%s", err, out)
	}

	// Decrypt
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")
	cmd = exec.Command(cryptumBin,
		"-decrypt",
		"-private-key", keyPrefix+".private",
		"-input", encryptedFile,
		"-output", decryptedFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Decryption failed: %v\n%s", err, out)
	}

	// Verify
	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != message {
		t.Errorf("Decrypted message does not match original.\nWant: %q\nGot: %q", message, string(decrypted))
	}
}

func testEncryptDecryptStdin(t *testing.T, cryptumBin, tmpDir string) {
	// Generate keys
	keyPrefix := filepath.Join(tmpDir, "stdin_keys")
	exec.Command(cryptumBin, "-generate", "-output", keyPrefix).Run()

	message := "Test message via stdin"
	var encryptedOutput bytes.Buffer

	// Encrypt via stdin
	encryptCmd := exec.Command(cryptumBin,
		"-encrypt",
		"-public-key", keyPrefix+".public",
		"-input", "-",
		"-output", "-",
	)
	encryptCmd.Stdin = strings.NewReader(message)
	encryptCmd.Stdout = &encryptedOutput
	if err := encryptCmd.Run(); err != nil {
		t.Fatal("Encryption failed:", err)
	}

	// Decrypt via stdin
	decryptCmd := exec.Command(cryptumBin,
		"-decrypt",
		"-private-key", keyPrefix+".private",
		"-input", "-",
		"-output", "-",
	)
	decryptCmd.Stdin = &encryptedOutput
	var decryptedOutput bytes.Buffer
	decryptCmd.Stdout = &decryptedOutput

	if err := decryptCmd.Run(); err != nil {
		t.Fatal("Decryption failed:", err)
	}

	if decryptedOutput.String() != message {
		t.Errorf("Decrypted message does not match original.\nWant: %q\nGot: %q",
			message, decryptedOutput.String())
	}
}

func testInvalidInputs(t *testing.T, cryptumBin, tmpDir string) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "No command specified",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "Invalid command",
			args:    []string{"-invalid"},
			wantErr: true,
		},
		{
			name:    "Encrypt without public key",
			args:    []string{"-encrypt", "-input", "test.txt"},
			wantErr: true,
		},
		{
			name:    "Decrypt without private key",
			args:    []string{"-decrypt", "-input", "test.txt"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(cryptumBin, tt.args...)
			err := cmd.Run()
			if (err != nil) != tt.wantErr {
				t.Errorf("Want error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return err == nil
}
