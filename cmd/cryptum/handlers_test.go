package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatflux/cryptum-go/internal/logger"
	"github.com/threatflux/cryptum-go/pkg/encryption"
)

func TestHandleGenerate(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptum-handlers-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Reset logger instance
	logger.ResetInstance()
	log = logger.GetInstance()

	// Create buffer for log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)

	// Override exit function
	origExitFunc := exitFunc
	exitCalled := false
	exitFunc = func(code int) {
		exitCalled = true
		panic("expected exit")
	}
	defer func() { exitFunc = origExitFunc }()

	tests := []struct {
		name      string
		keyPrefix string
		setup     func() error
		validate  func(t *testing.T)
		wantError bool
	}{
		{
			name:      "Generate keys successfully",
			keyPrefix: filepath.Join(tmpDir, "test_keys"),
			validate: func(t *testing.T) {
				// Check if both public and private key files exist
				publicKeyPath := filepath.Join(tmpDir, "test_keys.public")
				privateKeyPath := filepath.Join(tmpDir, "test_keys.private")

				if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
					t.Errorf("Public key file was not created at %s", publicKeyPath)
				}
				if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
					t.Errorf("Private key file was not created at %s", privateKeyPath)
				}

				// Verify key contents are valid
				publicKey, err := os.ReadFile(publicKeyPath)
				if err != nil {
					t.Fatal(err)
				}
				privateKey, err := os.ReadFile(privateKeyPath)
				if err != nil {
					t.Fatal(err)
				}

				// Try to parse the keys
				if _, err := encryption.ParsePublicKey(string(publicKey)); err != nil {
					t.Error("Failed to parse generated public key:", err)
				}
				if _, err := encryption.ParsePrivateKey(string(privateKey)); err != nil {
					t.Error("Failed to parse generated private key:", err)
				}

				// Log the contents for debugging
				t.Logf("Public key file contents: %s", string(publicKey))
				t.Logf("Private key file contents: %s", string(privateKey))
			},
			wantError: false,
		},
		{
			name:      "Generate keys in nonexistent directory",
			keyPrefix: filepath.Join(tmpDir, "nonexistent", "test_keys"),
			setup: func() error {
				// Create the nonexistent directory
				return os.MkdirAll(filepath.Join(tmpDir, "nonexistent"), 0755)
			},
			validate: func(t *testing.T) {
				// Check if both key files exist
				publicKeyPath := filepath.Join(tmpDir, "nonexistent", "test_keys.public")
				privateKeyPath := filepath.Join(tmpDir, "nonexistent", "test_keys.private")

				if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
					t.Errorf("Public key file was not created at %s", publicKeyPath)
				}
				if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
					t.Errorf("Private key file was not created at %s", privateKeyPath)
				}

				// Log the directory contents for debugging
				files, err := os.ReadDir(filepath.Join(tmpDir, "nonexistent"))
				if err != nil {
					t.Logf("Error reading directory: %v", err)
				} else {
					t.Log("Directory contents:")
					for _, file := range files {
						t.Logf("- %s", file.Name())
					}
				}
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset exitCalled
			exitCalled = false

			// Run setup if provided
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatal(err)
				}
			}

			// Run the generate command
			func() {
				defer func() {
					if r := recover(); r != nil && r != "expected exit" {
						t.Errorf("Unexpected panic: %v", r)
					}
				}()
				handleGenerate(tt.keyPrefix)
			}()

			// Check error status
			if tt.wantError {
				if !exitCalled {
					t.Error("Expected exit to be called")
				}
			} else if exitCalled {
				t.Error("Exit called unexpectedly")
			}

			// Run validation
			if tt.validate != nil {
				tt.validate(t)
			}

			// Log any output from the logger
			if logBuf.Len() > 0 {
				t.Logf("Logger output:\n%s", logBuf.String())
			}
		})
	}
}

func TestHandleEncryptDecrypt(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptum-handlers-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test keys
	keyPrefix := filepath.Join(tmpDir, "test_keys")
	handleGenerate(keyPrefix)

	// Test data
	testMessage := "Hello, World!"
	inputFile := filepath.Join(tmpDir, "input.txt")
	encryptedFile := filepath.Join(tmpDir, "encrypted.txt")
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")

	// Write test message to file
	if err := os.WriteFile(inputFile, []byte(testMessage), 0644); err != nil {
		t.Fatal(err)
	}

	// Test encryption
	t.Run("Encrypt file", func(t *testing.T) {
		handleEncrypt(keyPrefix+".public", inputFile, encryptedFile)

		// Verify encrypted file exists and is not empty
		encrypted, err := os.ReadFile(encryptedFile)
		if err != nil {
			t.Fatal("Failed to read encrypted file:", err)
		}
		if len(encrypted) == 0 {
			t.Error("Encrypted file is empty")
		}
		if strings.Contains(string(encrypted), testMessage) {
			t.Error("Encrypted data contains plaintext message")
		}
	})

	// Test decryption
	t.Run("Decrypt file", func(t *testing.T) {
		handleDecrypt(keyPrefix+".private", encryptedFile, decryptedFile)

		// Verify decrypted content matches original
		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatal("Failed to read decrypted file:", err)
		}
		if string(decrypted) != testMessage {
			t.Errorf("Decrypted message = %q, want %q", string(decrypted), testMessage)
		}
	})
}

func TestHandleEncryptErrors(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptum-handlers-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Reset logger instance
	logger.ResetInstance()
	log = logger.GetInstance()

	// Create buffer for log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)

	// Override exit function
	oldExitFunc := logger.ExitFunc
	exitCalled := false
	logger.ExitFunc = func(code int) {
		exitCalled = true
	}
	defer func() {
		logger.ExitFunc = oldExitFunc
		logger.ResetInstance() // Reset logger for other tests
	}()

	// Generate test keys for valid key test cases
	keyPrefix := filepath.Join(tmpDir, "test_keys")
	handleGenerate(keyPrefix)

	tests := []struct {
		name       string
		publicKey  string
		input      string
		output     string
		setup      func() error
		cleanup    func()
		shouldFail bool
		errorMsg   string
	}{
		{
			name:       "Missing public key",
			publicKey:  filepath.Join(tmpDir, "nonexistent.key"),
			input:      filepath.Join(tmpDir, "test.txt"),
			output:     filepath.Join(tmpDir, "out.txt"),
			shouldFail: true,
			errorMsg:   "Failed to read public key",
		},
		{
			name:       "Missing input file",
			publicKey:  keyPrefix + ".public",
			input:      filepath.Join(tmpDir, "nonexistent.txt"),
			output:     filepath.Join(tmpDir, "out.txt"),
			shouldFail: true,
			errorMsg:   "Failed to read input",
		},
		{
			name:      "Invalid public key data",
			publicKey: filepath.Join(tmpDir, "invalid.pub"),
			input:     filepath.Join(tmpDir, "test.txt"),
			output:    filepath.Join(tmpDir, "out.txt"),
			setup: func() error {
				// Create invalid public key file
				if err := os.WriteFile(filepath.Join(tmpDir, "invalid.pub"), []byte("invalid key data"), 0644); err != nil {
					return err
				}
				// Create input file
				return os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test data"), 0644)
			},
			shouldFail: true,
			errorMsg:   "Failed to parse public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log buffer
			logBuf.Reset()
			exitCalled = false

			// Run setup if provided
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatal(err)
				}
			}

			// Run cleanup if provided
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			handleEncrypt(tt.publicKey, tt.input, tt.output)

			// Check if error was logged and exit was called
			if tt.shouldFail {
				logOutput := logBuf.String()
				// Split log output into lines and check each line for the error message
				logLines := strings.Split(logOutput, "\n")
				foundError := false
				for _, line := range logLines {
					if strings.Contains(line, "[FATAL]") && strings.Contains(line, tt.errorMsg) {
						foundError = true
						break
					}
				}
				if !foundError {
					t.Errorf("Expected fatal error message containing %q in one of these lines:\n", tt.errorMsg)
					for _, line := range logLines {
						t.Errorf("  %s", line)
					}
				}
				if !exitCalled {
					t.Error("Expected exit to be called")
				}
			} else if exitCalled {
				t.Error("Exit called unexpectedly")
			}
		})
	}
}

func TestHandleDecryptErrors(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptum-handlers-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Reset logger instance
	logger.ResetInstance()
	log = logger.GetInstance()

	// Create buffer for log output
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)

	// Override exit function
	oldExitFunc := logger.ExitFunc
	exitCalled := false
	logger.ExitFunc = func(code int) {
		exitCalled = true
	}
	defer func() {
		logger.ExitFunc = oldExitFunc
		logger.ResetInstance() // Reset logger for other tests
	}()

	// Generate test keys for valid key test cases
	keyPrefix := filepath.Join(tmpDir, "test_keys")
	handleGenerate(keyPrefix)

	tests := []struct {
		name       string
		privateKey string
		input      string
		output     string
		setup      func() error
		cleanup    func()
		shouldFail bool
		errorMsg   string
	}{
		{
			name:       "Missing private key",
			privateKey: filepath.Join(tmpDir, "nonexistent.key"),
			input:      filepath.Join(tmpDir, "test.txt"),
			output:     filepath.Join(tmpDir, "out.txt"),
			shouldFail: true,
			errorMsg:   "Failed to read private key",
		},
		{
			name:       "Missing input file",
			privateKey: keyPrefix + ".private",
			input:      filepath.Join(tmpDir, "nonexistent.txt"),
			output:     filepath.Join(tmpDir, "out.txt"),
			shouldFail: true,
			errorMsg:   "Failed to read input",
		},
		{
			name:       "Invalid encrypted data",
			privateKey: keyPrefix + ".private",
			input:      filepath.Join(tmpDir, "invalid.txt"),
			output:     filepath.Join(tmpDir, "out.txt"),
			setup: func() error {
				return os.WriteFile(filepath.Join(tmpDir, "invalid.txt"), []byte("invalid data"), 0644)
			},
			shouldFail: true,
			errorMsg:   "Decryption failed",
		},
		{
			name:       "Invalid private key data",
			privateKey: filepath.Join(tmpDir, "invalid.key"),
			input:      filepath.Join(tmpDir, "test.txt"),
			output:     filepath.Join(tmpDir, "out.txt"),
			setup: func() error {
				// Create invalid private key file
				if err := os.WriteFile(filepath.Join(tmpDir, "invalid.key"), []byte("invalid key data"), 0644); err != nil {
					return err
				}
				// Create input file
				return os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test data"), 0644)
			},
			shouldFail: true,
			errorMsg:   "Failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset log buffer and exit flag
			logBuf.Reset()
			exitCalled = false

			// Run setup if provided
			if tt.setup != nil {
				if err := tt.setup(); err != nil {
					t.Fatal(err)
				}
			}

			// Run cleanup if provided
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			// Run the decrypt command and handle expected panic
			defer func() {
				if r := recover(); r != nil && r != "expected exit" {
					t.Errorf("Unexpected panic: %v", r)
				}
			}()
			handleDecrypt(tt.privateKey, tt.input, tt.output)

			// Check if error was logged and exit was called
			logOutput := logBuf.String()
			if tt.shouldFail {
				if !exitCalled {
					t.Errorf("Expected exit to be called for test %q", tt.name)
				}
				if !strings.Contains(logOutput, "[FATAL]") || !strings.Contains(logOutput, tt.errorMsg) {
					t.Errorf("Test %q:\nExpected log containing '[FATAL]' and %q\nGot log output: %q",
						tt.name, tt.errorMsg, logOutput)
				}
			} else if exitCalled {
				t.Errorf("Test %q: Exit called unexpectedly", tt.name)
			}
		})
	}
}
