package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatflux/cryptum-go/internal/logger"
	"github.com/threatflux/cryptum-go/internal/testutil"
	"github.com/threatflux/cryptum-go/pkg/encryption"
)

var testExitCalled bool

func setupTest(t *testing.T) (string, *bytes.Buffer, func()) {
	// Create temporary directory
	tmpDir, cleanup := testutil.SetupTestDir(t, "cryptum-main-*")

	// Change to temp directory
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	// Setup logger
	var logBuf bytes.Buffer
	logger.ResetInstance()
	log = logger.GetInstance()
	log.SetOutput(&logBuf)

	// Save original state
	origArgs := os.Args
	oldExitFunc := logger.ExitFunc
	testExitCalled = false
	logger.ExitFunc = func(code int) {
		testExitCalled = true
	}

	// Reset flag state
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cleanupAll := func() {
		os.Chdir(origWd)
		cleanup()
		os.Args = origArgs
		logger.ExitFunc = oldExitFunc
		logger.ResetInstance()
	}

	return tmpDir, &logBuf, cleanupAll
}

func TestMainIntegration_Generate(t *testing.T) {
	tmpDir, _, cleanup := setupTest(t)
	defer cleanup()

	os.Args = []string{"cryptum", "-generate", "-output", "test_keys"}

	// Run main
	main()

	// Validate results
	if testExitCalled {
		t.Error("Exit called unexpectedly")
	}
	privateKey := filepath.Join(tmpDir, "test_keys.private")
	publicKey := filepath.Join(tmpDir, "test_keys.public")
	if _, err := os.Stat(privateKey); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}
	if _, err := os.Stat(publicKey); os.IsNotExist(err) {
		t.Error("Public key file was not created")
	}
}

func TestMainIntegration_Encrypt(t *testing.T) {
	tmpDir, _, cleanup := setupTest(t)
	defer cleanup()

	// Generate test files
	_, pubKey, err := encryption.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	testutil.CreateTestFile(t, tmpDir, "test.pub", pubKey)
	testutil.CreateTestFile(t, tmpDir, "test.txt", testutil.TestData.ShortMessage)

	os.Args = []string{"cryptum", "-encrypt", "-public-key", "test.pub", "-input", "test.txt", "-output", "test.enc"}

	// Run main
	main()

	// Validate results
	if testExitCalled {
		t.Error("Exit called unexpectedly")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "test.enc")); os.IsNotExist(err) {
		t.Error("Encrypted file was not created")
	}
}

func TestMainIntegration_NoCommand(t *testing.T) {
	_, logBuf, cleanup := setupTest(t)
	defer cleanup()

	// Reset flag state
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	// Set up test args
	os.Args = []string{"cryptum"}

	// Run cryptum directly
	runCryptum(false, false, false, "", "", "", "", false)

	// Validate results
	if !testExitCalled {
		t.Error("Expected exit to be called")
	}
	if !strings.Contains(logBuf.String(), "Exactly one command must be specified") {
		t.Error("Expected error message about command count")
	}
}

func TestMainIntegration_MultipleCommands(t *testing.T) {
	_, logBuf, cleanup := setupTest(t)
	defer cleanup()

	os.Args = []string{"cryptum", "-generate", "-encrypt"}

	// Run main
	main()

	// Validate results
	if !testExitCalled {
		t.Error("Expected exit to be called")
	}
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[FATAL]") {
		t.Error("Expected fatal error message")
	}
	if !strings.Contains(logOutput, "Exactly one command must be specified") {
		t.Error("Expected error message about command count")
	}
}

func TestMainIntegration_Debug(t *testing.T) {
	_, logBuf, cleanup := setupTest(t)
	defer cleanup()

	// Set debug level and add a debug message
	log.SetLevel(logger.DEBUG)
	log.Debug("Debug test message")

	// Run cryptum directly with debug flag
	runCryptum(true, false, false, "", "", "", "test_keys", true)

	// Validate results
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[DEBUG] Debug test message") {
		t.Errorf("Expected debug output in logs, got: %s", logOutput)
	}
}

func TestMainIntegration_StdinStdout(t *testing.T) {
	tmpDir, _, cleanup := setupTest(t)
	defer cleanup()

	// Generate key pair first
	keyPrefix := filepath.Join(tmpDir, "test_keys")
	runCryptum(true, false, false, "", "", "", keyPrefix, false)

	// Set up stdin/stdout
	stdin, stdout, cleanupIO := testutil.SetupStdinStdout(t)
	defer cleanupIO()

	// Write test data to stdin
	go func() {
		stdin.Write([]byte(testutil.TestData.ShortMessage))
		stdin.Close()
	}()

	// Run encryption with stdin/stdout
	runCryptum(false, true, false, keyPrefix+".public", "", "-", "-", false)

	// Read encrypted output
	encryptedData, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}

	if len(encryptedData) == 0 {
		t.Error("No encrypted data written to stdout")
	}
}

func TestMainIntegration_MissingRequiredFlags(t *testing.T) {
	_, logBuf, cleanup := setupTest(t)
	defer cleanup()

	os.Args = []string{"cryptum", "-encrypt"}

	// Run main
	main()

	// Validate results
	if !testExitCalled {
		t.Error("Expected exit to be called")
	}
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "[FATAL]") {
		t.Error("Expected fatal error message")
	}
	if !strings.Contains(logOutput, "Public key file is required") {
		t.Error("Expected error message about missing public key")
	}
}
