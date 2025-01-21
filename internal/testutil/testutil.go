package testutil

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SetupTestDir creates a temporary directory and returns its path along with a cleanup function
func SetupTestDir(t *testing.T, prefix string) (string, func()) {
	tmpDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

// CreateTestFile creates a file with the given content in the specified directory
func CreateTestFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// IsBase64 checks if a string is base64 encoded
func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	return err == nil
}

// SetupStdinStdout creates pipes for stdin/stdout testing and returns cleanup function
func SetupStdinStdout(t *testing.T) (stdin *os.File, stdout *os.File, cleanup func()) {
	oldStdin := os.Stdin
	oldStdout := os.Stdout

	// Create pipes for stdin and stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW

	cleanup = func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		r.Close()
		w.Close()
		outR.Close()
		outW.Close()
	}

	return w, outR, cleanup
}

// CaptureOutput captures stdout/stderr output and returns it as a string
func CaptureOutput(f func()) string {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	f()
	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	return <-outC
}

// TestData contains common test data used across different test files
var TestData = struct {
	ShortMessage  string
	LongMessage   string
	SpecialChars  string
	UnicodeChars  string
	BinaryData    []byte
	MaxSizeData   []byte
	InvalidBase64 string
}{
	ShortMessage:  "Hello, World!",
	LongMessage:   strings.Repeat("Long message for testing. ", 100),
	SpecialChars:  "!@#$%^&*()_+-=[]{}|;:,.<>?",
	UnicodeChars:  "Hello, 世界! ¡Hola, мир! 👋🌍",
	BinaryData:    []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	MaxSizeData:   bytes.Repeat([]byte("a"), 512*1024), // 512KB
	InvalidBase64: "not-base64!",
}
