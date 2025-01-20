package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/threatflux/cryptum-go/internal/logger"
	"github.com/threatflux/cryptum-go/pkg/encryption"
)

var (
	log = logger.GetInstance()
)

func main() {
	// Command line flags
	generateCmd := flag.Bool("generate", false, "Generate new RSA key pair")
	encryptCmd := flag.Bool("encrypt", false, "Encrypt data")
	decryptCmd := flag.Bool("decrypt", false, "Decrypt data")
	publicKeyFile := flag.String("public-key", "", "Public key file path")
	privateKeyFile := flag.String("private-key", "", "Private key file path")
	inputFile := flag.String("input", "", "Input file path (use '-' for stdin)")
	outputFile := flag.String("output", "", "Output file path (use '-' for stdout)")
	debug := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	// Set log level
	if *debug {
		log.SetLevel(logger.DEBUG)
	}

	// Validate command
	cmdCount := 0
	if *generateCmd {
		cmdCount++
	}
	if *encryptCmd {
		cmdCount++
	}
	if *decryptCmd {
		cmdCount++
	}
	if cmdCount != 1 {
		log.Fatal("Exactly one command must be specified: -generate, -encrypt, or -decrypt")
	}

	// Execute command
	switch {
	case *generateCmd:
		handleGenerate(*outputFile)
	case *encryptCmd:
		if *publicKeyFile == "" {
			log.Fatal("Public key file is required for encryption")
		}
		handleEncrypt(*publicKeyFile, *inputFile, *outputFile)
	case *decryptCmd:
		if *privateKeyFile == "" {
			log.Fatal("Private key file is required for decryption")
		}
		handleDecrypt(*privateKeyFile, *inputFile, *outputFile)
	}
}

func handleGenerate(outputFile string) {
	privateKey, publicKey, err := encryption.GenerateKeyPair()
	if err != nil {
		log.Fatal("Failed to generate key pair", logger.StringField("error", err.Error()))
	}

	if outputFile == "" {
		// Print to stdout
		fmt.Printf("Private Key:\n%s\n\nPublic Key:\n%s\n", privateKey, publicKey)
		return
	}

	// Save to files
	privateKeyFile := outputFile + ".private"
	publicKeyFile := outputFile + ".public"

	err = os.WriteFile(privateKeyFile, []byte(privateKey), 0600)
	if err != nil {
		log.Fatal("Failed to save private key", logger.StringField("error", err.Error()))
	}

	err = os.WriteFile(publicKeyFile, []byte(publicKey), 0644)
	if err != nil {
		log.Fatal("Failed to save public key", logger.StringField("error", err.Error()))
	}

	log.Info("Key pair generated successfully",
		logger.StringField("private_key", privateKeyFile),
		logger.StringField("public_key", publicKeyFile))
}

func handleEncrypt(publicKeyFile, inputFile, outputFile string) {
	// Read public key
	keyData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		log.Fatal("Failed to read public key", logger.StringField("error", err.Error()))
	}

	pubKey, err := encryption.ParsePublicKey(string(keyData))
	if err != nil {
		log.Fatal("Failed to parse public key", logger.StringField("error", err.Error()))
	}

	// Read input data
	data, err := readInput(inputFile)
	if err != nil {
		log.Fatal("Failed to read input", logger.StringField("error", err.Error()))
	}

	// Encrypt data
	encrypted, err := encryption.EncryptBlob(data, pubKey)
	if err != nil {
		log.Fatal("Encryption failed", logger.StringField("error", err.Error()))
	}

	// Encode to base64
	encoded := base64.URLEncoding.EncodeToString(encrypted)

	// Write output
	err = writeOutput(outputFile, []byte(encoded))
	if err != nil {
		log.Fatal("Failed to write output", logger.StringField("error", err.Error()))
	}

	log.Info("Data encrypted successfully")
}

func handleDecrypt(privateKeyFile, inputFile, outputFile string) {
	// Read private key
	keyData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatal("Failed to read private key", logger.StringField("error", err.Error()))
	}

	privKey, err := encryption.ParsePrivateKey(string(keyData))
	if err != nil {
		log.Fatal("Failed to parse private key", logger.StringField("error", err.Error()))
	}

	// Read input data
	data, err := readInput(inputFile)
	if err != nil {
		log.Fatal("Failed to read input", logger.StringField("error", err.Error()))
	}

	// Decode from base64
	decoded, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		log.Fatal("Failed to decode base64 input", logger.StringField("error", err.Error()))
	}

	// Decrypt data
	decrypted, err := encryption.DecryptBlob(decoded, privKey)
	if err != nil {
		log.Fatal("Decryption failed", logger.StringField("error", err.Error()))
	}

	// Write output
	err = writeOutput(outputFile, decrypted)
	if err != nil {
		log.Fatal("Failed to write output", logger.StringField("error", err.Error()))
	}

	log.Info("Data decrypted successfully")
}

func readInput(inputFile string) ([]byte, error) {
	if inputFile == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(inputFile)
}

func writeOutput(outputFile string, data []byte) error {
	if outputFile == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(outputFile, data, 0644)
}