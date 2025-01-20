// Package encryption provides cryptographic operations for the cryptum-go library.
package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// GenerateKeyPair generates a new RSA key pair with 4096-bit key size.
// Returns base64 encoded private and public keys.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	// Generate 4096 bit RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Convert public key to PEM format
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
	})

	// Base64 encode the PEM formatted keys
	privateKey = base64.URLEncoding.EncodeToString(privateKeyPEM)
	publicKey = base64.URLEncoding.EncodeToString(publicKeyPEM)

	return privateKey, publicKey, nil
}

// ParsePrivateKey decodes a base64 encoded private key string into an RSA private key.
func ParsePrivateKey(privateKeyStr string) (*rsa.PrivateKey, error) {
	// Decode base64
	pemBytes, err := base64.URLEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}

	// Decode PEM
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	// Parse RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// ParsePublicKey decodes a base64 encoded public key string into an RSA public key.
func ParsePublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	// Decode base64
	pemBytes, err := base64.URLEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, err
	}

	// Decode PEM
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	// Parse RSA public key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
