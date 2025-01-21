# Cryptum-Go

[![Tests](https://github.com/threatflux/cryptum-go/actions/workflows/test.yml/badge.svg)](https://github.com/threatflux/cryptum-go/actions/workflows/test.yml)
[![Release](https://github.com/threatflux/cryptum-go/actions/workflows/release.yml/badge.svg)](https://github.com/threatflux/cryptum-go/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/threatflux/cryptum-go/branch/main/graph/badge.svg)](https://codecov.io/gh/threatflux/cryptum-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/threatflux/cryptum-go)](https://goreportcard.com/report/github.com/threatflux/cryptum-go)
[![GoDoc](https://godoc.org/github.com/threatflux/cryptum-go?status.svg)](https://godoc.org/github.com/threatflux/cryptum-go)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/60aed15ad2bb4d598dcc009db4966646)](https://app.codacy.com/gh/ThreatFlux/cryptum-go/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

A robust Go implementation of the Cryptum encryption framework, providing secure hybrid encryption capabilities using RSA and AES. This project maintains compatibility with the Python cryptum library while leveraging Go's strong cryptographic primitives.

## Features

- **Strong Encryption**
  - RSA key pair generation (4096-bit)
  - Hybrid encryption using RSA+AES
  - AES-GCM for authenticated encryption
  - Secure random number generation
  - OAEP padding with SHA-512 for RSA operations

- **Usability**
  - Command-line interface
  - Library API for Go applications
  - Base64 encoding for data transport
  - Cross-language compatibility with Python cryptum

- **Quality Assurance**
  - 90%+ test coverage
  - Continuous integration
  - Automated releases
  - Docker support

## Installation

### Using Go Install
```bash
go install github.com/threatflux/cryptum-go/cmd/cryptum@latest
```

### Using Docker
```bash
docker pull threatflux/cryptum:latest
docker run -it threatflux/cryptum:latest cryptum -help
```

### Building from Source
```bash
git clone https://github.com/threatflux/cryptum-go.git
cd cryptum-go
go build ./...
```

## Usage

### Command Line Interface

1. Generate a new key pair:
```bash
cryptum -generate -output keys
# Creates keys.private and keys.public
```

2. Encrypt data:
```bash
# From file
cryptum -encrypt -public-key keys.public -input plaintext.txt -output encrypted.txt

# From stdin
echo "secret message" | cryptum -encrypt -public-key keys.public -input - -output -
```

3. Decrypt data:
```bash
# From file
cryptum -decrypt -private-key keys.private -input encrypted.txt -output decrypted.txt

# From stdin
cat encrypted.txt | cryptum -decrypt -private-key keys.private -input - -output -
```

### Library Usage

```go
package main

import (
    "fmt"
    "github.com/threatflux/cryptum-go/pkg/encryption"
)

func main() {
    // Generate key pair
    privateKey, publicKey, err := encryption.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Parse keys for use
    pubKey, err := encryption.ParsePublicKey(publicKey)
    if err != nil {
        panic(err)
    }

    privKey, err := encryption.ParsePrivateKey(privateKey)
    if err != nil {
        panic(err)
    }

    // Encrypt data
    message := []byte("Hello, World!")
    encrypted, err := encryption.EncryptBlob(message, pubKey)
    if err != nil {
        panic(err)
    }

    // Decrypt data
    decrypted, err := encryption.DecryptBlob(encrypted, privKey)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## Security Considerations

- Uses industry-standard cryptographic algorithms
- Regular security updates and dependency maintenance
- No known vulnerabilities
- Follows cryptographic best practices

## Development

### Requirements
- Go 1.23.5 or higher
- Docker (optional)
- Make (optional)

### Testing
```bash
# Run all tests with coverage
go test -v -cover ./...

# Run specific test
go test -v ./cmd/cryptum -run TestHandleEncrypt

# Run tests with race detection
go test -v -race ./...
```

### Code Quality
- Maintains 90%+ test coverage
- Uses Go best practices
- Follows standard Go project layout
- Includes comprehensive documentation

## CI/CD Pipeline

- Automated tests on pull requests
- Code coverage reporting
- Automated releases on main branch
- Multi-platform binary builds
- Docker image publishing

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Pull Request Requirements
- Must pass all tests
- Must maintain 90% code coverage
- Must include documentation updates
- Must follow Go best practices

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- [Open an issue](https://github.com/threatflux/cryptum-go/issues/new)
- [Read the documentation](https://godoc.org/github.com/threatflux/cryptum-go)
- [View the changelog](CHANGELOG.md)