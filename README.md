# Cryptum-Go

A Go implementation of the Cryptum encryption framework, providing secure hybrid encryption capabilities using RSA and AES. This project is compatible with the Python cryptum library while leveraging Go's strong cryptographic primitives.

## Features

- RSA key pair generation (4096-bit)
- Hybrid encryption using RSA+AES
- AES-GCM for authenticated encryption
- Base64 encoding for data transport
- Command-line interface
- Compatible with Python cryptum library

## Installation

```bash
go install github.com/threatflux/cryptum-go/cmd/cryptum@latest
```

Or clone and build from source:

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

## Cross-Language Compatibility

This library maintains compatibility with the Python cryptum library. Encrypted data from either library can be decrypted by the other, ensuring seamless integration in mixed-language environments.

## Security

- Uses 4096-bit RSA keys
- Implements AES-256-GCM for authenticated encryption
- Secure random number generation
- OAEP padding with SHA-512 for RSA operations

## Development

Requirements:
- Go 1.23.5 or higher
- Make (optional)

Running tests:
```bash
go test ./...
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request