# Technical Context

## Technologies Used
1. Go 1.23.5
   - crypto/rsa for asymmetric encryption
   - crypto/aes for symmetric encryption
   - crypto/cipher for GCM mode
   - crypto/rand for secure random generation
   - encoding/base64 for data encoding
   - encoding/pem for key formatting

2. Development Tools
   - go mod for dependency management
   - go test for comprehensive testing
   - golangci-lint for code quality
   - godoc for API documentation

## Development Setup
1. Requirements
   - Go 1.23.5 or higher
   - Git for version control
   - make (optional, for build automation)

2. Build Process
   ```bash
   # Get the package
   go get github.com/threatflux/cryptum-go

   # Build CLI tool
   go install github.com/threatflux/cryptum-go/cmd/cryptum@latest

   # Run tests
   go test ./...

   # Build from source
   git clone https://github.com/threatflux/cryptum-go.git
   cd cryptum-go
   go build ./...
   ```

3. Project Structure
   - /cmd - Command line tools
   - /pkg - Public packages
   - /internal - Private packages
   - /tests - Test suites

## Technical Constraints
1. Compatibility
   - Must maintain data format compatibility with Python cryptum
   - Must support RSA 4096-bit keys
   - Must use AES-GCM for symmetric encryption

2. Security Requirements
   - Use secure random number generation
   - Implement proper key management
   - Follow cryptographic best practices

3. Performance Goals
   - Efficient handling of large data blocks
   - Minimal memory footprint
   - Fast encryption/decryption operations

## Dependencies
1. Standard Library
   - crypto/rsa
   - crypto/aes
   - crypto/cipher
   - crypto/rand
   - encoding/base64
   - encoding/pem

2. External (if needed)
   - None currently required

## Development Guidelines
1. Code Style
   - Follow Go standard formatting (gofmt)
   - Use golangci-lint for static analysis
   - Write godoc comments for all exported items

2. Testing
   - Write unit tests for all packages
   - Include integration tests
   - Maintain test coverage above 80%

3. Documentation
   - Maintain godoc documentation
   - Keep README.md updated
   - Document all public APIs