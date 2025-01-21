# System Patterns

## Architecture
The project follows a modular architecture with clear separation of concerns:

### Core Components
1. Encryption Package (pkg/encryption)
   - RSA key generation and management (keys.go)
   - Hybrid encryption implementation (encrypt.go)
   - Decryption operations (decrypt.go)
   - Base64 and PEM encoding utilities
   - Comprehensive error handling

2. CLI Package (cmd/cryptum)
   - Command-line interface with flag parsing
   - File and stdin/stdout handling
   - User-friendly error messages
   - Debug logging support

3. Logger Package (internal/logger)
   - Structured logging
   - Log levels (DEBUG, INFO, WARN, ERROR, FATAL)
   - Thread-safe singleton pattern
   - Field-based contextual logging

### Design Patterns
1. Singleton Pattern
   - Logger instance management
   - Thread-safe implementation

2. Factory Methods
   - Key pair generation
   - Cipher creation
   - Error type construction

3. Builder Pattern
   - Encryption operation construction
   - Decryption workflow
   - CLI flag configuration

4. Interface-based Design
   - Clear encryption interfaces
   - Mockable components for testing
   - Extensible logging system

## Technical Decisions
1. Go Standard Library Usage
   - crypto/rsa for RSA operations
   - crypto/aes for AES operations
   - crypto/cipher for GCM mode
   - encoding/base64 for encoding

2. Error Handling
   - Explicit error returns
   - Custom error types for specific failures
   - Detailed error messages

3. Testing Strategy
   - Table-driven tests
   - Benchmark tests for performance
   - Integration tests with Python version

## Code Organization
```
cryptum-go/
├── cmd/
│   └── cryptum/
│       └── main.go
├── pkg/
│   └── encryption/
│       ├── keys.go
│       ├── encrypt.go
│       ├── decrypt.go
│       └── utils.go
├── internal/
│   └── logger/
└── tests/
    ├── unit/
    └── integration/