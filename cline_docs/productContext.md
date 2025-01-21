# Product Context

## Purpose
Cryptum-go is a production-ready Go implementation of the Cryptum encryption framework, providing secure hybrid encryption capabilities using RSA and AES. This project successfully ports the Python cryptum library to Go, maintaining full compatibility while leveraging Go's strong cryptographic primitives and performance benefits.

## Problems Solved
1. Secure Data Encryption
   - Hybrid RSA+AES encryption for optimal security
   - Authenticated encryption using AES-GCM
   - Secure key generation and management
   - Protection against common cryptographic attacks

2. Cross-Platform Compatibility
   - Full compatibility with Python cryptum library
   - Consistent encryption format across languages
   - Seamless data exchange between Go and Python systems
   - Platform-independent key generation

3. Developer Experience
   - Simple, intuitive API design
   - Comprehensive CLI tool
   - Clear error messages and logging
   - Extensive documentation and examples

4. Production Requirements
   - Thread-safe operations
   - Performance optimized
   - Memory efficient
   - Proper error handling

## How It Works
The library implements a sophisticated hybrid encryption scheme:
1. Key Generation
   - RSA 4096-bit key pairs
   - Secure random number generation
   - PEM encoding for key storage
   - Base64 transport encoding

2. Encryption Process
   - Generate random AES-256 session key
   - Encrypt session key with RSA-OAEP
   - Encrypt data with AES-GCM
   - Combine encrypted components

3. Decryption Process
   - Extract encrypted session key
   - Decrypt session key with RSA
   - Verify and decrypt data with AES-GCM
   - Authenticate decrypted data

## Key Features
1. Cryptographic Operations
   - RSA key pair generation (4096-bit)
   - Hybrid encryption (RSA+AES)
   - Authenticated encryption (GCM mode)
   - Secure random number generation

2. Developer Tools
   - Command-line interface
   - Programmatic API
   - Streaming capabilities
   - Key management utilities

3. Security Features
   - OAEP padding with SHA-512
   - Authenticated encryption
   - Secure key handling
   - Memory security practices