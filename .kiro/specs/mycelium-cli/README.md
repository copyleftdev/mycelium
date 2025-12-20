# Mycelium CLI Specification

## Overview

This specification defines the complete implementation of Mycelium - a zero-knowledge secrets management system that uses GitHub as its backend. The system provides end-to-end encrypted secret storage, sharing, and rotation without requiring any server infrastructure.

## Specification Documents

### 1. Requirements (`requirements.md`)
Comprehensive requirements document with 25 major requirements covering:
- Zero-knowledge architecture and security
- Cargo workspace structure
- Cryptographic primitives
- Core data model and serialization
- Device identity and local storage
- GitHub backend integration
- Envelope encryption and PDK lifecycle
- Secret set encryption and versioning
- Membership and access control
- Key rotation and revocation
- CLI architecture and commands
- GitHub Actions CI integration
- Audit logs and integrity verification
- Key recovery and account continuity
- CLI user experience
- Import/export formats
- Testing and quality assurance
- Supply chain security
- Documentation
- Performance
- Secrets lifecycle management

Each requirement includes detailed acceptance criteria following EARS (Easy Approach to Requirements Syntax) patterns.

### 2. Design (`design.md`)
Comprehensive design document including:
- **Architecture**: System architecture, crate architecture, data flow diagrams
- **Components & Interfaces**: Detailed API specifications for all modules
- **Data Models**: GitHub repository structure, local storage structure, serialization formats
- **55 Correctness Properties**: Derived from acceptance criteria, covering all critical system behaviors
- **Error Handling**: Error types and handling strategies
- **Testing Strategy**: Unit tests, property-based tests, integration tests
- **Security Considerations**: Threat model, security properties, cryptographic assumptions
- **Performance**: Optimization strategies, targets, scalability limits
- **Deployment**: Installation, configuration, monitoring, backup/recovery

### 3. Tasks (`tasks.md`)
Implementation plan organized into 17 phases with 150+ tasks:
- **Phase 1-2**: Foundation (workspace, crypto, data model)
- **Phase 3-4**: Device identity and GitHub integration
- **Phase 5-6**: Envelope encryption and PDK management
- **Phase 7-8**: Secret encryption and membership
- **Phase 9-10**: Rotation and audit logging
- **Phase 11-13**: Import/export, CLI, output formatting
- **Phase 14-15**: UX and key recovery
- **Phase 16-17**: Testing, documentation, polish

Each task includes:
- Clear implementation steps
- References to specific requirements
- Property-based tests with explicit property references
- Unit and integration tests

## Key Design Principles

1. **Zero-Trust Storage**: GitHub never sees plaintext secrets or decryption keys
2. **Client-Side Crypto**: All encryption, signing, and verification happens locally
3. **Envelope Encryption**: Symmetric PDKs encrypt secrets; PDKs are wrapped to device keys
4. **Immutable Versioning**: All changes create new versions; history is append-only
5. **Cryptographic Integrity**: Signatures and hash chains detect tampering
6. **Separation of Concerns**: Clear boundaries between crypto, domain logic, and I/O

## Technology Stack

- **Language**: Rust (stable)
- **Crypto**: ChaCha20-Poly1305, X25519, Ed25519, HKDF-SHA256, BLAKE3, Argon2id
- **CLI Framework**: clap v4
- **Async Runtime**: tokio
- **GitHub API**: octocrab
- **Testing**: proptest for property-based testing
- **Supply Chain**: cargo-vet, cargo-audit, cargo-deny

## Crate Architecture

```
mycelium/
├── myc-crypto/      # Pure cryptographic operations (no I/O)
├── myc-core/        # Domain types and business logic
├── myc-github/      # GitHub API client and OAuth
├── myc-cli/         # CLI binary and orchestration
└── myc-test-utils/  # Shared test utilities
```

## Getting Started with Implementation

1. **Read the Requirements**: Start with `requirements.md` to understand what needs to be built
2. **Study the Design**: Review `design.md` for architecture and component details
3. **Follow the Tasks**: Implement according to `tasks.md`, phase by phase
4. **Test Continuously**: Each phase includes tests - run them as you go
5. **Verify Properties**: Ensure all 55 correctness properties hold

## Testing Approach

### Property-Based Testing
- 55 correctness properties derived from requirements
- Each property test runs 100+ iterations
- Tests tagged with explicit property references
- Covers: encryption, signatures, serialization, PDK management, permissions, audit logs

### Unit Testing
- Specific examples and edge cases
- Error condition testing
- Integration points between components

### Integration Testing
- End-to-end workflows
- Vault lifecycle
- Membership flows
- Recovery scenarios
- CI integration

## Security Model

**Threat Model**: System is secure even if GitHub is fully compromised. Attackers cannot decrypt secrets without authorized device keys.

**Cryptographic Guarantees**:
- Confidentiality: AEAD encryption (ChaCha20-Poly1305)
- Integrity: Signatures (Ed25519) and hash chains (BLAKE3)
- Authenticity: All mutations signed by device keys
- Forward Secrecy: PDK rotation on member removal

**Key Management**:
- Device keys: Generated locally, encrypted at rest with Argon2id
- PDKs: Generated with OS CSPRNG, wrapped to device keys
- All keys zeroized on drop

## Implementation Status

This is a complete specification ready for implementation. All phases are defined with clear tasks, requirements, and acceptance criteria.

To begin implementation:
```bash
# Start with Phase 1: Foundation
# See tasks.md for detailed steps
```

## References

- RFCs: See `rfcs/` directory for detailed design documents
- PRD: See `prd.json` for product requirements
- Diagrams: See `diagrams/` directory for architecture visualizations

## Questions or Issues?

Refer to:
1. Requirements document for "what" needs to be built
2. Design document for "how" it should be built
3. Tasks document for "when" and in what order
4. RFCs for detailed technical specifications
