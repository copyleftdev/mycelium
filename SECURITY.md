# Mycelium Security Documentation

> Comprehensive security model, threat analysis, and cryptographic design

## Table of Contents

1. [Security Model](#security-model)
2. [Threat Model](#threat-model)
3. [Cryptographic Design](#cryptographic-design)
4. [Key Management](#key-management)
5. [Attack Scenarios](#attack-scenarios)
6. [Security Best Practices](#security-best-practices)
7. [Incident Response](#incident-response)
8. [Compliance and Auditing](#compliance-and-auditing)

## Security Model

### Core Security Principle

**Zero-Knowledge Storage**: Mycelium is designed so that even if GitHub (the storage backend) is fully compromised, attackers cannot decrypt secrets without authorized device keys.

### Security Guarantees

1. **Confidentiality**: Secrets are encrypted with ChaCha20-Poly1305 AEAD
2. **Integrity**: All data is protected by Ed25519 signatures and BLAKE3 hash chains
3. **Authenticity**: All mutations are signed by authorized device keys
4. **Forward Secrecy**: Key rotation ensures compromised keys cannot decrypt future secrets
5. **Non-Repudiation**: All actions are cryptographically attributed to specific devices

### Trust Boundaries

- **Trusted**: Client devices, device keys, user passphrases
- **Semi-Trusted**: GitHub API (availability and integrity, not confidentiality)
- **Untrusted**: Network, GitHub storage, GitHub employees, other GitHub users

## Threat Model

### Assumptions

#### What We Protect Against
- ✅ GitHub data breach or compromise
- ✅ Malicious GitHub employees
- ✅ Network eavesdropping (MITM attacks)
- ✅ Compromised individual devices (with forward secrecy)
- ✅ Insider threats (with proper access controls)
- ✅ Supply chain attacks on dependencies (with cargo-vet)

#### What We Don't Protect Against
- ❌ Compromise of all authorized devices simultaneously
- ❌ Compromise of the client binary itself
- ❌ Physical access to unlocked devices
- ❌ Keyloggers capturing passphrases
- ❌ Social engineering attacks on users

### Attack Scenarios

#### Scenario 1: GitHub Compromise
**Attack**: GitHub is fully compromised, attackers have access to all stored data.

**Protection**: 
- All secrets are encrypted with device-specific keys
- Attackers see only ciphertext, metadata, and access patterns
- No plaintext secrets are recoverable

**Impact**: None on secret confidentiality

#### Scenario 2: Device Compromise
**Attack**: An authorized device is compromised.

**Protection**:
- Device revocation immediately triggers PDK rotation
- Compromised device cannot decrypt secrets encrypted after revocation
- Historical secrets remain accessible to legitimate users

**Impact**: Limited to secrets accessible before revocation

#### Scenario 3: Network Interception
**Attack**: Attacker intercepts network traffic between client and GitHub.

**Protection**:
- All communication over HTTPS/TLS
- Only encrypted data transmitted
- OAuth tokens are short-lived and scoped

**Impact**: None on secret confidentiality

#### Scenario 4: Malicious Insider
**Attack**: Authorized user attempts to access secrets beyond their permissions.

**Protection**:
- Role-based access control enforced cryptographically
- All actions logged in immutable audit trail
- PDK wrapping ensures users can only decrypt authorized projects

**Impact**: Limited to user's authorized access level

## Cryptographic Design

### Primitives

All cryptographic primitives are from well-audited, production-ready libraries:

- **AEAD**: ChaCha20-Poly1305 (RFC 8439)
  - Library: `chacha20poly1305` v0.10 (RustCrypto)
  - Key size: 256 bits (32 bytes)
  - Nonce size: 96 bits (12 bytes, randomly generated per encryption)
  - Tag size: 128 bits (16 bytes)
  - Implementation: Constant-time, side-channel resistant

- **Key Agreement**: X25519 (RFC 7748)
  - Library: `x25519-dalek` v2.0
  - Key size: 256 bits (32 bytes)
  - Used for PDK wrapping (ECIES-style envelope encryption)
  - Implementation: Constant-time Curve25519 operations

- **Signatures**: Ed25519 (RFC 8032)
  - Library: `ed25519-dalek` v2.0
  - Key size: 256 bits (32 bytes private, 32 bytes public)
  - Signature size: 512 bits (64 bytes)
  - Used for authentication and integrity verification
  - Implementation: Constant-time, deterministic signatures

- **Key Derivation**: HKDF-SHA256 (RFC 5869)
  - Library: `hkdf` v0.12 (RustCrypto)
  - Hash function: SHA-256
  - Used for domain separation in PDK wrapping
  - Extract-and-expand paradigm for key stretching

- **Hashing**: BLAKE3
  - Library: `blake3` v1.5
  - Output size: 256 bits (32 bytes)
  - Used for content hashing and audit chain construction
  - Performance: Faster than SHA-256, cryptographically secure

- **Password Hashing**: Argon2id (RFC 9106)
  - Library: `argon2` v0.5 (RustCrypto)
  - Used for local device key encryption
  - Parameters: Memory cost 65536 KB, time cost 3, parallelism 4
  - Resistant to GPU and ASIC attacks

- **Random Number Generation**: OS CSPRNG
  - Library: `getrandom` v0.2
  - Source: OS-provided cryptographically secure random number generator
  - Used for key generation, nonce generation, and all randomness needs

### Envelope Encryption Architecture

```
Secrets (plaintext)
    ↓ Encrypt with PDK
Encrypted Secrets
    ↓ Store in GitHub
GitHub Repository

PDK (Project Data Key)
    ↓ Wrap to each device
Device 1: Wrapped PDK
Device 2: Wrapped PDK
Device N: Wrapped PDK
    ↓ Store in GitHub
GitHub Repository
```

### PDK Wrapping (ECIES-style)

For each device, PDKs are wrapped using an ECIES-like scheme:

1. Generate ephemeral X25519 keypair `(ephemeral_sk, ephemeral_pk)`
2. Compute shared secret: `shared = X25519(ephemeral_sk, device_pk)`
3. Derive wrapping key: `wrap_key = HKDF(shared, "mycelium-pdk-wrap", device_id)`
4. Encrypt PDK: `wrapped_pdk = ChaCha20Poly1305(wrap_key, pdk)`
5. Store `(ephemeral_pk, wrapped_pdk)`

### Signature Scheme

All mutable data is signed using Ed25519:

1. Serialize data to canonical JSON (sorted keys, no whitespace)
2. Compute signature: `sig = Ed25519Sign(device_sk, canonical_json)`
3. Store signature alongside data
4. Verify on read: `Ed25519Verify(device_pk, canonical_json, sig)`

### Hash Chaining

Audit events and secret versions use BLAKE3 hash chains:

1. Compute content hash: `content_hash = BLAKE3(canonical_json)`
2. Compute chain hash: `chain_hash = BLAKE3(previous_chain_hash || content_hash)`
3. Store both hashes with the data
4. Verify chain integrity by recomputing all hashes

## Key Management

### Device Keys

Each device has two keypairs:
- **Ed25519**: For signatures and authentication
- **X25519**: For key agreement and PDK unwrapping

#### Key Generation
```rust
// Ed25519 signing key
let signing_keypair = Ed25519Keypair::generate(&mut OsRng);

// X25519 encryption key  
let encryption_keypair = X25519Keypair::generate(&mut OsRng);
```

#### Key Storage
- Keys are encrypted at rest using Argon2id-derived keys
- Passphrase-based encryption (optional but recommended)
- File permissions: 0600 (owner read/write only)
- Keys are zeroized in memory after use

### Project Data Keys (PDKs)

- **Generation**: 256-bit random keys using `getrandom`
- **Rotation**: New PDK generated when members are removed
- **Wrapping**: Encrypted to each authorized device's X25519 key
- **Caching**: Cached in memory only, cleared on profile switch

### Key Rotation

#### Automatic Rotation Triggers
- Member removal from project
- Device revocation
- Policy-based rotation (age, schedule)

#### Rotation Process
1. Generate new PDK
2. Increment version number
3. Wrap new PDK to all authorized devices
4. Update project metadata
5. Sign and commit changes
6. Create audit event

### Recovery Keys

#### Multi-Device Recovery
- Users can enroll multiple devices
- Each device has independent keypairs
- Loss of one device doesn't prevent access

#### Recovery Contacts
- Users can designate trusted contacts
- Contacts can wrap PDKs to new devices
- Only for projects the contact has access to

#### Organization Recovery Keys (Shamir's Secret Sharing)
- Organization-level recovery mechanism
- Master key split using Shamir's Secret Sharing
- Requires threshold of admin shares to reconstruct
- Used only for emergency recovery

## Attack Scenarios

### Detailed Analysis

#### 1. GitHub Data Breach

**Scenario**: Attackers gain full access to GitHub's infrastructure and data.

**What Attackers See**:
- Repository structure and file names
- Encrypted secret data (ciphertext only)
- Wrapped PDKs (encrypted to device keys)
- Metadata (project names, member lists, timestamps)
- Audit logs (signed but readable)

**What Attackers Cannot Do**:
- Decrypt secrets (no access to device keys)
- Forge signatures (no access to signing keys)
- Modify data undetectably (signatures would break)

**Mitigation**: None required - system designed for this scenario.

#### 2. Compromised Device

**Scenario**: Attacker gains access to an authorized device.

**Timeline**:
- T0: Device compromised
- T1: Admin notices compromise, revokes device
- T2: PDK rotation triggered automatically
- T3+: Compromised device cannot decrypt new secrets

**What Attacker Can Access**:
- Secrets encrypted before T2
- Cached PDKs (if any)

**What Attacker Cannot Access**:
- Secrets encrypted after T2
- Other users' device keys
- Future PDK versions

**Mitigation**: Immediate device revocation, PDK rotation.

#### 3. Supply Chain Attack

**Scenario**: Malicious code injected into dependencies.

**Protection**:
- All dependencies vetted using cargo-vet with security rationale
- Minimal dependency tree (< 50 direct dependencies)
- Prefer RustCrypto and dalek ecosystems (extensively audited)
- Regular security audits and vulnerability scanning
- Pinned dependency versions in Cargo.lock
- Automated dependency updates with security review

**Detection**:
- cargo-audit for known vulnerabilities (runs in CI)
- cargo-deny for license compliance and duplicate checks
- cargo-vet for dependency vetting and audit trail
- CI pipeline enforces all security checks before merge
- Dependabot alerts for security vulnerabilities

**Current Security Posture**:
- **Last audit**: December 2024
- **Vulnerabilities**: 0 known critical or high severity
- **Vet coverage**: 100% of dependencies vetted or exempted
- **License compliance**: MIT/Apache-2.0 only

#### 4. Social Engineering

**Scenario**: Attacker tricks user into revealing credentials or installing malware.

**Limitations**:
- Device keys are encrypted at rest
- Passphrases required for key access
- No single point of failure (multiple devices)

**Mitigation**:
- User education
- Multi-device enrollment
- Recovery contacts
- Audit trail for detection

## Security Best Practices

### For Users

#### Device Security
1. **Use strong passphrases** for device key encryption
2. **Enroll multiple devices** for redundancy
3. **Keep devices updated** and secure
4. **Use full-disk encryption** on devices
5. **Lock devices when unattended**

#### Access Management
1. **Follow principle of least privilege**
2. **Regularly review project membership**
3. **Remove access for departing team members**
4. **Use separate projects for different environments**

#### Key Management
1. **Rotate keys regularly** (quarterly recommended)
2. **Revoke compromised devices immediately**
3. **Set up recovery contacts**
4. **Test recovery procedures**

### For Organizations

#### Governance
1. **Define clear access policies**
2. **Regular access reviews**
3. **Incident response procedures**
4. **Security training for users**

#### Technical Controls
1. **Enforce PDK rotation policies**
2. **Monitor audit logs**
3. **Regular integrity verification**
4. **Backup audit logs externally**

#### Compliance
1. **Export audit logs for compliance**
2. **Document security procedures**
3. **Regular security assessments**
4. **Vendor risk management for GitHub**

## Incident Response

### Detection

#### Indicators of Compromise
- Unexpected device enrollments
- Unusual access patterns in audit logs
- Failed decryption attempts
- Unauthorized membership changes

#### Monitoring
```bash
# Regular audit log review
myc audit list --last 7d --format json | jq '.events[] | select(.event_type == "device_enrolled")'

# Integrity verification
myc verify --all-projects

# Check for suspicious activity
myc audit list --event-type membership_changed --last 30d
```

### Response Procedures

#### 1. Device Compromise (Confirmed)
```bash
# Immediate actions
myc device revoke <compromised-device-id>

# Verify rotation completed
myc audit list --event-type pdk_rotated --last 1h

# Review access logs
myc audit list --device <compromised-device-id> --last 30d
```

#### 2. Suspected Unauthorized Access
```bash
# Review recent activity
myc audit list --last 24h --format json > incident-audit.json

# Check integrity
myc verify --all-projects > integrity-check.log

# Rotate all PDKs as precaution
for project in $(myc project list --json | jq -r '.projects[].name'); do
    myc rotate "$project" --reason "security-incident"
done
```

#### 3. GitHub Account Compromise
```bash
# Revoke OAuth tokens
myc profile remove <compromised-profile>

# Re-enroll with new GitHub account
myc profile add <new-profile>

# Admin adds new identity to projects
myc share add <project> <new-github-user> --role <previous-role>
```

### Recovery Procedures

#### Lost Device Access
1. Enroll new device: `myc profile add recovery-device`
2. Contact recovery contacts or admins
3. Request PDK wrapping to new device
4. Verify access to all required projects
5. Revoke old device if compromised

#### Lost Organization Access
1. Contact organization admins
2. Provide new GitHub identity
3. Admin removes old identity, adds new one
4. Use organization recovery keys if available
5. Re-establish access to required projects

## Compliance and Auditing

### Audit Trail

Every action in Mycelium creates an immutable audit record:

```json
{
  "event_id": "01234567-89ab-cdef-0123-456789abcdef",
  "event_type": "secret_updated",
  "timestamp": "2024-12-19T10:30:00Z",
  "actor": {
    "user_id": "alice@company.com",
    "device_id": "device-123"
  },
  "project_id": "proj-456",
  "details": {
    "set_id": "production",
    "version": 15,
    "keys_changed": ["DATABASE_URL", "API_KEY"]
  },
  "signature": "...",
  "chain_hash": "...",
  "previous_event_id": "..."
}
```

### Compliance Features

#### SOC 2 Type II
- Immutable audit logs
- Cryptographic integrity protection
- Access control enforcement
- Regular integrity verification

#### GDPR
- Data minimization (only necessary metadata stored)
- Right to erasure (remove user from all projects)
- Data portability (export audit logs)
- Breach notification (audit trail for incidents)

#### HIPAA
- Encryption at rest and in transit
- Access controls and audit logs
- Integrity protection
- Administrative safeguards

### Verification and Monitoring

#### Automated Checks
```bash
# Daily integrity verification
myc verify --all-projects --json > daily-integrity-$(date +%Y%m%d).json

# Weekly audit export
myc audit export --format csv --last 7d > weekly-audit-$(date +%Y%m%d).csv

# Monthly access review
myc share list --all-projects --json > monthly-access-$(date +%Y%m%d).json
```

#### Manual Reviews
1. **Quarterly access reviews**: Verify all project memberships
2. **Annual security assessments**: Review policies and procedures
3. **Incident response testing**: Test recovery procedures
4. **Penetration testing**: External security validation

This security documentation provides a comprehensive overview of Mycelium's security model, threat analysis, and operational security practices. Regular review and updates ensure continued security effectiveness.