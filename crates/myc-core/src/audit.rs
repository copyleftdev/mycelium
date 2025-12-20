//! Audit event types and operations.
//!
//! This module defines the audit event structure and related types for tracking
//! all mutating operations in the vault.

use crate::ids::{DeviceId, OrgId, ProjectId, SecretSetId};
use myc_crypto::sign::Signature;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Unique identifier for an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(Uuid);

impl EventId {
    /// Create a new random event ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an event ID from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Organization events
    /// Organization was created.
    OrgCreated,
    /// Organization settings were updated.
    OrgSettingsUpdated,

    // Device events
    /// Device was enrolled.
    DeviceEnrolled,
    /// Device was approved.
    DeviceApproved,
    /// Device was revoked.
    DeviceRevoked,

    // Project events
    /// Project was created.
    ProjectCreated,
    /// Project was deleted.
    ProjectDeleted,

    // Membership events
    /// Member was added to project.
    MemberAdded,
    /// Member was removed from project.
    MemberRemoved,
    /// Member's role was changed.
    RoleChanged,
    /// Ownership was transferred.
    OwnershipTransferred,

    // Secret events
    /// Secret set was created.
    SecretSetCreated,
    /// Secret set was deleted.
    SecretSetDeleted,
    /// Secret version was created (push).
    SecretVersionCreated,

    // Key events
    /// PDK was rotated.
    PdkRotated,
    /// PDK was wrapped to new device.
    PdkWrapped,

    // Admin events
    /// Manual audit note was added.
    AuditNote,
    /// Recovery was initiated.
    RecoveryInitiated,
    /// Recovery was completed.
    RecoveryCompleted,

    // CI events
    /// CI device was enrolled.
    CiEnrolled,
    /// CI device pulled secrets.
    CiPull,
    /// CI device expired.
    CiExpired,
    /// CI device was revoked.
    CiRevoked,
}

/// Details specific to each event type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventDetails {
    /// Organization event details.
    Org(OrgEventDetails),
    /// Device event details.
    Device(DeviceEventDetails),
    /// Project event details.
    Project(ProjectEventDetails),
    /// Membership event details.
    Membership(MembershipEventDetails),
    /// Secret event details.
    Secret(SecretEventDetails),
    /// Key event details.
    Key(KeyEventDetails),
    /// Admin event details.
    Admin(AdminEventDetails),
    /// CI event details.
    Ci(CiEventDetails),
}

/// Organization event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgEventDetails {
    /// Organization name.
    pub name: String,
    /// Optional settings changes.
    pub settings: Option<serde_json::Value>,
}

/// Device event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEventDetails {
    /// Device ID.
    pub device_id: DeviceId,
    /// Device name.
    pub device_name: String,
    /// Device type (interactive or CI).
    pub device_type: String,
    /// Optional reason for action.
    pub reason: Option<String>,
}

/// Project event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectEventDetails {
    /// Project ID.
    pub project_id: ProjectId,
    /// Project name.
    pub project_name: String,
}

/// Membership event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipEventDetails {
    /// Project ID.
    pub project_id: ProjectId,
    /// User ID being added/removed/changed.
    pub user_id: String,
    /// Role assigned or changed to.
    pub role: Option<String>,
    /// Previous role (for role changes).
    pub previous_role: Option<String>,
}

/// Secret event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEventDetails {
    /// Project ID.
    pub project_id: ProjectId,
    /// Secret set ID.
    pub set_id: SecretSetId,
    /// Secret set name.
    pub set_name: String,
    /// Version number (for version created events).
    pub version: Option<u64>,
    /// Optional commit message.
    pub message: Option<String>,
}

/// Key event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEventDetails {
    /// Project ID.
    pub project_id: ProjectId,
    /// PDK version number.
    pub pdk_version: u64,
    /// Reason for rotation.
    pub reason: String,
    /// Devices excluded from new PDK version.
    pub excluded_devices: Vec<DeviceId>,
}

/// Admin event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminEventDetails {
    /// Note or message.
    pub note: String,
    /// Optional related project.
    pub project_id: Option<ProjectId>,
}

/// CI event details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiEventDetails {
    /// CI device ID.
    pub device_id: DeviceId,
    /// Repository (e.g., "myorg/myrepo").
    pub repository: String,
    /// Workflow name.
    pub workflow: Option<String>,
    /// Git ref.
    pub git_ref: Option<String>,
    /// Project ID (for pull events).
    pub project_id: Option<ProjectId>,
    /// Secret set ID (for pull events).
    pub set_id: Option<SecretSetId>,
}

/// An audit event recording a mutating operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version for future evolution.
    pub schema_version: u32,
    /// Unique event identifier.
    pub event_id: EventId,
    /// Type of event.
    pub event_type: EventType,
    /// Timestamp when event occurred.
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Device that performed the action.
    pub actor_device_id: DeviceId,
    /// User ID of the actor.
    pub actor_user_id: String,
    /// Organization ID.
    pub org_id: OrgId,
    /// Optional project ID (if event is project-specific).
    pub project_id: Option<ProjectId>,
    /// Event-specific details.
    pub details: EventDetails,
    /// Hash chain linking to previous event.
    pub chain_hash: Vec<u8>,
    /// ID of previous event in chain.
    pub previous_event_id: Option<EventId>,
}

/// Signed audit event with signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuditEvent {
    /// The audit event data.
    #[serde(flatten)]
    pub event: AuditEvent,
    /// Signature over canonical JSON of event data.
    #[serde(with = "signature_serde")]
    pub signature: Signature,
    /// Device ID that signed the event.
    pub signed_by: DeviceId,
}

// Serde helpers for Signature as base64
mod signature_serde {
    use myc_crypto::sign::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.as_bytes());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(array))
    }
}

impl AuditEvent {
    /// Create a new audit event.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_type: EventType,
        actor_device_id: DeviceId,
        actor_user_id: String,
        org_id: OrgId,
        project_id: Option<ProjectId>,
        details: EventDetails,
        chain_hash: Vec<u8>,
        previous_event_id: Option<EventId>,
    ) -> Self {
        Self {
            schema_version: 1,
            event_id: EventId::new(),
            event_type,
            timestamp: OffsetDateTime::now_utc(),
            actor_device_id,
            actor_user_id,
            org_id,
            project_id,
            details,
            chain_hash,
            previous_event_id,
        }
    }

    /// Compute the chain hash for this event.
    ///
    /// The chain hash is computed as: BLAKE3(previous_chain_hash || canonical_json(event_data))
    ///
    /// # Arguments
    ///
    /// * `previous_chain_hash` - The chain hash from the previous event (empty for first event)
    ///
    /// # Returns
    ///
    /// The computed chain hash as a byte vector
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails
    pub fn compute_chain_hash(&self, previous_chain_hash: &[u8]) -> crate::error::Result<Vec<u8>> {
        use crate::canonical::to_canonical_json;
        use myc_crypto::hash::chain_hash;

        // Serialize event data to canonical JSON
        let canonical = to_canonical_json(self)?;

        // Compute chain hash: BLAKE3(previous_chain_hash || canonical_json)
        let hash_output = chain_hash(
            &myc_crypto::hash::HashOutput::from_bytes(
                previous_chain_hash.try_into().unwrap_or([0u8; 32]),
            ),
            canonical.as_bytes(),
        );

        Ok(hash_output.as_bytes().to_vec())
    }
}

/// Audit chain operations.
pub mod chain {
    use super::*;
    use crate::error::Result;
    use myc_crypto::hash::{chain_hash, HashOutput};

    /// Event data for hash computation (excludes chain_hash field).
    #[derive(Debug, Serialize)]
    struct EventDataForHash<'a> {
        schema_version: u32,
        event_id: EventId,
        event_type: &'a EventType,
        #[serde(with = "time::serde::rfc3339")]
        timestamp: OffsetDateTime,
        actor_device_id: DeviceId,
        actor_user_id: &'a str,
        org_id: OrgId,
        project_id: Option<ProjectId>,
        details: &'a EventDetails,
        previous_event_id: Option<EventId>,
    }

    /// Compute the chain hash for an audit event.
    ///
    /// The chain hash links events together cryptographically:
    /// chain_hash = BLAKE3(previous_chain_hash || canonical_json(event_data))
    ///
    /// Note: The chain_hash field itself is NOT included in the hash computation.
    ///
    /// # Arguments
    ///
    /// * `previous_chain_hash` - Hash from the previous event (empty for first event)
    /// * `event` - The audit event to hash
    ///
    /// # Returns
    ///
    /// The computed chain hash
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails
    pub fn compute_chain_hash(previous_chain_hash: &[u8], event: &AuditEvent) -> Result<Vec<u8>> {
        use crate::canonical::to_canonical_json;

        // Create event data structure without chain_hash field
        let event_data = EventDataForHash {
            schema_version: event.schema_version,
            event_id: event.event_id,
            event_type: &event.event_type,
            timestamp: event.timestamp,
            actor_device_id: event.actor_device_id,
            actor_user_id: &event.actor_user_id,
            org_id: event.org_id,
            project_id: event.project_id,
            details: &event.details,
            previous_event_id: event.previous_event_id,
        };

        // Serialize event data to canonical JSON
        let canonical = to_canonical_json(&event_data)?;

        // Convert previous hash to HashOutput (use zeros if empty)
        let prev_hash = if previous_chain_hash.is_empty() {
            HashOutput::from_bytes([0u8; 32])
        } else if previous_chain_hash.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(previous_chain_hash);
            HashOutput::from_bytes(arr)
        } else {
            return Err(crate::error::CoreError::ValidationError(
                crate::error::ValidationError::InvalidName {
                    reason: "invalid previous chain hash length".to_string(),
                },
            ));
        };

        // Compute chain hash
        let hash_output = chain_hash(&prev_hash, canonical.as_bytes());

        Ok(hash_output.as_bytes().to_vec())
    }

    /// Verify the hash chain for a sequence of audit events.
    ///
    /// # Arguments
    ///
    /// * `events` - Ordered list of audit events to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the chain is valid, error with the version where it breaks otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any event's chain_hash doesn't match the computed value
    /// - Events are not properly linked via previous_event_id
    pub fn verify_chain(events: &[AuditEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        for event in events {
            // Verify previous_event_id linkage
            if event.previous_event_id != previous_event_id {
                return Err(crate::error::CoreError::ChainBroken {
                    version: 0, // We don't have version numbers for audit events
                });
            }

            // Compute expected chain hash
            let expected_hash = compute_chain_hash(&previous_chain_hash, event)?;

            // Verify it matches the stored hash
            if event.chain_hash != expected_hash {
                return Err(crate::error::CoreError::HashMismatch {
                    expected: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &expected_hash,
                    ),
                    actual: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &event.chain_hash,
                    ),
                });
            }

            // Update for next iteration
            previous_chain_hash = event.chain_hash.clone();
            previous_event_id = Some(event.event_id);
        }

        Ok(())
    }
}

/// Audit event storage operations.
pub mod storage {
    use super::*;

    /// Generate the storage path for an audit event.
    ///
    /// Events are organized by month: `.mycelium/audit/<YYYY-MM>/<event-id>.json`
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event
    ///
    /// # Returns
    ///
    /// The relative path where the event should be stored
    pub fn event_path(event: &AuditEvent) -> String {
        let year_month = event
            .timestamp
            .format(&time::format_description::parse("[year]-[month]").unwrap())
            .unwrap();
        format!(".mycelium/audit/{}/{}.json", year_month, event.event_id)
    }

    /// Generate the storage path for a signed audit event.
    ///
    /// # Arguments
    ///
    /// * `signed_event` - The signed audit event
    ///
    /// # Returns
    ///
    /// The relative path where the event should be stored
    pub fn signed_event_path(signed_event: &SignedAuditEvent) -> String {
        event_path(&signed_event.event)
    }

    /// Get the directory path for a given year-month.
    ///
    /// # Arguments
    ///
    /// * `year` - The year (e.g., 2025)
    /// * `month` - The month (1-12)
    ///
    /// # Returns
    ///
    /// The directory path for that month
    pub fn month_directory(year: i32, month: u8) -> String {
        format!(".mycelium/audit/{:04}-{:02}", year, month)
    }

    /// Path to the audit index file.
    pub const INDEX_PATH: &str = ".mycelium/audit/index.json";
}

/// Audit index for tracking the latest event and chain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditIndex {
    /// Schema version for future evolution.
    pub schema_version: u32,
    /// ID of the latest event in the chain.
    pub latest_event_id: Option<EventId>,
    /// Chain hash of the latest event.
    pub latest_chain_hash: Vec<u8>,
    /// Timestamp of the latest event.
    #[serde(with = "option_rfc3339")]
    pub latest_timestamp: Option<OffsetDateTime>,
    /// Total number of events in the audit log.
    pub total_events: u64,
}

impl AuditIndex {
    /// Create a new empty audit index.
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            latest_event_id: None,
            latest_chain_hash: vec![],
            latest_timestamp: None,
            total_events: 0,
        }
    }

    /// Update the index with a new event.
    ///
    /// # Arguments
    ///
    /// * `event` - The new event to add to the index
    pub fn update(&mut self, event: &AuditEvent) {
        self.latest_event_id = Some(event.event_id);
        self.latest_chain_hash = event.chain_hash.clone();
        self.latest_timestamp = Some(event.timestamp);
        self.total_events += 1;
    }
}

impl Default for AuditIndex {
    fn default() -> Self {
        Self::new()
    }
}

// Serde helpers for Option<OffsetDateTime>
mod option_rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(dt: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(dt) => time::serde::rfc3339::serialize(dt, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| {
                OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

/// Comprehensive audit verification.
pub mod verification {
    use super::*;
    use crate::error::Result;
    use myc_crypto::sign::Ed25519PublicKey;

    /// Result of audit verification.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerificationResult {
        /// Total number of events verified.
        pub total_events: usize,
        /// Number of signatures verified.
        pub signatures_verified: usize,
        /// Number of hash chain links verified.
        pub chain_links_verified: usize,
        /// Whether all verifications passed.
        pub all_passed: bool,
        /// Any errors encountered during verification.
        pub errors: Vec<String>,
    }

    impl VerificationResult {
        /// Create a new successful verification result.
        pub fn success(total_events: usize) -> Self {
            Self {
                total_events,
                signatures_verified: total_events,
                chain_links_verified: if total_events > 0 {
                    total_events - 1
                } else {
                    0
                },
                all_passed: true,
                errors: vec![],
            }
        }

        /// Create a new failed verification result.
        pub fn failure(total_events: usize, error: String) -> Self {
            Self {
                total_events,
                signatures_verified: 0,
                chain_links_verified: 0,
                all_passed: false,
                errors: vec![error],
            }
        }
    }

    /// Verify all aspects of a sequence of signed audit events.
    ///
    /// This performs comprehensive verification:
    /// - Verifies each event's signature
    /// - Verifies the hash chain linkage
    /// - Verifies previous_event_id linkage
    ///
    /// # Arguments
    ///
    /// * `signed_events` - The signed events to verify
    /// * `get_public_key` - Function to retrieve the public key for a device ID
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with details of what was verified
    ///
    /// # Errors
    ///
    /// Returns an error if any verification fails
    pub fn verify_all<F>(
        signed_events: &[SignedAuditEvent],
        get_public_key: F,
    ) -> Result<VerificationResult>
    where
        F: FnMut(&DeviceId) -> Result<Ed25519PublicKey>,
    {
        if signed_events.is_empty() {
            return Ok(VerificationResult::success(0));
        }

        // Extract events for chain verification
        let events: Vec<AuditEvent> = signed_events.iter().map(|se| se.event.clone()).collect();

        // Verify hash chain
        if let Err(e) = chain::verify_chain(&events) {
            return Ok(VerificationResult::failure(
                signed_events.len(),
                format!("Hash chain verification failed: {}", e),
            ));
        }

        // Verify signatures
        if let Err(e) = signing::verify_signatures(signed_events, get_public_key) {
            return Ok(VerificationResult::failure(
                signed_events.len(),
                format!("Signature verification failed: {}", e),
            ));
        }

        Ok(VerificationResult::success(signed_events.len()))
    }

    /// Verify a single signed audit event.
    ///
    /// # Arguments
    ///
    /// * `signed_event` - The signed event to verify
    /// * `previous_chain_hash` - The chain hash from the previous event
    /// * `previous_event_id` - The ID of the previous event
    /// * `public_key` - The public key to verify the signature
    ///
    /// # Returns
    ///
    /// `Ok(())` if all verifications pass, error otherwise
    pub fn verify_single(
        signed_event: &SignedAuditEvent,
        previous_chain_hash: &[u8],
        previous_event_id: Option<EventId>,
        public_key: &Ed25519PublicKey,
    ) -> Result<()> {
        // Verify previous_event_id linkage
        if signed_event.event.previous_event_id != previous_event_id {
            return Err(crate::error::CoreError::ChainBroken { version: 0 });
        }

        // Verify chain hash
        let expected_hash = chain::compute_chain_hash(previous_chain_hash, &signed_event.event)?;
        if signed_event.event.chain_hash != expected_hash {
            return Err(crate::error::CoreError::HashMismatch {
                expected: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &expected_hash,
                ),
                actual: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &signed_event.event.chain_hash,
                ),
            });
        }

        // Verify signature
        signing::verify_signature(signed_event, public_key)?;

        Ok(())
    }
}

/// Audit export formats and operations.
pub mod export {
    use super::*;
    use crate::error::Result;

    /// Export format for audit events.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExportFormat {
        /// JSON format (default).
        Json,
        /// CSV format.
        Csv,
        /// Syslog format.
        Syslog,
    }

    /// Filter criteria for audit export.
    #[derive(Debug, Clone, Default)]
    pub struct ExportFilter {
        /// Filter by start date (inclusive).
        pub start_date: Option<OffsetDateTime>,
        /// Filter by end date (inclusive).
        pub end_date: Option<OffsetDateTime>,
        /// Filter by project ID.
        pub project_id: Option<ProjectId>,
        /// Filter by user ID.
        pub user_id: Option<String>,
        /// Filter by event type.
        pub event_type: Option<EventType>,
    }

    impl ExportFilter {
        /// Create a new empty filter.
        pub fn new() -> Self {
            Self::default()
        }

        /// Check if an event matches the filter criteria.
        pub fn matches(&self, event: &AuditEvent) -> bool {
            if let Some(start) = self.start_date {
                if event.timestamp < start {
                    return false;
                }
            }

            if let Some(end) = self.end_date {
                if event.timestamp > end {
                    return false;
                }
            }

            if let Some(ref project_id) = self.project_id {
                if event.project_id.as_ref() != Some(project_id) {
                    return false;
                }
            }

            if let Some(ref user_id) = self.user_id {
                if &event.actor_user_id != user_id {
                    return false;
                }
            }

            if let Some(ref event_type) = self.event_type {
                if &event.event_type != event_type {
                    return false;
                }
            }

            true
        }
    }

    /// Export signed audit events to JSON format.
    ///
    /// # Arguments
    ///
    /// * `events` - The events to export
    /// * `filter` - Optional filter criteria
    ///
    /// # Returns
    ///
    /// JSON string containing the filtered events
    pub fn to_json(events: &[SignedAuditEvent], filter: Option<&ExportFilter>) -> Result<String> {
        let filtered: Vec<&SignedAuditEvent> = if let Some(f) = filter {
            events.iter().filter(|e| f.matches(&e.event)).collect()
        } else {
            events.iter().collect()
        };

        serde_json::to_string_pretty(&filtered).map_err(|e| e.into())
    }

    /// Export signed audit events to CSV format.
    ///
    /// # Arguments
    ///
    /// * `events` - The events to export
    /// * `filter` - Optional filter criteria
    ///
    /// # Returns
    ///
    /// CSV string containing the filtered events
    pub fn to_csv(events: &[SignedAuditEvent], filter: Option<&ExportFilter>) -> Result<String> {
        let filtered: Vec<&SignedAuditEvent> = if let Some(f) = filter {
            events.iter().filter(|e| f.matches(&e.event)).collect()
        } else {
            events.iter().collect()
        };

        let mut csv = String::from(
            "event_id,event_type,timestamp,actor_device_id,actor_user_id,org_id,project_id\n",
        );

        for signed_event in filtered {
            let event = &signed_event.event;
            csv.push_str(&format!(
                "{},{:?},{},{},{},{},{}\n",
                event.event_id,
                event.event_type,
                event.timestamp,
                event.actor_device_id,
                event.actor_user_id,
                event.org_id,
                event
                    .project_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| String::from(""))
            ));
        }

        Ok(csv)
    }

    /// Export signed audit events to syslog format.
    ///
    /// # Arguments
    ///
    /// * `events` - The events to export
    /// * `filter` - Optional filter criteria
    ///
    /// # Returns
    ///
    /// Syslog-formatted string containing the filtered events
    pub fn to_syslog(events: &[SignedAuditEvent], filter: Option<&ExportFilter>) -> Result<String> {
        let filtered: Vec<&SignedAuditEvent> = if let Some(f) = filter {
            events.iter().filter(|e| f.matches(&e.event)).collect()
        } else {
            events.iter().collect()
        };

        let mut syslog = String::new();

        for signed_event in filtered {
            let event = &signed_event.event;
            // Syslog format: <timestamp> <hostname> <app>: <message>
            syslog.push_str(&format!(
                "{} mycelium audit[{}]: event_type={:?} actor={} org={} project={}\n",
                event.timestamp,
                event.event_id,
                event.event_type,
                event.actor_user_id,
                event.org_id,
                event
                    .project_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| String::from("none"))
            ));
        }

        Ok(syslog)
    }

    /// Export signed audit events in the specified format.
    ///
    /// # Arguments
    ///
    /// * `events` - The events to export
    /// * `format` - The export format
    /// * `filter` - Optional filter criteria
    ///
    /// # Returns
    ///
    /// Formatted string containing the filtered events
    pub fn export(
        events: &[SignedAuditEvent],
        format: ExportFormat,
        filter: Option<&ExportFilter>,
    ) -> Result<String> {
        match format {
            ExportFormat::Json => to_json(events, filter),
            ExportFormat::Csv => to_csv(events, filter),
            ExportFormat::Syslog => to_syslog(events, filter),
        }
    }
}

/// Manual audit note operations.
pub mod notes {
    use super::*;
    use crate::error::Result;
    use myc_crypto::sign::Ed25519SecretKey;

    /// Create a manual audit note event.
    ///
    /// Audit notes allow administrators to add manual entries to the audit log
    /// for documentation purposes.
    ///
    /// # Arguments
    ///
    /// * `note` - The note text
    /// * `actor_device_id` - The device creating the note
    /// * `actor_user_id` - The user creating the note
    /// * `org_id` - The organization ID
    /// * `project_id` - Optional project ID if note is project-specific
    /// * `previous_chain_hash` - The chain hash from the previous event
    /// * `previous_event_id` - The ID of the previous event
    /// * `signing_key` - The device's signing key
    ///
    /// # Returns
    ///
    /// A signed audit event containing the note
    #[allow(clippy::too_many_arguments)]
    pub fn create_note(
        note: String,
        actor_device_id: DeviceId,
        actor_user_id: String,
        org_id: OrgId,
        project_id: Option<ProjectId>,
        previous_chain_hash: &[u8],
        previous_event_id: Option<EventId>,
        signing_key: &Ed25519SecretKey,
    ) -> Result<SignedAuditEvent> {
        let details = EventDetails::Admin(AdminEventDetails { note, project_id });

        let mut event = AuditEvent::new(
            EventType::AuditNote,
            actor_device_id,
            actor_user_id,
            org_id,
            project_id,
            details,
            vec![],
            previous_event_id,
        );

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(previous_chain_hash, &event)?;
        event.chain_hash = chain_hash;

        // Sign the event
        signing::sign_event(event, signing_key)
    }
}

/// Audit event signing operations.
pub mod signing {
    use super::*;
    use crate::error::Result;
    use myc_crypto::sign::{sign, verify, Ed25519PublicKey, Ed25519SecretKey};

    /// Sign an audit event.
    ///
    /// Creates a signature over the canonical JSON of the event data.
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event to sign
    /// * `signing_key` - The device's Ed25519 secret key
    ///
    /// # Returns
    ///
    /// A `SignedAuditEvent` containing the event and signature
    ///
    /// # Errors
    ///
    /// Returns an error if canonical JSON serialization fails
    pub fn sign_event(
        event: AuditEvent,
        signing_key: &Ed25519SecretKey,
    ) -> Result<SignedAuditEvent> {
        use crate::canonical::to_canonical_json;

        // Serialize event to canonical JSON
        let canonical = to_canonical_json(&event)?;

        // Sign the canonical JSON
        let signature = sign(signing_key, canonical.as_bytes());

        Ok(SignedAuditEvent {
            signed_by: event.actor_device_id,
            event,
            signature,
        })
    }

    /// Verify the signature on a signed audit event.
    ///
    /// # Arguments
    ///
    /// * `signed_event` - The signed audit event to verify
    /// * `public_key` - The public key of the device that signed the event
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, error otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Canonical JSON serialization fails
    /// - Signature verification fails
    pub fn verify_signature(
        signed_event: &SignedAuditEvent,
        public_key: &Ed25519PublicKey,
    ) -> Result<()> {
        use crate::canonical::to_canonical_json;

        // Serialize event to canonical JSON
        let canonical = to_canonical_json(&signed_event.event)?;

        // Verify the signature
        verify(public_key, canonical.as_bytes(), &signed_event.signature)
            .map_err(|_| crate::error::CoreError::SignatureInvalid)?;

        Ok(())
    }

    /// Verify signatures for a sequence of signed audit events.
    ///
    /// # Arguments
    ///
    /// * `signed_events` - The signed events to verify
    /// * `get_public_key` - Function to retrieve the public key for a device ID
    ///
    /// # Returns
    ///
    /// `Ok(())` if all signatures are valid, error otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if any signature verification fails
    pub fn verify_signatures<F>(
        signed_events: &[SignedAuditEvent],
        mut get_public_key: F,
    ) -> Result<()>
    where
        F: FnMut(&DeviceId) -> Result<Ed25519PublicKey>,
    {
        for signed_event in signed_events {
            let public_key = get_public_key(&signed_event.signed_by)?;
            verify_signature(signed_event, &public_key)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_creation() {
        let id1 = EventId::new();
        let id2 = EventId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent {
            schema_version: 1,
            event_id: EventId::new(),
            event_type: EventType::ProjectCreated,
            timestamp: OffsetDateTime::now_utc(),
            actor_device_id: DeviceId::new(),
            actor_user_id: "github|12345".to_string(),
            org_id: OrgId::new(),
            project_id: Some(ProjectId::new()),
            details: EventDetails::Project(ProjectEventDetails {
                project_id: ProjectId::new(),
                project_name: "test-project".to_string(),
            }),
            chain_hash: vec![0u8; 32],
            previous_event_id: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_id, deserialized.event_id);
        assert_eq!(event.event_type, deserialized.event_type);
    }

    #[test]
    fn test_chain_hash_computation() {
        let event = AuditEvent {
            schema_version: 1,
            event_id: EventId::new(),
            event_type: EventType::ProjectCreated,
            timestamp: OffsetDateTime::now_utc(),
            actor_device_id: DeviceId::new(),
            actor_user_id: "github|12345".to_string(),
            org_id: OrgId::new(),
            project_id: Some(ProjectId::new()),
            details: EventDetails::Project(ProjectEventDetails {
                project_id: ProjectId::new(),
                project_name: "test-project".to_string(),
            }),
            chain_hash: vec![],
            previous_event_id: None,
        };

        // Compute chain hash for first event (no previous hash)
        let hash1 = chain::compute_chain_hash(&[], &event).unwrap();
        assert_eq!(hash1.len(), 32);

        // Compute chain hash for second event
        let hash2 = chain::compute_chain_hash(&hash1, &event).unwrap();
        assert_eq!(hash2.len(), 32);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_chain_verification_empty() {
        let events: Vec<AuditEvent> = vec![];
        assert!(chain::verify_chain(&events).is_ok());
    }

    #[test]
    fn test_chain_verification_single_event() {
        let mut event = create_test_event();
        event.previous_event_id = None;
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = chain_hash.clone();

        let events = vec![event.clone()];
        let result = chain::verify_chain(&events);
        if let Err(e) = &result {
            eprintln!("Verification failed: {:?}", e);
            eprintln!(
                "Expected hash: {}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &chain_hash)
            );
            eprintln!(
                "Stored hash: {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &event.chain_hash
                )
            );
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_chain_verification_multiple_events() {
        let mut events = vec![];
        let mut previous_hash = vec![];
        let mut previous_id: Option<EventId> = None;

        for _ in 0..3 {
            let mut event = create_test_event();
            event.previous_event_id = previous_id;
            let hash = chain::compute_chain_hash(&previous_hash, &event).unwrap();
            event.chain_hash = hash.clone();

            previous_hash = hash;
            previous_id = Some(event.event_id);
            events.push(event);
        }

        assert!(chain::verify_chain(&events).is_ok());
    }

    #[test]
    fn test_chain_verification_broken_hash() {
        let mut events = vec![];
        let mut previous_hash = vec![];
        let mut previous_id: Option<EventId> = None;

        for i in 0..3 {
            let mut event = create_test_event();
            let hash = chain::compute_chain_hash(&previous_hash, &event).unwrap();
            event.chain_hash = if i == 1 {
                // Break the chain at second event
                vec![0u8; 32]
            } else {
                hash.clone()
            };
            event.previous_event_id = previous_id;

            previous_hash = hash;
            previous_id = Some(event.event_id);
            events.push(event);
        }

        assert!(chain::verify_chain(&events).is_err());
    }

    #[test]
    fn test_chain_verification_broken_linkage() {
        let mut events: Vec<AuditEvent> = vec![];
        let mut previous_hash = vec![];

        for i in 0..3 {
            let mut event = create_test_event();
            let hash = chain::compute_chain_hash(&previous_hash, &event).unwrap();
            event.chain_hash = hash.clone();
            event.previous_event_id = if i == 1 {
                // Break the linkage at second event
                Some(EventId::new())
            } else if i == 0 {
                None
            } else {
                Some(events[i - 1].event_id)
            };

            previous_hash = hash;
            events.push(event);
        }

        assert!(chain::verify_chain(&events).is_err());
    }

    fn create_test_event() -> AuditEvent {
        AuditEvent {
            schema_version: 1,
            event_id: EventId::new(),
            event_type: EventType::ProjectCreated,
            timestamp: OffsetDateTime::now_utc(),
            actor_device_id: DeviceId::new(),
            actor_user_id: "github|12345".to_string(),
            org_id: OrgId::new(),
            project_id: Some(ProjectId::new()),
            details: EventDetails::Project(ProjectEventDetails {
                project_id: ProjectId::new(),
                project_name: "test-project".to_string(),
            }),
            chain_hash: vec![],
            previous_event_id: None,
        }
    }

    #[test]
    fn test_sign_and_verify_event() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();

        let signed_event = signing::sign_event(event, &secret_key).unwrap();
        assert!(signing::verify_signature(&signed_event, &public_key).is_ok());
    }

    #[test]
    fn test_verify_with_wrong_key() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key1, _) = generate_ed25519_keypair().unwrap();
        let (_, public_key2) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();

        let signed_event = signing::sign_event(event, &secret_key1).unwrap();
        assert!(signing::verify_signature(&signed_event, &public_key2).is_err());
    }

    #[test]
    fn test_verify_tampered_event() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();

        let mut signed_event = signing::sign_event(event, &secret_key).unwrap();

        // Tamper with the event
        signed_event.event.actor_user_id = "github|99999".to_string();

        assert!(signing::verify_signature(&signed_event, &public_key).is_err());
    }

    #[test]
    fn test_verify_multiple_signatures() {
        use myc_crypto::sign::generate_ed25519_keypair;
        use std::collections::HashMap;

        let mut keys = HashMap::new();
        let mut signed_events = vec![];

        for _ in 0..3 {
            let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
            let mut event = create_test_event();
            let device_id = DeviceId::new();
            event.actor_device_id = device_id;

            let signed_event = signing::sign_event(event, &secret_key).unwrap();
            keys.insert(device_id, public_key);
            signed_events.push(signed_event);
        }

        let result = signing::verify_signatures(&signed_events, |device_id| {
            keys.get(device_id)
                .copied()
                .ok_or(crate::error::CoreError::SignatureInvalid)
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_signed_event_serialization() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();

        let signed_event = signing::sign_event(event, &secret_key).unwrap();
        let json = serde_json::to_string(&signed_event).unwrap();
        let deserialized: SignedAuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(signed_event.event.event_id, deserialized.event.event_id);
        assert_eq!(signed_event.signature, deserialized.signature);
        assert_eq!(signed_event.signed_by, deserialized.signed_by);
    }

    #[test]
    fn test_event_path_generation() {
        let event = create_test_event();
        let path = storage::event_path(&event);

        // Path should be in format .mycelium/audit/YYYY-MM/<event-id>.json
        assert!(path.starts_with(".mycelium/audit/"));
        assert!(path.ends_with(".json"));
        assert!(path.contains(&event.event_id.to_string()));
    }

    #[test]
    fn test_month_directory() {
        let dir = storage::month_directory(2025, 12);
        assert_eq!(dir, ".mycelium/audit/2025-12");

        let dir = storage::month_directory(2025, 1);
        assert_eq!(dir, ".mycelium/audit/2025-01");
    }

    #[test]
    fn test_audit_index_new() {
        let index = AuditIndex::new();
        assert_eq!(index.schema_version, 1);
        assert_eq!(index.latest_event_id, None);
        assert_eq!(index.latest_chain_hash, Vec::<u8>::new());
        assert_eq!(index.latest_timestamp, None);
        assert_eq!(index.total_events, 0);
    }

    #[test]
    fn test_audit_index_update() {
        let mut index = AuditIndex::new();
        let event = create_test_event();

        index.update(&event);

        assert_eq!(index.latest_event_id, Some(event.event_id));
        assert_eq!(index.latest_chain_hash, event.chain_hash);
        assert_eq!(index.latest_timestamp, Some(event.timestamp));
        assert_eq!(index.total_events, 1);
    }

    #[test]
    fn test_audit_index_serialization() {
        let mut index = AuditIndex::new();
        let event = create_test_event();
        index.update(&event);

        let json = serde_json::to_string(&index).unwrap();
        let deserialized: AuditIndex = serde_json::from_str(&json).unwrap();

        assert_eq!(index.latest_event_id, deserialized.latest_event_id);
        assert_eq!(index.total_events, deserialized.total_events);
    }

    #[test]
    fn test_verify_all_empty() {
        use myc_crypto::sign::Ed25519PublicKey;
        use std::collections::HashMap;
        let events: Vec<SignedAuditEvent> = vec![];
        let keys: HashMap<DeviceId, Ed25519PublicKey> = HashMap::new();

        let result = verification::verify_all(&events, |device_id| {
            keys.get(device_id)
                .copied()
                .ok_or(crate::error::CoreError::SignatureInvalid)
        })
        .unwrap();

        assert!(result.all_passed);
        assert_eq!(result.total_events, 0);
    }

    #[test]
    fn test_verify_all_success() {
        use myc_crypto::sign::generate_ed25519_keypair;
        use std::collections::HashMap;

        let mut keys = HashMap::new();
        let mut signed_events = vec![];
        let mut previous_hash = vec![];
        let mut previous_id: Option<EventId> = None;

        for _ in 0..3 {
            let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
            let mut event = create_test_event();
            let device_id = DeviceId::new();
            event.actor_device_id = device_id;
            event.previous_event_id = previous_id;

            let hash = chain::compute_chain_hash(&previous_hash, &event).unwrap();
            event.chain_hash = hash.clone();

            let signed_event = signing::sign_event(event, &secret_key).unwrap();
            keys.insert(device_id, public_key);

            previous_hash = hash;
            previous_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        let result = verification::verify_all(&signed_events, |device_id| {
            keys.get(device_id)
                .copied()
                .ok_or(crate::error::CoreError::SignatureInvalid)
        })
        .unwrap();

        assert!(result.all_passed);
        assert_eq!(result.total_events, 3);
        assert_eq!(result.signatures_verified, 3);
        assert_eq!(result.chain_links_verified, 2);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verify_all_broken_chain() {
        use myc_crypto::sign::generate_ed25519_keypair;
        use std::collections::HashMap;

        let mut keys = HashMap::new();
        let mut signed_events = vec![];
        let mut previous_hash = vec![];
        let mut previous_id: Option<EventId> = None;

        for i in 0..3 {
            let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
            let mut event = create_test_event();
            let device_id = DeviceId::new();
            event.actor_device_id = device_id;
            event.previous_event_id = previous_id;

            let hash = chain::compute_chain_hash(&previous_hash, &event).unwrap();
            event.chain_hash = if i == 1 {
                // Break the chain at second event
                vec![0u8; 32]
            } else {
                hash.clone()
            };

            let signed_event = signing::sign_event(event, &secret_key).unwrap();
            keys.insert(device_id, public_key);

            previous_hash = hash;
            previous_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        let result = verification::verify_all(&signed_events, |device_id| {
            keys.get(device_id)
                .copied()
                .ok_or(crate::error::CoreError::SignatureInvalid)
        })
        .unwrap();

        assert!(!result.all_passed);
        assert_eq!(result.total_events, 3);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_verify_single_success() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
        let mut event = create_test_event();
        event.previous_event_id = None;

        let hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = hash;

        let signed_event = signing::sign_event(event, &secret_key).unwrap();

        assert!(verification::verify_single(&signed_event, &[], None, &public_key).is_ok());
    }

    #[test]
    fn test_verify_single_wrong_previous_id() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
        let mut event = create_test_event();
        event.previous_event_id = None;

        let hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = hash;

        let signed_event = signing::sign_event(event, &secret_key).unwrap();

        // Try to verify with wrong previous_event_id
        assert!(
            verification::verify_single(&signed_event, &[], Some(EventId::new()), &public_key)
                .is_err()
        );
    }

    #[test]
    fn test_export_filter_matches() {
        let event = create_test_event();
        let filter = export::ExportFilter::new();

        assert!(filter.matches(&event));
    }

    #[test]
    fn test_export_filter_by_user() {
        let event = create_test_event();
        let mut filter = export::ExportFilter::new();
        filter.user_id = Some("github|12345".to_string());

        assert!(filter.matches(&event));

        filter.user_id = Some("github|99999".to_string());
        assert!(!filter.matches(&event));
    }

    #[test]
    fn test_export_filter_by_project() {
        let mut event = create_test_event();
        let project_id = ProjectId::new();
        event.project_id = Some(project_id);

        let mut filter = export::ExportFilter::new();
        filter.project_id = Some(project_id);

        assert!(filter.matches(&event));

        filter.project_id = Some(ProjectId::new());
        assert!(!filter.matches(&event));
    }

    #[test]
    fn test_export_to_json() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();
        let signed_event = signing::sign_event(event, &secret_key).unwrap();

        let json = export::to_json(&[signed_event], None).unwrap();
        assert!(json.contains("event_id"));
        assert!(json.contains("event_type"));
    }

    #[test]
    fn test_export_to_csv() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();
        let signed_event = signing::sign_event(event, &secret_key).unwrap();

        let csv = export::to_csv(std::slice::from_ref(&signed_event), None).unwrap();
        assert!(csv.contains("event_id,event_type"));
        assert!(csv.contains(&signed_event.event.event_id.to_string()));
    }

    #[test]
    fn test_export_to_syslog() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();
        let signed_event = signing::sign_event(event, &secret_key).unwrap();

        let syslog = export::to_syslog(std::slice::from_ref(&signed_event), None).unwrap();
        assert!(syslog.contains("mycelium audit"));
        assert!(syslog.contains(&signed_event.event.event_id.to_string()));
    }

    #[test]
    fn test_export_with_filter() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();

        let mut event1 = create_test_event();
        event1.actor_user_id = "github|12345".to_string();
        let signed_event1 = signing::sign_event(event1, &secret_key).unwrap();

        let mut event2 = create_test_event();
        event2.actor_user_id = "github|99999".to_string();
        let signed_event2 = signing::sign_event(event2, &secret_key).unwrap();

        let mut filter = export::ExportFilter::new();
        filter.user_id = Some("github|12345".to_string());

        let json = export::to_json(&[signed_event1, signed_event2], Some(&filter)).unwrap();

        // Should only contain the first event
        assert!(json.contains("github|12345"));
        assert!(!json.contains("github|99999"));
    }

    #[test]
    fn test_export_format_selection() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let event = create_test_event();
        let signed_event = signing::sign_event(event, &secret_key).unwrap();

        let json = export::export(
            std::slice::from_ref(&signed_event),
            export::ExportFormat::Json,
            None,
        )
        .unwrap();
        assert!(json.contains("event_id"));

        let csv = export::export(
            std::slice::from_ref(&signed_event),
            export::ExportFormat::Csv,
            None,
        )
        .unwrap();
        assert!(csv.contains("event_id,event_type"));

        let syslog = export::export(&[signed_event], export::ExportFormat::Syslog, None).unwrap();
        assert!(syslog.contains("mycelium audit"));
    }

    #[test]
    fn test_create_audit_note() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
        let device_id = DeviceId::new();
        let org_id = OrgId::new();

        let signed_note = notes::create_note(
            "This is a test note".to_string(),
            device_id,
            "github|12345".to_string(),
            org_id,
            None,
            &[],
            None,
            &secret_key,
        )
        .unwrap();

        assert_eq!(signed_note.event.event_type, EventType::AuditNote);
        assert_eq!(signed_note.event.actor_device_id, device_id);
        assert!(signing::verify_signature(&signed_note, &public_key).is_ok());
    }

    #[test]
    fn test_audit_note_with_project() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let signed_note = notes::create_note(
            "Project-specific note".to_string(),
            device_id,
            "github|12345".to_string(),
            org_id,
            Some(project_id),
            &[],
            None,
            &secret_key,
        )
        .unwrap();

        assert_eq!(signed_note.event.project_id, Some(project_id));

        if let EventDetails::Admin(details) = &signed_note.event.details {
            assert_eq!(details.note, "Project-specific note");
            assert_eq!(details.project_id, Some(project_id));
        } else {
            panic!("Expected Admin event details");
        }
    }

    #[test]
    fn test_audit_note_chain() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
        let device_id = DeviceId::new();
        let org_id = OrgId::new();

        // Create first note
        let note1 = notes::create_note(
            "First note".to_string(),
            device_id,
            "github|12345".to_string(),
            org_id,
            None,
            &[],
            None,
            &secret_key,
        )
        .unwrap();

        // Create second note chained to first
        let note2 = notes::create_note(
            "Second note".to_string(),
            device_id,
            "github|12345".to_string(),
            org_id,
            None,
            &note1.event.chain_hash,
            Some(note1.event.event_id),
            &secret_key,
        )
        .unwrap();

        // Verify both notes
        assert!(signing::verify_signature(&note1, &public_key).is_ok());
        assert!(signing::verify_signature(&note2, &public_key).is_ok());

        // Verify chain linkage
        assert_eq!(note2.event.previous_event_id, Some(note1.event.event_id));

        // Verify chain hash
        let expected_hash =
            chain::compute_chain_hash(&note1.event.chain_hash, &note2.event).unwrap();
        assert_eq!(note2.event.chain_hash, expected_hash);
    }

    #[test]
    fn test_audit_note_serialization() {
        use myc_crypto::sign::generate_ed25519_keypair;

        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let device_id = DeviceId::new();
        let org_id = OrgId::new();

        let signed_note = notes::create_note(
            "Serialization test".to_string(),
            device_id,
            "github|12345".to_string(),
            org_id,
            None,
            &[],
            None,
            &secret_key,
        )
        .unwrap();

        let json = serde_json::to_string(&signed_note).unwrap();
        let deserialized: SignedAuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(signed_note.event.event_id, deserialized.event.event_id);
        assert_eq!(signed_note.event.event_type, deserialized.event.event_type);
    }
}
