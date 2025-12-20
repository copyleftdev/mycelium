//! Project and membership types.

use crate::error::{Result, ValidationError};
use crate::ids::{DeviceId, OrgId, ProjectId, UserId, VersionNumber};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Project metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Unique project identifier.
    pub id: ProjectId,

    /// Organization this project belongs to.
    pub org_id: OrgId,

    /// Project name.
    pub name: String,

    /// Creation timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// Device that created this project.
    pub created_by: DeviceId,

    /// Current PDK version number.
    pub current_pdk_version: VersionNumber,
}

impl Project {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Maximum name length in characters.
    pub const MAX_NAME_LENGTH: usize = 256;

    /// Create a new project.
    pub fn new(org_id: OrgId, name: String, created_by: DeviceId) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            id: ProjectId::new(),
            org_id,
            name,
            created_at: OffsetDateTime::now_utc(),
            created_by,
            current_pdk_version: VersionNumber::FIRST,
        }
    }

    /// Validate the project.
    pub fn validate(&self) -> Result<()> {
        // Validate name
        if self.name.is_empty() {
            return Err(ValidationError::InvalidName {
                reason: "name cannot be empty".to_string(),
            }
            .into());
        }

        if self.name.len() > Self::MAX_NAME_LENGTH {
            return Err(ValidationError::InvalidName {
                reason: format!(
                    "name exceeds maximum length of {} characters",
                    Self::MAX_NAME_LENGTH
                ),
            }
            .into());
        }

        // Validate timestamp is not in the future
        let now = OffsetDateTime::now_utc();
        if self.created_at > now {
            return Err(ValidationError::FutureTimestamp {
                timestamp: self.created_at.to_string(),
            }
            .into());
        }

        Ok(())
    }
}

/// Project member with role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMember {
    /// User identifier.
    pub user_id: UserId,

    /// Member's role in the project.
    pub role: Role,

    /// When the member was added (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,

    /// Device that added this member.
    pub added_by: DeviceId,
}

impl ProjectMember {
    /// Create a new project member.
    pub fn new(user_id: UserId, role: Role, added_by: DeviceId) -> Self {
        Self {
            user_id,
            role,
            added_at: OffsetDateTime::now_utc(),
            added_by,
        }
    }
}

/// Role defines access permissions within a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reader role (level 1): read-only access.
    Reader,

    /// Member role (level 2): read and write access.
    Member,

    /// Admin role (level 3): read, write, share, and rotate access.
    Admin,

    /// Owner role (level 4): all permissions including project deletion and ownership transfer.
    Owner,
}

impl Role {
    /// Get the numeric level of this role (1-4).
    pub fn level(&self) -> u8 {
        match self {
            Role::Reader => 1,
            Role::Member => 2,
            Role::Admin => 3,
            Role::Owner => 4,
        }
    }

    /// Check if this role has a specific permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        match permission {
            Permission::Read => matches!(
                self,
                Role::Reader | Role::Member | Role::Admin | Role::Owner
            ),
            Permission::Write => matches!(self, Role::Member | Role::Admin | Role::Owner),
            Permission::Share => matches!(self, Role::Admin | Role::Owner),
            Permission::Rotate => matches!(self, Role::Admin | Role::Owner),
            Permission::DeleteProject => matches!(self, Role::Owner),
            Permission::TransferOwnership => matches!(self, Role::Owner),
        }
    }

    /// Get all permissions for this role.
    pub fn permissions(&self) -> Vec<Permission> {
        Permission::all()
            .into_iter()
            .filter(|p| self.has_permission(*p))
            .collect()
    }
}

/// Permission types for project operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read secrets.
    Read,

    /// Write/update secrets.
    Write,

    /// Add/remove members and change roles.
    Share,

    /// Rotate PDK.
    Rotate,

    /// Delete the project.
    DeleteProject,

    /// Transfer ownership to another admin.
    TransferOwnership,
}

impl Permission {
    /// Get all possible permissions.
    pub fn all() -> Vec<Permission> {
        vec![
            Permission::Read,
            Permission::Write,
            Permission::Share,
            Permission::Rotate,
            Permission::DeleteProject,
            Permission::TransferOwnership,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_creation() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let project = Project::new(org_id, "Test Project".to_string(), device_id);

        assert_eq!(project.schema_version, Project::SCHEMA_VERSION);
        assert_eq!(project.name, "Test Project");
        assert_eq!(project.org_id, org_id);
        assert_eq!(project.created_by, device_id);
        assert_eq!(project.current_pdk_version, VersionNumber::FIRST);
        assert!(project.validate().is_ok());
    }

    #[test]
    fn test_project_validation_empty_name() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let mut project = Project::new(org_id, "Test Project".to_string(), device_id);
        project.name = String::new();
        assert!(project.validate().is_err());
    }

    #[test]
    fn test_project_validation_name_too_long() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let long_name = "a".repeat(Project::MAX_NAME_LENGTH + 1);
        let mut project = Project::new(org_id, "Test Project".to_string(), device_id);
        project.name = long_name;
        assert!(project.validate().is_err());
    }

    #[test]
    fn test_project_serialization() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let project = Project::new(org_id, "Test Project".to_string(), device_id);

        let json = serde_json::to_string(&project).unwrap();
        let deserialized: Project = serde_json::from_str(&json).unwrap();
        assert_eq!(project, deserialized);
    }

    #[test]
    fn test_role_levels() {
        assert_eq!(Role::Reader.level(), 1);
        assert_eq!(Role::Member.level(), 2);
        assert_eq!(Role::Admin.level(), 3);
        assert_eq!(Role::Owner.level(), 4);
    }

    #[test]
    fn test_role_ordering() {
        assert!(Role::Reader < Role::Member);
        assert!(Role::Member < Role::Admin);
        assert!(Role::Admin < Role::Owner);
    }

    #[test]
    fn test_owner_permissions() {
        let role = Role::Owner;
        assert!(role.has_permission(Permission::Read));
        assert!(role.has_permission(Permission::Write));
        assert!(role.has_permission(Permission::Share));
        assert!(role.has_permission(Permission::Rotate));
        assert!(role.has_permission(Permission::DeleteProject));
        assert!(role.has_permission(Permission::TransferOwnership));
        assert_eq!(role.permissions().len(), 6);
    }

    #[test]
    fn test_admin_permissions() {
        let role = Role::Admin;
        assert!(role.has_permission(Permission::Read));
        assert!(role.has_permission(Permission::Write));
        assert!(role.has_permission(Permission::Share));
        assert!(role.has_permission(Permission::Rotate));
        assert!(!role.has_permission(Permission::DeleteProject));
        assert!(!role.has_permission(Permission::TransferOwnership));
        assert_eq!(role.permissions().len(), 4);
    }

    #[test]
    fn test_member_permissions() {
        let role = Role::Member;
        assert!(role.has_permission(Permission::Read));
        assert!(role.has_permission(Permission::Write));
        assert!(!role.has_permission(Permission::Share));
        assert!(!role.has_permission(Permission::Rotate));
        assert!(!role.has_permission(Permission::DeleteProject));
        assert!(!role.has_permission(Permission::TransferOwnership));
        assert_eq!(role.permissions().len(), 2);
    }

    #[test]
    fn test_reader_permissions() {
        let role = Role::Reader;
        assert!(role.has_permission(Permission::Read));
        assert!(!role.has_permission(Permission::Write));
        assert!(!role.has_permission(Permission::Share));
        assert!(!role.has_permission(Permission::Rotate));
        assert!(!role.has_permission(Permission::DeleteProject));
        assert!(!role.has_permission(Permission::TransferOwnership));
        assert_eq!(role.permissions().len(), 1);
    }

    #[test]
    fn test_project_member_creation() {
        let user_id = UserId::from("github|12345678");
        let device_id = DeviceId::new();
        let member = ProjectMember::new(user_id.clone(), Role::Admin, device_id);

        assert_eq!(member.user_id, user_id);
        assert_eq!(member.role, Role::Admin);
        assert_eq!(member.added_by, device_id);
    }

    #[test]
    fn test_role_serialization() {
        let role = Role::Admin;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"admin\"");

        let deserialized: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(role, deserialized);
    }
}
