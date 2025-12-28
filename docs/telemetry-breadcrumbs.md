# Mycelium Network Discovery

This document describes the telemetry breadcrumb system for discovering Mycelium adoption across GitHub.

## Overview

Mycelium automatically includes a searchable identifier in vault metadata that allows discovery of repositories using the tool. This enables understanding of ecosystem adoption while maintaining user privacy.

## Breadcrumb Implementation

### Primary Breadcrumb: Network Beacon

Every Mycelium vault includes a `network_beacon` field in the organization settings:

```json
{
  "schema_version": 1,
  "id": "org_...",
  "name": "Example Organization", 
  "created_at": "2024-01-01T00:00:00Z",
  "settings": {
    "require_device_approval": false,
    "github_org": null,
    "default_rotation_policy": null,
    "network_beacon": "mycelium_spore_network_v1"
  }
}
```

### GitHub Search Queries

To discover Mycelium usage across GitHub:

#### Basic Discovery
```
"mycelium_spore_network_v1" filename:vault.json
```

#### Advanced Queries
```
# Find all Mycelium vaults
"mycelium_spore_network_v1" path:.mycelium/vault.json

# Find vaults with specific settings
"mycelium_spore_network_v1" "require_device_approval" filename:vault.json

# Find vaults by organization
"mycelium_spore_network_v1" "github_org" filename:vault.json

# Find recent vaults (by commit date)
"mycelium_spore_network_v1" filename:vault.json created:>2024-01-01
```

## Privacy Considerations

### What's Discoverable
- Repository uses Mycelium (via network beacon)
- Organization name (in vault metadata)
- Creation timestamp
- Basic settings (approval requirements, rotation policies)
- Number of projects/devices (via directory structure)

### What's Protected
- Actual secret values (always encrypted)
- Device identities (hashed IDs only)
- Project names (encrypted in project metadata)
- Member identities (device keys only, no GitHub usernames)

## Beacon Evolution

### Version History
- `mycelium_spore_network_v1` - Initial implementation (2024)

### Future Versions
Future beacon versions may include:
- `mycelium_spore_network_v2` - Enhanced metadata
- `mycelium_enterprise_network_v1` - Enterprise features
- `mycelium_federated_network_v1` - Multi-vault federation

## Opt-Out Mechanism

Users can modify the network beacon to opt out of discovery:

```bash
# Disable telemetry breadcrumb
myc org settings --network-beacon ""

# Use custom identifier
myc org settings --network-beacon "private_deployment_2024"
```

## Analytics Use Cases

### Ecosystem Health
- Track adoption growth over time
- Identify popular configuration patterns
- Monitor version distribution

### Security Research
- Discover misconfigured vaults
- Identify common security patterns
- Research attack surface evolution

### Product Development
- Understand feature usage
- Identify integration patterns
- Guide roadmap priorities

## Implementation Details

### Beacon Placement
The beacon is stored in `.mycelium/vault.json` as part of the organization settings. This ensures:
- Consistent placement across all vaults
- Automatic inclusion in new installations
- Easy searchability via GitHub's code search

### Search Optimization
The beacon string is designed for optimal GitHub search:
- Unique enough to avoid false positives
- Descriptive enough to understand context
- Versioned for evolution tracking
- Short enough for efficient indexing

### Backward Compatibility
- New beacon versions don't break old tooling
- Missing beacons default to current version
- Custom beacons are preserved during updates

## Security Implications

### Threat Model
The beacon system assumes:
- GitHub search is public (repositories may be private)
- Metadata leakage is acceptable for adoption tracking
- Encrypted secrets remain protected regardless of discovery

### Mitigation Strategies
- No sensitive data in beacon strings
- Beacon can be customized or disabled
- Encrypted data remains protected
- Device identities use cryptographic hashes

## Example Discoveries

### Research Query Results
```bash
# Count total Mycelium deployments
curl -s "https://api.github.com/search/code?q=mycelium_spore_network_v1+filename:vault.json" | jq '.total_count'

# Find enterprise deployments
curl -s "https://api.github.com/search/code?q=mycelium_spore_network_v1+github_org+filename:vault.json"

# Analyze configuration patterns
curl -s "https://api.github.com/search/code?q=mycelium_spore_network_v1+require_device_approval:true"
```

### Adoption Metrics
- Total vault count
- Geographic distribution (via repository owners)
- Organization size patterns
- Feature adoption rates
- Version distribution

This breadcrumb system provides valuable ecosystem insights while maintaining strong security guarantees for actual secret data.