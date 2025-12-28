# Network Beacon Usage Examples

This document shows how to use the network beacon feature for ecosystem discovery.

## Default Behavior

When you create a new Mycelium vault, it automatically includes the network beacon:

```bash
# Initialize a new vault
myc org init "My Company"

# The vault.json will contain:
# {
#   "schema_version": 1,
#   "id": "org_...",
#   "name": "My Company",
#   "created_at": "2024-01-01T00:00:00Z",
#   "settings": {
#     "require_device_approval": false,
#     "github_org": null,
#     "default_rotation_policy": {...},
#     "network_beacon": "mycelium_spore_network_v1"
#   }
# }
```

## Viewing Current Beacon

```bash
# Show current organization settings including beacon
myc org show

# Show just settings
myc org settings
```

## Customizing the Beacon

```bash
# Set a custom beacon for private deployments
myc org settings --network-beacon "private_deployment_2024"

# Disable telemetry completely
myc org settings --network-beacon ""

# Use a company-specific identifier
myc org settings --network-beacon "acme_corp_secrets_mesh"
```

## Discovery Queries

### Basic GitHub Search

```bash
# Find all public Mycelium vaults
site:github.com "mycelium_spore_network_v1" filename:vault.json

# Find vaults with custom beacons
site:github.com "private_deployment" filename:vault.json path:.mycelium
```

### GitHub API Queries

```bash
# Count total deployments
curl -s "https://api.github.com/search/code?q=mycelium_spore_network_v1+filename:vault.json" \
  | jq '.total_count'

# Find enterprise deployments
curl -s "https://api.github.com/search/code?q=mycelium_spore_network_v1+github_org+filename:vault.json" \
  | jq '.items[].repository.full_name'

# Analyze configuration patterns
curl -s "https://api.github.com/search/code?q=mycelium_spore_network_v1+require_device_approval:true" \
  | jq '.items | length'
```

### Advanced Analytics

```python
import requests
import json
from collections import Counter

def analyze_mycelium_adoption():
    # Search for all Mycelium vaults
    query = "mycelium_spore_network_v1 filename:vault.json"
    url = f"https://api.github.com/search/code?q={query}&per_page=100"
    
    response = requests.get(url)
    data = response.json()
    
    print(f"Total Mycelium vaults found: {data['total_count']}")
    
    # Analyze repository patterns
    repo_owners = [item['repository']['owner']['login'] for item in data['items']]
    owner_counts = Counter(repo_owners)
    
    print(f"Unique organizations: {len(owner_counts)}")
    print(f"Top adopters: {owner_counts.most_common(5)}")
    
    return data

# Run analysis
adoption_data = analyze_mycelium_adoption()
```

## Privacy Considerations

### What's Discoverable
- Repository uses Mycelium (via beacon search)
- Organization name (in vault metadata)
- Basic configuration patterns
- Adoption trends over time

### What Remains Private
- Actual secret values (always encrypted)
- Project names (encrypted)
- Member identities (cryptographic hashes only)
- Secret content and structure

## Beacon Evolution

### Current Version: v1
- `mycelium_spore_network_v1` - Standard deployment beacon
- Stable identifier for ecosystem tracking
- Compatible with all Mycelium versions

### Future Versions
- `mycelium_spore_network_v2` - Enhanced metadata support
- `mycelium_enterprise_v1` - Enterprise feature tracking
- `mycelium_federated_v1` - Multi-vault federation support

## Security Implications

The network beacon is designed to be:
- **Safe to expose**: Contains no sensitive information
- **Easily searchable**: Optimized for GitHub's search algorithms
- **Version-aware**: Enables tracking of feature adoption
- **Customizable**: Can be modified or disabled by users

Even if attackers discover Mycelium usage through beacons:
- Encrypted secrets remain protected by cryptographic keys
- Device identities use secure hashes
- Access control is enforced through GitHub permissions
- Audit trails maintain integrity through signatures

The beacon provides valuable ecosystem insights while maintaining Mycelium's zero-knowledge security model.