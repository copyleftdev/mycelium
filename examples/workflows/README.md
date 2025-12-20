# Mycelium Example Workflows

This directory contains example configurations and workflows for common Mycelium use cases.

## Directory Structure

- `basic-setup/` - Simple single-developer setup
- `team-project/` - Multi-developer team project
- `ci-cd/` - GitHub Actions CI/CD integration
- `enterprise/` - Enterprise setup with recovery keys
- `multi-environment/` - Development, staging, production environments

## Quick Examples

### Basic .myc.yaml Configuration

```yaml
# Simple project configuration
vault: my-secrets-vault
project: my-app
set: development
export_format: dotenv
output_file: .env
```

### GitHub Actions Workflow

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Install Mycelium
        run: |
          curl -L https://github.com/your-org/mycelium/releases/latest/download/myc-linux-x64.tar.gz | tar xz
          sudo mv myc /usr/local/bin/
      - name: Deploy with secrets
        run: |
          myc ci pull my-app production --format shell > secrets.env
          source secrets.env
          ./deploy.sh
        env:
          MYC_NON_INTERACTIVE: "1"
```

### Recovery Setup Script

```bash
#!/bin/bash
# Set up recovery for a new user

# Enroll multiple devices
myc profile add laptop
myc profile add desktop  
myc profile add phone

# Set recovery contacts
myc recovery set-contacts alice@company.com bob@company.com

# Check recovery status
myc recovery status
```

See individual directories for complete examples and detailed explanations.