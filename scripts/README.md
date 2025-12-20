# Mycelium Scripts

Utility scripts for documentation, diagrams, and development.

## Architecture Diagrams

Generate visual architecture diagrams using Python's `diagrams` library.

### Prerequisites

1. Install Graphviz (system dependency):
   ```bash
   # Ubuntu/Debian
   sudo apt install graphviz

   # macOS
   brew install graphviz

   # Fedora
   sudo dnf install graphviz
   ```

2. Install Python dependencies:
   ```bash
   pip install -r scripts/requirements.txt
   ```

### Generate Diagrams

```bash
cd /path/to/mycelium
python scripts/architecture_diagram.py
```

### Output

Diagrams are generated in `./diagrams/`:

| File | Description |
|------|-------------|
| `01_high_level_architecture.png` | System overview: CLI + GitHub backend |
| `02_envelope_encryption.png` | PDK wrapping and secret encryption |
| `03_data_flow.png` | Pull/push operation flow |
| `04_github_actions_oidc.png` | CI authentication flow |
| `05_pdk_rotation.png` | Key rotation on member removal |
| `06_repo_structure.png` | Vault repository layout |

### Diagrams Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         MYCELIUM                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐         ┌──────────────────────────────────┐ │
│  │   Developer  │         │     GitHub (Untrusted Storage)   │ │
│  │              │         │                                  │ │
│  │  ┌────────┐  │  OAuth  │  ┌────────────────────────────┐  │ │
│  │  │ myc    │──┼────────►│  │   Vault Repository         │  │ │
│  │  │ CLI    │  │   API   │  │                            │  │ │
│  │  └────────┘  │         │  │  .mycelium/                │  │ │
│  │      │       │         │  │  ├── vault.json            │  │ │
│  │      ▼       │         │  │  ├── devices/              │  │ │
│  │  ┌────────┐  │         │  │  ├── projects/             │  │ │
│  │  │ Device │  │         │  │  │   └── <id>/             │  │ │
│  │  │ Keys   │  │         │  │  │       ├── pdk/          │  │ │
│  │  │(local) │  │         │  │  │       ├── sets/         │  │ │
│  │  └────────┘  │         │  │  │       └── members.json  │  │ │
│  └──────────────┘         │  │  └── audit/                │  │ │
│                           │  └────────────────────────────┘  │ │
│  ┌──────────────┐         │                                  │ │
│  │GitHub Actions│  OIDC   │  Only ciphertext ever reaches    │ │
│  │  Workflow    │─────────┤  GitHub. Plaintext stays local.  │ │
│  └──────────────┘         └──────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
