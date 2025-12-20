#!/usr/bin/env python3
"""
Mycelium Architecture Diagram

Generates visual architecture diagrams using the `diagrams` library.
Install: pip install diagrams

Run: python scripts/architecture_diagram.py
Output: mycelium_architecture.png
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.custom import Custom
from diagrams.onprem.client import User, Users
from diagrams.onprem.compute import Server
from diagrams.onprem.security import Vault
from diagrams.programming.language import Rust
from diagrams.saas.chat import Slack
from diagrams.generic.storage import Storage
from diagrams.generic.compute import Rack
from diagrams.onprem.vcs import Github
from diagrams.programming.framework import React


def create_high_level_architecture():
    """High-level system overview: CLI + GitHub backend"""
    
    graph_attr = {
        "fontsize": "20",
        "bgcolor": "white",
        "pad": "0.5",
        "splines": "spline",
    }
    
    with Diagram(
        "Mycelium: Zero-Knowledge Secrets on GitHub",
        show=False,
        filename="diagrams/01_high_level_architecture",
        direction="LR",
        graph_attr=graph_attr,
    ):
        # Actors
        with Cluster("Users"):
            developer = User("Developer")
            ci = Server("GitHub Actions")
        
        # CLI
        with Cluster("Local Device"):
            cli = Rust("myc CLI")
            local_keys = Vault("Device Keys\n(Ed25519 + X25519)")
            local_cache = Storage("Local Cache")
            
            cli - local_keys
            cli - local_cache
        
        # GitHub Backend
        with Cluster("GitHub (Untrusted Storage)"):
            gh_api = Github("GitHub API")
            
            with Cluster("Vault Repository"):
                vault_json = Storage("vault.json")
                devices = Storage("devices/")
                projects = Storage("projects/")
                audit = Storage("audit/")
            
            gh_api >> vault_json
            gh_api >> devices
            gh_api >> projects
            gh_api >> audit
        
        # Connections
        developer >> Edge(label="Commands") >> cli
        ci >> Edge(label="OIDC Auth") >> cli
        cli >> Edge(label="OAuth + API\n(ciphertext only)", color="blue") >> gh_api


def create_crypto_flow():
    """Envelope encryption flow diagram"""
    
    graph_attr = {
        "fontsize": "16",
        "bgcolor": "white",
        "rankdir": "TB",
    }
    
    with Diagram(
        "Mycelium: Envelope Encryption Flow",
        show=False,
        filename="diagrams/02_envelope_encryption",
        direction="TB",
        graph_attr=graph_attr,
    ):
        with Cluster("Secret Encryption (Push)"):
            plaintext = Storage("Plaintext\n.env file")
            pdk = Vault("PDK\n(Project Data Key)")
            ciphertext = Storage("Ciphertext\n(ChaCha20-Poly1305)")
            
            plaintext >> Edge(label="Encrypt with PDK") >> pdk >> ciphertext
        
        with Cluster("Key Wrapping"):
            with Cluster("Device A"):
                dev_a_pub = Vault("Device A\nX25519 Pubkey")
                wrapped_a = Storage("Wrapped PDK\nfor Device A")
            
            with Cluster("Device B"):
                dev_b_pub = Vault("Device B\nX25519 Pubkey")
                wrapped_b = Storage("Wrapped PDK\nfor Device B")
            
            with Cluster("CI Identity"):
                ci_pub = Vault("CI\nX25519 Pubkey")
                wrapped_ci = Storage("Wrapped PDK\nfor CI")
        
        pdk >> Edge(label="ECIES Wrap") >> dev_a_pub >> wrapped_a
        pdk >> Edge(label="ECIES Wrap") >> dev_b_pub >> wrapped_b
        pdk >> Edge(label="ECIES Wrap") >> ci_pub >> wrapped_ci


def create_data_flow():
    """Data flow for pull/push operations"""
    
    graph_attr = {
        "fontsize": "16",
        "bgcolor": "white",
    }
    
    with Diagram(
        "Mycelium: Pull/Push Data Flow",
        show=False,
        filename="diagrams/03_data_flow",
        direction="LR",
        graph_attr=graph_attr,
    ):
        dev = User("Developer")
        
        with Cluster("myc CLI"):
            cli = Rust("CLI")
            
            with Cluster("Local Operations"):
                sign = Vault("Sign\n(Ed25519)")
                encrypt = Vault("Encrypt\n(ChaCha20)")
                decrypt = Vault("Decrypt")
                verify = Vault("Verify Sig")
        
        with Cluster("GitHub"):
            api = Github("API")
            repo = Storage("Vault Repo\n(ciphertext)")
        
        # Push flow
        dev >> Edge(label="1. myc push", color="green") >> cli
        cli >> Edge(label="2. Encrypt + Sign", color="green") >> encrypt
        encrypt >> Edge(label="3. PUT ciphertext", color="green") >> api
        api >> Edge(label="4. Store", color="green") >> repo
        
        # Pull flow (shown with different color)
        repo >> Edge(label="5. GET ciphertext", color="blue", style="dashed") >> api
        api >> Edge(label="6. Fetch", color="blue", style="dashed") >> verify
        verify >> Edge(label="7. Decrypt", color="blue", style="dashed") >> decrypt
        decrypt >> Edge(label="8. Plaintext", color="blue", style="dashed") >> dev


def create_github_actions_flow():
    """GitHub Actions OIDC authentication flow"""
    
    graph_attr = {
        "fontsize": "16",
        "bgcolor": "white",
    }
    
    with Diagram(
        "Mycelium: GitHub Actions OIDC Flow",
        show=False,
        filename="diagrams/04_github_actions_oidc",
        direction="TB",
        graph_attr=graph_attr,
    ):
        with Cluster("GitHub Actions Workflow"):
            workflow = Server("Workflow Job")
            oidc_token = Vault("OIDC Token\n(JWT)")
        
        with Cluster("myc CLI (in workflow)"):
            cli = Rust("myc ci auth")
            validate = Vault("Validate JWT\nvs GitHub OIDC")
            check_authz = Storage("Check Authorized\nPatterns")
        
        with Cluster("Vault Repository"):
            members = Storage("members.json\n(CI patterns)")
            wrapped_pdk = Storage("Wrapped PDK\nfor CI identity")
            secrets = Storage("Encrypted\nSecrets")
        
        workflow >> Edge(label="1. Request OIDC token") >> oidc_token
        oidc_token >> Edge(label="2. Pass to CLI") >> cli
        cli >> Edge(label="3. Validate") >> validate
        validate >> Edge(label="4. Extract claims:\nrepo, ref, workflow") >> check_authz
        check_authz >> Edge(label="5. Match pattern?") >> members
        members >> Edge(label="6. If authorized") >> wrapped_pdk
        wrapped_pdk >> Edge(label="7. Unwrap PDK,\ndecrypt secrets") >> secrets


def create_membership_rotation():
    """PDK rotation on membership change"""
    
    graph_attr = {
        "fontsize": "16",
        "bgcolor": "white",
    }
    
    with Diagram(
        "Mycelium: PDK Rotation on Member Removal",
        show=False,
        filename="diagrams/05_pdk_rotation",
        direction="TB",
        graph_attr=graph_attr,
    ):
        admin = User("Admin")
        
        with Cluster("Before: PDK v1"):
            pdk_v1 = Vault("PDK v1")
            with Cluster("Wrapped to"):
                alice_v1 = Storage("Alice ✓")
                bob_v1 = Storage("Bob ✓")
                charlie_v1 = Storage("Charlie ✓")
        
        with Cluster("Remove Charlie"):
            remove_cmd = Rust("myc share remove\nproject charlie")
        
        with Cluster("After: PDK v2 (rotated)"):
            pdk_v2 = Vault("PDK v2\n(new key)")
            with Cluster("Wrapped to"):
                alice_v2 = Storage("Alice ✓")
                bob_v2 = Storage("Bob ✓")
                charlie_v2 = Storage("Charlie ✗\n(no access)")
        
        admin >> remove_cmd
        remove_cmd >> Edge(label="1. Generate new PDK") >> pdk_v2
        remove_cmd >> Edge(label="2. Wrap to remaining\nmembers only", style="dashed") >> alice_v2
        

def create_repo_structure():
    """Visual representation of vault repository structure"""
    
    graph_attr = {
        "fontsize": "14",
        "bgcolor": "white",
        "rankdir": "TB",
    }
    
    with Diagram(
        "Mycelium: Vault Repository Structure",
        show=False,
        filename="diagrams/06_repo_structure",
        direction="TB",
        graph_attr=graph_attr,
    ):
        repo = Github("myorg/secrets-vault")
        
        with Cluster(".mycelium/"):
            vault = Storage("vault.json\n(org metadata)")
            
            with Cluster("devices/"):
                dev1 = Storage("abc123.json\n(pubkeys)")
                dev2 = Storage("def456.json")
            
            with Cluster("projects/"):
                with Cluster("proj-uuid-1/"):
                    proj_json = Storage("project.json")
                    members = Storage("members.json")
                    
                    with Cluster("pdk/"):
                        pdk1 = Storage("v1.json")
                        pdk2 = Storage("v2.json")
                    
                    with Cluster("sets/"):
                        with Cluster("set-uuid-1/"):
                            set_json = Storage("set.json")
                            v1_enc = Storage("v1.enc")
                            v1_meta = Storage("v1.meta.json")
            
            with Cluster("audit/"):
                audit1 = Storage("2025-12/\nevents...")
        
        repo >> vault


if __name__ == "__main__":
    import os
    
    # Create output directory
    os.makedirs("diagrams", exist_ok=True)
    
    print("Generating Mycelium architecture diagrams...")
    
    print("  1/6: High-level architecture...")
    create_high_level_architecture()
    
    print("  2/6: Envelope encryption flow...")
    create_crypto_flow()
    
    print("  3/6: Pull/Push data flow...")
    create_data_flow()
    
    print("  4/6: GitHub Actions OIDC flow...")
    create_github_actions_flow()
    
    print("  5/6: PDK rotation...")
    create_membership_rotation()
    
    print("  6/6: Repository structure...")
    create_repo_structure()
    
    print("\n✓ All diagrams generated in ./diagrams/")
    print("  - 01_high_level_architecture.png")
    print("  - 02_envelope_encryption.png")
    print("  - 03_data_flow.png")
    print("  - 04_github_actions_oidc.png")
    print("  - 05_pdk_rotation.png")
    print("  - 06_repo_structure.png")
