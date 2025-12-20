#!/bin/bash
# Enterprise recovery setup with organization keys and multiple recovery mechanisms

set -e

echo "🍄 Setting up enterprise recovery for Mycelium..."

VAULT_NAME="enterprise-vault"
PROJECT_NAME="critical-app"

echo "This script demonstrates enterprise recovery setup."
echo "Run sections as appropriate for your organization."

echo ""
echo "=== 1. Multi-Device Enrollment ==="
echo "Each user should enroll multiple devices:"
echo ""
echo "# Primary laptop"
echo "myc profile add work-laptop"
echo ""
echo "# Backup desktop"  
echo "myc profile add work-desktop"
echo ""
echo "# Mobile device for emergency access"
echo "myc profile add mobile-device"
echo ""

echo ""
echo "=== 2. Recovery Contacts Setup ==="
echo "Users should set up recovery contacts:"
echo ""
echo "# Set trusted colleagues as recovery contacts"
echo "myc recovery set-contacts alice@company.com bob@company.com"
echo ""
echo "# Verify recovery status"
echo "myc recovery status"
echo ""

echo ""
echo "=== 3. Organization Recovery Key (Shamir's Secret Sharing) ==="
echo "Organization admins should set up emergency recovery:"
echo ""
echo "# Generate organization recovery key with 3-of-5 threshold"
echo "# This requires 5 admins, any 3 can recover"
echo "myc recovery org-key generate --threshold 3 --shares 5"
echo ""
echo "# Each admin will receive an encrypted share"
echo "# Shares are encrypted to admin device keys"
echo ""

echo ""
echo "=== 4. Recovery Policies ==="
echo "Set up organizational recovery policies:"
echo ""

cat > recovery-policy.md << 'EOF'
# Enterprise Recovery Policy

## Device Management
- All employees must enroll at least 2 devices
- Mobile devices should be enrolled for emergency access
- Devices must be revoked immediately upon employee departure

## Recovery Contacts
- Each employee must designate 2+ recovery contacts
- Recovery contacts must be from the same team/project
- Contacts should be updated when team members change

## Organization Recovery Key
- 5 admin shares with 3-of-5 threshold
- Shares distributed to: CTO, Security Lead, DevOps Lead, Senior Architect, Engineering Manager
- Recovery key rotation: annually or after admin changes
- Emergency recovery requires approval from 2+ C-level executives

## Incident Response
1. User reports lost access
2. Verify identity through HR/manager
3. User enrolls new device
4. Recovery contact or org recovery assists
5. Old devices revoked
6. Incident logged and reviewed

## Audit Requirements
- Monthly access reviews
- Quarterly recovery testing
- Annual security assessment
- All recovery actions logged and monitored
EOF

echo "Created recovery-policy.md with organizational guidelines"

echo ""
echo "=== 5. Recovery Testing ==="
echo "Regular recovery testing procedures:"
echo ""

cat > test-recovery.sh << 'EOF'
#!/bin/bash
# Recovery testing script - run quarterly

echo "Testing recovery procedures..."

# Test 1: Multi-device access
echo "1. Testing multi-device access..."
myc device list --json | jq '.devices | length'

# Test 2: Recovery contact verification
echo "2. Verifying recovery contacts..."
myc recovery show-contacts

# Test 3: Organization recovery key status
echo "3. Checking org recovery key..."
myc recovery org-key status

# Test 4: Simulate recovery (in test environment)
echo "4. Simulating recovery process..."
echo "   - Enroll test device"
echo "   - Request recovery from contact"
echo "   - Verify access to test project"

echo "Recovery testing complete. Review results and update procedures as needed."
EOF

chmod +x test-recovery.sh
echo "Created test-recovery.sh for quarterly testing"

echo ""
echo "=== 6. Monitoring and Alerting ==="
echo "Set up monitoring for recovery events:"
echo ""

cat > monitor-recovery.sh << 'EOF'
#!/bin/bash
# Recovery monitoring script - run daily

# Check for recent recovery events
echo "Recent recovery events:"
myc audit list --event-type recovery_requested --last 7d

echo "Recent device enrollments:"
myc audit list --event-type device_enrolled --last 7d

echo "Recent device revocations:"
myc audit list --event-type device_revoked --last 7d

# Alert on suspicious activity
RECENT_RECOVERIES=$(myc audit list --event-type recovery_requested --last 24h --json | jq '.events | length')
if [ "$RECENT_RECOVERIES" -gt 0 ]; then
    echo "ALERT: $RECENT_RECOVERIES recovery requests in last 24h"
    # Send alert to security team
fi
EOF

chmod +x monitor-recovery.sh
echo "Created monitor-recovery.sh for daily monitoring"

echo ""
echo "=== 7. Compliance Documentation ==="
echo "Generate compliance reports:"
echo ""

cat > generate-compliance-report.sh << 'EOF'
#!/bin/bash
# Generate compliance report for auditors

REPORT_DATE=$(date +%Y%m%d)
REPORT_DIR="compliance-report-$REPORT_DATE"

mkdir -p "$REPORT_DIR"

echo "Generating compliance report for $REPORT_DATE..."

# Device inventory
myc device list --json > "$REPORT_DIR/device-inventory.json"

# Access control matrix
myc share list --all-projects --json > "$REPORT_DIR/access-matrix.json"

# Recovery configuration
myc recovery status --json > "$REPORT_DIR/recovery-status.json"

# Audit logs (last 90 days)
myc audit export --format csv --last 90d > "$REPORT_DIR/audit-log-90d.csv"

# Recovery events
myc audit list --event-type recovery_requested --last 90d --json > "$REPORT_DIR/recovery-events.json"

echo "Compliance report generated in $REPORT_DIR/"
echo "Submit to auditors as required."
EOF

chmod +x generate-compliance-report.sh
echo "Created generate-compliance-report.sh for compliance reporting"

echo ""
echo "✅ Enterprise recovery setup complete!"
echo ""
echo "Next steps:"
echo "1. Review and customize recovery-policy.md for your organization"
echo "2. Train admins on recovery procedures"
echo "3. Set up automated monitoring with monitor-recovery.sh"
echo "4. Schedule quarterly recovery testing with test-recovery.sh"
echo "5. Integrate compliance reporting into audit processes"
echo ""
echo "Remember:"
echo "- Test recovery procedures regularly"
echo "- Keep recovery contacts updated"
echo "- Monitor for suspicious recovery activity"
echo "- Document all recovery incidents"