#!/bin/bash
# Basic Mycelium setup for a single developer

set -e

echo "🍄 Setting up Mycelium for basic development..."

# Step 1: Create profile
echo "Creating profile..."
myc profile add personal

# Step 2: Initialize vault
echo "Initializing vault..."
myc org init my-secrets-vault

# Step 3: Create project
echo "Creating project..."
myc project create my-app

# Step 4: Create development secrets
echo "Setting up development secrets..."
cat > .env.template << EOF
# Database
DATABASE_URL=postgres://localhost:5432/myapp_dev
REDIS_URL=redis://localhost:6379

# API Keys (replace with real values)
STRIPE_SECRET_KEY=sk_test_your_key_here
SENDGRID_API_KEY=SG.your_key_here

# Application
APP_ENV=development
DEBUG=true
LOG_LEVEL=debug
EOF

echo "Created .env.template - please edit with your actual values"
echo "Then run: myc push my-app development .env.template"

# Step 5: Set up .myc.yaml
echo "Creating .myc.yaml configuration..."
cat > .myc.yaml << EOF
vault: my-secrets-vault
project: my-app
set: development
export_format: dotenv
output_file: .env
EOF

# Step 6: Add to .gitignore
echo "Adding secrets to .gitignore..."
myc gitignore

echo "✅ Basic setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env.template with your actual secret values"
echo "2. Run: myc push .env.template"
echo "3. Run: myc pull (to test pulling secrets)"
echo "4. Run: myc run -- your-dev-command (to run with secrets)"