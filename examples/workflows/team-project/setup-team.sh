#!/bin/bash
# Team project setup with multiple members and environments

set -e

echo "🍄 Setting up Mycelium for team collaboration..."

# Configuration
VAULT_NAME="acme-corp-vault"
PROJECT_NAME="web-app"

# Step 1: Admin creates vault and project
echo "Creating vault and project (run by admin)..."
myc org init "$VAULT_NAME"
myc project create "$PROJECT_NAME"

# Step 2: Create multiple environments
echo "Creating environments..."
myc set create "$PROJECT_NAME" development
myc set create "$PROJECT_NAME" staging  
myc set create "$PROJECT_NAME" production

# Step 3: Set up development secrets
echo "Setting up development secrets..."
cat > dev-secrets.env << EOF
# Database
DATABASE_URL=postgres://dev-db:5432/webapp_dev
REDIS_URL=redis://dev-redis:6379

# External APIs
STRIPE_SECRET_KEY=sk_test_dev_key
SENDGRID_API_KEY=SG.dev_key

# Application
APP_ENV=development
DEBUG=true
LOG_LEVEL=debug
JWT_SECRET=dev-jwt-secret-key
EOF

myc push "$PROJECT_NAME" development dev-secrets.env

# Step 4: Set up staging secrets
echo "Setting up staging secrets..."
cat > staging-secrets.env << EOF
# Database
DATABASE_URL=postgres://staging-db:5432/webapp_staging
REDIS_URL=redis://staging-redis:6379

# External APIs
STRIPE_SECRET_KEY=sk_test_staging_key
SENDGRID_API_KEY=SG.staging_key

# Application
APP_ENV=staging
DEBUG=false
LOG_LEVEL=info
JWT_SECRET=staging-jwt-secret-key
EOF

myc push "$PROJECT_NAME" staging staging-secrets.env

# Step 5: Set up production secrets (admin only)
echo "Setting up production secrets..."
cat > production-secrets.env << EOF
# Database
DATABASE_URL=postgres://prod-db:5432/webapp_prod
REDIS_URL=redis://prod-redis:6379

# External APIs
STRIPE_SECRET_KEY=sk_live_REPLACE_WITH_REAL_KEY
SENDGRID_API_KEY=SG.REPLACE_WITH_REAL_KEY

# Application
APP_ENV=production
DEBUG=false
LOG_LEVEL=warn
JWT_SECRET=REPLACE_WITH_STRONG_PRODUCTION_SECRET
EOF

myc push "$PROJECT_NAME" production production-secrets.env

# Step 6: Add team members
echo "Adding team members..."
echo "Run these commands to add team members:"
echo "  myc share add $PROJECT_NAME alice@company.com --role admin"
echo "  myc share add $PROJECT_NAME bob@company.com --role member"
echo "  myc share add $PROJECT_NAME charlie@company.com --role member"
echo "  myc share add $PROJECT_NAME diana@company.com --role reader"

# Step 7: Set up CI/CD access
echo "Setting up CI/CD access..."
echo "Run this command to enroll CI:"
echo "  myc ci enroll $PROJECT_NAME production --repo acme-corp/web-app --workflow deploy.yml --environment production"
echo "  myc ci enroll $PROJECT_NAME staging --repo acme-corp/web-app --workflow deploy.yml --environment staging"

# Step 8: Create project configs for different environments
echo "Creating project configurations..."

mkdir -p configs

cat > configs/.myc.dev.yaml << EOF
vault: $VAULT_NAME
project: $PROJECT_NAME
set: development
export_format: dotenv
output_file: .env.development
EOF

cat > configs/.myc.staging.yaml << EOF
vault: $VAULT_NAME
project: $PROJECT_NAME
set: staging
export_format: dotenv
output_file: .env.staging
EOF

cat > configs/.myc.prod.yaml << EOF
vault: $VAULT_NAME
project: $PROJECT_NAME
set: production
export_format: dotenv
output_file: .env.production
EOF

# Clean up temporary files
rm -f dev-secrets.env staging-secrets.env production-secrets.env

echo "✅ Team project setup complete!"
echo ""
echo "Team members should:"
echo "1. Create their profiles: myc profile add work-laptop"
echo "2. Copy appropriate .myc.yaml config to their project root"
echo "3. Pull secrets: myc pull"
echo ""
echo "Admins should:"
echo "1. Add team members using the commands above"
echo "2. Set up recovery contacts: myc recovery set-contacts"
echo "3. Review access regularly: myc share list $PROJECT_NAME"