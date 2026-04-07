#!/bin/bash

set -e  # Stop on error

echo "🔄 Updating system..."
sudo apt update -y

echo "📦 Installing system dependencies..."
sudo apt install -y python3-pip python3-venv git curl unzip terraform awscli

echo "🐍 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "⬆️ Upgrading pip..."
pip install --upgrade pip

echo "🛡️ Installing cloud security tools..."
pip install prowler scoutsuite c7n ansible --prefer-binary

echo "🔐 Installing OPA (Open Policy Agent)..."
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/

echo "✅ Verifying installations..."
prowler --version || echo "Prowler not found"
scout --version || echo "ScoutSuite not found"
custodian version || echo "Cloud Custodian not found"
ansible --version || echo "Ansible not found"
opa version || echo "OPA not found"

echo "🎉 Setup complete! Activate environment with: source venv/bin/activate"
