sudo apt update && sudo apt install -y python3-pip python3-venv git curl unzip terraform awscli

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install prowler scoutsuite c7n ansible --prefer-binary

curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa
sudo mv opa /usr/local/bin/
