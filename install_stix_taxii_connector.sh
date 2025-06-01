#!/bin/bash

# Update and install dependencies
sudo apt update
sudo apt install -y python3.8 python3.8-venv python3.8-dev

# Navigate to working directory
cd /usr/local/bin

# Create virtual environment
sudo python3.8 -m venv myenv

# Activate the virtual environment
source /usr/local/bin/myenv/bin/activate

# Install required Python packages
pip install --upgrade pip
pip install certifi lxml cabby requests

# Copy your Python connector script here (replace with actual path)
# Example:
# sudo cp ~/Downloads/stix-taxii-connector-v1.0.py /usr/local/bin/

# Ensure your script is executable
chmod +x /usr/local/bin/stix-taxii-connector-v1.0.py

# Create configuration file if not present
CONFIG_FILE="/usr/local/bin/configuration.cfg"
if [ ! -f "$CONFIG_FILE" ]; then
    cat <<EOF | sudo tee "$CONFIG_FILE"
[umbrella_org1]
key = TBA
secret = TBA
org_id = TBA
destination_list_name = TBA

[otx]
username = TBA
password = TBA
host = TBA
use_https = false
discovery_path = TBA
poll_days = 10

[namespace]
stix = http://stix.mitre.org/stix-1
cybox = http://cybox.mitre.org/cybox-2
URIObj = http://cybox.mitre.org/objects#URIObject-2
DomainNameObj = http://cybox.mitre.org/objects#DomainNameObject-1
AddressObj = http://cybox.mitre.org/objects#AddressObject-2
EOF
    echo "configuration.cfg created at $CONFIG_FILE"
else
    echo "configuration.cfg already exists at $CONFIG_FILE"
fi

# Add cron job
CRON_LINE="0 * * * * /usr/bin/env bash -c 'source /usr/local/bin/myenv/bin/activate && python /usr/local/bin/stix-taxii-connector-v1.0.py >> /tmp/script.log 2>&1'"
(crontab -l 2>/dev/null | grep -v 'stix-taxii-connector'; echo "$CRON_LINE") | crontab -

echo "Installation complete. The connector will run every hour via cron."
