# Home Assistant Installation Guide

Home Assistant is a free and open-source home automation platform that runs on Python. It puts local control and privacy first, serving as a FOSS alternative to proprietary smart home platforms like Google Home, Amazon Alexa, Apple HomeKit, or Samsung SmartThings. Home Assistant supports over 2000 integrations and protocols for controlling smart home devices locally without requiring cloud connectivity.

## Prerequisites

### Hardware Requirements
- **CPU**: Dual-core ARM or x86 processor (1.5+ GHz recommended)
- **RAM**: 2 GB minimum (4 GB recommended for production)
- **Storage**: 32 GB minimum (64 GB+ recommended)
- **Network**: Ethernet or WiFi connectivity
- **USB Ports**: For Z-Wave/Zigbee dongles (if using)

### Operating System Requirements
- RHEL 8/9, CentOS Stream 8/9, Rocky Linux 8/9, AlmaLinux 8/9, Fedora 37+
- Debian 11/12, Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling), Manjaro
- Alpine Linux 3.18+
- openSUSE Leap 15.5+, Tumbleweed, SLES 15 SP5+
- macOS 12+ (Monterey and later)

### Network Requirements
- **HTTP**: Port 8123 (default web interface)
- **HTTPS**: Port 8123 with TLS (recommended)
- **mDNS**: Port 5353 UDP (for device discovery)
- **MQTT**: Port 1883/8883 (if using MQTT broker)
- **SSH**: Port 22 (for remote management)

### Dependencies
- **Python**: 3.10 or later (3.11+ recommended)
- **pip**: Python package manager
- **Git**: For component updates
- **Build tools**: For compiling native extensions
- **MQTT Broker**: Mosquitto (optional but recommended)

### Required System Access
- **Root/sudo**: Required for installation and service setup
- **Dedicated user**: homeassistant user account (created during setup)
- **Hardware access**: USB devices for Z-Wave/Zigbee dongles

### Domain/DNS Requirements (Optional)
- Domain name for remote access
- Dynamic DNS service (if using residential internet)
- Valid SSL certificate (Let's Encrypt recommended)

## Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

#### Method 1: Core Installation (Recommended)

```bash
# Install EPEL repository for additional packages
sudo dnf install -y epel-release

# Install Python 3.11 and development tools
sudo dnf install -y python3.11 python3.11-pip python3.11-devel python3.11-venv \
                    gcc gcc-c++ make git curl wget \
                    systemd-devel libffi-devel openssl-devel \
                    bluez-libs-devel

# Create dedicated homeassistant user
sudo useradd -r -s /bin/bash -d /opt/homeassistant homeassistant

# Create installation directory
sudo mkdir -p /opt/homeassistant
sudo chown homeassistant:homeassistant /opt/homeassistant

# Switch to homeassistant user
sudo -u homeassistant -H -s

# Create and activate virtual environment
cd /opt/homeassistant
python3.11 -m venv .
source bin/activate

# Upgrade pip and install wheel
python -m pip install --upgrade pip wheel

# Install Home Assistant
python -m pip install homeassistant

# Exit homeassistant user session
exit
```

#### Method 2: Supervised Installation

```bash
# Install Docker (required for Supervised)
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
sudo systemctl enable --now docker

# Install additional dependencies
sudo dnf install -y curl jq apparmor-utils systemd-journal-remote

# Download and install Home Assistant Supervised
curl -Lo installer.sh https://github.com/home-assistant/supervised-installer/releases/latest/download/homeassistant-supervised.sh
sudo bash installer.sh --machine qemux86-64
```

### Debian/Ubuntu

#### Method 1: Core Installation (Recommended)

```bash
# Update package list
sudo apt update

# Install Python 3.11 and development tools
sudo apt install -y python3.11 python3.11-pip python3.11-dev python3.11-venv \
                    build-essential git curl wget \
                    libsystemd-dev libffi-dev libssl-dev \
                    bluetooth libbluetooth-dev

# Create dedicated homeassistant user
sudo useradd -r -s /bin/bash -d /opt/homeassistant homeassistant

# Create installation directory
sudo mkdir -p /opt/homeassistant
sudo chown homeassistant:homeassistant /opt/homeassistant

# Switch to homeassistant user
sudo -u homeassistant -H -s

# Create and activate virtual environment
cd /opt/homeassistant
python3.11 -m venv .
source bin/activate

# Upgrade pip and install wheel
python -m pip install --upgrade pip wheel

# Install Home Assistant
python -m pip install homeassistant

# Exit homeassistant user session
exit
```

#### Method 2: Supervised Installation

```bash
# Install Docker
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

# Add Docker GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Install additional dependencies
sudo apt install -y jq curl apparmor systemd-journal-remote

# Download and install Home Assistant Supervised
curl -Lo installer.sh https://github.com/home-assistant/supervised-installer/releases/latest/download/homeassistant-supervised.sh
sudo bash installer.sh --machine qemux86-64
```

### Arch Linux

```bash
# Update system
sudo pacman -Syu

# Install Python and development tools
sudo pacman -S python python-pip python-virtualenv \
               base-devel git curl wget \
               systemd libffi openssl \
               bluez-libs

# Create dedicated homeassistant user
sudo useradd -r -s /bin/bash -d /opt/homeassistant homeassistant

# Create installation directory
sudo mkdir -p /opt/homeassistant
sudo chown homeassistant:homeassistant /opt/homeassistant

# Switch to homeassistant user
sudo -u homeassistant -H -s

# Create and activate virtual environment
cd /opt/homeassistant
python -m venv .
source bin/activate

# Upgrade pip and install wheel
python -m pip install --upgrade pip wheel

# Install Home Assistant
python -m pip install homeassistant

# Exit homeassistant user session
exit
```

### Alpine Linux

```bash
# Update package index
apk update

# Install Python and development tools
apk add --no-cache python3 py3-pip python3-dev \
                   build-base git curl wget \
                   systemd-dev libffi-dev openssl-dev \
                   bluez-dev linux-headers

# Create dedicated homeassistant user
adduser -D -s /bin/ash -h /opt/homeassistant homeassistant

# Create installation directory
mkdir -p /opt/homeassistant
chown homeassistant:homeassistant /opt/homeassistant

# Switch to homeassistant user
su - homeassistant

# Create and activate virtual environment
cd /opt/homeassistant
python3 -m venv .
source bin/activate

# Upgrade pip and install wheel
python -m pip install --upgrade pip wheel

# Install Home Assistant
python -m pip install homeassistant

# Exit homeassistant user session
exit
```

### openSUSE/SLES

```bash
# Install Python and development tools
sudo zypper install -y python311 python311-pip python311-devel python311-virtualenv \
                        gcc gcc-c++ make git curl wget \
                        systemd-devel libffi-devel libopenssl-devel \
                        bluez-devel

# Create dedicated homeassistant user
sudo useradd -r -s /bin/bash -d /opt/homeassistant homeassistant

# Create installation directory
sudo mkdir -p /opt/homeassistant
sudo chown homeassistant:homeassistant /opt/homeassistant

# Switch to homeassistant user
sudo -u homeassistant -H -s

# Create and activate virtual environment
cd /opt/homeassistant
python3.11 -m venv .
source bin/activate

# Upgrade pip and install wheel
python -m pip install --upgrade pip wheel

# Install Home Assistant
python -m pip install homeassistant

# Exit homeassistant user session
exit
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.11
brew install python@3.11

# Create dedicated homeassistant user directory
sudo mkdir -p /opt/homeassistant
sudo chown $(whoami):staff /opt/homeassistant

# Create and activate virtual environment
cd /opt/homeassistant
python3.11 -m venv .
source bin/activate

# Upgrade pip and install wheel
python -m pip install --upgrade pip wheel

# Install Home Assistant
python -m pip install homeassistant
```

## Initial Configuration

### First-Run Setup

```bash
# Switch to homeassistant user
sudo -u homeassistant -H -s

# Activate virtual environment
cd /opt/homeassistant
source bin/activate

# Start Home Assistant for initial setup (will create config directory)
hass --config /opt/homeassistant/.homeassistant

# Home Assistant will be available at http://localhost:8123
# Complete the onboarding process in your web browser
# Press Ctrl+C to stop after initial setup
```

### Default Credentials
**WARNING:** Home Assistant does not have default credentials. You must create an admin account during the onboarding process.

### Configuration File Locations

```bash
# Main configuration directory
/opt/homeassistant/.homeassistant/

# Main configuration file
/opt/homeassistant/.homeassistant/configuration.yaml

# Secrets file (for passwords and API keys)
/opt/homeassistant/.homeassistant/secrets.yaml

# Automations
/opt/homeassistant/.homeassistant/automations.yaml

# Scripts
/opt/homeassistant/.homeassistant/scripts.yaml

# Scenes
/opt/homeassistant/.homeassistant/scenes.yaml

# Custom components
/opt/homeassistant/.homeassistant/custom_components/

# Log file
/opt/homeassistant/.homeassistant/home-assistant.log
```

### Essential Settings to Change

```yaml
# Edit /opt/homeassistant/.homeassistant/configuration.yaml
homeassistant:
  name: Home
  latitude: 32.87336  # Change to your location
  longitude: 117.22743  # Change to your location
  elevation: 430  # Change to your elevation
  unit_system: metric  # or imperial
  time_zone: America/Los_Angeles  # Change to your time zone
  
# Enable advanced mode and disable introduction
system_health:
frontend:
  themes: !include_dir_merge_named themes

# Enable logging
logger:
  default: info
  logs:
    homeassistant.core: debug

# Enable history and recorder
history:
recorder:
  purge_keep_days: 7

# HTTP configuration
http:
  server_port: 8123
  ssl_certificate: /path/to/certificate.pem  # Optional
  ssl_key: /path/to/private.key  # Optional
```

## Service Management

### systemd (RHEL, Debian, Arch, SUSE)

```bash
# Create systemd service file
sudo tee /etc/systemd/system/homeassistant.service > /dev/null <<EOF
[Unit]
Description=Home Assistant
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=homeassistant
Group=homeassistant
WorkingDirectory=/opt/homeassistant
ExecStart=/opt/homeassistant/bin/hass -c "/opt/homeassistant/.homeassistant"
RestartForceExitStatus=100
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable homeassistant.service

# Service management commands
sudo systemctl start homeassistant    # Start service
sudo systemctl stop homeassistant     # Stop service
sudo systemctl restart homeassistant  # Restart service
sudo systemctl status homeassistant   # Check status
sudo journalctl -u homeassistant -f   # View logs
```

### OpenRC (Alpine)

```bash
# Create OpenRC service file
sudo tee /etc/init.d/homeassistant > /dev/null <<'EOF'
#!/sbin/openrc-run

name="Home Assistant"
description="Open source home automation"

user="homeassistant"
group="homeassistant"
pidfile="/var/run/homeassistant.pid"
command="/opt/homeassistant/bin/hass"
command_args="-c /opt/homeassistant/.homeassistant --pid-file ${pidfile} --daemon"
command_background="yes"

depend() {
    need net
    after firewall
}
EOF

# Make executable and enable
sudo chmod +x /etc/init.d/homeassistant
sudo rc-update add homeassistant

# Service management commands
sudo service homeassistant start    # Start service
sudo service homeassistant stop     # Stop service
sudo service homeassistant restart  # Restart service
sudo service homeassistant status   # Check status
```

### launchd (macOS)

```bash
# Create launchd plist file
sudo tee /Library/LaunchDaemons/io.homeassistant.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.homeassistant</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homeassistant/bin/hass</string>
        <string>-c</string>
        <string>/opt/homeassistant/.homeassistant</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/opt/homeassistant/homeassistant.log</string>
    <key>StandardOutPath</key>
    <string>/opt/homeassistant/homeassistant.log</string>
</dict>
</plist>
EOF

# Load and start service
sudo launchctl load /Library/LaunchDaemons/io.homeassistant.plist
sudo launchctl start io.homeassistant

# Service management commands
sudo launchctl start io.homeassistant   # Start service
sudo launchctl stop io.homeassistant    # Stop service
sudo launchctl unload /Library/LaunchDaemons/io.homeassistant.plist  # Disable
```

## Advanced Configuration

### Configuration File Syntax

Home Assistant uses YAML for configuration. Key concepts:

```yaml
# Basic syntax
key: value
key_with_list:
  - item1
  - item2
key_with_dict:
  subkey: value

# Including other files
group: !include groups.yaml
automation: !include_dir_list automations/
script: !include_dir_named scripts/

# Using secrets
api_key: !secret weather_api_key
```

### Environment Variables

```bash
# Set environment variables for Home Assistant
export HASS_SERVER_HOST=0.0.0.0
export HASS_SERVER_PORT=8123

# Add to ~/.bashrc or systemd service file
Environment=HASS_SERVER_HOST=0.0.0.0
Environment=HASS_SERVER_PORT=8123
```

### Command-line Parameters

```bash
# Common command-line options
hass -c /path/to/config          # Specify config directory
hass --script check_config       # Check configuration
hass --script ensure_config      # Create default config
hass --open-ui                   # Open web interface after start
hass --debug                     # Enable debug logging
hass --daemon                    # Run as daemon
hass --pid-file /var/run/hass.pid # Specify PID file
```

### Integration with Other Services

#### MQTT Integration

```yaml
# Add to configuration.yaml
mqtt:
  broker: localhost
  port: 1883
  username: !secret mqtt_username
  password: !secret mqtt_password
  discovery: true
  discovery_prefix: homeassistant
```

#### Zigbee Integration (zigbee2mqtt)

```yaml
# Add to configuration.yaml
mqtt:
  broker: localhost
  port: 1883
  discovery: true
  discovery_prefix: homeassistant

# zigbee2mqtt will automatically create devices
```

#### Z-Wave Integration

```yaml
# Add to configuration.yaml (for Z-Wave JS)
zwave_js:
  url: "ws://localhost:3000"
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/homeassistant
server {
    listen 80;
    server_name homeassistant.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name homeassistant.example.com;

    ssl_certificate /etc/ssl/certs/homeassistant.crt;
    ssl_certificate_key /etc/ssl/private/homeassistant.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://127.0.0.1:8123;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
}
```

### Apache Configuration

```apache
# /etc/apache2/sites-available/homeassistant.conf
<VirtualHost *:80>
    ServerName homeassistant.example.com
    Redirect permanent / https://homeassistant.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName homeassistant.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/homeassistant.crt
    SSLCertificateKeyFile /etc/ssl/private/homeassistant.key
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass / http://127.0.0.1:8123/
    ProxyPassReverse / http://127.0.0.1:8123/
    
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:8123/$1" [P,L]
</VirtualHost>
```

### Caddy Configuration

```caddy
# /etc/caddy/Caddyfile
homeassistant.example.com {
    reverse_proxy 127.0.0.1:8123
    
    header {
        Strict-Transport-Security max-age=31536000;
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer-when-downgrade
    }
}
```

### Traefik Configuration

```yaml
# docker-compose.yml for Traefik
version: '3.7'

services:
  traefik:
    image: traefik:v2.10
    command:
      - --api.dashboard=true
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --providers.file.filename=/etc/traefik/dynamic.yml
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./traefik.yml:/etc/traefik/dynamic.yml:ro
      - ./certs:/certs:ro

# traefik.yml
http:
  routers:
    homeassistant:
      rule: "Host(`homeassistant.example.com`)"
      service: homeassistant
      tls: {}
  
  services:
    homeassistant:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8123"
```

## Security Configuration

### Authentication Setup

```yaml
# Add to configuration.yaml
homeassistant:
  auth_providers:
    - type: homeassistant
    - type: trusted_networks
      trusted_networks:
        - 192.168.1.0/24
        - 127.0.0.1
      trusted_users:
        192.168.1.0/24:
          - user_id_here
```

### SSL/TLS Configuration

```yaml
# Add to configuration.yaml
http:
  ssl_certificate: /etc/ssl/certs/homeassistant.crt
  ssl_key: /etc/ssl/private/homeassistant.key
  ssl_profile: modern
  server_port: 8123
  cors_allowed_origins:
    - https://cast.home-assistant.io
```

### Firewall Rules

#### firewalld (RHEL/CentOS/Fedora)

```bash
# Allow Home Assistant port
sudo firewall-cmd --permanent --add-port=8123/tcp
sudo firewall-cmd --reload

# Create custom service
sudo tee /etc/firewalld/services/homeassistant.xml > /dev/null <<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Home Assistant</short>
  <description>Home Assistant automation platform</description>
  <port protocol="tcp" port="8123"/>
  <port protocol="udp" port="5353"/>
</service>
EOF

sudo firewall-cmd --reload
sudo firewall-cmd --permanent --add-service=homeassistant
sudo firewall-cmd --reload
```

#### ufw (Ubuntu/Debian)

```bash
# Allow Home Assistant ports
sudo ufw allow 8123/tcp comment 'Home Assistant'
sudo ufw allow 5353/udp comment 'mDNS'

# Enable firewall
sudo ufw enable
```

#### iptables

```bash
# Add rules for Home Assistant
sudo iptables -A INPUT -p tcp --dport 8123 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5353 -j ACCEPT

# Save rules (command varies by distribution)
sudo iptables-save > /etc/iptables/rules.v4  # Debian/Ubuntu
sudo service iptables save  # RHEL/CentOS
```

### SELinux Policies (RHEL/CentOS/Fedora)

```bash
# Allow Home Assistant to bind to port 8123
sudo setsebool -P httpd_can_network_connect 1

# Create custom SELinux policy if needed
sudo ausearch -c 'hass' --raw | audit2allow -M homeassistant
sudo semodule -i homeassistant.pp
```

### Security Best Practices

```yaml
# Add to configuration.yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1
  ip_ban_enabled: true
  login_attempts_threshold: 5

# Enable additional security features
logger:
  default: warning
  logs:
    homeassistant.components.http.ban: warning

# Disable unnecessary integrations
default_config:
```

### API Key/Token Management

```yaml
# Create long-lived access tokens in Home Assistant UI
# Navigate to Profile -> Long-Lived Access Tokens

# Use in external applications
Authorization: Bearer YOUR_LONG_LIVED_ACCESS_TOKEN
```

## Database Setup

### SQLite (Default)

```yaml
# configuration.yaml - SQLite is default, no configuration needed
recorder:
  db_url: sqlite:////opt/homeassistant/.homeassistant/home-assistant_v2.db
  purge_keep_days: 7
  auto_purge: true
```

### PostgreSQL

```bash
# Install PostgreSQL
sudo dnf install -y postgresql postgresql-server  # RHEL/CentOS
sudo apt install -y postgresql postgresql-contrib  # Debian/Ubuntu

# Initialize and start PostgreSQL
sudo postgresql-setup --initdb  # RHEL/CentOS
sudo systemctl enable --now postgresql

# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE homeassistant;
CREATE USER hass WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE homeassistant TO hass;
\q
EOF
```

```yaml
# configuration.yaml
recorder:
  db_url: postgresql://hass:secure_password@localhost/homeassistant
  purge_keep_days: 7
  auto_purge: true
```

### MySQL/MariaDB

```bash
# Install MariaDB
sudo dnf install -y mariadb-server  # RHEL/CentOS
sudo apt install -y mariadb-server  # Debian/Ubuntu

# Start and secure MariaDB
sudo systemctl enable --now mariadb
sudo mysql_secure_installation

# Create database and user
sudo mysql <<EOF
CREATE DATABASE homeassistant CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'hass'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON homeassistant.* TO 'hass'@'localhost';
FLUSH PRIVILEGES;
EOF
```

```yaml
# configuration.yaml
recorder:
  db_url: mysql://hass:secure_password@localhost/homeassistant?charset=utf8mb4
  purge_keep_days: 7
  auto_purge: true
```

## Performance Optimization

### Resource Tuning

```yaml
# configuration.yaml
recorder:
  purge_keep_days: 3  # Reduce database size
  auto_purge: true
  commit_interval: 1
  exclude:
    domains:
      - automation
      - updater
    entity_globs:
      - sensor.weather_*

# Reduce logging
logger:
  default: warning

# Optimize frontend
frontend:
  javascript_version: latest
```

### Caching Configuration

```yaml
# Enable caching for better performance
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1

# Cache static files
frontend:
  themes: !include_dir_merge_named themes
  extra_module_url:
    - /local/my-custom-card.js?v=1
```

### Memory Optimization for Raspberry Pi

```bash
# Increase swap file size
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=100/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile
sudo dphys-swapfile setup
sudo dphys-swapfile swapon

# Add to /boot/config.txt
gpu_mem=16
disable_overscan=1
```

### Scaling Options

```yaml
# Use multiple workers for better performance
# Add to systemd service file
ExecStart=/opt/homeassistant/bin/hass -c "/opt/homeassistant/.homeassistant" --runner-threads 4

# Distribute load with nginx
upstream homeassistant {
    least_conn;
    server 127.0.0.1:8123;
    server 127.0.0.1:8124;  # Additional instance
}
```

## Monitoring

### Built-in Health Checks

```yaml
# Add to configuration.yaml
system_health:

# Enable system monitor
sensor:
  - platform: systemmonitor
    resources:
      - type: disk_use_percent
        arg: /opt/homeassistant
      - type: memory_use_percent
      - type: processor_use
      - type: last_boot
```

### Log Locations and Configuration

```yaml
# configuration.yaml
logger:
  default: info
  logs:
    homeassistant.core: debug
    homeassistant.components.mqtt: debug
    homeassistant.components.zwave_js: debug

# Log files location
# /opt/homeassistant/.homeassistant/home-assistant.log
```

### Metrics Endpoints

```yaml
# Enable Prometheus metrics
prometheus:
  namespace: hass

# Expose metrics on port 8123/api/prometheus
# Access with: curl http://localhost:8123/api/prometheus
```

### Integration with Monitoring Systems

#### Grafana Dashboard

```bash
# Install Grafana
sudo dnf install -y grafana  # RHEL/CentOS
sudo apt install -y grafana  # Debian/Ubuntu

# Configure Prometheus data source
# Import Home Assistant dashboard: https://grafana.com/grafana/dashboards/11693
```

#### Nagios/Icinga

```bash
# Check Home Assistant API
/usr/lib/nagios/plugins/check_http -H localhost -p 8123 -u /api/ -e 401
```

### Alert Configuration

```yaml
# Add to configuration.yaml
notify:
  - name: email
    platform: smtp
    server: smtp.gmail.com
    port: 587
    sender: alerts@example.com
    username: !secret email_username
    password: !secret email_password
    recipient: admin@example.com

automation:
  - alias: "System Health Alert"
    trigger:
      platform: numeric_state
      entity_id: sensor.processor_use
      above: 90
    action:
      service: notify.email
      data:
        title: "High CPU Usage"
        message: "CPU usage is {{ states('sensor.processor_use') }}%"
```

## Backup and Restore

### What to Backup

Essential files and directories:
- `/opt/homeassistant/.homeassistant/` (entire config directory)
- SSL certificates (if used)
- Database files (if using external database)
- Custom components and themes

### Backup Scripts

```bash
#!/bin/bash
# /usr/local/bin/homeassistant-backup.sh

BACKUP_DIR="/backup/homeassistant"
CONFIG_DIR="/opt/homeassistant/.homeassistant"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop Home Assistant
sudo systemctl stop homeassistant

# Create backup
tar -czf "$BACKUP_DIR/homeassistant_backup_$DATE.tar.gz" \
    -C "/opt/homeassistant" ".homeassistant"

# Start Home Assistant
sudo systemctl start homeassistant

# Keep only last 7 backups
find "$BACKUP_DIR" -name "homeassistant_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed: homeassistant_backup_$DATE.tar.gz"
```

### Restore Procedures

```bash
#!/bin/bash
# Restore Home Assistant from backup

BACKUP_FILE="/backup/homeassistant/homeassistant_backup_20250916_120000.tar.gz"
CONFIG_DIR="/opt/homeassistant/.homeassistant"

# Stop Home Assistant
sudo systemctl stop homeassistant

# Backup current config (safety)
sudo mv "$CONFIG_DIR" "${CONFIG_DIR}.$(date +%Y%m%d_%H%M%S)"

# Restore from backup
sudo tar -xzf "$BACKUP_FILE" -C "/opt/homeassistant"

# Fix permissions
sudo chown -R homeassistant:homeassistant "$CONFIG_DIR"

# Start Home Assistant
sudo systemctl start homeassistant

echo "Restore completed from $BACKUP_FILE"
```

### Automated Backup Setup

```bash
# Add to crontab for automated daily backups
sudo crontab -e

# Add this line for daily backups at 2 AM
0 2 * * * /usr/local/bin/homeassistant-backup.sh >> /var/log/homeassistant-backup.log 2>&1
```

### Testing Restore Procedures

```bash
# Test restore on separate system
# 1. Install Home Assistant on test system
# 2. Stop service
# 3. Replace config with backup
# 4. Start service and verify functionality
# 5. Test automations and integrations

# Verify backup integrity
tar -tzf /backup/homeassistant/homeassistant_backup_latest.tar.gz | head -20
```

## Troubleshooting

### Common Installation Issues

**Python version conflicts:**
```bash
# Check Python version
python3 --version
# Should be 3.10 or later

# If wrong version, install correct Python
sudo dnf install python3.11  # RHEL/CentOS
sudo apt install python3.11  # Debian/Ubuntu
```

**Missing development packages:**
```bash
# Install missing development tools
sudo dnf groupinstall "Development Tools"  # RHEL/CentOS
sudo apt install build-essential  # Debian/Ubuntu
```

**Permission errors during pip install:**
```bash
# Ensure you're in the virtual environment
source /opt/homeassistant/bin/activate
# Check virtual environment is active
which python
# Should show: /opt/homeassistant/bin/python
```

### Service Startup Problems

**Service fails to start:**
```bash
# Check service status
sudo systemctl status homeassistant

# Check logs
sudo journalctl -u homeassistant -f

# Common issues:
# 1. Configuration errors
# 2. Port already in use
# 3. Permission problems
```

**Configuration validation:**
```bash
# Check configuration syntax
sudo -u homeassistant -H -s
cd /opt/homeassistant
source bin/activate
hass --script check_config -c .homeassistant
```

**Port conflicts:**
```bash
# Check what's using port 8123
sudo netstat -tlnp | grep 8123
sudo lsof -i :8123

# Kill conflicting process or change port in configuration.yaml
```

### Permission Errors

**File permission issues:**
```bash
# Fix ownership
sudo chown -R homeassistant:homeassistant /opt/homeassistant

# Fix permissions
sudo chmod -R 755 /opt/homeassistant
sudo chmod -R 644 /opt/homeassistant/.homeassistant/*.yaml
```

**SELinux context issues (RHEL/CentOS):**
```bash
# Check SELinux status
sestatus

# Fix SELinux contexts
sudo restorecon -Rv /opt/homeassistant
sudo setsebool -P httpd_can_network_connect 1
```

### Network/Connectivity Issues

**Web interface not accessible:**
```bash
# Check if service is running
sudo systemctl status homeassistant

# Check listening ports
sudo netstat -tlnp | grep python

# Check firewall
sudo firewall-cmd --list-all  # RHEL/CentOS
sudo ufw status  # Ubuntu/Debian
```

**mDNS discovery not working:**
```bash
# Install and start Avahi
sudo dnf install avahi avahi-tools  # RHEL/CentOS
sudo apt install avahi-daemon avahi-utils  # Debian/Ubuntu
sudo systemctl enable --now avahi-daemon

# Test mDNS
avahi-browse -r _http._tcp
```

### Debug Mode Activation

```bash
# Enable debug logging
# Edit configuration.yaml
logger:
  default: debug
  logs:
    homeassistant.core: debug
    homeassistant.components: debug

# Restart Home Assistant
sudo systemctl restart homeassistant

# Monitor logs
sudo journalctl -u homeassistant -f
```

### Log Analysis

```bash
# Common log locations
tail -f /opt/homeassistant/.homeassistant/home-assistant.log

# Filter specific components
grep "ERROR" /opt/homeassistant/.homeassistant/home-assistant.log
grep "WARNING" /opt/homeassistant/.homeassistant/home-assistant.log

# Check startup issues
sudo journalctl -u homeassistant --since "10 minutes ago"
```

## Maintenance

### Update Procedures

**Update Home Assistant Core:**
```bash
# Switch to homeassistant user
sudo -u homeassistant -H -s
cd /opt/homeassistant
source bin/activate

# Update pip and Home Assistant
python -m pip install --upgrade pip
python -m pip install --upgrade homeassistant

# Check for breaking changes before updating
# Visit: https://www.home-assistant.io/blog/categories/release-notes/

# Restart service
sudo systemctl restart homeassistant
```

**Update Python dependencies:**
```bash
# Update all packages
python -m pip list --outdated
python -m pip install --upgrade package_name

# Or update all at once (use with caution)
python -m pip freeze | cut -d'=' -f1 | xargs python -m pip install --upgrade
```

### Version Upgrades

**Major version upgrades:**
```bash
# Before upgrading, always backup
/usr/local/bin/homeassistant-backup.sh

# Check breaking changes
# Visit release notes at: https://www.home-assistant.io/blog/

# Perform upgrade
sudo -u homeassistant -H -s
cd /opt/homeassistant
source bin/activate
python -m pip install --upgrade homeassistant

# Check configuration after upgrade
hass --script check_config -c .homeassistant

# Restart service
sudo systemctl restart homeassistant
```

### Migration Between Systems

**Export configuration:**
```bash
# Create migration package
tar -czf homeassistant_migration.tar.gz \
    -C /opt/homeassistant .homeassistant \
    --exclude=.homeassistant/home-assistant.log \
    --exclude=.homeassistant/home-assistant_v2.db

# Copy SSL certificates if used
tar -czf ssl_certs.tar.gz /etc/ssl/private/homeassistant.*
```

**Import on new system:**
```bash
# Install Home Assistant on new system
# Stop service
sudo systemctl stop homeassistant

# Extract configuration
sudo tar -xzf homeassistant_migration.tar.gz -C /opt/homeassistant
sudo chown -R homeassistant:homeassistant /opt/homeassistant/.homeassistant

# Update IP addresses and device paths in configuration
sudo -u homeassistant nano /opt/homeassistant/.homeassistant/configuration.yaml

# Start service
sudo systemctl start homeassistant
```

### Cleanup Procedures

**Database cleanup:**
```bash
# Enable database purging
# Add to configuration.yaml
recorder:
  purge_keep_days: 7
  auto_purge: true

# Manual purge
sudo -u homeassistant -H -s
cd /opt/homeassistant
source bin/activate
hass --script purge_db --days 30
```

**Log rotation:**
```bash
# Configure logrotate
sudo tee /etc/logrotate.d/homeassistant > /dev/null <<EOF
/opt/homeassistant/.homeassistant/home-assistant.log {
    daily
    missingok
    rotate 7
    compress
    notifempty
    copytruncate
    su homeassistant homeassistant
}
EOF
```

**Clear cache and temporary files:**
```bash
# Clear Home Assistant cache
sudo -u homeassistant rm -rf /opt/homeassistant/.homeassistant/.cache
sudo -u homeassistant rm -rf /opt/homeassistant/.homeassistant/deps

# Clear pip cache
sudo -u homeassistant python -m pip cache purge
```

## Integration Examples

### MQTT Device Integration

```yaml
# configuration.yaml
mqtt:
  sensor:
    - name: "Temperature Sensor"
      state_topic: "home/livingroom/temperature"
      unit_of_measurement: "°C"
      device_class: temperature
    
    - name: "Humidity Sensor"
      state_topic: "home/livingroom/humidity"
      unit_of_measurement: "%"
      device_class: humidity

  switch:
    - name: "Living Room Light"
      state_topic: "home/livingroom/light/state"
      command_topic: "home/livingroom/light/set"
      payload_on: "ON"
      payload_off: "OFF"
```

### REST API Usage Examples

```bash
# Get states of all entities
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8123/api/states

# Control a switch
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "switch.living_room_light"}' \
  http://localhost:8123/api/services/switch/turn_on

# Get specific entity state
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8123/api/states/sensor.temperature
```

### Python Client Library Example

```python
# pip install homeassistant-api
import homeassistant.remote as remote

# Connect to Home Assistant
api = remote.API('localhost', 'YOUR_TOKEN', 8123)

# Get all states
states = remote.get_states(api)
for state in states:
    print(f"{state.entity_id}: {state.state}")

# Turn on a light
remote.call_service(api, 'switch', 'turn_on', {'entity_id': 'switch.living_room_light'})

# Get state of specific entity
state = remote.get_state(api, 'sensor.temperature')
print(f"Temperature: {state.state}°C")
```

### Webhook Configuration

```yaml
# configuration.yaml
automation:
  - alias: "Webhook Triggered Action"
    trigger:
      platform: webhook
      webhook_id: your_webhook_id
    action:
      service: notify.mobile_app_your_phone
      data:
        message: "Webhook triggered with data: {{ trigger.json }}"

# URL to trigger webhook:
# POST http://localhost:8123/api/webhook/your_webhook_id
```

### Zigbee2MQTT Integration

```bash
# Install Mosquitto MQTT broker
sudo dnf install mosquitto mosquitto-clients  # RHEL/CentOS
sudo apt install mosquitto mosquitto-clients  # Debian/Ubuntu

# Start MQTT broker
sudo systemctl enable --now mosquitto

# Install Node.js and npm
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo dnf install -y nodejs

# Install Zigbee2MQTT
sudo npm install -g zigbee2mqtt

# Configure Zigbee2MQTT
sudo mkdir -p /opt/zigbee2mqtt
sudo tee /opt/zigbee2mqtt/configuration.yaml > /dev/null <<EOF
homeassistant: true
permit_join: false
mqtt:
  base_topic: zigbee2mqtt
  server: 'mqtt://localhost'
serial:
  port: /dev/ttyUSB0  # Adjust to your Zigbee dongle
advanced:
  network_key: GENERATE
  pan_id: GENERATE
EOF
```

## Additional Resources

- [Official Home Assistant Documentation](https://www.home-assistant.io/docs/)
- [Home Assistant GitHub Repository](https://github.com/home-assistant/core)
- [Home Assistant Community Forum](https://community.home-assistant.io/)
- [Home Assistant Discord](https://discord.gg/c5DvZ4e)
- [Home Assistant YouTube Channel](https://www.youtube.com/c/HomeAssistant)
- [Awesome Home Assistant](https://github.com/frenck/awesome-home-assistant)
- [HACS (Home Assistant Community Store)](https://hacs.xyz/)
- [ESPHome Documentation](https://esphome.io/)
- [Zigbee2MQTT Documentation](https://www.zigbee2mqtt.io/)
- [Z-Wave JS Documentation](https://zwave-js.github.io/node-zwave-js/)
- [Home Assistant Blueprints Exchange](https://community.home-assistant.io/c/blueprints-exchange/)
- [Home Assistant Configuration Examples](https://github.com/home-assistant/home-assistant.io/tree/current/source/_cookbook)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.