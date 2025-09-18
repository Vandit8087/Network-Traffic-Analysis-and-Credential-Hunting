# Installation Guide 🚀

This guide provides comprehensive installation instructions for the Network Traffic Analysis Toolkit across different operating systems.

## System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 18.04+), macOS (10.14+), Windows 10+
- **RAM**: 4GB (8GB recommended for large PCAP analysis)
- **Storage**: 2GB for tools + additional space for PCAP files
- **Network**: Administrative access for packet capture
- **Python**: 3.8+ with pip

### Recommended Specifications
- **RAM**: 16GB+ for enterprise-scale analysis
- **Storage**: 50GB+ SSD for optimal performance
- **CPU**: Multi-core processor for parallel analysis
- **Network**: Dedicated analysis interface

## Quick Installation

### Linux (Ubuntu/Debian)

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade -y

# Clone the repository
git clone https://github.com/your-org/network-traffic-analysis-toolkit.git
cd network-traffic-analysis-toolkit

# Run automated installation
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh

# Install Python dependencies
pip3 install -r requirements.txt

# Verify installation
./scripts/verify-installation.sh
```

### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Clone repository
git clone https://github.com/your-org/network-traffic-analysis-toolkit.git
cd network-traffic-analysis-toolkit

# Run macOS setup
chmod +x scripts/setup-macos.sh
./scripts/setup-macos.sh

# Install Python dependencies
pip3 install -r requirements.txt
```

### Windows

```powershell
# Run PowerShell as Administrator

# Clone repository
git clone https://github.com/your-org/network-traffic-analysis-toolkit.git
cd network-traffic-analysis-toolkit

# Run Windows setup script
.\scripts\setup-windows.ps1

# Install Python dependencies
pip install -r requirements.txt
```

## Detailed Component Installation

### 1. Core Network Analysis Tools

#### Wireshark Installation

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install wireshark

# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# CentOS/RHEL/Fedora
sudo yum install wireshark  # CentOS 7
sudo dnf install wireshark  # Fedora/CentOS 8+
```

**macOS:**
```bash
# Using Homebrew
brew install --cask wireshark

# Or download from official site
# https://www.wireshark.org/download.html
```

**Windows:**
- Download installer from https://www.wireshark.org/download.html
- Run installer as Administrator
- Select "Install WinPcap" during installation

#### TCPDump Installation

**Linux:**
```bash
# Usually pre-installed, if not:
sudo apt-get install tcpdump  # Ubuntu/Debian
sudo yum install tcpdump      # CentOS/RHEL
```

**macOS:**
```bash
# Pre-installed on macOS
tcpdump --version

# Or install latest version
brew install tcpdump
```

**Windows:**
```powershell
# Install WinDump (Windows version of tcpdump)
# Download from: https://www.winpcap.org/windump/
# Or use tcpdump in WSL
```

### 2. Automated Analysis Tools

#### PCredz Installation

```bash
# Clone and setup PCredz
git clone https://github.com/lgandx/PCredz.git
cd PCredz

# Install dependencies
sudo apt-get install python3-pip libpcap-dev
pip3 install Cython python-libpcap

# Test installation
python3 Pcredz.py --help
```

#### CredSlayer Installation

```bash
# Install CredSlayer
pip3 install credslayer

# Install tshark (required dependency)
sudo apt-get install tshark

# Test installation  
credslayer --help
```

#### NetworkMiner Installation

**Linux:**
```bash
# Install Mono (required for NetworkMiner)
sudo apt-get install mono-complete

# Download NetworkMiner Free
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip
cd NetworkMiner*/

# Run NetworkMiner
mono NetworkMiner.exe
```

### 3. Python Dependencies

Create `requirements.txt`:
```
scapy>=2.4.5
pandas>=1.3.0
numpy>=1.21.0
matplotlib>=3.5.0
seaborn>=0.11.0
pyshark>=0.4.3
netaddr>=0.8.0
python-nmap>=0.6.1
requests>=2.25.0
jinja2>=3.0.0
pyyaml>=5.4.0
click>=8.0.0
colorama>=0.4.4
tqdm>=4.62.0
```

Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

### 4. Additional Security Tools

#### Nmap Installation
```bash
# Linux
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

#### DSniff Installation
```bash
# Linux
sudo apt-get install dsniff

# macOS
brew install dsniff
```

## Configuration

### 1. Wireshark Configuration

#### Set Up Capture Permissions (Linux)
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Logout and login again, or use:
newgrp wireshark

# Verify permissions
ls -la /usr/bin/dumpcap
```

#### Configure Wireshark Preferences
```bash
# Copy default preferences
cp config/wireshark-preferences.cfg ~/.config/wireshark/preferences

# Or manually configure:
# Edit → Preferences → Protocols → HTTP
# ✓ Reassemble HTTP bodies spanning multiple TCP segments
# ✓ Show detailed HTTP request/response info
```

### 2. Python Environment Setup

#### Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv network-analysis-env

# Activate environment
source network-analysis-env/bin/activate  # Linux/macOS
# network-analysis-env\Scripts\activate   # Windows

# Install dependencies in virtual environment
pip install -r requirements.txt
```

### 3. Tool Configuration

#### Configure Analysis Settings
```bash
# Copy default configuration
cp config/analysis-settings.json.example config/analysis-settings.json

# Edit configuration file
nano config/analysis-settings.json
```

Example configuration:
```json
{
    "capture_settings": {
        "default_interface": "eth0",
        "max_packet_count": 100000,
        "capture_filter": "not port 22"
    },
    "analysis_settings": {
        "credential_extraction": true,
        "suspicious_activity_detection": true,
        "generate_statistics": true
    },
    "output_settings": {
        "report_format": "markdown",
        "include_screenshots": true,
        "evidence_retention_days": 90
    }
}
```

## Verification

### 1. Test Core Tools

```bash
# Test Wireshark
wireshark --version

# Test TCPDump
sudo tcpdump --version

# Test TShark
tshark --version
```

### 2. Test Python Scripts

```bash
# Test credential extractor
python3 tools/automated-tools/credential-extractor.py --help

# Test traffic analyzer
python3 tools/automated-tools/traffic-analyzer.py --version

# Test report generator
python3 tools/automated-tools/report-generator.py --test
```

### 3. Run Verification Script

```bash
# Run complete verification
./scripts/verify-installation.sh

# Expected output:
# ✅ Wireshark: Installed and configured
# ✅ TCPDump: Available and accessible
# ✅ Python dependencies: All satisfied
# ✅ Analysis tools: Functional
# ✅ Sample data: Available
```

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Fix Wireshark permissions
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER

# Fix TCPDump permissions
sudo chmod +s /usr/sbin/tcpdump
```

#### Python Module Issues
```bash
# Upgrade pip
python3 -m pip install --upgrade pip

# Clear pip cache
pip cache purge

# Reinstall requirements
pip3 install -r requirements.txt --force-reinstall
```

#### Network Interface Issues
```bash
# List available interfaces
ip link show        # Linux
ifconfig -a         # macOS/BSD

# Test interface access
sudo tcpdump -i eth0 -c 5
```

## Performance Optimization

### 1. System Tuning

```bash
# Increase capture buffer size
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.rmem_default = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Optimize for large PCAP analysis
ulimit -n 65536
```

### 2. Analysis Optimization

```bash
# Use ramdisk for temporary analysis
sudo mkdir /mnt/analysis-tmp
sudo mount -t tmpfs -o size=4G tmpfs /mnt/analysis-tmp

# Configure analysis to use ramdisk
export ANALYSIS_TEMP_DIR="/mnt/analysis-tmp"
```

## Security Considerations

### 1. Secure Installation

- Install tools from official repositories only
- Verify package checksums when possible
- Use package managers instead of manual downloads
- Keep tools updated to latest versions

### 2. Access Control

```bash
# Restrict access to analysis tools
sudo chown root:wireshark /usr/bin/wireshark
sudo chmod 750 /usr/bin/wireshark

# Secure PCAP storage directory
mkdir ~/pcap-analysis
chmod 700 ~/pcap-analysis
```

### 3. Data Protection

- Use encrypted storage for sensitive PCAP files
- Implement secure deletion of temporary files
- Configure automatic cleanup of old analysis data
- Use VPN when transferring analysis results

## Next Steps

After successful installation:

1. **Read the [User Manual](user-manual.md)** for detailed usage instructions
2. **Complete the [Tutorial](../tutorials/getting-started.md)** for hands-on practice
3. **Review [Best Practices](../best-practices.md)** for professional usage
4. **Join the [Community](../community.md)** for support and updates

## Support

If you encounter issues during installation:

- **Check [Troubleshooting Guide](troubleshooting.md)**
- **Search [GitHub Issues](https://github.com/your-org/network-traffic-analysis-toolkit/issues)**
- **Ask on [Discussions](https://github.com/your-org/network-traffic-analysis-toolkit/discussions)**
- **Contact Support**: installation-support@yourorg.com

---

**Installation complete!** You're ready to start analyzing network traffic professionally. 🚀