# Troubleshooting Guide 🔧

**Network Traffic Analysis Toolkit - Problem Resolution Guide**

This guide helps resolve common issues encountered when using the Network Traffic Analysis Toolkit.

## 📋 Table of Contents

1. [Installation Issues](#installation-issues)
2. [Capture Problems](#capture-problems)
3. [Analysis Issues](#analysis-issues)
4. [Tool-Specific Problems](#tool-specific-problems)
5. [Performance Issues](#performance-issues)
6. [Platform-Specific Issues](#platform-specific-issues)
7. [Error Messages](#error-messages)

---

## Installation Issues

### Python Dependencies

#### Problem: "ModuleNotFoundError" when running Python scripts

**Solution:**
```bash
# Activate virtual environment first
source venv/bin/activate

# Install missing dependencies
pip install -r requirements.txt

# If specific module is missing
pip install scapy pyshark pandas numpy matplotlib
```

#### Problem: "Permission denied" during pip install

**Solution:**
```bash
# Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Or install with user flag
pip install --user -r requirements.txt
```

### Wireshark Installation Issues

#### Problem: "You don't have permission to capture on that device"

**Solution for Linux:**
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Logout and login again, or use:
newgrp wireshark

# Reconfigure wireshark-common
sudo dpkg-reconfigure wireshark-common
# Select "Yes" when asked about non-superusers

# Set capabilities for dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

**Solution for macOS:**
```bash
# Install with Homebrew (includes proper permissions)
brew install --cask wireshark

# Or manually set permissions
sudo chgrp admin /dev/bpf*
sudo chmod g+rw /dev/bpf*
```

#### Problem: Wireshark GUI won't start

**Solution:**
```bash
# Linux: Install GUI libraries
sudo apt-get install libqt5gui5 libqt5widgets5

# macOS: Ensure X11 support
brew install --cask xquartz

# Test command-line version first
tshark --version
```

### TCPDump Issues

#### Problem: "tcpdump: command not found"

**Solution:**
```bash
# Linux (Debian/Ubuntu)
sudo apt-get install tcpdump

# Linux (RedHat/CentOS)
sudo yum install tcpdump

# macOS (usually pre-installed)
which tcpdump  # Should show /usr/sbin/tcpdump

# If missing on macOS
brew install tcpdump
```

#### Problem: "Operation not permitted" when running tcpdump

**Solution:**
```bash
# Use sudo for packet capture
sudo tcpdump -i eth0

# Or set capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Add user to appropriate groups
sudo usermod -a -G wireshark $USER
```

---

## Capture Problems

### Interface Issues

#### Problem: "No suitable device found" or interface not visible

**Solution:**
```bash
# List available interfaces
ip link show              # Linux
ifconfig -a              # macOS/BSD
netsh interface show     # Windows

# For Wireshark, check interface permissions
ls -la /dev/net/tun      # Should be accessible

# Restart network services if needed
sudo systemctl restart networking  # Linux
```

#### Problem: "Interface is not up" error

**Solution:**
```bash
# Bring interface up
sudo ip link set eth0 up

# Check interface status
ip link show eth0

# For wireless interfaces
sudo iwconfig wlan0 up
```

### Capture Filter Issues

#### Problem: "Invalid capture filter" error

**Common Issues and Solutions:**
```bash
# Wrong syntax - use BPF syntax for capture filters
# WRONG: http.request.method == "POST"
# RIGHT: port 80

# Correct capture filter examples:
port 80                    # HTTP traffic
host 192.168.1.1          # Specific host
net 192.168.1.0/24        # Network range
port 53 and udp           # DNS queries

# Test filter syntax
sudo tcpdump -d 'port 80'  # Show compiled filter
```

### Buffer and Memory Issues

#### Problem: "Dropped packets" or "Buffer full" errors

**Solution:**
```bash
# Increase buffer size
sudo tcpdump -i eth0 -B 65536 -w capture.pcap

# Use rotating capture files
sudo tcpdump -i eth0 -C 100 -W 5 -w rotate.pcap

# Set kernel buffer parameters
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.rmem_default = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Analysis Issues

### Wireshark Display Problems

#### Problem: "No packets in capture" after applying filter

**Solution:**
```bash
# Clear display filter to see all packets
# Check if capture actually contains packets
tshark -r capture.pcap -c 10

# Common filter mistakes:
# WRONG: tcp.port = 80  (use == not =)
# RIGHT: tcp.port == 80

# Case sensitivity issues:
# WRONG: HTTP.request.method == "post"
# RIGHT: http.request.method == "POST"
```

#### Problem: "Malformed packets" or "Dissector errors"

**Solution:**
```bash
# Update Wireshark to latest version
# Enable/disable protocol dissectors:
# Edit → Preferences → Protocols → [Protocol Name]

# For HTTP issues, try:
# Edit → Preferences → Protocols → HTTP
# ✓ Reassemble HTTP bodies spanning multiple TCP segments

# Reset preferences if needed
rm -rf ~/.config/wireshark/  # Linux
rm -rf ~/Library/Application\ Support/Wireshark/  # macOS
```

### Python Script Issues

#### Problem: "Permission denied" when reading PCAP files

**Solution:**
```bash
# Make PCAP files readable
chmod 644 *.pcap

# Or run script with appropriate permissions
sudo python3 tools/automated-tools/credential-extractor.py capture.pcap

# Check file ownership
ls -la capture.pcap
```

#### Problem: Scripts hang or run very slowly

**Solution:**
```bash
# Process smaller chunks first
editcap -c 1000 large.pcap small.pcap

# Use command-line tools for large files
tshark instead of pyshark for basic analysis

# Monitor resource usage
htop  # Linux
Activity Monitor  # macOS
```

---

## Tool-Specific Problems

### PCredz Issues

#### Problem: "No module named 'Cython'" or compilation errors

**Solution:**
```bash
# Install build dependencies
sudo apt-get install python3-dev libpcap-dev build-essential

# Install Cython first
pip install Cython

# Then install python-libpcap
pip install python-libpcap

# Alternative: Use system package
sudo apt-get install python3-libpcap
```

### CredSlayer Issues

#### Problem: "tshark not found" error

**Solution:**
```bash
# Install tshark (part of Wireshark)
sudo apt-get install tshark

# Verify installation
tshark --version

# Add to PATH if needed
export PATH=$PATH:/usr/bin
```

### NetworkMiner Issues

#### Problem: "Mono runtime not found" (Linux)

**Solution:**
```bash
# Install Mono runtime
sudo apt-get install mono-complete

# Or use alternative package manager
sudo snap install mono

# Verify installation
mono --version

# Run NetworkMiner
mono NetworkMiner.exe
```

---

## Performance Issues

### Memory Problems

#### Problem: "Out of memory" errors with large PCAP files

**Solution:**
```bash
# Split large files
editcap -c 10000 large.pcap chunk.pcap

# Use command-line tools instead of GUI
tshark -r large.pcap -Y "http.request.method == POST" > results.txt

# Increase system limits
ulimit -m unlimited
ulimit -v unlimited

# Use streaming analysis
tshark -r large.pcap -T fields -e http.request.method -e http.file_data | grep POST
```

### CPU Performance

#### Problem: Analysis taking too long

**Solution:**
```bash
# Use parallel processing
parallel -j 4 python3 credential-extractor.py ::: *.pcap

# Optimize filters for performance
# SLOW: frame contains "password"
# FAST: http.request.method == "POST" and frame contains "password"

# Use capture filters to reduce data
sudo tcpdump -i eth0 'port 80' -w http-only.pcap
```

### Disk Space Issues

#### Problem: "No space left on device"

**Solution:**
```bash
# Check available space
df -h

# Clean up temporary files
rm -rf /tmp/wireshark*
rm -rf ~/.local/share/Trash/

# Use compression
gzip *.pcap

# Rotate capture files automatically
sudo tcpdump -i eth0 -C 100 -W 10 -w capture.pcap
```

---

## Platform-Specific Issues

### Linux Issues

#### Problem: "Interface busy" or "Device or resource busy"

**Solution:**
```bash
# Stop NetworkManager from interfering
sudo systemctl stop NetworkManager

# Or exclude interface from NetworkManager
sudo nmcli device set eth0 managed no

# Kill processes using the interface
sudo lsof | grep eth0
sudo kill -9 <PID>
```

#### Problem: SELinux/AppArmor blocking operations

**Solution:**
```bash
# Check SELinux status
sestatus

# Temporarily disable SELinux
sudo setenforce 0

# For AppArmor
sudo aa-complain /usr/bin/tcpdump
sudo aa-complain /usr/bin/wireshark
```

### macOS Issues

#### Problem: "System Integrity Protection" errors

**Solution:**
```bash
# Disable SIP temporarily (not recommended for production)
# Boot into Recovery Mode: Cmd+R during startup
# csrutil disable

# Better: Use proper installation methods
brew install --cask wireshark
```

#### Problem: "Operation not permitted" even with sudo

**Solution:**
```bash
# Grant Full Disk Access to Terminal
# System Preferences → Security & Privacy → Privacy → Full Disk Access
# Add Terminal.app

# Use Homebrew versions
brew install wireshark tcpdump
```

### Windows Issues

#### Problem: WinPcap/Npcap installation issues

**Solution:**
```powershell
# Uninstall old WinPcap
# Install latest Npcap from https://nmap.org/npcap/

# Verify installation
npcap -v

# Restart after installation
shutdown /r /t 0
```

#### Problem: "Access denied" errors

**Solution:**
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"

# For WSL users
wsl --install
# Use Linux version inside WSL
```

---

## Error Messages

### Common Error Messages and Solutions

#### "libpcap not found"

```bash
# Linux
sudo apt-get install libpcap-dev

# macOS
brew install libpcap

# Verify
ldconfig -p | grep pcap  # Linux
```

#### "pyshark.capture.capture.TSharkNotFoundException"

```bash
# Install tshark
sudo apt-get install tshark

# Add to PATH
export PATH=$PATH:/usr/bin

# Verify
which tshark
tshark --version
```

#### "scapy.error.Scapy_Exception: No route found"

```bash
# Check network configuration
ip route show    # Linux
route -n get default  # macOS

# Reset network stack
sudo systemctl restart networking  # Linux
sudo dscacheutil -flushcache      # macOS
```

#### "Permission denied: '/dev/bpf0'"

```bash
# macOS solution
sudo chgrp admin /dev/bpf*
sudo chmod g+rw /dev/bpf*

# Or use Wireshark installer which sets permissions correctly
```

#### "Could not open file: Bad file descriptor"

```bash
# File corruption check
file capture.pcap

# Try different tools
tshark -r capture.pcap -c 1  # Test readability
hexdump -C capture.pcap | head  # Check file format

# Repair if possible
editcap -F pcap capture.pcap repaired.pcap
```

---

## Getting Additional Help

### Log Files and Debugging

#### Enable Verbose Logging

```bash
# Wireshark debug
wireshark -v

# TCPDump verbose
sudo tcpdump -vv -i eth0

# Python scripts debug
python3 -u script.py --verbose 2>&1 | tee debug.log
```

#### Check System Logs

```bash
# Linux
journalctl -f
tail -f /var/log/syslog

# macOS
log stream --predicate 'process CONTAINS "wireshark"'
tail -f /var/log/system.log
```

### Community Resources

#### Before Asking for Help

1. **Check the logs** for specific error messages
2. **Try minimal examples** to isolate the problem
3. **Search existing issues** in GitHub repository
4. **Document your environment**: OS version, Python version, tool versions

#### Where to Get Help

- **GitHub Issues**: https://github.com/your-org/network-traffic-analysis-toolkit/issues
- **GitHub Discussions**: Community Q&A and troubleshooting
- **Email Support**: support@yourorg.com
- **Documentation**: This guide and other docs in `/docs/`

#### When Reporting Issues

Include this information:
```
- Operating System: [Linux/macOS/Windows + version]
- Python Version: [python3 --version]
- Error Message: [exact error text]
- Steps to Reproduce: [detailed steps]
- Expected Behavior: [what should happen]
- Actual Behavior: [what actually happens]
- Log Files: [relevant log excerpts]
```

---

## Quick Reference

### Most Common Solutions

1. **Permission Issues**: Use sudo, add user to groups, check file permissions
2. **Missing Dependencies**: Install required packages, use virtual environment
3. **Interface Problems**: Check interface status, verify permissions
4. **Memory Issues**: Split large files, use streaming analysis
5. **Filter Errors**: Check syntax, use correct operators

### Emergency Troubleshooting Checklist

```bash
# 1. Verify basic tools work
wireshark --version
tcpdump --version
python3 --version

# 2. Test with sample data
python3 tools/automated-tools/credential-extractor.py sample-data/pcap-files/sample-http-traffic.pcap

# 3. Check permissions
ls -la capture.pcap
groups $USER

# 4. Verify network access
ping 8.8.8.8
ip link show

# 5. Clean and reinstall if needed
./scripts/clean-install.sh
```

---

**Still need help?** 

- 📧 Email: troubleshooting@yourorg.com
- 💬 Community: [GitHub Discussions](https://github.com/your-org/network-traffic-analysis-toolkit/discussions)
- 🐛 Bug Report: [GitHub Issues](https://github.com/your-org/network-traffic-analysis-toolkit/issues)

---

*Troubleshooting Guide v2.1.0 - Last updated: September 18, 2024*