
# NETWORK TRAFFIC ANALYSIS AND CREDENTIAL HUNTING: PRACTICAL IMPLEMENTATION GUIDE

## 1. INITIAL SETUP AND PREPARATION

### 1.1 Wireshark Setup Commands
```bash
# Install Wireshark on Ubuntu/Debian
sudo apt-get update
sudo apt-get install wireshark

# Add user to wireshark group to avoid sudo requirement
sudo usermod -a -G wireshark $USER

# Start Wireshark
wireshark
```

### 1.2 TCPDump Setup Commands  
```bash
# Install tcpdump (usually pre-installed on Linux)
sudo apt-get install tcpdump

# List available network interfaces
tcpdump -D

# Basic permission check
sudo tcpdump --version
```

## 2. LIVE TRAFFIC CAPTURE PROCEDURES

### 2.1 Wireshark Live Capture
1. Open Wireshark
2. Select network interface (eth0, wlan0, etc.)
3. Apply capture filter if needed: `port 80 or port 443`
4. Click "Start" to begin capture
5. Generate traffic by browsing websites, logging into services
6. Click "Stop" to end capture
7. Save as .pcap file: File > Save As > capture.pcap

### 2.2 TCPDump Live Capture Commands
```bash
# Basic capture to file
sudo tcpdump -i eth0 -w live_capture.pcap

# Capture HTTP traffic only
sudo tcpdump -i eth0 port 80 -w http_capture.pcap

# Capture with timestamp and ASCII output
sudo tcpdump -i eth0 -tttt -A port 80

# Capture POST requests specifically
sudo tcpdump -i eth0 -s 0 -A -n 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
```

## 3. CREDENTIAL HUNTING TECHNIQUES

### 3.1 Wireshark Display Filters for Credentials
```
# Find HTTP POST requests (common for login forms)
http.request.method == "POST"

# Search for password-related keywords
frame contains "password"
frame contains "passwd" 
frame contains "pwd"
http contains "login"

# Find form data submissions
http.request.method == "POST" and http contains "username"

# Locate authentication headers
http.authorization

# Search for cookies and session tokens
http.cookie or http.set_cookie
```

### 3.2 Manual Credential Extraction Steps
1. Apply filter: `http.request.method == "POST"`
2. Look for packets with "HTML Form URL Encoded" in protocol tree
3. Expand "Hypertext Transfer Protocol" section
4. Expand "HTML Form URL Encoded" to view form data
5. Look for username/password field pairs
6. Document findings with packet numbers and timestamps

### 3.3 Automated Credential Extraction Tools

#### PCredz Installation and Usage
```bash
# Install PCredz
git clone https://github.com/lgandx/PCredz.git
cd PCredz
sudo apt-get install python3-pip libpcap-dev
pip3 install Cython python-libpcap

# Run PCredz on PCAP file
python3 Pcredz.py -f capture.pcap
```

#### CredSlayer Installation and Usage  
```bash
# Install CredSlayer
pip3 install credslayer
sudo apt install tshark

# Run CredSlayer
credslayer capture.pcap
```

#### DSniff Usage
```bash
# Install DSniff
sudo apt install dsniff

# Extract credentials from PCAP
dsniff -p capture.pcap
```

## 4. SUSPICIOUS ACTIVITY DETECTION

### 4.1 Port Scanning Detection
```bash
# Wireshark filter for SYN scans
tcp.flags.syn == 1 and tcp.flags.ack == 0

# TCPDump command for scan detection
sudo tcpdump 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'
```

### 4.2 Brute Force Detection
```bash
# Look for repeated failed authentications
tcp.stream eq X  # Follow specific TCP stream
http.response.code == 401  # Failed HTTP authentication
```

### 4.3 Data Exfiltration Detection
```bash
# Large file transfers
http.content_length > 1000000  # Files over 1MB
tcp.len > 1460  # Large TCP segments

# Unusual protocols or ports
not (tcp.port == 80 or tcp.port == 443 or tcp.port == 22)
```

## 5. SECURITY ANALYSIS PROCEDURES

### 5.1 Protocol Analysis Checklist
- [ ] HTTP traffic for plaintext credentials
- [ ] FTP connections for clear-text passwords  
- [ ] SMTP/POP3 for email credentials
- [ ] SNMP for community strings
- [ ] Telnet for terminal access credentials
- [ ] DNS queries for suspicious domains
- [ ] ARP traffic for spoofing attempts

### 5.2 Statistical Analysis in Wireshark
1. Go to Statistics > Protocol Hierarchy
2. Check Statistics > Conversations 
3. Review Statistics > Endpoints
4. Analyze Statistics > I/O Graph for traffic patterns
5. Use Tools > Credentials for automated credential extraction

### 5.3 Advanced Analysis Techniques
```bash
# Follow TCP streams for full conversations
Right-click packet > Follow > TCP Stream

# Export HTTP objects
File > Export Objects > HTTP

# Apply time-based filters
frame.time >= "2024-09-18 10:00:00" and frame.time <= "2024-09-18 11:00:00"
```

## 6. DOCUMENTATION AND REPORTING

### 6.1 Evidence Collection
- Save original PCAP files with timestamps
- Screenshot suspicious packets
- Export specific conversations
- Document filter strings used
- Record packet numbers for reference

### 6.2 Report Structure Template
1. Executive Summary
2. Analysis Methodology
3. Network Traffic Overview
4. Security Findings
   - Credential Exposures
   - Suspicious Activities  
   - Potential Vulnerabilities
5. Risk Assessment
6. Recommendations
7. Technical Appendix

### 6.3 PCAP File Management
```bash
# Split large PCAP files
editcap -c 10000 large_capture.pcap split_capture.pcap

# Merge multiple PCAP files  
mergecap -w combined.pcap file1.pcap file2.pcap file3.pcap

# Convert PCAP formats
tshark -r old_format.pcap -w new_format.pcapng
```

## 7. COMMON SECURITY ISSUES TO IDENTIFY

### 7.1 Critical Findings
- Plaintext passwords in HTTP POST data
- Unencrypted FTP/Telnet credentials
- Session tokens transmitted over HTTP
- Sensitive data in DNS queries
- Default SNMP community strings

### 7.2 High Priority Issues  
- Port scanning activities
- Brute force authentication attempts
- ARP spoofing/MITM attacks
- Unusual outbound connections
- Large data transfers to external hosts

### 7.3 Medium Priority Issues
- Deprecated SSL/TLS versions
- Weak encryption ciphers
- Information disclosure in headers
- Unnecessary service advertisements
- Excessive broadcast traffic

## 8. BEST PRACTICES AND RECOMMENDATIONS

### 8.1 Analysis Best Practices
- Always work on copies of PCAP files
- Document all filter strings and procedures
- Cross-reference findings with multiple tools
- Validate automated tool results manually
- Maintain chain of custody for evidence

### 8.2 Network Security Recommendations
- Implement HTTPS for all web applications
- Use encrypted protocols (SSH, SFTP, etc.)
- Deploy network segmentation
- Enable network access control (NAC)
- Implement intrusion detection systems (IDS)
- Regular security assessments and monitoring
