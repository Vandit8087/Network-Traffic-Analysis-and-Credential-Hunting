# PCAP Files 📦

This directory contains sample network packet captures (PCAP files) for testing and educational purposes.

## 📋 Available Sample Files

### 🌐 sample-http-traffic.pcap
**Purpose**: HTTP credential hunting demonstration  
**Content**: Web application authentication traffic  
**Size**: ~50 KB  
**Duration**: 5 minutes  
**Packets**: ~2,500  

**Contains:**
- HTTP POST login attempts
- Form-based authentication
- Session cookie handling
- DNS resolution traffic
- Multiple credential exposures

**Expected Findings:**
- 3 HTTP POST credential pairs
- 2 session tokens
- 1 API key in headers
- Multiple authentication attempts

**Analysis Commands:**
```bash
# Extract credentials
python3 ../../tools/automated-tools/credential-extractor.py sample-http-traffic.pcap

# Wireshark filters to use
http.request.method == "POST"
http.authorization
frame contains "password"
```

---

### 🚨 suspicious-activity.pcap  
**Purpose**: Security threat detection training  
**Content**: Malicious network activity simulation  
**Size**: ~120 KB  
**Duration**: 15 minutes  
**Packets**: ~8,000  

**Contains:**
- Port scanning activities
- Brute force SSH attempts  
- DNS tunneling attempts
- Suspicious outbound connections
- Failed authentication patterns

**Expected Findings:**
- 1 comprehensive port scan
- 47 SSH brute force attempts
- 3 DNS tunneling indicators
- 2 data exfiltration attempts

**Analysis Commands:**
```bash
# Full threat analysis
python3 ../../tools/automated-tools/traffic-analyzer.py suspicious-activity.pcap --analysis-type threats

# Wireshark filters to use
tcp.flags.syn == 1 and tcp.flags.ack == 0
ssh and tcp.analysis.retransmission
dns and frame.len > 512
```

---

### 🔄 mixed-protocols.pcap
**Purpose**: Multi-protocol analysis training  
**Content**: Diverse network protocol traffic  
**Size**: ~200 KB  
**Duration**: 30 minutes  
**Packets**: ~15,000  

**Contains:**
- HTTP/HTTPS web traffic
- FTP file transfers
- SMTP email communication  
- SSH remote access
- DNS queries and responses
- ICMP ping traffic

**Expected Findings:**
- Protocol distribution analysis
- Service identification
- Conversation flow tracking
- Bandwidth utilization patterns

**Analysis Commands:**
```bash
# Protocol statistics
python3 ../../tools/automated-tools/traffic-analyzer.py mixed-protocols.pcap --analysis-type stats

# Wireshark analysis
Statistics → Protocol Hierarchy
Statistics → Conversations
Statistics → Endpoints
```

## 🛠️ Working with PCAP Files

### Opening in Wireshark
```bash
# Open specific file
wireshark sample-http-traffic.pcap

# Open with specific display filter
wireshark -Y "http.request.method == POST" sample-http-traffic.pcap
```

### Command-line Analysis with TShark
```bash
# Basic packet information
tshark -r sample-http-traffic.pcap -T fields -e frame.number -e ip.src -e ip.dst -e frame.protocols

# Extract HTTP POST data
tshark -r sample-http-traffic.pcap -Y "http.request.method==POST" -T fields -e http.file_data

# Protocol hierarchy statistics
tshark -r mixed-protocols.pcap -z phs -q
```

### Using TCPDump for Analysis
```bash
# Read and display packet summary
tcpdump -r sample-http-traffic.pcap -nn

# Extract specific protocols
tcpdump -r mixed-protocols.pcap -nn 'port 80 or port 443'

# Show packet contents
tcpdump -r suspicious-activity.pcap -nn -A 'port 22'
```

## 📊 File Specifications

| File | Protocols | Key IPs | Time Range | Use Case |
|------|-----------|---------|------------|----------|
| sample-http-traffic.pcap | HTTP, DNS, TCP | 192.168.1.100-110 | 14:00-14:05 | Credential hunting |
| suspicious-activity.pcap | TCP, SSH, DNS, ICMP | 10.0.0.0/8 range | 22:00-22:15 | Threat detection |
| mixed-protocols.pcap | HTTP, FTP, SSH, SMTP, DNS | 172.16.1.0/24 | 09:00-09:30 | Protocol analysis |

## 🔍 Analysis Scenarios

### Scenario 1: Web Application Security Assessment
**File**: sample-http-traffic.pcap  
**Objective**: Identify credential exposures in web traffic  
**Steps**:
1. Open in Wireshark with HTTP POST filter
2. Examine form data in packet details
3. Extract credentials using automated tools
4. Generate security findings report

### Scenario 2: Incident Response Investigation
**File**: suspicious-activity.pcap  
**Objective**: Investigate potential security breach  
**Steps**:
1. Identify scanning activities with SYN flag analysis
2. Correlate brute force attempts across time
3. Analyze DNS queries for tunneling indicators
4. Create incident timeline and impact assessment

### Scenario 3: Network Baseline Analysis
**File**: mixed-protocols.pcap  
**Objective**: Establish normal traffic patterns  
**Steps**:
1. Generate protocol distribution statistics
2. Identify top talkers and conversations
3. Analyze traffic patterns by time
4. Create network baseline documentation

## 🚫 Important Notes

### Data Safety
- **All data is synthetic and safe for analysis**
- No real credentials or personal information
- IP addresses use RFC documentation ranges
- Safe for educational and testing environments

### File Integrity
```bash
# Verify file integrity (example checksums)
md5sum sample-http-traffic.pcap
# Expected: a1b2c3d4e5f6789012345678901234567

sha256sum suspicious-activity.pcap  
# Expected: 9876543210abcdef...
```

### Storage Requirements
- **Total size**: ~370 KB for all samples
- **Compressed**: ~150 KB when gzipped
- **Recommended**: 1 GB free space for analysis results

## 🔄 Regenerating Samples

If sample files become corrupted or need updates:

```bash
# Restore from repository
git checkout HEAD -- sample-data/pcap-files/

# Or re-run setup script
./scripts/setup.sh --restore-samples

# Generate custom samples (advanced)
python3 scripts/generate-sample-data.py --output-dir sample-data/pcap-files/
```

## 📚 Educational Uses

### Training Exercises
1. **Beginner**: Identify different protocols in mixed-protocols.pcap
2. **Intermediate**: Find all credentials in sample-http-traffic.pcap
3. **Advanced**: Reconstruct attack timeline from suspicious-activity.pcap

### Certification Practice
- **GCIH**: Incident handling with suspicious-activity.pcap
- **GNFA**: Forensic analysis of all samples
- **CEH**: Penetration testing reconnaissance patterns
- **Security+**: Network security concepts demonstration

### Research Projects
- Protocol behavior analysis
- Attack pattern classification
- Anomaly detection algorithm development
- Network forensics methodology validation

## 🤝 Contributing New Samples

### Guidelines for New PCAP Files
1. **Sanitize all data**: Remove real IP addresses, credentials, personal information
2. **Document thoroughly**: Provide analysis guides and expected results
3. **Test compatibility**: Ensure files work with all toolkit components
4. **Size limits**: Keep individual files under 10 MB for distribution

### Submission Process
1. Create sanitized PCAP file
2. Write analysis documentation
3. Test with toolkit components
4. Submit via GitHub pull request
5. Include MD5/SHA256 checksums

## 📞 Support

### File Issues
- **Corrupted files**: Re-download from repository
- **Missing files**: Run setup script to restore
- **Analysis errors**: Check file permissions and tool compatibility

### Getting Help
- 📧 **Email**: pcap-support@yourorg.com
- 💬 **Community**: [GitHub Discussions](https://github.com/your-org/network-traffic-analysis-toolkit/discussions)
- 📋 **Bug Reports**: [GitHub Issues](https://github.com/your-org/network-traffic-analysis-toolkit/issues)

---

*PCAP Files Directory - Network Traffic Analysis Toolkit v2.1.0*

**⚠️ Remember**: These files are for authorized testing and educational use only. Always ensure you have proper authorization before analyzing real network traffic.