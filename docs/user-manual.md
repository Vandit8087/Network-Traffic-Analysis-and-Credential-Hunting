# User Manual 📖

**Network Traffic Analysis Toolkit - Complete User Guide**

Welcome to the comprehensive user manual for the Network Traffic Analysis Toolkit. This guide will walk you through every aspect of using the toolkit for professional network security analysis.

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Operations](#basic-operations)
3. [Credential Hunting](#credential-hunting)
4. [Traffic Analysis](#traffic-analysis)
5. [Automated Tools](#automated-tools)
6. [Reporting](#reporting)
7. [Advanced Techniques](#advanced-techniques)
8. [Best Practices](#best-practices)

---

## Getting Started

### Prerequisites
- Completed installation (see [Installation Guide](installation-guide.md))
- Basic understanding of networking concepts
- Administrative access for packet capture
- Sample PCAP files (included in toolkit)

### First Steps

1. **Activate the Toolkit Environment**
   ```bash
   cd network-traffic-analysis-toolkit
   source activate.sh
   ```

2. **Verify Installation**
   ```bash
   wireshark --version
   tcpdump --version
   python3 tools/automated-tools/credential-extractor.py --version
   ```

3. **Test with Sample Data**
   ```bash
   python3 tools/automated-tools/credential-extractor.py sample-data/pcap-files/sample-http-traffic.pcap
   ```

---

## Basic Operations

### Capturing Network Traffic

#### Using Wireshark (GUI)

1. **Launch Wireshark**
   ```bash
   wireshark
   ```

2. **Select Network Interface**
   - Choose your network interface (eth0, wlan0, etc.)
   - Apply capture filter if needed: `port 80 or port 443`

3. **Start Capture**
   - Click "Start" button
   - Generate traffic by browsing websites or using applications
   - Click "Stop" when finished

4. **Save Capture**
   - File → Save As → choose location
   - Save as .pcap format

#### Using TCPDump (Command Line)

1. **Basic Capture**
   ```bash
   sudo tcpdump -i eth0 -w capture.pcap
   ```

2. **Protocol-Specific Capture**
   ```bash
   # HTTP traffic only
   sudo tcpdump -i eth0 port 80 -w http_capture.pcap
   
   # Multiple protocols
   sudo tcpdump -i eth0 'port 80 or port 443 or port 22' -w web_ssh.pcap
   ```

3. **Time-Limited Capture**
   ```bash
   # Capture for 60 seconds
   timeout 60 sudo tcpdump -i eth0 -w timed_capture.pcap
   ```

### Basic Analysis with Wireshark

#### Essential Display Filters

```bash
# View all filters
cat tools/wireshark-filters/security-filters.txt
```

**Common Filters:**
- `http.request.method == "POST"` - HTTP form submissions
- `ftp.request.command == "USER" or ftp.request.command == "PASS"` - FTP credentials
- `tcp.flags.syn == 1 and tcp.flags.ack == 0` - Port scanning detection
- `http.response.code == 401` - Authentication failures

#### Navigation and Analysis

1. **Apply Display Filters**
   - Enter filter in filter bar
   - Press Enter to apply
   - Use filter buttons for commonly used filters

2. **Follow TCP Streams**
   - Right-click packet → Follow → TCP Stream
   - View complete conversation
   - Export stream data if needed

3. **Protocol Analysis**
   - Statistics → Protocol Hierarchy
   - Statistics → Conversations
   - Statistics → Endpoints

---

## Credential Hunting

### Manual Credential Hunting

#### HTTP POST Analysis

1. **Filter for POST Requests**
   ```
   http.request.method == "POST"
   ```

2. **Inspect Packet Details**
   - Expand "Hypertext Transfer Protocol"
   - Look for "HTML Form URL Encoded" section
   - Examine form data for credentials

3. **Common Credential Fields**
   - username, user, login, email
   - password, passwd, pwd, pass
   - token, session, auth

#### FTP Credential Extraction

1. **Filter FTP Authentication**
   ```
   ftp.request.command == "USER" or ftp.request.command == "PASS"
   ```

2. **Examine FTP Commands**
   - USER command contains username
   - PASS command contains password
   - Note source/destination IPs

#### Email Protocol Analysis

```
# POP3 credentials
pop.request.command == "USER" or pop.request.command == "PASS"

# IMAP credentials  
imap.request.command contains "LOGIN"

# SMTP authentication
smtp.req.command == "AUTH"
```

### Automated Credential Extraction

#### Using the Built-in Extractor

1. **Basic Usage**
   ```bash
   python3 tools/automated-tools/credential-extractor.py capture.pcap
   ```

2. **Advanced Options**
   ```bash
   # JSON output
   python3 tools/automated-tools/credential-extractor.py capture.pcap -o json -f results.json
   
   # CSV output with verbose logging
   python3 tools/automated-tools/credential-extractor.py capture.pcap -o csv -v
   
   # Custom output directory
   python3 tools/automated-tools/credential-extractor.py capture.pcap -d ./analysis/
   ```

3. **Batch Processing**
   ```bash
   # Process multiple files
   for file in *.pcap; do
       python3 tools/automated-tools/credential-extractor.py "$file" -o json
   done
   ```

#### Using External Tools

1. **PCredz**
   ```bash
   python3 external-tools/PCredz/Pcredz.py -f capture.pcap
   ```

2. **CredSlayer**
   ```bash
   credslayer capture.pcap
   ```

3. **Wireshark Built-in**
   - Tools → Credentials
   - Automatically extracts from supported protocols

---

## Traffic Analysis

### Statistical Analysis

#### Protocol Distribution

1. **Wireshark Statistics**
   - Statistics → Protocol Hierarchy
   - View protocol percentages and packet counts
   - Identify unusual protocol usage

2. **Python Analysis**
   ```bash
   python3 tools/automated-tools/traffic-analyzer.py capture.pcap --stats
   ```

#### Conversation Analysis

1. **Top Talkers**
   - Statistics → Conversations
   - Sort by packets or bytes
   - Identify high-volume communications

2. **Endpoint Analysis**
   - Statistics → Endpoints
   - Review IP addresses and ports
   - Look for suspicious endpoints

### Anomaly Detection

#### Unusual Traffic Patterns

1. **Port Scanning Detection**
   ```
   tcp.flags.syn == 1 and tcp.flags.ack == 0
   ```

2. **Brute Force Detection**
   ```
   http.response.code == 401
   tcp.analysis.retransmission
   ```

3. **Data Exfiltration**
   ```
   http.content_length > 1000000
   tcp.len > 1460 and tcp.flags.psh == 1
   ```

#### Time-Based Analysis

1. **Off-Hours Activity**
   ```
   frame.time >= "18:00:00" or frame.time <= "09:00:00"
   ```

2. **Rapid Sequential Requests**
   ```
   tcp.time_delta < 0.001
   ```

---

## Automated Tools

### Traffic Analyzer

```bash
python3 tools/automated-tools/traffic-analyzer.py capture.pcap [options]
```

**Options:**
- `--credentials` - Extract credentials only
- `--stats` - Generate traffic statistics  
- `--suspicious` - Identify suspicious activity
- `--output json|csv|html` - Output format
- `--verbose` - Detailed logging

### Report Generator

```bash
python3 tools/automated-tools/report-generator.py [options]
```

**Usage Examples:**
```bash
# Generate from analysis results
python3 tools/automated-tools/report-generator.py --input results/ --output report.pdf

# Custom template
python3 tools/automated-tools/report-generator.py --template templates/security-assessment.md

# Multiple formats
python3 tools/automated-tools/report-generator.py --formats pdf,html,docx
```

### Batch Analysis Pipeline

```bash
./scripts/run-analysis.sh capture.pcap
```

This script:
1. Runs credential extraction
2. Performs traffic analysis
3. Generates security report
4. Creates visualizations
5. Exports results

---

## Reporting

### Report Templates

#### Security Assessment Report

```bash
# Use built-in template
cp reports/templates/security-assessment-template.md my-assessment.md
```

**Template Sections:**
- Executive Summary
- Methodology
- Findings and Evidence
- Risk Assessment
- Recommendations
- Technical Appendix

#### Incident Response Report

```bash
# Copy incident template
cp reports/templates/incident-response-template.md incident-report.md
```

### Custom Reports

#### Markdown Reports

1. **Basic Structure**
   ```markdown
   # Network Analysis Report
   
   ## Executive Summary
   [High-level findings]
   
   ## Technical Analysis
   [Detailed findings with evidence]
   
   ## Recommendations
   [Actionable security improvements]
   ```

2. **Including Evidence**
   ```markdown
   ### Credential Exposure
   
   Source: 192.168.1.45
   Destination: 203.0.113.10:80
   Protocol: HTTP POST
   
   ```
   Evidence: username=admin, password=123456
   ```
   ```

#### Automated Report Generation

```python
# Custom report script example
from tools.automated_tools.report_generator import ReportGenerator

generator = ReportGenerator()
generator.load_analysis_results("results/")
generator.generate_report(
    template="security-assessment",
    output="final-report.pdf",
    include_charts=True
)
```

---

## Advanced Techniques

### Custom Filter Development

#### Creating Complex Filters

1. **Logical Operators**
   ```
   # Multiple conditions
   (http.request.method == "POST") and (frame contains "password")
   
   # OR conditions
   tcp.port == 80 or tcp.port == 443 or tcp.port == 8080
   
   # NOT operator
   not (tcp.port == 22)
   ```

2. **Regular Expressions**
   ```
   # Pattern matching
   dns.qry.name matches ".*malicious.*"
   http.user_agent matches ".*bot.*"
   ```

3. **Byte-Level Filtering**
   ```
   # TCP flags
   tcp[tcpflags] & 0x18 == 0x18  # PSH+ACK
   
   # HTTP POST detection
   tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354
   ```

### Scripted Analysis

#### Python Packet Analysis

```python
#!/usr/bin/env python3
import pyshark

def analyze_credentials(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    credentials = []
    
    for packet in cap:
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'request_method'):
                if packet.http.request_method == 'POST':
                    # Extract POST data
                    if hasattr(packet.http, 'file_data'):
                        post_data = packet.http.file_data
                        # Analyze for credentials
                        if 'password' in post_data.lower():
                            credentials.append({
                                'src': packet.ip.src,
                                'dst': packet.ip.dst,
                                'data': post_data
                            })
    
    return credentials

# Usage
creds = analyze_credentials('capture.pcap')
for cred in creds:
    print(f"Found credential: {cred}")
```

#### Bash Automation

```bash
#!/bin/bash
# Automated analysis pipeline

PCAP_FILE=$1
OUTPUT_DIR="analysis-$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

# Extract credentials
python3 tools/automated-tools/credential-extractor.py "$PCAP_FILE" \
  -o json -f "$OUTPUT_DIR/credentials.json"

# Generate statistics
tshark -r "$PCAP_FILE" -z io,stat,60 > "$OUTPUT_DIR/traffic-stats.txt"

# Protocol hierarchy
tshark -r "$PCAP_FILE" -z phs > "$OUTPUT_DIR/protocols.txt"

# Generate report
python3 tools/automated-tools/report-generator.py \
  --input "$OUTPUT_DIR" \
  --output "$OUTPUT_DIR/security-report.pdf"

echo "Analysis complete: $OUTPUT_DIR"
```

### Integration with Security Tools

#### SIEM Integration

```python
# Example: Send findings to SIEM
import requests
import json

def send_to_siem(findings, siem_endpoint):
    for finding in findings:
        alert = {
            'timestamp': finding['timestamp'],
            'severity': finding['risk_level'],
            'source_ip': finding['source_ip'],
            'description': finding['details'],
            'category': 'credential_exposure'
        }
        
        response = requests.post(
            siem_endpoint,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(alert)
        )
```

#### Threat Intelligence Integration

```python
# Check IPs against threat intelligence
def check_threat_intelligence(ip_addresses):
    results = {}
    for ip in ip_addresses:
        # Query threat intelligence API
        response = requests.get(f"https://api.threatintel.com/check/{ip}")
        if response.status_code == 200:
            results[ip] = response.json()
    return results
```

---

## Best Practices

### Security Considerations

#### Legal and Ethical Guidelines

1. **Authorization Requirements**
   - Always obtain written permission
   - Document scope and limitations
   - Follow organizational policies

2. **Data Handling**
   - Use encrypted storage for PCAP files
   - Implement data retention policies
   - Secure deletion of sensitive data

3. **Privacy Protection**
   - Anonymize personal data when possible
   - Follow GDPR/CCPA requirements
   - Limit data collection to necessary scope

#### Technical Best Practices

1. **Capture Configuration**
   ```bash
   # Use capture filters to reduce noise
   sudo tcpdump -i eth0 'not port 22' -w capture.pcap
   
   # Limit packet size if needed
   sudo tcpdump -i eth0 -s 96 -w headers-only.pcap
   ```

2. **Analysis Workflow**
   - Work with copies of original PCAP files
   - Document all filter strings used
   - Validate findings with multiple tools
   - Cross-reference automated results manually

3. **Performance Optimization**
   ```bash
   # Use ramdisk for large analyses
   sudo mount -t tmpfs -o size=4G tmpfs /tmp/analysis
   
   # Process in chunks for very large files
   editcap -c 10000 large.pcap chunk.pcap
   ```

### Documentation Standards

#### Evidence Documentation

1. **Required Information**
   - Packet numbers for specific findings
   - Timestamps of suspicious activity
   - Source and destination details
   - Protocol and port information
   - Screenshot or text export of evidence

2. **Report Structure**
   ```
   Finding: [Brief description]
   Severity: [Critical/High/Medium/Low]
   Evidence: [Packet numbers, screenshots]
   Impact: [Business impact assessment]
   Recommendation: [Specific remediation steps]
   ```

#### Chain of Custody

1. **File Management**
   - Hash verification of original files
   - Access logging and audit trails
   - Secure storage and backup procedures
   - Version control for analysis results

---

## Troubleshooting Reference

For common issues and solutions, see [troubleshooting.md](troubleshooting.md).

## Additional Resources

### Training Materials
- **SANS Network Forensics** courses
- **Wireshark Certified Network Analyst** certification
- **Online tutorials** and video series

### Community Resources
- **Wireshark User Guide**: https://www.wireshark.org/docs/
- **TCPDump Manual**: https://www.tcpdump.org/manpages/
- **Security Forums**: Network analysis communities

### Tool Documentation
- [Credential Extractor API](../tools/automated-tools/README.md)
- [Wireshark Filters Reference](../tools/wireshark-filters/README.md)
- [TCPDump Commands Guide](../tools/tcpdump-commands/README.md)

---

**Need Help?** 
- 📧 Email: support@yourorg.com
- 💬 GitHub Discussions: [Join the community](https://github.com/your-org/network-traffic-analysis-toolkit/discussions)
- 🐛 Bug Reports: [GitHub Issues](https://github.com/your-org/network-traffic-analysis-toolkit/issues)

---

*User Manual v2.1.0 - Last updated: September 18, 2024*