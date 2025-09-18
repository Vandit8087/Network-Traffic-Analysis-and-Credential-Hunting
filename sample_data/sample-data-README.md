# Sample Data 📊

This directory contains sample network captures and analysis results for testing and demonstration purposes.

## 📁 Directory Structure

### 📦 PCAP Files (`pcap-files/`)
Sample network traffic captures for analysis:
- **sample-http-traffic.pcap** - HTTP traffic containing credentials
- **suspicious-activity.pcap** - Network traffic with security issues
- **mixed-protocols.pcap** - Multi-protocol traffic sample

### 📈 Analysis Results (`analysis-results/`)
Pre-generated analysis outputs showing expected results:
- **network_security_analysis.csv** - Structured security findings
- **extracted-credentials.json** - Sample credential extraction results  
- **traffic-statistics.json** - Network analysis metrics

## 🎯 Purpose and Usage

### Educational Training
- Learn network traffic analysis techniques
- Practice using Wireshark and TCPDump
- Understand credential hunting methodologies
- Study attack pattern recognition

### Tool Testing
- Verify installation and configuration
- Test automated analysis scripts
- Validate report generation functionality
- Benchmark performance with known datasets

### Demonstration
- Show capabilities to stakeholders
- Present security findings examples
- Illustrate risk assessment processes
- Demonstrate professional reporting

## 🚀 Quick Start Examples

### Test Credential Extraction
```bash
# Analyze sample HTTP traffic
python3 tools/automated-tools/credential-extractor.py sample-data/pcap-files/sample-http-traffic.pcap

# Expected output: HTTP credentials found
```

### Test Traffic Analysis  
```bash
# Full traffic analysis
python3 tools/automated-tools/traffic-analyzer.py sample-data/pcap-files/suspicious-activity.pcap --full-analysis

# Expected output: Anomalies and threats detected
```

### Test Report Generation
```bash
# Generate security report from sample data
python3 tools/automated-tools/report-generator.py --input sample-data/analysis-results/ --format pdf

# Expected output: Professional security report
```

## 📋 Sample Data Descriptions

### HTTP Traffic Sample
- **File**: sample-http-traffic.pcap
- **Content**: Web application login attempts
- **Credentials**: 3 username/password pairs
- **Size**: ~50KB
- **Duration**: 5 minutes of traffic
- **Protocols**: HTTP, DNS, TCP

### Suspicious Activity Sample  
- **File**: suspicious-activity.pcap
- **Content**: Port scanning and brute force attempts
- **Threats**: 2 scanning activities, 1 brute force
- **Size**: ~120KB  
- **Duration**: 15 minutes of traffic
- **Protocols**: TCP, UDP, ICMP

### Mixed Protocols Sample
- **File**: mixed-protocols.pcap
- **Content**: Diverse protocol traffic
- **Features**: FTP, SSH, SMTP, DNS, HTTP
- **Size**: ~200KB
- **Duration**: 30 minutes of traffic
- **Use Case**: Protocol analysis training

## 🔍 Expected Analysis Results

### Credential Extraction Results
When analyzing sample data, you should find:
- **HTTP POST credentials**: 3 instances
- **FTP authentication**: 1 instance  
- **Base64 encoded data**: 2 instances
- **API tokens**: 1 instance
- **Total sensitive items**: 7

### Security Issues Detection
Expected findings include:
- **Port scanning**: 1 major incident
- **Brute force attempts**: 1 incident
- **Suspicious DNS queries**: 3 instances
- **Data exfiltration indicators**: 1 instance
- **Overall risk level**: HIGH

### Traffic Statistics
Typical analysis metrics:
- **Total packets**: ~15,000
- **Unique IP addresses**: 25-30
- **Protocol distribution**: HTTP (45%), TCP (30%), DNS (15%), Other (10%)
- **Top ports**: 80, 443, 22, 21, 53
- **Peak traffic hour**: Hour 14 (2 PM)

## 🛡️ Security Considerations

### Safe for Testing
- All sample data is sanitized and anonymized
- No real credentials or personal information
- Safe for educational and testing environments
- Designed for controlled analysis scenarios

### Privacy Protection
- IP addresses are from RFC 5737 documentation ranges
- Hostnames are fictional and non-routable
- All sensitive data has been redacted or replaced
- Complies with data protection requirements

## 🔧 Customization

### Creating Your Own Samples

#### Capture New Traffic
```bash
# Capture your own samples (authorized networks only)
sudo tcpdump -i eth0 -w my-sample.pcap -c 1000

# Sanitize the capture
editcap --novlan my-sample.pcap sanitized-sample.pcap
```

#### Generate Synthetic Data
```bash
# Use sample generation tools
python3 scripts/generate-sample-pcap.py --type credential-demo --output custom-sample.pcap
```

### Modify Existing Samples
```bash
# Edit existing PCAP files
editcap -c 100 sample-http-traffic.pcap small-sample.pcap  # First 100 packets
editcap -A "2024-01-01 00:00:00" sample.pcap time-shifted.pcap  # Change timestamps
```

## 📚 Learning Exercises

### Beginner Level
1. **Basic Analysis**
   - Open samples in Wireshark
   - Apply display filters from security-filters.txt
   - Identify different protocols

2. **Credential Hunting**
   - Search for POST requests
   - Find FTP authentication
   - Locate Base64 encoded data

### Intermediate Level  
1. **Anomaly Detection**
   - Identify port scanning patterns
   - Detect brute force attempts
   - Find unusual traffic patterns

2. **Statistical Analysis**
   - Generate protocol distribution charts
   - Analyze conversation patterns
   - Create timeline visualizations

### Advanced Level
1. **Custom Analysis**
   - Write custom Wireshark dissectors
   - Create specialized analysis scripts
   - Develop automated detection rules

2. **Report Generation**
   - Generate executive summaries
   - Create technical appendices
   - Develop risk assessment matrices

## 🤝 Contributing

### Adding New Samples
Help expand the sample dataset by:
- Contributing sanitized PCAP files
- Providing analysis result templates
- Creating specialized test scenarios
- Documenting analysis procedures

### Quality Guidelines
When contributing samples:
- Ensure all data is anonymized
- Provide clear documentation
- Include expected analysis results
- Test with all toolkit components

## 📞 Support

### Sample Data Issues
- **Missing files**: Re-run setup.sh to restore samples
- **Corrupted captures**: Download fresh copies from repository
- **Analysis errors**: Check file permissions and tool installations
- **Custom samples**: See documentation for creating your own

### Getting Help
- 📧 **Email**: samples@yourorg.com
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-org/network-traffic-analysis-toolkit/discussions)
- 📋 **Issues**: [GitHub Issues](https://github.com/your-org/network-traffic-analysis-toolkit/issues)

---

*Sample Data Package - Network Traffic Analysis Toolkit v2.1.0*