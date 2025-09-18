# Scripts Directory 📜

This directory contains automation scripts for the Network Traffic Analysis Toolkit.

## 📁 Available Scripts

### 🚀 **setup.sh**
**Location:** `../setup.sh` (in root directory)  
**Purpose:** Complete automated installation and configuration  
**Usage:**
```bash
chmod +x setup.sh
sudo ./setup.sh
```

### 🔧 **install-tools.sh** 
**Purpose:** Install external security analysis tools  
**Dependencies:** System package managers (apt, yum, brew)  
**Usage:**
```bash
./scripts/install-tools.sh [--force] [--quiet]
```

**Installs:**
- PCredz for credential extraction
- CredSlayer for advanced credential hunting  
- NetworkMiner for network forensics
- Additional penetration testing tools

### 📊 **run-analysis.sh**
**Purpose:** Complete analysis pipeline automation  
**Dependencies:** All toolkit components installed  
**Usage:**
```bash
./scripts/run-analysis.sh <pcap-file> [options]
```

**Pipeline Steps:**
1. PCAP validation and preprocessing
2. Credential extraction analysis
3. Network traffic pattern analysis
4. Threat detection and anomaly identification
5. Professional report generation
6. Results archiving and notification

**Options:**
- `--output-dir DIR` - Specify output directory
- `--format FORMAT` - Report format (pdf/html/json)
- `--template TEMPLATE` - Report template to use
- `--notify EMAIL` - Email notification on completion
- `--verbose` - Detailed logging output

### 🧹 **cleanup.sh**
**Purpose:** Clean temporary files and reset environment  
**Usage:**
```bash
./scripts/cleanup.sh [--deep] [--logs] [--temp]
```

**Options:**
- `--deep` - Remove all generated files and analysis results
- `--logs` - Clean log files older than 30 days
- `--temp` - Remove temporary analysis files only

### 📦 **backup-results.sh**
**Purpose:** Archive analysis results for long-term storage  
**Usage:**
```bash
./scripts/backup-results.sh [--compress] [--encrypt] [--remote]
```

## 🔄 Automation Examples

### Daily Analysis Automation
```bash
#!/bin/bash
# Add to crontab for daily analysis
0 6 * * * /path/to/toolkit/scripts/daily-analysis.sh
```

### Batch Processing
```bash
# Process multiple PCAP files
for pcap in /captures/*.pcap; do
    ./scripts/run-analysis.sh "$pcap" --output-dir "/results/$(basename $pcap .pcap)"
done
```

### Integration with SIEM
```bash
# Send results to SIEM system
./scripts/run-analysis.sh capture.pcap --format json --notify siem@company.com
```

## 🛠️ Custom Script Development

### Script Template
```bash
#!/bin/bash
# Network Analysis Toolkit Custom Script Template

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="$TOOLKIT_DIR/logs/custom-script.log"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Your custom logic here
main() {
    log "Starting custom analysis..."
    # Add your analysis code
    log "Analysis complete"
}

main "$@"
```

### Python Script Integration
```python
#!/usr/bin/env python3
"""
Custom analysis script template
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'tools', 'automated-tools'))

from credential_extractor import CredentialExtractor
from traffic_analyzer import NetworkTrafficAnalyzer
from report_generator import SecurityReportGenerator

def custom_analysis(pcap_file):
    """Custom analysis workflow"""
    # Your custom analysis logic
    pass

if __name__ == '__main__':
    custom_analysis(sys.argv[1])
```

## 📋 Script Configuration

### Environment Variables
```bash
# Set in ~/.bashrc or toolkit environment
export TOOLKIT_HOME="/path/to/toolkit"
export PCAP_DIR="$TOOLKIT_HOME/pcap-samples"  
export RESULTS_DIR="$TOOLKIT_HOME/results"
export LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
export REPORT_FORMAT="pdf"  # Default report format
export NOTIFICATION_EMAIL="security-team@company.com"
```

### Configuration Files
- `scripts/config/default.conf` - Default script configuration
- `scripts/config/analysis.conf` - Analysis pipeline settings
- `scripts/config/notification.conf` - Email/alert settings

## 🔐 Security Considerations

### Script Security
- All scripts run with minimal required privileges
- Input validation for all parameters
- Secure temporary file handling
- Audit logging for all actions
- Error handling and cleanup procedures

### Credential Handling
- No hardcoded passwords or API keys
- Secure credential storage using environment variables
- Encrypted storage for sensitive configuration
- Regular credential rotation procedures

### Network Access
- Scripts minimize network connectivity requirements  
- Proxy support for corporate environments
- SSL/TLS verification for external communications
- Network access logging and monitoring

## 📊 Monitoring and Alerting

### Script Monitoring
```bash
# Monitor script execution
tail -f logs/run-analysis.log

# Check for failed analyses
grep "ERROR" logs/*.log | tail -20

# Performance monitoring
scripts/monitor-performance.sh --report hourly
```

### Alert Configuration
```bash
# Email alerts for critical findings
CRITICAL_THRESHOLD=5  # Number of critical findings
ALERT_EMAIL="security-alerts@company.com"

# Slack integration
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
SLACK_CHANNEL="#security-alerts"
```

### Health Checks
```bash
# Automated health checks
scripts/health-check.sh --components all --notify admin@company.com

# Service status monitoring  
scripts/check-services.sh --restart-failed --log-status
```

## 🚀 Performance Optimization

### Parallel Processing
```bash
# Process multiple files in parallel
find /captures -name "*.pcap" | xargs -P 4 -I {} ./scripts/run-analysis.sh {}

# Background processing
nohup ./scripts/run-analysis.sh large-capture.pcap &
```

### Resource Management
```bash
# Limit resource usage
ulimit -m 4194304  # 4GB memory limit
nice -n 10 ./scripts/run-analysis.sh capture.pcap  # Lower priority

# Cleanup old results automatically
scripts/cleanup.sh --older-than 30days --compress
```

## 🤝 Community Scripts

### Contributing Scripts
1. Follow the script template format
2. Include comprehensive error handling
3. Add usage documentation
4. Test with sample data
5. Submit via pull request

### Quality Guidelines
- **Documentation:** Clear usage instructions and examples
- **Error Handling:** Comprehensive error checking and recovery
- **Logging:** Appropriate logging levels and output
- **Security:** Secure coding practices and input validation
- **Performance:** Efficient resource usage and optimization

### Script Categories
- **Analysis Scripts:** Custom analysis workflows
- **Automation Scripts:** Task automation and scheduling  
- **Integration Scripts:** SIEM and tool integrations
- **Utility Scripts:** Helper functions and tools
- **Reporting Scripts:** Custom report generation

## 📞 Support

### Script Issues
- **Execution Errors:** Check logs in `logs/` directory
- **Permission Issues:** Ensure proper file permissions
- **Dependency Issues:** Run `./setup.sh` to reinstall
- **Configuration Issues:** Verify environment variables

### Getting Help
- 📧 **Email:** scripts@yourorg.com
- 💬 **Community:** [GitHub Discussions](https://github.com/your-org/network-traffic-analysis-toolkit/discussions)
- 📋 **Bug Reports:** [GitHub Issues](https://github.com/your-org/network-traffic-analysis-toolkit/issues)
- 📚 **Documentation:** [User Manual](../docs/user-manual.md)

### Professional Services
- **Custom Script Development** for enterprise customers
- **Integration Consulting** for SIEM and security tools
- **Training Workshops** for script development and automation
- **Support Contracts** for production environments

---

## 📜 Example Script Usage

### Quick Analysis
```bash
# Analyze single PCAP file
./scripts/run-analysis.sh sample-data/pcap-files/sample-http-traffic.pcap

# Generate PDF report
./scripts/run-analysis.sh capture.pcap --format pdf --output-dir ./reports/
```

### Automated Monitoring  
```bash
# Set up automated daily analysis
echo "0 6 * * * /path/to/toolkit/scripts/daily-analysis.sh" | crontab -

# Monitor live traffic (requires root)
sudo tcpdump -i eth0 -w - | ./scripts/live-analysis.sh --realtime
```

### Enterprise Integration
```bash
# Integration with enterprise systems
./scripts/run-analysis.sh capture.pcap \
  --notify security-team@company.com \
  --siem-export \
  --compliance-report \
  --encrypt-results
```

---

*Scripts Directory - Network Traffic Analysis Toolkit v2.1.0*

**⚡ Automation made simple - from capture to comprehensive security insights**