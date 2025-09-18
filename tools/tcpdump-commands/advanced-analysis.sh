#!/bin/bash

# Advanced TCPDump Analysis Commands
# Network Traffic Analysis Toolkit - Advanced TCPDump Techniques

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Advanced TCPDump Analysis Commands${NC}"
echo -e "${BLUE}========================================${NC}"

# ========================================
# ADVANCED PACKET FILTERING
# ========================================

echo -e "\n${GREEN}1. Advanced Packet Filtering Techniques${NC}"

echo -e "\n${PURPLE}# HTTP POST Request Detection${NC}"
echo -e "${YELLOW}# Detect HTTP POST requests by matching hex signature${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A -n 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'"

echo -e "\n${PURPLE}# Advanced TCP Flag Analysis${NC}"
echo -e "${YELLOW}# SYN flood detection${NC}"
echo "sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 and tcp[tcpflags] & (tcp-rst) == 0'"

echo -e "\n${YELLOW}# FIN scan detection${NC}"
echo "sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-fin) != 0 and tcp[tcpflags] & (tcp-syn) == 0 and tcp[tcpflags] & (tcp-ack) == 0'"

echo -e "\n${YELLOW}# XMAS scan detection (FIN, PSH, URG flags)${NC}"
echo "sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-fin|tcp-push|tcp-urg) == (tcp-fin|tcp-push|tcp-urg)'"

echo -e "\n${PURPLE}# Advanced Protocol Analysis${NC}"
echo -e "${YELLOW}# DNS queries for specific types${NC}"
echo "sudo tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0 and udp[11] & 0x0f = 1'"  # A records
echo "sudo tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0 and udp[11] & 0x0f = 16'" # TXT records

echo -e "\n${YELLOW}# DHCP packet analysis${NC}"
echo "sudo tcpdump -i eth0 'udp port 67 or udp port 68'"
echo "sudo tcpdump -i eth0 'port 67 and udp[8:1] = 0x1'"  # DHCP Discover
echo "sudo tcpdump -i eth0 'port 67 and udp[8:1] = 0x2'"  # DHCP Offer

# ========================================
# SECURITY-FOCUSED ANALYSIS
# ========================================

echo -e "\n${GREEN}2. Security-Focused Analysis${NC}"

echo -e "\n${PURPLE}# Malware Communication Detection${NC}"
echo -e "${YELLOW}# Suspicious outbound connections${NC}"
echo "sudo tcpdump -i eth0 'src net 192.168.0.0/16 and dst not net 192.168.0.0/16 and dst not net 10.0.0.0/8 and dst not net 172.16.0.0/12'"

echo -e "\n${YELLOW}# DNS tunneling detection (large DNS responses)${NC}"
echo "sudo tcpdump -i eth0 'udp port 53 and length > 512'"

echo -e "\n${YELLOW}# IRC/P2P traffic detection${NC}"
echo "sudo tcpdump -i eth0 'port 6667 or port 6668 or port 6669 or port 7000'"

echo -e "\n${PURPLE}# Brute Force Attack Detection${NC}"
echo -e "${YELLOW}# SSH brute force monitoring${NC}"
echo "sudo tcpdump -i eth0 'port 22 and tcp[tcpflags] & (tcp-syn) != 0'"

echo -e "\n${YELLOW}# HTTP authentication failures${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450' | grep -i '401\\|403'"

echo -e "\n${YELLOW}# FTP brute force detection${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 21' | grep -E 'USER|PASS|530'"

echo -e "\n${PURPLE}# Data Exfiltration Monitoring${NC}"
echo -e "${YELLOW}# Large data transfers${NC}"
echo "sudo tcpdump -i eth0 'tcp and greater 1500'"

echo -e "\n${YELLOW}# Unusual protocol usage${NC}"
echo "sudo tcpdump -i eth0 'not port 80 and not port 443 and not port 53 and not port 22 and not icmp'"

# ========================================
# ADVANCED CREDENTIAL HUNTING
# ========================================

echo -e "\n${GREEN}3. Advanced Credential Hunting${NC}"

echo -e "\n${PURPLE}# Multi-Protocol Credential Monitoring${NC}"
echo -e "${YELLOW}# Monitor all common credential protocols${NC}"
cat << 'EOF'
sudo tcpdump -i eth0 -s 0 -A \
  'port 80 or port 21 or port 23 or port 25 or port 110 or port 143 or port 993 or port 995' | \
  grep -iE "(USER|PASS|AUTH|LOGIN|username|password)"
EOF

echo -e "\n${YELLOW}# HTTP Form Data Extraction${NC}"
cat << 'EOF'
sudo tcpdump -i eth0 -s 0 -A -n \
  'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)' | \
  grep -E "(username|password|email|login)" --color=never | \
  sed 's/&/\n/g'
EOF

echo -e "\n${YELLOW}# Base64 Authentication Detection${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 80' | grep -i 'authorization: basic' | base64 -d"

echo -e "\n${PURPLE}# Protocol-Specific Credential Extraction${NC}"
echo -e "${YELLOW}# POP3 credential monitoring${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 110' | grep -E '^(USER|PASS)'"

echo -e "\n${YELLOW}# IMAP credential monitoring${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 143' | grep -i 'login'"

echo -e "\n${YELLOW}# SNMP community string detection${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 161' | grep -oE 'community=[^,}]*'"

# ========================================
# TRAFFIC PATTERN ANALYSIS
# ========================================

echo -e "\n${GREEN}4. Traffic Pattern Analysis${NC}"

echo -e "\n${PURPLE}# Connection Analysis${NC}"
echo -e "${YELLOW}# Monitor connection establishment patterns${NC}"
echo "sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' | awk '{print \$3}' | sort | uniq -c | sort -nr"

echo -e "\n${YELLOW}# Failed connection attempts${NC}"
echo "sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-rst) != 0' | awk '{print \$3}' | sort | uniq -c | sort -nr"

echo -e "\n${PURPLE}# Bandwidth Analysis${NC}"
echo -e "${YELLOW}# Top bandwidth consumers${NC}"
cat << 'EOF'
sudo tcpdump -i eth0 -tt -n | \
  awk '{
    if($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
      src=$3; dst=$5; 
      gsub(/:[0-9]+$/, "", src); 
      gsub(/:[0-9]+.*$/, "", dst);
      print src " -> " dst;
    }
  }' | sort | uniq -c | sort -nr | head -20
EOF

echo -e "\n${PURPLE}# Temporal Analysis${NC}"
echo -e "${YELLOW}# Traffic patterns by hour${NC}"
cat << 'EOF'
sudo tcpdump -i eth0 -tt | \
  awk '{print strftime("%H", $1)}' | \
  sort | uniq -c | \
  awk '{printf "%02d:00 - %02d:59: %d packets\n", $2, $2, $1}'
EOF

# ========================================
# FORENSIC ANALYSIS TECHNIQUES
# ========================================

echo -e "\n${GREEN}5. Forensic Analysis Techniques${NC}"

echo -e "\n${PURPLE}# Evidence Collection${NC}"
echo -e "${YELLOW}# Capture with full forensic details${NC}"
echo "sudo tcpdump -i eth0 -s 65535 -tttt -vv -XX -w forensic_capture_\$(date +%Y%m%d_%H%M%S).pcap"

echo -e "\n${YELLOW}# Timeline reconstruction${NC}"
echo "sudo tcpdump -r capture.pcap -tttt | head -20"

echo -e "\n${PURPLE}# Protocol Statistics${NC}"
echo -e "${YELLOW}# Generate protocol distribution${NC}"
cat << 'EOF'
tcpdump -r capture.pcap -n | \
  awk '{print $8}' | \
  sort | uniq -c | \
  sort -nr | \
  awk '{printf "%-15s: %d packets\n", $2, $1}'
EOF

echo -e "\n${YELLOW}# Extract unique IP addresses${NC}"
echo "tcpdump -r capture.pcap -n | awk '{print \$3, \$5}' | tr ' ' '\n' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u"

# ========================================
# AUTOMATED ANALYSIS PIPELINES
# ========================================

echo -e "\n${GREEN}6. Automated Analysis Pipelines${NC}"

echo -e "\n${PURPLE}# Real-time Security Monitoring${NC}"
echo -e "${YELLOW}# Live credential monitoring pipeline${NC}"
cat << 'EOF'
# Create named pipe for real-time processing
mkfifo /tmp/security_monitor
sudo tcpdump -i eth0 -s 0 -A 'port 80 or port 21 or port 23' > /tmp/security_monitor &

# Process the stream
while read line; do
  if echo "$line" | grep -qiE "(username|password|USER|PASS)"; then
    echo "$(date): CREDENTIAL DETECTED: $line" | tee -a security_log.txt
  fi
done < /tmp/security_monitor
EOF

echo -e "\n${YELLOW}# Automated threat detection${NC}"
cat << 'EOF'
# Port scan detection script
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' | \
while read line; do
  src=$(echo $line | awk '{print $3}' | cut -d. -f1-4)
  dst=$(echo $line | awk '{print $5}' | cut -d. -f1-4)
  port=$(echo $line | awk '{print $5}' | cut -d: -f2 | cut -d. -f1)
  
  echo "$src scanning $dst:$port at $(date)" >> scan_log.txt
  
  # Alert on rapid scanning
  recent_scans=$(tail -100 scan_log.txt | grep "$src" | wc -l)
  if [ $recent_scans -gt 20 ]; then
    echo "ALERT: Port scan from $src detected!" | wall
  fi
done
EOF

# ========================================
# STATISTICAL ANALYSIS
# ========================================

echo -e "\n${GREEN}7. Statistical Analysis${NC}"

echo -e "\n${PURPLE}# Connection Statistics${NC}"
echo -e "${YELLOW}# Calculate connection success rate${NC}"
cat << 'EOF'
syn_packets=$(tcpdump -r capture.pcap 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' | wc -l)
synack_packets=$(tcpdump -r capture.pcap 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) != 0' | wc -l)
success_rate=$((synack_packets * 100 / syn_packets))
echo "Connection Success Rate: $success_rate%"
EOF

echo -e "\n${YELLOW}# Traffic volume analysis${NC}"
cat << 'EOF'
tcpdump -r capture.pcap -nn | \
awk '{
  split($3, src, ":"); 
  split($5, dst, ":"); 
  connections[src[1] " -> " dst[1]]++
} 
END {
  for (conn in connections) {
    print connections[conn], conn
  }
}' | sort -nr | head -10
EOF

# ========================================
# ADVANCED FILTERING EXAMPLES
# ========================================

echo -e "\n${GREEN}8. Advanced Filtering Examples${NC}"

echo -e "\n${PURPLE}# Complex Boolean Logic${NC}"
echo -e "${YELLOW}# Detect suspicious combinations${NC}"
echo "sudo tcpdump -i eth0 '(tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420) or (tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'"

echo -e "\n${YELLOW}# Time-based filtering${NC}"
echo "sudo tcpdump -i eth0 'tcp and host 192.168.1.1 and (port 80 or port 443)' -G 3600 -w 'hourly_%Y%m%d_%H.pcap'"

echo -e "\n${PURPLE}# Payload Content Filtering${NC}"
echo -e "${YELLOW}# Detect specific malware signatures${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A | grep -i 'specific_malware_string'"

echo -e "\n${YELLOW}# SQL injection attempt detection${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 80' | grep -iE \"(select|union|drop|insert|update|delete).*from\""

# ========================================
# PERFORMANCE OPTIMIZATION
# ========================================

echo -e "\n${GREEN}9. Performance Optimization${NC}"

echo -e "\n${PURPLE}# High-Performance Capture${NC}"
echo -e "${YELLOW}# Optimized for high-traffic environments${NC}"
echo "sudo tcpdump -i eth0 -B 65536 -s 96 --immediate-mode -w fast_capture.pcap"

echo -e "\n${YELLOW}# Parallel processing for multiple interfaces${NC}"
cat << 'EOF'
# Capture on multiple interfaces simultaneously
sudo tcpdump -i eth0 -w eth0_capture.pcap &
sudo tcpdump -i wlan0 -w wlan0_capture.pcap &
sudo tcpdump -i lo -w lo_capture.pcap &
wait
EOF

echo -e "\n${PURPLE}# Memory-Efficient Analysis${NC}"
echo -e "${YELLOW}# Process large files in chunks${NC}"
cat << 'EOF'
# Split large PCAP files
editcap -c 10000 large_capture.pcap chunk.pcap

# Process each chunk
for chunk in chunk_*.pcap; do
  echo "Processing $chunk..."
  tcpdump -r "$chunk" 'tcp port 80' >> http_traffic.txt
done
EOF

# ========================================
# INTEGRATION WITH OTHER TOOLS
# ========================================

echo -e "\n${GREEN}10. Integration with Other Tools${NC}"

echo -e "\n${PURPLE}# Integration Examples${NC}"
echo -e "${YELLOW}# Pipe to Wireshark for GUI analysis${NC}"
echo "sudo tcpdump -i eth0 -U -s0 -w - 'port 80' | wireshark -k -i -"

echo -e "\n${YELLOW}# Export to various formats${NC}"
cat << 'EOF'
# Convert to CSV for analysis
tcpdump -r capture.pcap -tt -n | \
awk '{print $1","$3","$5","$8}' > traffic.csv

# Send alerts via email
if sudo tcpdump -c 1 -i eth0 'icmp[icmptype] == icmp-echo'; then
  echo "ICMP detected" | mail -s "Network Alert" admin@company.com
fi
EOF

echo -e "\n${YELLOW}# Integration with SIEM systems${NC}"
cat << 'EOF'
# Send logs to syslog
sudo tcpdump -i eth0 'tcp port 80' | \
while read line; do
  logger -t "tcpdump-monitor" "$line"
done
EOF

# Function to demonstrate interactive examples
run_advanced_examples() {
    echo -e "\n${CYAN}Choose an advanced example to run:${NC}"
    echo "1. Port scan detection (real-time)"
    echo "2. Credential monitoring pipeline"
    echo "3. Traffic statistics generation"  
    echo "4. Malware communication detection"
    echo "5. Exit"
    
    read -p "Enter choice (1-5): " choice
    
    case $choice in
        1)
            echo -e "${GREEN}Starting port scan detection (Ctrl+C to stop)...${NC}"
            sudo timeout 30 tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' | \
            while read line; do
                src=$(echo $line | awk '{print $3}' | cut -d: -f1)
                dst=$(echo $line | awk '{print $5}' | cut -d: -f1)
                echo "$(date): Potential scan from $src to $dst"
            done
            ;;
        2)
            echo -e "${GREEN}Starting credential monitoring (30 seconds)...${NC}"
            sudo timeout 30 tcpdump -i eth0 -s 0 -A 'port 80 or port 21' | \
            grep -iE "(USER|PASS|username|password|login)" --line-buffered | \
            while read line; do
                echo "$(date): CREDENTIAL ACTIVITY: $line"
            done
            ;;
        3)
            echo -e "${GREEN}Generating traffic statistics...${NC}"
            if [ -f "capture.pcap" ]; then
                echo "Protocol Distribution:"
                tcpdump -r capture.pcap -n 2>/dev/null | awk '{print $8}' | sort | uniq -c | sort -nr | head -10
            else
                echo "No capture.pcap file found. Creating sample capture..."
                sudo timeout 10 tcpdump -i eth0 -w sample.pcap 2>/dev/null
                echo "Sample capture created: sample.pcap"
            fi
            ;;
        4)
            echo -e "${GREEN}Monitoring for suspicious outbound connections (30 seconds)...${NC}"
            sudo timeout 30 tcpdump -i eth0 'src net 192.168.0.0/16 and dst not net 192.168.0.0/16' | \
            while read line; do
                dst=$(echo $line | awk '{print $5}' | cut -d: -f1)
                echo "$(date): Outbound connection to external host: $dst"
            done
            ;;
        5)
            echo -e "${GREEN}Exiting...${NC}"
            return
            ;;
        *)
            echo -e "${RED}Invalid choice!${NC}"
            run_advanced_examples
            ;;
    esac
}

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}  Advanced TCPDump Commands Ready!${NC}"
echo -e "${BLUE}========================================${NC}"

# If script is run directly, offer examples
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo -e "\n${CYAN}Would you like to run an advanced example? (y/n)${NC}"
    read -p "> " answer
    if [[ $answer =~ ^[Yy]$ ]]; then
        run_advanced_examples
    fi
fi