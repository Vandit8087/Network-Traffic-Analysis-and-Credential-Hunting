#!/bin/bash

# Basic TCPDump Capture Commands
# Network Traffic Analysis Toolkit - TCPDump Commands Collection

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  TCPDump Basic Capture Commands${NC}"
echo -e "${BLUE}========================================${NC}"

# ========================================
# BASIC PACKET CAPTURE
# ========================================

echo -e "\n${GREEN}1. Basic Packet Capture${NC}"

# Capture all traffic on default interface
echo -e "${YELLOW}# Capture all traffic (default interface)${NC}"
echo "tcpdump"

# Capture on specific interface
echo -e "\n${YELLOW}# Capture on specific interface${NC}"
echo "sudo tcpdump -i eth0"

# Capture to file
echo -e "\n${YELLOW}# Capture to PCAP file${NC}"
echo "sudo tcpdump -i eth0 -w capture.pcap"

# Capture with packet count limit
echo -e "\n${YELLOW}# Capture limited number of packets${NC}"
echo "sudo tcpdump -i eth0 -c 100 -w limited.pcap"

# ========================================
# PROTOCOL-SPECIFIC CAPTURE
# ========================================

echo -e "\n${GREEN}2. Protocol-Specific Capture${NC}"

# HTTP traffic only
echo -e "\n${YELLOW}# Capture HTTP traffic only${NC}"
echo "sudo tcpdump -i eth0 port 80 -w http_traffic.pcap"

# HTTPS traffic only  
echo -e "\n${YELLOW}# Capture HTTPS traffic only${NC}"
echo "sudo tcpdump -i eth0 port 443 -w https_traffic.pcap"

# DNS traffic
echo -e "\n${YELLOW}# Capture DNS queries and responses${NC}"
echo "sudo tcpdump -i eth0 port 53 -w dns_traffic.pcap"

# FTP traffic
echo -e "\n${YELLOW}# Capture FTP traffic${NC}"
echo "sudo tcpdump -i eth0 port 21 -w ftp_traffic.pcap"

# SSH traffic
echo -e "\n${YELLOW}# Capture SSH traffic${NC}"
echo "sudo tcpdump -i eth0 port 22 -w ssh_traffic.pcap"

# Multiple ports
echo -e "\n${YELLOW}# Capture multiple protocols${NC}"
echo "sudo tcpdump -i eth0 'port 80 or port 443 or port 22' -w web_ssh.pcap"

# ========================================
# HOST-SPECIFIC CAPTURE
# ========================================

echo -e "\n${GREEN}3. Host-Specific Capture${NC}"

# Traffic to/from specific host
echo -e "\n${YELLOW}# Capture traffic to/from specific host${NC}"
echo "sudo tcpdump -i eth0 host 192.168.1.100 -w host_traffic.pcap"

# Traffic from specific source
echo -e "\n${YELLOW}# Capture traffic from specific source${NC}"
echo "sudo tcpdump -i eth0 src host 192.168.1.100 -w source_traffic.pcap"

# Traffic to specific destination
echo -e "\n${YELLOW}# Capture traffic to specific destination${NC}"
echo "sudo tcpdump -i eth0 dst host 192.168.1.100 -w destination_traffic.pcap"

# Network range capture
echo -e "\n${YELLOW}# Capture traffic for entire subnet${NC}"
echo "sudo tcpdump -i eth0 net 192.168.1.0/24 -w network_traffic.pcap"

# ========================================
# ADVANCED FILTERING
# ========================================

echo -e "\n${GREEN}4. Advanced Filtering${NC}"

# TCP SYN packets only (port scanning detection)
echo -e "\n${YELLOW}# Capture TCP SYN packets only${NC}"
echo "sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' -w syn_scan.pcap"

# HTTP POST requests
echo -e "\n${YELLOW}# Capture HTTP POST requests${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A -n 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)' -w http_posts.pcap"

# ICMP traffic (ping, etc.)
echo -e "\n${YELLOW}# Capture ICMP traffic${NC}"
echo "sudo tcpdump -i eth0 icmp -w icmp_traffic.pcap"

# ARP traffic
echo -e "\n${YELLOW}# Capture ARP traffic${NC}"
echo "sudo tcpdump -i eth0 arp -w arp_traffic.pcap"

# ========================================
# OUTPUT FORMATTING OPTIONS
# ========================================

echo -e "\n${GREEN}5. Output Formatting Options${NC}"

# Verbose output
echo -e "\n${YELLOW}# Verbose output with details${NC}"
echo "sudo tcpdump -i eth0 -v port 80"

# Very verbose output
echo -e "\n${YELLOW}# Very verbose output${NC}"
echo "sudo tcpdump -i eth0 -vv port 80"

# Show packet contents in hex and ASCII
echo -e "\n${YELLOW}# Show packet contents in hex and ASCII${NC}"
echo "sudo tcpdump -i eth0 -X port 80"

# Show ASCII only
echo -e "\n${YELLOW}# Show packet contents in ASCII only${NC}"
echo "sudo tcpdump -i eth0 -A port 80"

# Don't resolve hostnames (faster)
echo -e "\n${YELLOW}# Don't resolve hostnames${NC}"
echo "sudo tcpdump -i eth0 -n port 80"

# Don't resolve hostnames or port names
echo -e "\n${YELLOW}# Don't resolve hostnames or ports${NC}"
echo "sudo tcpdump -i eth0 -nn port 80"

# ========================================
# TIME-BASED CAPTURE
# ========================================

echo -e "\n${GREEN}6. Time-Based Capture${NC}"

# Capture for specific duration
echo -e "\n${YELLOW}# Capture for 60 seconds${NC}"
echo "timeout 60 sudo tcpdump -i eth0 -w timed_capture.pcap"

# Rotate capture files by size
echo -e "\n${YELLOW}# Rotate files every 100MB${NC}"
echo "sudo tcpdump -i eth0 -C 100 -W 5 -w rotating_capture.pcap"

# Timestamp with microsecond precision
echo -e "\n${YELLOW}# High precision timestamps${NC}"
echo "sudo tcpdump -i eth0 -ttt -w timestamped.pcap"

# ========================================
# BUFFER AND PERFORMANCE OPTIONS
# ========================================

echo -e "\n${GREEN}7. Performance Options${NC}"

# Set snapshot length (capture more/less of each packet)
echo -e "\n${YELLOW}# Capture full packets${NC}"
echo "sudo tcpdump -i eth0 -s 65535 -w full_packets.pcap"

# Capture headers only
echo -e "\n${YELLOW}# Capture headers only (faster)${NC}"
echo "sudo tcpdump -i eth0 -s 96 -w headers_only.pcap"

# Line buffered output (for real-time analysis)
echo -e "\n${YELLOW}# Line buffered output${NC}"
echo "sudo tcpdump -i eth0 -l port 80 | grep 'POST'"

# ========================================
# SECURITY-FOCUSED CAPTURE COMMANDS
# ========================================

echo -e "\n${GREEN}8. Security-Focused Commands${NC}"

# Capture potential credential traffic
echo -e "\n${YELLOW}# Capture potential credential traffic${NC}"
echo "sudo tcpdump -i eth0 -s 0 -A 'port 80 or port 21 or port 23 or port 25 or port 110 or port 143' -w credentials.pcap"

# Monitor for brute force attacks
echo -e "\n${YELLOW}# Monitor for potential brute force${NC}"
echo "sudo tcpdump -i eth0 'port 22 or port 3389 or port 21' -w brute_force_monitor.pcap"

# Detect suspicious outbound connections
echo -e "\n${YELLOW}# Monitor unusual outbound traffic${NC}"
echo "sudo tcpdump -i eth0 'src net 192.168.0.0/16 and dst not net 192.168.0.0/16' -w outbound_suspicious.pcap"

# Monitor DNS for potential tunneling
echo -e "\n${YELLOW}# Monitor DNS for potential tunneling${NC}"
echo "sudo tcpdump -i eth0 -s 0 'port 53 and greater 512' -w dns_large.pcap"

# ========================================
# PRACTICAL EXAMPLES
# ========================================

echo -e "\n${GREEN}9. Practical Usage Examples${NC}"

# Daily monitoring script
echo -e "\n${YELLOW}# Example: Daily security monitoring${NC}"
cat << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
sudo tcpdump -i eth0 -C 100 -W 24 -w "daily_monitor_${DATE}.pcap" &
EOF

# Credential hunting session
echo -e "\n${YELLOW}# Example: Credential hunting session${NC}"
cat << 'EOF'
#!/bin/bash
sudo tcpdump -i eth0 -s 0 -A -n 'port 80 or port 21 or port 23' | \
    tee capture.txt | \
    grep -E "(USER|PASS|password|login)"
EOF

# Network baseline creation
echo -e "\n${YELLOW}# Example: Create network baseline${NC}"
cat << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d)
sudo tcpdump -i eth0 -c 10000 -w "baseline_${DATE}.pcap"
tcpdump -r "baseline_${DATE}.pcap" -nn | \
    awk '{print $3}' | sort | uniq -c | sort -nr > "top_destinations_${DATE}.txt"
EOF

# ========================================
# COMMON FILTERS REFERENCE
# ========================================

echo -e "\n${GREEN}10. Common Filter Reference${NC}"

echo -e "\n${YELLOW}# Protocol Filters:${NC}"
echo "tcp, udp, icmp, arp, ip, ip6"

echo -e "\n${YELLOW}# Direction Filters:${NC}"
echo "src, dst, src or dst, src and dst"

echo -e "\n${YELLOW}# Port Filters:${NC}"
echo "port 80, src port 80, dst port 80, portrange 80-443"

echo -e "\n${YELLOW}# Host Filters:${NC}"
echo "host 192.168.1.1, src host 192.168.1.1, dst host 192.168.1.1"

echo -e "\n${YELLOW}# Network Filters:${NC}"
echo "net 192.168.1.0/24, src net 192.168.1.0/24"

echo -e "\n${YELLOW}# Logical Operators:${NC}"
echo "and (&&), or (||), not (!)"

echo -e "\n${YELLOW}# Advanced TCP Flags:${NC}"
echo "'tcp[tcpflags] & tcp-syn != 0'  # SYN packets"
echo "'tcp[tcpflags] & tcp-ack != 0'  # ACK packets"  
echo "'tcp[tcpflags] & tcp-rst != 0'  # RST packets"

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}  Commands ready for execution!${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to run example captures
run_examples() {
    echo -e "\n${YELLOW}Choose an example to run:${NC}"
    echo "1. Basic HTTP capture (60 seconds)"
    echo "2. Credential hunting session"
    echo "3. Network scanning detection"
    echo "4. DNS monitoring"
    echo "5. Exit"
    
    read -p "Enter choice (1-5): " choice
    
    case $choice in
        1)
            echo -e "${GREEN}Starting HTTP capture for 60 seconds...${NC}"
            sudo timeout 60 tcpdump -i eth0 port 80 -w example_http.pcap
            echo -e "${GREEN}Capture saved to example_http.pcap${NC}"
            ;;
        2)
            echo -e "${GREEN}Starting credential hunting session...${NC}"
            sudo tcpdump -i eth0 -s 0 -A -c 100 'port 80 or port 21 or port 23' | grep -E "(USER|PASS|password|login)"
            ;;
        3)
            echo -e "${GREEN}Monitoring for port scans (Ctrl+C to stop)...${NC}"
            sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'
            ;;
        4)
            echo -e "${GREEN}Monitoring DNS traffic (Ctrl+C to stop)...${NC}"
            sudo tcpdump -i eth0 -vv port 53
            ;;
        5)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice!${NC}"
            run_examples
            ;;
    esac
}

# If script is run directly, offer examples
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo -e "\n${BLUE}Would you like to run an example? (y/n)${NC}"
    read -p "> " answer
    if [[ $answer =~ ^[Yy]$ ]]; then
        run_examples
    fi
fi