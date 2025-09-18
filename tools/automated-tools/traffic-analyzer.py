#!/usr/bin/env python3
"""
Network Traffic Analyzer
========================

A comprehensive tool for analyzing network traffic patterns, detecting anomalies,
and generating security insights from PCAP files.

Features:
- Protocol distribution analysis
- Connection pattern analysis
- Anomaly detection
- Bandwidth analysis
- Threat detection
- Statistical reporting
- Geographic analysis (with GeoIP)
- Timeline analysis

Author: Network Security Team
License: MIT
Version: 2.1.0
"""

import argparse
import json
import csv
import sys
import os
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict, Counter
import subprocess
import ipaddress
import sqlite3
import tempfile

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    print("Warning: pyshark not available. Install with: pip install pyshark")
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False

try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    print("Warning: pandas/numpy not available. Install with: pip install pandas numpy")
    PANDAS_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    print("Warning: matplotlib/seaborn not available. Install with: pip install matplotlib seaborn")
    PLOTTING_AVAILABLE = False

class NetworkTrafficAnalyzer:
    """Main class for comprehensive network traffic analysis"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.analysis_results = {
            'metadata': {},
            'protocol_stats': {},
            'connection_stats': {},
            'anomalies': [],
            'threats': [],
            'bandwidth_analysis': {},
            'temporal_analysis': {},
            'geographic_analysis': {}
        }
        
        # Create temporary database for analysis
        self.db_path = tempfile.mktemp(suffix='.db')
        self.init_database()
        
    def log(self, message: str, level: str = "INFO"):
        """Logging function with timestamp"""
        if self.verbose or level in ['ERROR', 'WARNING']:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")

    def init_database(self):
        """Initialize SQLite database for analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables for different analysis types
        cursor.execute('''
            CREATE TABLE packets (
                id INTEGER PRIMARY KEY,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flags TEXT,
                payload_size INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE connections (
                id INTEGER PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                start_time REAL,
                end_time REAL,
                packets INTEGER,
                bytes INTEGER,
                flags TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE anomalies (
                id INTEGER PRIMARY KEY,
                timestamp REAL,
                type TEXT,
                description TEXT,
                severity TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def analyze_pcap_file(self, pcap_file: str, analysis_type: str = "full") -> Dict:
        """Main analysis function"""
        self.log(f"Starting {analysis_type} analysis of {pcap_file}")
        
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        # Store metadata
        self.analysis_results['metadata'] = {
            'pcap_file': pcap_file,
            'analysis_type': analysis_type,
            'start_time': datetime.now().isoformat(),
            'file_size': os.path.getsize(pcap_file),
            'analyzer_version': '2.1.0'
        }
        
        if PYSHARK_AVAILABLE:
            self._analyze_with_pyshark(pcap_file, analysis_type)
        elif SCAPY_AVAILABLE:
            self._analyze_with_scapy(pcap_file, analysis_type)
        else:
            self._analyze_with_tshark(pcap_file, analysis_type)
        
        # Perform analysis based on collected data
        if analysis_type in ["full", "stats"]:
            self._generate_statistics()
        
        if analysis_type in ["full", "anomalies"]:
            self._detect_anomalies()
        
        if analysis_type in ["full", "threats"]:
            self._detect_threats()
        
        if analysis_type in ["full", "bandwidth"]:
            self._analyze_bandwidth()
        
        if analysis_type in ["full", "temporal"]:
            self._analyze_temporal_patterns()
        
        return self.analysis_results

    def _analyze_with_pyshark(self, pcap_file: str, analysis_type: str):
        """Analyze PCAP using PyShark"""
        self.log("Using PyShark for analysis")
        
        try:
            cap = pyshark.FileCapture(pcap_file)
            packet_count = 0
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for packet in cap:
                packet_count += 1
                
                try:
                    # Extract basic packet information
                    timestamp = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else 0
                    
                    # IP layer information
                    if hasattr(packet, 'ip'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        protocol = packet.highest_layer
                        packet_size = int(packet.length) if hasattr(packet, 'length') else 0
                        
                        # Transport layer information
                        src_port = dst_port = 0
                        flags = ""
                        
                        if hasattr(packet, 'tcp'):
                            src_port = int(packet.tcp.srcport) if hasattr(packet.tcp, 'srcport') else 0
                            dst_port = int(packet.tcp.dstport) if hasattr(packet.tcp, 'dstport') else 0
                            flags = packet.tcp.flags if hasattr(packet.tcp, 'flags') else ""
                        elif hasattr(packet, 'udp'):
                            src_port = int(packet.udp.srcport) if hasattr(packet.udp, 'srcport') else 0
                            dst_port = int(packet.udp.dstport) if hasattr(packet.udp, 'dstport') else 0
                        
                        # Calculate payload size
                        payload_size = packet_size - 20 - (20 if hasattr(packet, 'tcp') else 8 if hasattr(packet, 'udp') else 0)
                        payload_size = max(0, payload_size)
                        
                        # Insert into database
                        cursor.execute('''
                            INSERT INTO packets 
                            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_size)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_size))
                        
                        # Commit every 1000 packets for performance
                        if packet_count % 1000 == 0:
                            conn.commit()
                            self.log(f"Processed {packet_count} packets")
                
                except Exception as e:
                    self.log(f"Error processing packet {packet_count}: {e}", "WARNING")
                    continue
            
            conn.commit()
            conn.close()
            cap.close()
            
            self.analysis_results['metadata']['total_packets'] = packet_count
            self.log(f"Successfully processed {packet_count} packets")
            
        except Exception as e:
            self.log(f"Error analyzing with PyShark: {e}", "ERROR")
            raise

    def _analyze_with_scapy(self, pcap_file: str, analysis_type: str):
        """Analyze PCAP using Scapy"""
        self.log("Using Scapy for analysis")
        
        try:
            packets = rdpcap(pcap_file)
            packet_count = len(packets)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for i, packet in enumerate(packets):
                try:
                    if packet.haslayer(IP):
                        timestamp = packet.time if hasattr(packet, 'time') else 0
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        protocol = packet[IP].proto
                        packet_size = len(packet)
                        
                        src_port = dst_port = 0
                        flags = ""
                        
                        if packet.haslayer(TCP):
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                            flags = packet[TCP].flags
                            protocol = "TCP"
                        elif packet.haslayer(UDP):
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport
                            protocol = "UDP"
                        
                        payload_size = len(packet[Raw]) if packet.haslayer(Raw) else 0
                        
                        cursor.execute('''
                            INSERT INTO packets 
                            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_size)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, str(flags), payload_size))
                        
                        if (i + 1) % 1000 == 0:
                            conn.commit()
                            self.log(f"Processed {i + 1} packets")
                
                except Exception as e:
                    self.log(f"Error processing packet {i}: {e}", "WARNING")
                    continue
            
            conn.commit()
            conn.close()
            
            self.analysis_results['metadata']['total_packets'] = packet_count
            self.log(f"Successfully processed {packet_count} packets")
            
        except Exception as e:
            self.log(f"Error analyzing with Scapy: {e}", "ERROR")
            raise

    def _analyze_with_tshark(self, pcap_file: str, analysis_type: str):
        """Fallback analysis using tshark command line"""
        self.log("Using tshark for analysis")
        
        try:
            # Extract basic packet information
            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src', '-e', 'ip.dst',
                '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'udp.srcport', '-e', 'udp.dstport',
                '-e', 'frame.protocols',
                '-e', 'frame.len',
                '-e', 'tcp.flags'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                packet_count = 0
                
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 9:
                            try:
                                timestamp = float(parts[0]) if parts[0] else 0
                                src_ip = parts[1] if parts[1] else ""
                                dst_ip = parts[2] if parts[2] else ""
                                tcp_sport = int(parts[3]) if parts[3] else 0
                                tcp_dport = int(parts[4]) if parts[4] else 0
                                udp_sport = int(parts[5]) if parts[5] else 0
                                udp_dport = int(parts[6]) if parts[6] else 0
                                protocols = parts[7] if parts[7] else ""
                                packet_size = int(parts[8]) if parts[8] else 0
                                flags = parts[9] if len(parts) > 9 and parts[9] else ""
                                
                                # Determine primary protocol and ports
                                if tcp_sport or tcp_dport:
                                    src_port, dst_port, protocol = tcp_sport, tcp_dport, "TCP"
                                elif udp_sport or udp_dport:
                                    src_port, dst_port, protocol = udp_sport, udp_dport, "UDP"
                                else:
                                    src_port, dst_port, protocol = 0, 0, "Other"
                                
                                # Estimate payload size (rough approximation)
                                payload_size = max(0, packet_size - 40)  # IP + TCP/UDP headers
                                
                                cursor.execute('''
                                    INSERT INTO packets 
                                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_size)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_size))
                                
                                packet_count += 1
                                
                            except (ValueError, IndexError) as e:
                                self.log(f"Error parsing line: {e}", "WARNING")
                                continue
                
                conn.commit()
                conn.close()
                
                self.analysis_results['metadata']['total_packets'] = packet_count
                self.log(f"Successfully processed {packet_count} packets")
                
            else:
                raise RuntimeError(f"tshark error: {result.stderr}")
                
        except Exception as e:
            self.log(f"Error analyzing with tshark: {e}", "ERROR")
            raise

    def _generate_statistics(self):
        """Generate protocol and connection statistics"""
        self.log("Generating network statistics")
        
        conn = sqlite3.connect(self.db_path)
        
        # Protocol distribution
        protocol_stats = {}
        cursor = conn.execute('''
            SELECT protocol, COUNT(*) as packet_count, SUM(packet_size) as total_bytes
            FROM packets 
            GROUP BY protocol 
            ORDER BY packet_count DESC
        ''')
        
        for row in cursor.fetchall():
            protocol, count, bytes_total = row
            protocol_stats[protocol] = {
                'packet_count': count,
                'total_bytes': bytes_total or 0,
                'percentage': 0  # Will calculate after getting total
            }
        
        # Calculate percentages
        total_packets = sum(stats['packet_count'] for stats in protocol_stats.values())
        for protocol in protocol_stats:
            protocol_stats[protocol]['percentage'] = (protocol_stats[protocol]['packet_count'] / total_packets) * 100
        
        self.analysis_results['protocol_stats'] = protocol_stats
        
        # Top talkers (conversations)
        cursor = conn.execute('''
            SELECT src_ip, dst_ip, COUNT(*) as packet_count, SUM(packet_size) as total_bytes
            FROM packets 
            GROUP BY src_ip, dst_ip 
            ORDER BY packet_count DESC 
            LIMIT 20
        ''')
        
        conversations = []
        for row in cursor.fetchall():
            src_ip, dst_ip, count, bytes_total = row
            conversations.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_count': count,
                'total_bytes': bytes_total or 0
            })
        
        self.analysis_results['connection_stats']['top_conversations'] = conversations
        
        # Port analysis
        cursor = conn.execute('''
            SELECT dst_port, COUNT(*) as connection_count
            FROM packets 
            WHERE dst_port > 0
            GROUP BY dst_port 
            ORDER BY connection_count DESC 
            LIMIT 20
        ''')
        
        top_ports = []
        for row in cursor.fetchall():
            port, count = row
            top_ports.append({
                'port': port,
                'connection_count': count,
                'service': self._identify_service(port)
            })
        
        self.analysis_results['connection_stats']['top_ports'] = top_ports
        
        conn.close()

    def _detect_anomalies(self):
        """Detect network anomalies and suspicious patterns"""
        self.log("Detecting network anomalies")
        
        conn = sqlite3.connect(self.db_path)
        anomalies = []
        
        # Port scanning detection
        cursor = conn.execute('''
            SELECT src_ip, COUNT(DISTINCT dst_port) as unique_ports, COUNT(*) as total_attempts
            FROM packets 
            WHERE protocol = 'TCP' AND flags LIKE '%S%'
            GROUP BY src_ip 
            HAVING unique_ports > 20 OR total_attempts > 100
            ORDER BY unique_ports DESC
        ''')
        
        for row in cursor.fetchall():
            src_ip, unique_ports, attempts = row
            anomalies.append({
                'type': 'port_scan',
                'severity': 'HIGH' if unique_ports > 100 else 'MEDIUM',
                'src_ip': src_ip,
                'description': f"Port scanning detected: {unique_ports} unique ports, {attempts} attempts",
                'timestamp': datetime.now().isoformat()
            })
        
        # Brute force detection
        cursor = conn.execute('''
            SELECT src_ip, dst_ip, dst_port, COUNT(*) as attempts
            FROM packets 
            WHERE dst_port IN (22, 23, 21, 3389, 5900)
            GROUP BY src_ip, dst_ip, dst_port 
            HAVING attempts > 50
            ORDER BY attempts DESC
        ''')
        
        for row in cursor.fetchall():
            src_ip, dst_ip, port, attempts = row
            service = self._identify_service(port)
            anomalies.append({
                'type': 'brute_force',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'description': f"Possible brute force on {service} (port {port}): {attempts} attempts",
                'timestamp': datetime.now().isoformat()
            })
        
        # Unusual traffic patterns
        cursor = conn.execute('''
            SELECT src_ip, dst_ip, SUM(payload_size) as total_payload
            FROM packets 
            GROUP BY src_ip, dst_ip 
            HAVING total_payload > 10000000  -- 10MB threshold
            ORDER BY total_payload DESC
        ''')
        
        for row in cursor.fetchall():
            src_ip, dst_ip, payload = row
            anomalies.append({
                'type': 'data_transfer',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'description': f"Large data transfer: {payload/1024/1024:.1f} MB",
                'timestamp': datetime.now().isoformat()
            })
        
        self.analysis_results['anomalies'] = anomalies
        conn.close()

    def _detect_threats(self):
        """Detect potential security threats"""
        self.log("Detecting security threats")
        
        conn = sqlite3.connect(self.db_path)
        threats = []
        
        # DNS tunneling detection (large DNS responses)
        cursor = conn.execute('''
            SELECT src_ip, dst_ip, COUNT(*) as dns_count, AVG(packet_size) as avg_size
            FROM packets 
            WHERE dst_port = 53 AND packet_size > 512
            GROUP BY src_ip, dst_ip 
            HAVING dns_count > 10
            ORDER BY avg_size DESC
        ''')
        
        for row in cursor.fetchall():
            src_ip, dst_ip, count, avg_size = row
            threats.append({
                'type': 'dns_tunneling',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'description': f"Possible DNS tunneling: {count} large DNS packets, avg size {avg_size:.0f}",
                'timestamp': datetime.now().isoformat()
            })
        
        # Suspicious outbound connections
        cursor = conn.execute('''
            SELECT src_ip, dst_ip, dst_port, COUNT(*) as connection_count
            FROM packets 
            WHERE dst_port NOT IN (80, 443, 53, 22, 25, 110, 143, 993, 995)
            GROUP BY src_ip, dst_ip, dst_port 
            HAVING connection_count > 20
            ORDER BY connection_count DESC
        ''')
        
        for row in cursor.fetchall():
            src_ip, dst_ip, port, count = row
            # Check if destination is external (rough heuristic)
            if self._is_external_ip(dst_ip):
                threats.append({
                    'type': 'suspicious_outbound',
                    'severity': 'MEDIUM',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'description': f"Suspicious outbound connections to port {port}: {count} connections",
                    'timestamp': datetime.now().isoformat()
                })
        
        self.analysis_results['threats'] = threats
        conn.close()

    def _analyze_bandwidth(self):
        """Analyze bandwidth usage patterns"""
        self.log("Analyzing bandwidth patterns")
        
        conn = sqlite3.connect(self.db_path)
        
        # Top bandwidth consumers
        cursor = conn.execute('''
            SELECT src_ip, SUM(packet_size) as total_bytes_sent
            FROM packets 
            GROUP BY src_ip 
            ORDER BY total_bytes_sent DESC 
            LIMIT 10
        ''')
        
        top_senders = []
        for row in cursor.fetchall():
            ip, bytes_sent = row
            top_senders.append({
                'ip': ip,
                'bytes_sent': bytes_sent,
                'mb_sent': bytes_sent / (1024 * 1024)
            })
        
        cursor = conn.execute('''
            SELECT dst_ip, SUM(packet_size) as total_bytes_received
            FROM packets 
            GROUP BY dst_ip 
            ORDER BY total_bytes_received DESC 
            LIMIT 10
        ''')
        
        top_receivers = []
        for row in cursor.fetchall():
            ip, bytes_received = row
            top_receivers.append({
                'ip': ip,
                'bytes_received': bytes_received,
                'mb_received': bytes_received / (1024 * 1024)
            })
        
        self.analysis_results['bandwidth_analysis'] = {
            'top_senders': top_senders,
            'top_receivers': top_receivers
        }
        
        conn.close()

    def _analyze_temporal_patterns(self):
        """Analyze traffic patterns over time"""
        self.log("Analyzing temporal patterns")
        
        conn = sqlite3.connect(self.db_path)
        
        # Traffic by hour
        cursor = conn.execute('''
            SELECT 
                strftime('%H', datetime(timestamp, 'unixepoch')) as hour,
                COUNT(*) as packet_count,
                SUM(packet_size) as total_bytes
            FROM packets 
            WHERE timestamp > 0
            GROUP BY hour 
            ORDER BY hour
        ''')
        
        hourly_stats = []
        for row in cursor.fetchall():
            hour, count, bytes_total = row
            hourly_stats.append({
                'hour': int(hour),
                'packet_count': count,
                'total_bytes': bytes_total or 0
            })
        
        self.analysis_results['temporal_analysis'] = {
            'hourly_distribution': hourly_stats
        }
        
        conn.close()

    def _identify_service(self, port: int) -> str:
        """Identify service name for common ports"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3389: "RDP", 5900: "VNC", 1433: "MSSQL", 3306: "MySQL"
        }
        return services.get(port, f"Port {port}")

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP address is external (not RFC 1918)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private
        except:
            return False

    def generate_report(self, output_format: str = "json", output_file: str = None) -> str:
        """Generate analysis report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"traffic_analysis_{timestamp}.{output_format}"
        
        self.analysis_results['metadata']['end_time'] = datetime.now().isoformat()
        
        if output_format == "json":
            with open(output_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=2)
        
        elif output_format == "csv":
            # Export multiple CSV files for different data types
            base_name = output_file.replace('.csv', '')
            
            # Protocol stats
            with open(f"{base_name}_protocols.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Protocol', 'Packet Count', 'Total Bytes', 'Percentage'])
                for protocol, stats in self.analysis_results['protocol_stats'].items():
                    writer.writerow([protocol, stats['packet_count'], stats['total_bytes'], f"{stats['percentage']:.2f}%"])
            
            # Anomalies
            if self.analysis_results['anomalies']:
                with open(f"{base_name}_anomalies.csv", 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['type', 'severity', 'src_ip', 'dst_ip', 'description', 'timestamp'])
                    writer.writeheader()
                    writer.writerows(self.analysis_results['anomalies'])
        
        elif output_format == "txt":
            with open(output_file, 'w') as f:
                f.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                # Metadata
                f.write("ANALYSIS METADATA:\n")
                f.write("-" * 20 + "\n")
                for key, value in self.analysis_results['metadata'].items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
                
                # Protocol Statistics
                f.write("PROTOCOL DISTRIBUTION:\n")
                f.write("-" * 20 + "\n")
                for protocol, stats in self.analysis_results['protocol_stats'].items():
                    f.write(f"{protocol}: {stats['packet_count']} packets ({stats['percentage']:.1f}%)\n")
                f.write("\n")
                
                # Anomalies
                if self.analysis_results['anomalies']:
                    f.write("ANOMALIES DETECTED:\n")
                    f.write("-" * 20 + "\n")
                    for anomaly in self.analysis_results['anomalies']:
                        f.write(f"[{anomaly['severity']}] {anomaly['type']}: {anomaly['description']}\n")
                    f.write("\n")
        
        self.log(f"Report saved to: {output_file}")
        return output_file

    def cleanup(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception as e:
            self.log(f"Error cleaning up: {e}", "WARNING")

def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 traffic-analyzer.py capture.pcap
  python3 traffic-analyzer.py capture.pcap --analysis-type stats
  python3 traffic-analyzer.py capture.pcap --output json --file analysis.json
  python3 traffic-analyzer.py capture.pcap --full-analysis --verbose
        """
    )
    
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('--analysis-type', choices=['full', 'stats', 'anomalies', 'threats', 'bandwidth', 'temporal'], 
                       default='full', help='Type of analysis to perform')
    parser.add_argument('--output', choices=['json', 'csv', 'txt'], default='json', help='Output format')
    parser.add_argument('--file', help='Output file name')
    parser.add_argument('--full-analysis', action='store_true', help='Perform comprehensive analysis')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 2.1.0')
    
    args = parser.parse_args()
    
    if args.full_analysis:
        args.analysis_type = 'full'
    
    try:
        # Initialize analyzer
        analyzer = NetworkTrafficAnalyzer(verbose=args.verbose)
        
        # Perform analysis
        results = analyzer.analyze_pcap_file(args.pcap_file, args.analysis_type)
        
        # Generate report
        output_file = analyzer.generate_report(args.output, args.file)
        
        # Print summary
        print(f"\nAnalysis Complete!")
        print(f"PCAP File: {args.pcap_file}")
        print(f"Analysis Type: {args.analysis_type}")
        print(f"Total Packets: {results['metadata'].get('total_packets', 0)}")
        print(f"Protocols Found: {len(results.get('protocol_stats', {}))}")
        print(f"Anomalies Detected: {len(results.get('anomalies', []))}")
        print(f"Threats Identified: {len(results.get('threats', []))}")
        print(f"Report Saved: {output_file}")
        
        if results.get('anomalies'):
            print(f"\n⚠️  WARNING: {len(results['anomalies'])} anomalies detected!")
        
        if results.get('threats'):
            print(f"🚨 ALERT: {len(results['threats'])} potential threats identified!")
        
        # Cleanup
        analyzer.cleanup()
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()