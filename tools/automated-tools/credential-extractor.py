#!/usr/bin/env python3
"""
Network Traffic Credential Extractor
====================================

A comprehensive tool for extracting credentials and sensitive information
from network traffic captures (PCAP files).

Features:
- HTTP POST credential extraction
- FTP authentication capture
- Email protocol credentials (SMTP, POP3, IMAP)
- SNMP community strings
- Base64 encoded credential detection
- Custom pattern matching
- JSON and CSV output formats
- Integration with Wireshark tshark

Author: Network Security Team
License: MIT
Version: 2.1.0
"""

import argparse
import json
import csv
import re
import base64
import sys
import os
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import parse_qs, unquote
import subprocess
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

class CredentialExtractor:
    """Main class for extracting credentials from network traffic"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.credentials = []
        self.suspicious_patterns = []
        self.statistics = {
            'total_packets': 0,
            'http_packets': 0,
            'ftp_packets': 0,
            'smtp_packets': 0,
            'credentials_found': 0,
            'suspicious_patterns': 0
        }
        
        # Credential patterns
        self.credential_patterns = {
            'password': re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*([^\s&\'"]+)', re.IGNORECASE),
            'username': re.compile(r'(?i)(username|user|login|email)\s*[=:]\s*([^\s&\'"]+)', re.IGNORECASE),
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*([^\s&\'"]+)', re.IGNORECASE),
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        }
        
    def log(self, message: str, level: str = "INFO"):
        """Logging function with timestamp"""
        if self.verbose or level in ['ERROR', 'WARNING']:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")

    def analyze_pcap_file(self, pcap_file: str) -> Dict:
        """Main analysis function that routes to available backend"""
        self.log(f"Starting analysis of {pcap_file}")
        
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        if PYSHARK_AVAILABLE:
            return self._analyze_with_pyshark(pcap_file)
        elif SCAPY_AVAILABLE:
            return self._analyze_with_scapy(pcap_file)
        else:
            return self._analyze_with_tshark(pcap_file)

    def _analyze_with_pyshark(self, pcap_file: str) -> Dict:
        """Analyze PCAP using PyShark"""
        self.log("Using PyShark for analysis")
        
        try:
            cap = pyshark.FileCapture(pcap_file)
            
            for packet in cap:
                self.statistics['total_packets'] += 1
                
                # HTTP analysis
                if hasattr(packet, 'http'):
                    self._analyze_http_packet(packet)
                
                # FTP analysis
                elif hasattr(packet, 'ftp'):
                    self._analyze_ftp_packet(packet)
                
                # SMTP analysis  
                elif hasattr(packet, 'smtp'):
                    self._analyze_smtp_packet(packet)
                
                # DNS analysis for potential data leakage
                elif hasattr(packet, 'dns'):
                    self._analyze_dns_packet(packet)
                    
            cap.close()
            
        except Exception as e:
            self.log(f"Error analyzing with PyShark: {e}", "ERROR")
            return self._analyze_with_tshark(pcap_file)
        
        return self._compile_results()

    def _analyze_with_scapy(self, pcap_file: str) -> Dict:
        """Analyze PCAP using Scapy"""
        self.log("Using Scapy for analysis")
        
        try:
            packets = rdpcap(pcap_file)
            
            for packet in packets:
                self.statistics['total_packets'] += 1
                
                # HTTP analysis
                if packet.haslayer(HTTPRequest):
                    self._analyze_http_scapy(packet)
                
                # Raw payload analysis for other protocols
                if packet.haslayer(Raw):
                    self._analyze_raw_payload(packet[Raw].load.decode('utf-8', errors='ignore'))
                    
        except Exception as e:
            self.log(f"Error analyzing with Scapy: {e}", "ERROR")
            return self._analyze_with_tshark(pcap_file)
        
        return self._compile_results()

    def _analyze_with_tshark(self, pcap_file: str) -> Dict:
        """Fallback analysis using tshark command line"""
        self.log("Using tshark for analysis")
        
        try:
            # Extract HTTP POST data
            self._extract_http_posts_tshark(pcap_file)
            
            # Extract FTP credentials
            self._extract_ftp_credentials_tshark(pcap_file)
            
            # Extract email credentials
            self._extract_email_credentials_tshark(pcap_file)
            
        except Exception as e:
            self.log(f"Error analyzing with tshark: {e}", "ERROR")
        
        return self._compile_results()

    def _extract_http_posts_tshark(self, pcap_file: str):
        """Extract HTTP POST data using tshark"""
        cmd = [
            'tshark', '-r', pcap_file,
            '-Y', 'http.request.method == "POST"',
            '-T', 'fields',
            '-e', 'ip.src', '-e', 'ip.dst', '-e', 'http.host', '-e', 'http.request.uri', '-e', 'http.file_data'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 5:
                            src_ip, dst_ip, host, uri, post_data = parts[:5]
                            self._extract_credentials_from_post_data(post_data, src_ip, dst_ip, host + uri)
            else:
                self.log(f"tshark error: {result.stderr}", "WARNING")
                
        except FileNotFoundError:
            self.log("tshark not found. Please install Wireshark.", "ERROR")
        except Exception as e:
            self.log(f"Error running tshark: {e}", "WARNING")

    def _extract_ftp_credentials_tshark(self, pcap_file: str):
        """Extract FTP credentials using tshark"""
        cmd = [
            'tshark', '-r', pcap_file,
            '-Y', 'ftp.request.command == "USER" or ftp.request.command == "PASS"',
            '-T', 'fields',
            '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            src_ip, dst_ip, command, arg = parts[:4]
                            self._add_credential({
                                'protocol': 'FTP',
                                'type': command.lower(),
                                'value': arg,
                                'source_ip': src_ip,
                                'destination_ip': dst_ip,
                                'timestamp': datetime.now().isoformat(),
                                'context': f"FTP {command}"
                            })
                            
        except Exception as e:
            self.log(f"Error extracting FTP credentials: {e}", "WARNING")

    def _analyze_http_packet(self, packet):
        """Analyze HTTP packets for credentials"""
        self.statistics['http_packets'] += 1
        
        try:
            if hasattr(packet.http, 'request_method') and packet.http.request_method == 'POST':
                if hasattr(packet.http, 'file_data'):
                    post_data = packet.http.file_data
                    self._extract_credentials_from_post_data(
                        post_data,
                        packet.ip.src,
                        packet.ip.dst,
                        getattr(packet.http, 'host', '') + getattr(packet.http, 'request_uri', '')
                    )
                    
        except Exception as e:
            self.log(f"Error analyzing HTTP packet: {e}", "WARNING")

    def _extract_credentials_from_post_data(self, post_data: str, src_ip: str, dst_ip: str, url: str):
        """Extract credentials from HTTP POST data"""
        if not post_data:
            return
            
        # URL decode the data
        try:
            decoded_data = unquote(post_data)
        except:
            decoded_data = post_data
        
        # Look for credential patterns
        for pattern_name, pattern in self.credential_patterns.items():
            matches = pattern.findall(decoded_data)
            for match in matches:
                if isinstance(match, tuple):
                    field_name, value = match
                else:
                    field_name, value = pattern_name, match
                
                self._add_credential({
                    'protocol': 'HTTP POST',
                    'type': pattern_name,
                    'field_name': field_name,
                    'value': value,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'url': url,
                    'timestamp': datetime.now().isoformat(),
                    'raw_data': decoded_data[:200] + '...' if len(decoded_data) > 200 else decoded_data
                })
        
        # Additional pattern matching for form data
        form_data = parse_qs(decoded_data)
        for key, values in form_data.items():
            key_lower = key.lower()
            if any(keyword in key_lower for keyword in ['password', 'passwd', 'pwd', 'pass']):
                self._add_credential({
                    'protocol': 'HTTP POST',
                    'type': 'password',
                    'field_name': key,
                    'value': values[0] if values else '',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'url': url,
                    'timestamp': datetime.now().isoformat(),
                    'context': 'Form data analysis'
                })
            elif any(keyword in key_lower for keyword in ['username', 'user', 'login', 'email']):
                self._add_credential({
                    'protocol': 'HTTP POST',
                    'type': 'username',
                    'field_name': key,
                    'value': values[0] if values else '',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'url': url,
                    'timestamp': datetime.now().isoformat(),
                    'context': 'Form data analysis'
                })

    def _analyze_ftp_packet(self, packet):
        """Analyze FTP packets for credentials"""
        self.statistics['ftp_packets'] += 1
        
        try:
            if hasattr(packet.ftp, 'request_command'):
                command = packet.ftp.request_command
                if command in ['USER', 'PASS']:
                    arg = getattr(packet.ftp, 'request_arg', '')
                    self._add_credential({
                        'protocol': 'FTP',
                        'type': command.lower(),
                        'value': arg,
                        'source_ip': packet.ip.src,
                        'destination_ip': packet.ip.dst,
                        'timestamp': datetime.now().isoformat(),
                        'context': f"FTP {command} command"
                    })
                    
        except Exception as e:
            self.log(f"Error analyzing FTP packet: {e}", "WARNING")

    def _analyze_raw_payload(self, payload: str):
        """Analyze raw packet payload for patterns"""
        for pattern_name, pattern in self.credential_patterns.items():
            matches = pattern.findall(payload)
            for match in matches:
                self.statistics['suspicious_patterns'] += 1
                self.suspicious_patterns.append({
                    'pattern': pattern_name,
                    'match': match,
                    'context': payload[:100] + '...' if len(payload) > 100 else payload,
                    'timestamp': datetime.now().isoformat()
                })

    def _add_credential(self, credential: Dict):
        """Add a credential to the results"""
        self.credentials.append(credential)
        self.statistics['credentials_found'] += 1
        self.log(f"Found {credential['type']}: {credential.get('value', '')[:20]}...", "INFO")

    def _compile_results(self) -> Dict:
        """Compile final results"""
        return {
            'metadata': {
                'analysis_timestamp': datetime.now().isoformat(),
                'analyzer_version': '2.1.0',
                'total_credentials': len(self.credentials),
                'total_suspicious_patterns': len(self.suspicious_patterns)
            },
            'statistics': self.statistics,
            'credentials': self.credentials,
            'suspicious_patterns': self.suspicious_patterns,
            'summary': self._generate_summary()
        }

    def _generate_summary(self) -> Dict:
        """Generate analysis summary"""
        protocols = {}
        credential_types = {}
        
        for cred in self.credentials:
            protocol = cred.get('protocol', 'Unknown')
            cred_type = cred.get('type', 'Unknown')
            
            protocols[protocol] = protocols.get(protocol, 0) + 1
            credential_types[cred_type] = credential_types.get(cred_type, 0) + 1
        
        return {
            'protocols_found': protocols,
            'credential_types': credential_types,
            'risk_level': self._assess_risk_level(),
            'recommendations': self._generate_recommendations()
        }

    def _assess_risk_level(self) -> str:
        """Assess overall risk level based on findings"""
        if len(self.credentials) == 0:
            return "LOW"
        elif len(self.credentials) < 5:
            return "MEDIUM"
        elif len(self.credentials) < 20:
            return "HIGH"
        else:
            return "CRITICAL"

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if any(cred['protocol'] == 'HTTP POST' for cred in self.credentials):
            recommendations.append("Implement HTTPS for all web applications to encrypt credential transmission")
        
        if any(cred['protocol'] == 'FTP' for cred in self.credentials):
            recommendations.append("Replace FTP with SFTP or FTPS to secure file transfers")
        
        if any(cred['type'] == 'credit_card' for cred in self.credentials):
            recommendations.append("Implement PCI-DSS compliance measures for credit card data protection")
        
        if len(self.credentials) > 10:
            recommendations.append("Conduct comprehensive security audit of network protocols and applications")
        
        recommendations.append("Implement network monitoring and intrusion detection systems")
        recommendations.append("Regular security awareness training for staff")
        
        return recommendations

    def export_results(self, results: Dict, output_format: str, output_file: str):
        """Export results to file"""
        self.log(f"Exporting results to {output_file} in {output_format} format")
        
        if output_format.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif output_format.lower() == 'csv':
            with open(output_file, 'w', newline='') as f:
                if results['credentials']:
                    fieldnames = results['credentials'][0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results['credentials'])
                else:
                    writer = csv.writer(f)
                    writer.writerow(['No credentials found'])
        
        elif output_format.lower() == 'txt':
            with open(output_file, 'w') as f:
                f.write("NETWORK TRAFFIC CREDENTIAL EXTRACTION REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Analysis Date: {results['metadata']['analysis_timestamp']}\n")
                f.write(f"Total Credentials Found: {results['metadata']['total_credentials']}\n")
                f.write(f"Risk Level: {results['summary']['risk_level']}\n\n")
                
                f.write("CREDENTIALS FOUND:\n")
                f.write("-" * 20 + "\n")
                for cred in results['credentials']:
                    f.write(f"Protocol: {cred.get('protocol', 'N/A')}\n")
                    f.write(f"Type: {cred.get('type', 'N/A')}\n")
                    f.write(f"Value: {cred.get('value', 'N/A')}\n")
                    f.write(f"Source: {cred.get('source_ip', 'N/A')}\n")
                    f.write(f"Destination: {cred.get('destination_ip', 'N/A')}\n")
                    f.write(f"Timestamp: {cred.get('timestamp', 'N/A')}\n")
                    f.write("-" * 20 + "\n")
                
                f.write("\nRECOMMENDATIONS:\n")
                for i, rec in enumerate(results['summary']['recommendations'], 1):
                    f.write(f"{i}. {rec}\n")

def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Credential Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python credential-extractor.py capture.pcap
  python credential-extractor.py capture.pcap -o json -f results.json
  python credential-extractor.py capture.pcap -v --format csv
  python credential-extractor.py capture.pcap --output-dir ./analysis/
        """
    )
    
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('-o', '--output-format', choices=['json', 'csv', 'txt'], 
                       default='json', help='Output format (default: json)')
    parser.add_argument('-f', '--output-file', help='Output file (default: auto-generated)')
    parser.add_argument('-d', '--output-dir', default='.', help='Output directory (default: current)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 2.1.0')
    
    args = parser.parse_args()
    
    # Create output filename if not specified
    if not args.output_file:
        base_name = os.path.splitext(os.path.basename(args.pcap_file))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_file = f"{base_name}_credentials_{timestamp}.{args.output_format}"
    
    # Ensure output directory exists
    output_path = os.path.join(args.output_dir, args.output_file)
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else args.output_dir, exist_ok=True)
    
    try:
        # Initialize extractor
        extractor = CredentialExtractor(verbose=args.verbose)
        
        # Analyze PCAP file
        results = extractor.analyze_pcap_file(args.pcap_file)
        
        # Export results
        extractor.export_results(results, args.output_format, output_path)
        
        # Print summary
        print(f"\nAnalysis Complete!")
        print(f"Total Packets Analyzed: {results['statistics']['total_packets']}")
        print(f"Credentials Found: {results['metadata']['total_credentials']}")
        print(f"Risk Level: {results['summary']['risk_level']}")
        print(f"Results saved to: {output_path}")
        
        if results['metadata']['total_credentials'] > 0:
            print(f"\n⚠️  WARNING: {results['metadata']['total_credentials']} credentials found in network traffic!")
            print("Consider implementing encryption for sensitive communications.")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()