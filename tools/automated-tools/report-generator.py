#!/usr/bin/env python3
"""
Network Security Report Generator
=================================

A comprehensive tool for generating professional security reports from network
traffic analysis results.

Features:
- Multiple output formats (PDF, HTML, Markdown, DOCX)
- Executive summaries for management
- Technical details for security teams
- Risk assessments and recommendations
- Evidence documentation
- Chart and graph generation
- Template-based reporting

Author: Network Security Team
License: MIT
Version: 2.1.0
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional
import subprocess
import tempfile
from pathlib import Path

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    print("Warning: jinja2 not available. Install with: pip install jinja2")
    JINJA2_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    import numpy as np
    PLOTTING_AVAILABLE = True
    plt.style.use('seaborn-v0_8')  # Professional plotting style
except ImportError:
    print("Warning: plotting libraries not available. Install with: pip install matplotlib seaborn pandas numpy")
    PLOTTING_AVAILABLE = False

try:
    import markdown
    import pdfkit
    CONVERSION_AVAILABLE = True
except ImportError:
    print("Warning: conversion libraries not available. Install with: pip install markdown pdfkit")
    CONVERSION_AVAILABLE = False

class SecurityReportGenerator:
    """Main class for generating security reports"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.report_data = {}
        self.template_dir = "reports/templates"
        self.output_dir = "reports/generated"
        self.charts_dir = tempfile.mkdtemp(prefix="report_charts_")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Risk severity mapping
        self.risk_levels = {
            'CRITICAL': {'color': '#d32f2f', 'score': 9},
            'HIGH': {'color': '#f57c00', 'score': 7},
            'MEDIUM': {'color': '#fbc02d', 'score': 5},
            'LOW': {'color': '#388e3c', 'score': 3},
            'INFO': {'color': '#1976d2', 'score': 1}
        }

    def log(self, message: str, level: str = "INFO"):
        """Logging function with timestamp"""
        if self.verbose or level in ['ERROR', 'WARNING']:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")

    def load_analysis_results(self, input_path: str):
        """Load analysis results from file or directory"""
        self.log(f"Loading analysis results from {input_path}")
        
        if os.path.isfile(input_path):
            # Single file
            if input_path.endswith('.json'):
                with open(input_path, 'r') as f:
                    self.report_data = json.load(f)
            else:
                raise ValueError("Unsupported file format. Use JSON files.")
        
        elif os.path.isdir(input_path):
            # Directory with multiple analysis files
            self.report_data = {
                'metadata': {},
                'credentials': [],
                'anomalies': [],
                'threats': [],
                'protocol_stats': {},
                'connection_stats': {},
                'bandwidth_analysis': {},
                'temporal_analysis': {}
            }
            
            # Load all JSON files in directory
            for filename in os.listdir(input_path):
                if filename.endswith('.json'):
                    filepath = os.path.join(input_path, filename)
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            self._merge_analysis_data(data, filename)
                    except Exception as e:
                        self.log(f"Error loading {filename}: {e}", "WARNING")
        
        else:
            raise FileNotFoundError(f"Input path not found: {input_path}")

    def _merge_analysis_data(self, data: Dict, filename: str):
        """Merge analysis data from multiple files"""
        # Merge metadata
        if 'metadata' in data:
            self.report_data['metadata'][filename] = data['metadata']
        
        # Merge credentials
        if 'credentials' in data:
            self.report_data['credentials'].extend(data['credentials'])
        
        # Merge anomalies
        if 'anomalies' in data:
            self.report_data['anomalies'].extend(data['anomalies'])
        
        # Merge threats
        if 'threats' in data:
            self.report_data['threats'].extend(data['threats'])
        
        # Merge protocol stats
        if 'protocol_stats' in data:
            for protocol, stats in data['protocol_stats'].items():
                if protocol in self.report_data['protocol_stats']:
                    # Combine stats
                    existing = self.report_data['protocol_stats'][protocol]
                    existing['packet_count'] = existing.get('packet_count', 0) + stats.get('packet_count', 0)
                    existing['total_bytes'] = existing.get('total_bytes', 0) + stats.get('total_bytes', 0)
                else:
                    self.report_data['protocol_stats'][protocol] = stats

    def generate_charts(self) -> List[str]:
        """Generate charts and visualizations"""
        if not PLOTTING_AVAILABLE:
            self.log("Plotting libraries not available. Skipping chart generation.", "WARNING")
            return []
        
        chart_files = []
        
        # Protocol distribution pie chart
        if self.report_data.get('protocol_stats'):
            chart_file = self._create_protocol_chart()
            if chart_file:
                chart_files.append(chart_file)
        
        # Risk assessment chart
        if self.report_data.get('anomalies') or self.report_data.get('threats'):
            chart_file = self._create_risk_chart()
            if chart_file:
                chart_files.append(chart_file)
        
        # Timeline chart
        if self.report_data.get('temporal_analysis'):
            chart_file = self._create_timeline_chart()
            if chart_file:
                chart_files.append(chart_file)
        
        # Bandwidth analysis chart
        if self.report_data.get('bandwidth_analysis'):
            chart_file = self._create_bandwidth_chart()
            if chart_file:
                chart_files.append(chart_file)
        
        return chart_files

    def _create_protocol_chart(self) -> Optional[str]:
        """Create protocol distribution pie chart"""
        try:
            protocols = list(self.report_data['protocol_stats'].keys())
            counts = [stats['packet_count'] for stats in self.report_data['protocol_stats'].values()]
            
            plt.figure(figsize=(10, 8))
            colors = plt.cm.Set3(np.linspace(0, 1, len(protocols)))
            
            wedges, texts, autotexts = plt.pie(counts, labels=protocols, autopct='%1.1f%%', 
                                             colors=colors, startangle=90)
            
            # Enhance text properties
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
            plt.title('Network Protocol Distribution', fontsize=16, fontweight='bold', pad=20)
            plt.axis('equal')
            
            chart_file = os.path.join(self.charts_dir, 'protocol_distribution.png')
            plt.savefig(chart_file, dpi=300, bbox_inches='tight', 
                       facecolor='white', edgecolor='none')
            plt.close()
            
            self.log(f"Generated protocol chart: {chart_file}")
            return chart_file
            
        except Exception as e:
            self.log(f"Error creating protocol chart: {e}", "ERROR")
            return None

    def _create_risk_chart(self) -> Optional[str]:
        """Create risk assessment chart"""
        try:
            # Combine anomalies and threats
            all_issues = []
            
            for anomaly in self.report_data.get('anomalies', []):
                all_issues.append({
                    'type': anomaly.get('type', 'Unknown'),
                    'severity': anomaly.get('severity', 'MEDIUM')
                })
            
            for threat in self.report_data.get('threats', []):
                all_issues.append({
                    'type': threat.get('type', 'Unknown'),
                    'severity': threat.get('severity', 'MEDIUM')
                })
            
            if not all_issues:
                return None
            
            # Count by severity
            severity_counts = {}
            for issue in all_issues:
                severity = issue['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Create bar chart
            plt.figure(figsize=(10, 6))
            severities = list(severity_counts.keys())
            counts = list(severity_counts.values())
            colors = [self.risk_levels.get(sev, {}).get('color', '#666666') for sev in severities]
            
            bars = plt.bar(severities, counts, color=colors, alpha=0.8, edgecolor='black', linewidth=1)
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                        str(count), ha='center', va='bottom', fontweight='bold')
            
            plt.title('Security Issues by Severity Level', fontsize=16, fontweight='bold', pad=20)
            plt.xlabel('Severity Level', fontsize=12)
            plt.ylabel('Number of Issues', fontsize=12)
            plt.grid(axis='y', alpha=0.3)
            
            chart_file = os.path.join(self.charts_dir, 'risk_assessment.png')
            plt.savefig(chart_file, dpi=300, bbox_inches='tight',
                       facecolor='white', edgecolor='none')
            plt.close()
            
            self.log(f"Generated risk chart: {chart_file}")
            return chart_file
            
        except Exception as e:
            self.log(f"Error creating risk chart: {e}", "ERROR")
            return None

    def _create_timeline_chart(self) -> Optional[str]:
        """Create timeline analysis chart"""
        try:
            temporal_data = self.report_data.get('temporal_analysis', {})
            hourly_data = temporal_data.get('hourly_distribution', [])
            
            if not hourly_data:
                return None
            
            hours = [data['hour'] for data in hourly_data]
            packet_counts = [data['packet_count'] for data in hourly_data]
            
            plt.figure(figsize=(12, 6))
            plt.plot(hours, packet_counts, marker='o', linewidth=2, markersize=6,
                    color='#1976d2', markerfacecolor='#ffffff', markeredgecolor='#1976d2')
            
            plt.title('Network Traffic by Hour of Day', fontsize=16, fontweight='bold', pad=20)
            plt.xlabel('Hour of Day', fontsize=12)
            plt.ylabel('Packet Count', fontsize=12)
            plt.grid(True, alpha=0.3)
            plt.xticks(range(0, 24))
            
            # Fill area under curve
            plt.fill_between(hours, packet_counts, alpha=0.3, color='#1976d2')
            
            chart_file = os.path.join(self.charts_dir, 'timeline_analysis.png')
            plt.savefig(chart_file, dpi=300, bbox_inches='tight',
                       facecolor='white', edgecolor='none')
            plt.close()
            
            self.log(f"Generated timeline chart: {chart_file}")
            return chart_file
            
        except Exception as e:
            self.log(f"Error creating timeline chart: {e}", "ERROR")
            return None

    def _create_bandwidth_chart(self) -> Optional[str]:
        """Create bandwidth analysis chart"""
        try:
            bandwidth_data = self.report_data.get('bandwidth_analysis', {})
            top_senders = bandwidth_data.get('top_senders', [])
            
            if not top_senders:
                return None
            
            # Limit to top 10 for readability
            top_senders = top_senders[:10]
            
            ips = [sender['ip'] for sender in top_senders]
            mb_sent = [sender['mb_sent'] for sender in top_senders]
            
            plt.figure(figsize=(12, 8))
            bars = plt.barh(ips, mb_sent, color='#ff7043', alpha=0.8, edgecolor='black')
            
            # Add value labels
            for bar, value in zip(bars, mb_sent):
                plt.text(bar.get_width() + max(mb_sent) * 0.01, bar.get_y() + bar.get_height()/2,
                        f'{value:.1f} MB', ha='left', va='center', fontweight='bold')
            
            plt.title('Top Bandwidth Consumers (Outbound Traffic)', fontsize=16, fontweight='bold', pad=20)
            plt.xlabel('Data Sent (MB)', fontsize=12)
            plt.ylabel('IP Address', fontsize=12)
            plt.grid(axis='x', alpha=0.3)
            plt.tight_layout()
            
            chart_file = os.path.join(self.charts_dir, 'bandwidth_analysis.png')
            plt.savefig(chart_file, dpi=300, bbox_inches='tight',
                       facecolor='white', edgecolor='none')
            plt.close()
            
            self.log(f"Generated bandwidth chart: {chart_file}")
            return chart_file
            
        except Exception as e:
            self.log(f"Error creating bandwidth chart: {e}", "ERROR")
            return None

    def generate_executive_summary(self) -> Dict:
        """Generate executive summary for management"""
        summary = {
            'key_findings': [],
            'risk_level': 'LOW',
            'critical_issues': 0,
            'high_issues': 0,
            'recommendations': []
        }
        
        # Count issues by severity
        all_issues = []
        all_issues.extend(self.report_data.get('anomalies', []))
        all_issues.extend(self.report_data.get('threats', []))
        all_issues.extend(self.report_data.get('credentials', []))
        
        for issue in all_issues:
            severity = issue.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                summary['critical_issues'] += 1
            elif severity == 'HIGH':
                summary['high_issues'] += 1
        
        # Determine overall risk level
        if summary['critical_issues'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['high_issues'] > 5:
            summary['risk_level'] = 'HIGH'
        elif summary['high_issues'] > 0:
            summary['risk_level'] = 'MEDIUM'
        
        # Generate key findings
        if self.report_data.get('credentials'):
            summary['key_findings'].append(
                f"Found {len(self.report_data['credentials'])} credential exposures in network traffic"
            )
        
        if self.report_data.get('anomalies'):
            anomaly_types = set(a.get('type', 'unknown') for a in self.report_data['anomalies'])
            summary['key_findings'].append(
                f"Detected {len(anomaly_types)} types of network anomalies across {len(self.report_data['anomalies'])} incidents"
            )
        
        if self.report_data.get('threats'):
            summary['key_findings'].append(
                f"Identified {len(self.report_data['threats'])} potential security threats"
            )
        
        # Generate recommendations
        if summary['critical_issues'] > 0:
            summary['recommendations'].append("Immediate action required for critical security issues")
        
        if self.report_data.get('credentials'):
            summary['recommendations'].append("Implement encryption for all credential transmissions")
            summary['recommendations'].append("Deploy network monitoring for credential exposure detection")
        
        if any(a.get('type') == 'port_scan' for a in self.report_data.get('anomalies', [])):
            summary['recommendations'].append("Implement intrusion detection systems to prevent reconnaissance")
        
        summary['recommendations'].append("Regular security assessments and penetration testing")
        summary['recommendations'].append("Staff security awareness training")
        
        return summary

    def generate_report(self, template_name: str = "security-assessment", 
                       output_format: str = "markdown", output_file: str = None) -> str:
        """Generate the main security report"""
        
        # Generate charts first
        chart_files = self.generate_charts()
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary()
        
        # Prepare report context
        context = {
            'report_data': self.report_data,
            'executive_summary': executive_summary,
            'chart_files': chart_files,
            'generation_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_issues': len(self.report_data.get('anomalies', [])) + 
                          len(self.report_data.get('threats', [])) + 
                          len(self.report_data.get('credentials', [])),
            'risk_levels': self.risk_levels
        }
        
        # Generate report content based on format
        if output_format == "markdown":
            content = self._generate_markdown_report(context)
            if not output_file:
                output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        elif output_format == "html":
            content = self._generate_html_report(context)
            if not output_file:
                output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        elif output_format == "pdf":
            # Generate markdown first, then convert to PDF
            markdown_content = self._generate_markdown_report(context)
            return self._convert_to_pdf(markdown_content, output_file)
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        # Write the report
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.log(f"Report generated: {output_path}")
        return output_path

    def _generate_markdown_report(self, context: Dict) -> str:
        """Generate Markdown report content"""
        
        md_content = f"""# Network Security Analysis Report

**Generated:** {context['generation_time']}  
**Overall Risk Level:** {context['executive_summary']['risk_level']}  
**Total Issues Found:** {context['total_issues']}

---

## Executive Summary

### Key Findings

"""
        
        for finding in context['executive_summary']['key_findings']:
            md_content += f"- {finding}\n"
        
        md_content += f"""
### Risk Assessment

- **Critical Issues:** {context['executive_summary']['critical_issues']}
- **High Priority Issues:** {context['executive_summary']['high_issues']}
- **Overall Risk Level:** {context['executive_summary']['risk_level']}

### Immediate Recommendations

"""
        
        for rec in context['executive_summary']['recommendations'][:5]:  # Top 5 recommendations
            md_content += f"1. {rec}\n"
        
        # Protocol Analysis
        if context['report_data'].get('protocol_stats'):
            md_content += "\n## Network Protocol Analysis\n\n"
            md_content += "| Protocol | Packet Count | Total Bytes | Percentage |\n"
            md_content += "|----------|-------------|-------------|------------|\n"
            
            for protocol, stats in context['report_data']['protocol_stats'].items():
                md_content += f"| {protocol} | {stats.get('packet_count', 0):,} | {stats.get('total_bytes', 0):,} | {stats.get('percentage', 0):.1f}% |\n"
        
        # Security Issues
        if context['report_data'].get('anomalies') or context['report_data'].get('threats'):
            md_content += "\n## Security Issues Detected\n\n"
            
            # Anomalies
            if context['report_data'].get('anomalies'):
                md_content += "### Network Anomalies\n\n"
                for anomaly in context['report_data']['anomalies']:
                    md_content += f"**{anomaly.get('severity', 'MEDIUM')} - {anomaly.get('type', 'Unknown')}**\n"
                    md_content += f"- Source: {anomaly.get('src_ip', 'N/A')}\n"
                    md_content += f"- Description: {anomaly.get('description', 'No description available')}\n"
                    md_content += f"- Timestamp: {anomaly.get('timestamp', 'N/A')}\n\n"
            
            # Threats
            if context['report_data'].get('threats'):
                md_content += "### Security Threats\n\n"
                for threat in context['report_data']['threats']:
                    md_content += f"**{threat.get('severity', 'MEDIUM')} - {threat.get('type', 'Unknown')}**\n"
                    md_content += f"- Source: {threat.get('src_ip', 'N/A')}\n"
                    md_content += f"- Target: {threat.get('dst_ip', 'N/A')}\n"
                    md_content += f"- Description: {threat.get('description', 'No description available')}\n"
                    md_content += f"- Timestamp: {threat.get('timestamp', 'N/A')}\n\n"
        
        # Credential Analysis
        if context['report_data'].get('credentials'):
            md_content += "\n## Credential Exposures\n\n"
            md_content += "⚠️ **WARNING: Credentials found in network traffic**\n\n"
            
            credential_types = {}
            for cred in context['report_data']['credentials']:
                cred_type = cred.get('type', 'unknown')
                credential_types[cred_type] = credential_types.get(cred_type, 0) + 1
            
            md_content += "### Credential Types Found\n\n"
            for cred_type, count in credential_types.items():
                md_content += f"- **{cred_type.title()}:** {count} instances\n"
            
            md_content += "\n### Sample Findings\n\n"
            for i, cred in enumerate(context['report_data']['credentials'][:5], 1):  # Show first 5
                md_content += f"**Finding #{i}**\n"
                md_content += f"- Protocol: {cred.get('protocol', 'N/A')}\n"
                md_content += f"- Type: {cred.get('type', 'N/A')}\n"
                md_content += f"- Source: {cred.get('source_ip', 'N/A')}\n"
                md_content += f"- Destination: {cred.get('destination_ip', 'N/A')}\n\n"
        
        # Detailed Recommendations
        md_content += "\n## Detailed Recommendations\n\n"
        for i, rec in enumerate(context['executive_summary']['recommendations'], 1):
            md_content += f"{i}. {rec}\n"
        
        # Technical Appendix
        md_content += "\n## Technical Appendix\n\n"
        
        if context['report_data'].get('metadata'):
            md_content += "### Analysis Metadata\n\n"
            for key, value in context['report_data']['metadata'].items():
                md_content += f"- **{key.replace('_', ' ').title()}:** {value}\n"
        
        md_content += "\n### Report Generation Details\n\n"
        md_content += f"- **Report Generated:** {context['generation_time']}\n"
        md_content += f"- **Analysis Tool Version:** 2.1.0\n"
        md_content += f"- **Charts Generated:** {len(context['chart_files'])}\n"
        
        return md_content

    def _generate_html_report(self, context: Dict) -> str:
        """Generate HTML report content"""
        # For now, convert markdown to HTML
        markdown_content = self._generate_markdown_report(context)
        
        if not CONVERSION_AVAILABLE:
            # Fallback: simple HTML wrapper
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #f39c12; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #27ae60; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
<pre>{markdown_content}</pre>
</body>
</html>
"""
        
        # Convert markdown to HTML
        html_content = markdown.markdown(markdown_content, extensions=['tables', 'codehilite'])
        
        # Wrap in full HTML document
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Analysis Report</title>
    <meta charset="utf-8">
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }}
        h1, h2, h3 {{ color: #2c3e50; }}
        h1 {{ border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #f39c12; font-weight: bold; }}
        .medium {{ color: #f1c40f; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        table {{ 
            border-collapse: collapse; 
            width: 100%; 
            margin: 15px 0; 
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        th, td {{ 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }}
        th {{ 
            background-color: #34495e; 
            color: white; 
            font-weight: bold;
        }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .summary-box {{
            background-color: #ecf0f1;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
        }}
        .warning-box {{
            background-color: #fdf2e9;
            border-left: 4px solid #e67e22;
            padding: 20px;
            margin: 20px 0;
        }}
        .critical-box {{
            background-color: #fadbd8;
            border-left: 4px solid #e74c3c;
            padding: 20px;
            margin: 20px 0;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""

    def _convert_to_pdf(self, markdown_content: str, output_file: str = None) -> str:
        """Convert markdown content to PDF"""
        if not CONVERSION_AVAILABLE:
            raise RuntimeError("PDF conversion libraries not available. Install with: pip install pdfkit wkhtmltopdf")
        
        if not output_file:
            output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Convert markdown to HTML first
        html_content = markdown.markdown(markdown_content, extensions=['tables', 'codehilite'])
        
        # Wrap in styled HTML
        styled_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Network Security Analysis Report</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0; 
            padding: 20px;
        }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; }}
        h3 {{ color: #34495e; }}
        table {{ 
            border-collapse: collapse; 
            width: 100%; 
            margin: 15px 0;
        }}
        th, td {{ 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left; 
        }}
        th {{ 
            background-color: #34495e; 
            color: white; 
            font-weight: bold;
        }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .page-break {{ page-break-before: always; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""
        
        # PDF options
        options = {
            'page-size': 'A4',
            'margin-top': '1in',
            'margin-right': '1in',
            'margin-bottom': '1in',
            'margin-left': '1in',
            'encoding': 'UTF-8',
            'no-outline': None,
            'enable-local-file-access': None
        }
        
        try:
            output_path = os.path.join(self.output_dir, output_file)
            pdfkit.from_string(styled_html, output_path, options=options)
            self.log(f"PDF report generated: {output_path}")
            return output_path
        except Exception as e:
            self.log(f"Error generating PDF: {e}", "ERROR")
            # Fallback: save as HTML
            html_file = output_file.replace('.pdf', '.html')
            output_path = os.path.join(self.output_dir, html_file)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(styled_html)
            self.log(f"Fallback: HTML report saved as {output_path}")
            return output_path

    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            if os.path.exists(self.charts_dir):
                shutil.rmtree(self.charts_dir)
        except Exception as e:
            self.log(f"Error cleaning up: {e}", "WARNING")

def main():
    parser = argparse.ArgumentParser(
        description="Network Security Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 report-generator.py --input analysis_results.json
  python3 report-generator.py --input results/ --format pdf
  python3 report-generator.py --input results/ --template incident-response --output incident_report.html
  python3 report-generator.py --input analysis.json --formats markdown,pdf,html
        """
    )
    
    parser.add_argument('--input', required=True, help='Input file or directory with analysis results')
    parser.add_argument('--format', choices=['markdown', 'html', 'pdf'], default='markdown', 
                       help='Output format')
    parser.add_argument('--formats', help='Multiple output formats (comma-separated)')
    parser.add_argument('--template', default='security-assessment', 
                       help='Report template to use')
    parser.add_argument('--output', help='Output file name')
    parser.add_argument('--output-dir', default='reports/generated', 
                       help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 2.1.0')
    
    args = parser.parse_args()
    
    try:
        # Initialize generator
        generator = SecurityReportGenerator(verbose=args.verbose)
        generator.output_dir = args.output_dir
        
        # Load analysis results
        generator.load_analysis_results(args.input)
        
        # Generate reports
        output_files = []
        
        if args.formats:
            # Multiple formats
            formats = [fmt.strip() for fmt in args.formats.split(',')]
            for fmt in formats:
                if fmt in ['markdown', 'html', 'pdf']:
                    base_name = args.output or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    if '.' in base_name:
                        base_name = os.path.splitext(base_name)[0]
                    
                    output_file = f"{base_name}.{fmt}"
                    result_file = generator.generate_report(args.template, fmt, output_file)
                    output_files.append(result_file)
        else:
            # Single format
            result_file = generator.generate_report(args.template, args.format, args.output)
            output_files.append(result_file)
        
        # Print summary
        print(f"\nReport Generation Complete!")
        print(f"Input: {args.input}")
        print(f"Template: {args.template}")
        print(f"Generated {len(output_files)} report(s):")
        
        for file_path in output_files:
            print(f"  - {file_path}")
        
        # Cleanup
        generator.cleanup()
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()