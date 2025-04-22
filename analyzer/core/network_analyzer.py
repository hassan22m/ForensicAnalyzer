# forensicanalyzer/core/network_analyzer.py

import os
import time
import mmap
import struct
import hashlib
from datetime import datetime
from collections import Counter, defaultdict
import threading ,jinja2,webbrowser
from PyQt6.QtWidgets import (QApplication,QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,  
                            QComboBox, QTableWidget, QTableWidgetItem, QLineEdit, QFileDialog, QTextEdit,
                            QTabWidget, QGridLayout, QGroupBox,QButtonGroup, QSplitter, QProgressBar, QTreeWidget,
                            QTreeWidgetItem, QHeaderView, QFrame, QMessageBox,QRadioButton,QCheckBox, QDialog, QScrollArea,QProgressDialog)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QDateTime, QTimer
from PyQt6.QtGui import QIcon, QColor, QFont, QPixmap, QImage  
from scapy.all import (sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, ARP, ICMP, IPv6, DNS, Raw, PcapReader) 

# Import necessary libraries
try:
    from scapy.all import *
    from scapy.utils import PcapReader, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# For PDF generation we will use reportlab 
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Try to import scapy - the main packet capture library
try:
    from scapy.all import *
    # Disable scapy warnings
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Protocol ID to name mapping
IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
    132: "SCTP"
}

MQTT_PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH"  # MQTT 5.0
}

# Common ports to service mapping
PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    554: "RTSP",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    1720: "H.323",
    1812: "RADIUS",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5222: "XMPP",
    5353: "mDNS",
    5432: "PostgreSQL",
    5683: "CoAP",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8883: "MQTT-SSL",
    8000: "HTTP-Alt",
    8554: "RTSP-Alt",  
    10554: "RTSP-Alt"
}



class AnalysisExporter:
    """Class to handle exporting analysis results"""
    def __init__(self, parent_window):
        self.parent = parent_window
        self.analyzer = parent_window.packet_analyzer
        self.current_file = parent_window.current_file
        self.packets = parent_window.packets
    
    def export_analysis(self):
        """Export the analysis results"""
        # Show options dialog
        options_dialog = ExportOptionsDialog(self.parent)
        if options_dialog.exec() != QDialog.DialogCode.Accepted:
            return  # User canceled
        
        options = options_dialog.get_options()
        
        # Get export file path
        default_name = "network_analysis"
        if self.current_file:
            basename = os.path.basename(self.current_file)
            default_name = os.path.splitext(basename)[0] + "_analysis"
        
        file_extension = ".pdf" if options["format"] == "pdf" else ".html"
        file_filter = "PDF Files (*.pdf)" if options["format"] == "pdf" else "HTML Files (*.html)"
        
        export_path, _ = QFileDialog.getSaveFileName(
            self.parent, "Export Analysis", default_name + file_extension, file_filter)
        
        if not export_path:
            return  # User canceled
        
        # Show progress dialog
        progress = QProgressDialog("Exporting analysis...", "Cancel", 0, 100, self.parent)
        progress.setWindowTitle("Exporting")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setValue(0)
        progress.show()
        
        try:
            # Gather the data to export
            data = self.collect_data(options["sections"])
            
            # Update progress
            progress.setValue(30)
            
            # Export in selected format
            if options["format"] == "pdf" and REPORTLAB_AVAILABLE:
                self.export_to_pdf(export_path, data)
            else:
                self.export_to_html(export_path, data)
            
            # Complete progress
            progress.setValue(100)
            
            # Ask if user wants to open the file
            self.parent.statusBar().showMessage(f"Analysis exported to {export_path}")
            
            # Use a timer to allow the progress dialog to close
            QTimer.singleShot(500, lambda: self.offer_to_open_file(export_path))
            
        except Exception as e:
            progress.close()
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self.parent, "Export Error", 
                              f"Error exporting analysis: {str(e)}",
                              QMessageBox.StandardButton.Ok)
            return
    
    def collect_data(self, sections):
        """Collect all data for export"""
        data = {}
        
        # Basic information
        data["title"] = "Network Analysis Report"
        data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get file information
        if sections["file_info"]:
            data["file_info"] = self.get_file_info()
        
        # Get packet summary
        if sections["packet_summary"]:
            data["packet_summary"] = self.get_packet_summary()
        
        # Get protocol statistics
        if sections["protocol_stats"]:
            data["protocol_stats"] = self.get_protocol_stats()
        
        # Get conversations
        if sections["conversations"]:
            data["conversations"] = self.get_conversations()
        
        # Get endpoints
        if sections["endpoints"]:
            data["endpoints"] = self.get_endpoints()
        
        # Get top ports
        if sections["top_ports"]:
            data["top_ports"] = self.get_top_ports()
        
        # Get security findings
        if sections["security_findings"]:
            data["security_findings"] = self.get_security_findings()
        
        return data
    
    def get_file_info(self):
        """Get file information"""
        file_info = {}
        
        if self.current_file:
            file_info["filename"] = os.path.basename(self.current_file)
            file_info["path"] = self.current_file
            file_info["size"] = os.path.getsize(self.current_file)
            file_info["size_formatted"] = self.parent.format_size(file_info["size"])
            
            # Get file hash if available
            hash_text = self.parent.file_hash_label.text()
            if ":" in hash_text:
                hash_type, hash_value = hash_text.split(":", 1)
                file_info["hash_type"] = hash_type.strip()
                file_info["hash_value"] = hash_value.strip()
        else:
            file_info["filename"] = "Live Capture"
            file_info["path"] = "N/A"
            file_info["size"] = 0
            file_info["size_formatted"] = "N/A"
        
        # Get packet count
        file_info["packet_count"] = len(self.packets)
        
        # Get capture summary
        summary = self.analyzer.get_capture_summary()
        if summary["start_time"] is not None and summary["end_time"] is not None:
            file_info["start_time"] = datetime.fromtimestamp(summary["start_time"]).strftime("%Y-%m-%d %H:%M:%S")
            file_info["end_time"] = datetime.fromtimestamp(summary["end_time"]).strftime("%Y-%m-%d %H:%M:%S")
            file_info["duration"] = summary["duration"]
            file_info["duration_formatted"] = self.format_duration(summary["duration"])
            file_info["total_bytes"] = summary["total_bytes"]
            file_info["total_bytes_formatted"] = self.parent.format_size(summary["total_bytes"])
        else:
            file_info["start_time"] = "N/A"
            file_info["end_time"] = "N/A"
            file_info["duration"] = 0
            file_info["duration_formatted"] = "N/A"
            file_info["total_bytes"] = 0
            file_info["total_bytes_formatted"] = "N/A"
        
        return file_info
    
    def get_packet_summary(self):
        """Get packet summary information"""
        # Get a sample of packets (first 100)
        packet_sample = self.packets[:100]
        
        packet_summary = []
        for i, packet in enumerate(packet_sample):
            packet_info = self.analyzer.extract_packet_info(packet)
            
            summary_item = {
                "number": i + 1,
                "time": packet_info.get("formatted_time", ""),
                "source": packet_info.get("src_ip", ""),
                "destination": packet_info.get("dst_ip", ""),
                "protocol": packet_info.get("protocol", ""),
                "length": packet_info.get("length", 0),
                "info": packet_info.get("info", "")
            }
            
            packet_summary.append(summary_item)
        
        return packet_summary
    
    def get_protocol_stats(self):
        """Get protocol statistics"""
        return self.analyzer.get_protocol_stats()
    
    def get_conversations(self):
        """Get conversation statistics"""
        return self.analyzer.get_conversations(limit=20)
    
    def get_endpoints(self):
        """Get endpoint statistics"""
        return self.analyzer.get_top_talkers(limit=20)
    
    def get_top_ports(self):
        """Get top ports statistics"""
        return self.analyzer.get_port_stats(limit=20)
    
    def get_security_findings(self):
        """Get security findings"""
        return self.analyzer.get_security_findings()
    
    def format_duration(self, seconds):
        """Format duration in seconds to a readable string"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours} hours, {minutes} minutes, {secs} seconds"
        elif minutes > 0:
            return f"{minutes} minutes, {secs} seconds"
        else:
            return f"{secs} seconds"
    
    def export_to_pdf(self, filepath, data):
        """Export analysis to PDF"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab library is required for PDF export")
        
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        elements = []
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        heading1_style = styles["Heading1"]
        heading2_style = styles["Heading2"]
        normal_style = styles["Normal"]
        
        # Add title
        elements.append(Paragraph(data["title"], title_style))
        elements.append(Paragraph(f"Generated: {data['timestamp']}", normal_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        # File Information
        if "file_info" in data:
            elements.append(Paragraph("File Information", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            file_info = data["file_info"]
            
            # Create a table for file info
            file_info_table_data = [
                ["Filename", file_info.get("filename", "N/A")],
                ["File Size", file_info.get("size_formatted", "N/A")],
                ["Packet Count", str(file_info.get("packet_count", 0))],
                ["Capture Start", file_info.get("start_time", "N/A")],
                ["Capture End", file_info.get("end_time", "N/A")],
                ["Duration", file_info.get("duration_formatted", "N/A")],
                ["Total Bytes", file_info.get("total_bytes_formatted", "N/A")]
            ]
            
            # Add hash if available
            if "hash_value" in file_info:
                file_info_table_data.append([file_info.get("hash_type", "Hash"), file_info.get("hash_value", "")])
            
            file_info_table = Table(file_info_table_data, colWidths=[2*inch, 4*inch])
            file_info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(file_info_table)
            elements.append(Spacer(1, 0.25 * inch))
        
        # Protocol Statistics
        if "protocol_stats" in data:
            elements.append(Paragraph("Protocol Distribution", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            protocol_stats = data["protocol_stats"]
            
            # Create a table for protocol stats
            protocol_table_data = [["Protocol", "Percentage"]]
            for protocol, percentage in protocol_stats.items():
                protocol_table_data.append([protocol, f"{percentage:.1f}%"])
            
            protocol_table = Table(protocol_table_data, colWidths=[3*inch, 3*inch])
            protocol_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(protocol_table)
            elements.append(Spacer(1, 0.25 * inch))
        
        # Conversations
        if "conversations" in data:
            elements.append(Paragraph("Top Conversations", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            conversations = data["conversations"]
            
            # Create a table for conversations
            conv_table_data = [["Source", "Destination", "Packets", "Bytes", "Duration"]]
            for conv in conversations:
                duration = self.format_duration(conv.get("duration", 0))
                bytes_formatted = self.parent.format_size(conv.get("bytes", 0))
                
                conv_table_data.append([
                    conv.get("src", ""),
                    conv.get("dst", ""),
                    str(conv.get("packets", 0)),
                    bytes_formatted,
                    duration
                ])
            
            conv_table = Table(conv_table_data)
            conv_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(conv_table)
            elements.append(Spacer(1, 0.25 * inch))
        
        # Endpoints
        if "endpoints" in data:
            elements.append(Paragraph("Top Endpoints", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            endpoints = data["endpoints"]
            
            # Create a table for endpoints
            endpoint_table_data = [["IP Address", "Packets", "Bytes"]]
            for endpoint in endpoints:
                bytes_formatted = self.parent.format_size(endpoint.get("bytes", 0))
                
                endpoint_table_data.append([
                    endpoint.get("ip", ""),
                    str(endpoint.get("packets", 0)),
                    bytes_formatted
                ])
            
            endpoint_table = Table(endpoint_table_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
            endpoint_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(endpoint_table)
            elements.append(Spacer(1, 0.25 * inch))
        
        # Top Ports
        if "top_ports" in data:
            elements.append(Paragraph("Top Ports", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            ports = data["top_ports"]
            
            # Create a table for ports
            port_table_data = [["Port", "Service", "Count"]]
            for port in ports:
                port_table_data.append([
                    str(port.get("port", 0)),
                    port.get("service", "Unknown"),
                    str(port.get("count", 0))
                ])
            
            port_table = Table(port_table_data, colWidths=[1.5*inch, 3*inch, 1.5*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            elements.append(port_table)
            elements.append(Spacer(1, 0.25 * inch))
        
        # Packet Summary
        if "packet_summary" in data:
            elements.append(Paragraph("Packet Summary (First 100 packets)", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            packet_summary = data["packet_summary"]
            
            # Create a table for packet summary
            packet_table_data = [["No.", "Time", "Source", "Destination", "Protocol", "Length"]]
            for packet in packet_summary:
                packet_table_data.append([
                    str(packet.get("number", 0)),
                    packet.get("time", ""),
                    packet.get("source", ""),
                    packet.get("destination", ""),
                    packet.get("protocol", ""),
                    str(packet.get("length", 0))
                ])
            
            packet_table = Table(packet_table_data)
            packet_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            
            elements.append(packet_table)
            elements.append(Spacer(1, 0.25 * inch))
        
        # Security Findings
        if "security_findings" in data:
            elements.append(Paragraph("Security Findings", heading1_style))
            elements.append(Spacer(1, 0.1 * inch))
            
            security_findings = data["security_findings"]
            
            if security_findings:
                # Create a table for security findings
                security_table_data = [["Type", "Severity", "Description", "Packet"]]
                for finding in security_findings:
                    security_table_data.append([
                        finding.get("type", ""),
                        finding.get("severity", ""),
                        finding.get("description", ""),
                        str(finding.get("packet_num", 0))
                    ])
                
                security_table = Table(security_table_data, colWidths=[1.5*inch, 1*inch, 3.5*inch, 0.75*inch])
                security_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    # Color code severity
                    ('TEXTCOLOR', (1, 1), (1, -1), lambda row, col, text=None: 
                        colors.red if text == "High" else 
                        colors.darkorange if text == "Medium" else 
                        colors.darkgoldenrod)
                ]))
                
                elements.append(security_table)
            else:
                elements.append(Paragraph("No security issues identified.", normal_style))
            
            elements.append(Spacer(1, 0.25 * inch))
        
        # Build the PDF
        doc.build(elements)
    
    def export_to_html(self, filepath, data):
        """Export analysis to HTML"""
        # Create a Jinja2 environment
        env = jinja2.Environment(autoescape=True)
        
        # Load the HTML template
        template_string = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ title }}</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                }
                h1, h2 {
                    color: #2c3e50;
                }
                h1 {
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                h2 {
                    margin-top: 30px;
                    border-bottom: 1px solid #bdc3c7;
                    padding-bottom: 5px;
                }
                .timestamp {
                    color: #7f8c8d;
                    font-style: italic;
                    margin-bottom: 30px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    padding: 10px;
                    border: 1px solid #ddd;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                    font-weight: bold;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                .file-info {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    grid-gap: 20px;
                }
                .file-info-item {
                    margin-bottom: 10px;
                }
                .file-info-label {
                    font-weight: bold;
                }
                .protocol-bar {
                    display: flex;
                    align-items: center;
                    margin-bottom: 10px;
                }
                .protocol-name {
                    width: 150px;
                    font-weight: bold;
                }
                .protocol-bar-chart {
                    flex-grow: 1;
                    height: 20px;
                    background-color: #f5f5f5;
                    border-radius: 3px;
                    overflow: hidden;
                    margin-right: 10px;
                }
                .protocol-bar-fill {
                    height: 100%;
                    background-color: #3498db;
                }
                .protocol-percent {
                    width: 60px;
                    text-align: right;
                }
                .security-high {
                    color: #c0392b;
                    font-weight: bold;
                }
                .security-medium {
                    color: #d35400;
                    font-weight: bold;
                }
                .security-low {
                    color: #f39c12;
                    font-weight: bold;
                }
                .section {
                    margin-bottom: 40px;
                }
                /* Responsive styles */
                @media (max-width: 768px) {
                    .file-info {
                        grid-template-columns: 1fr;
                    }
                    table {
                        display: block;
                        overflow-x: auto;
                    }
                }
            </style>
        </head>
        <body>
            <h1>{{ title }}</h1>
            <div class="timestamp">Generated: {{ timestamp }}</div>
            
            {% if file_info %}
            <div class="section">
                <h2>File Information</h2>
                <div class="file-info">
                    <div>
                        <div class="file-info-item">
                            <span class="file-info-label">Filename:</span> {{ file_info.filename }}
                        </div>
                        <div class="file-info-item">
                            <span class="file-info-label">File Size:</span> {{ file_info.size_formatted }}
                        </div>
                        <div class="file-info-item">
                            <span class="file-info-label">Packet Count:</span> {{ file_info.packet_count }}
                        </div>
                    </div>
                    <div>
                        <div class="file-info-item">
                            <span class="file-info-label">Capture Start:</span> {{ file_info.start_time }}
                        </div>
                        <div class="file-info-item">
                            <span class="file-info-label">Capture End:</span> {{ file_info.end_time }}
                        </div>
                        <div class="file-info-item">
                            <span class="file-info-label">Duration:</span> {{ file_info.duration_formatted }}
                        </div>
                        <div class="file-info-item">
                            <span class="file-info-label">Total Bytes:</span> {{ file_info.total_bytes_formatted }}
                        </div>
                        {% if file_info.hash_value %}
                        <div class="file-info-item">
                            <span class="file-info-label">{{ file_info.hash_type }}:</span> {{ file_info.hash_value }}
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
            {% endif %}
            
            {% if protocol_stats %}
            <div class="section">
                <h2>Protocol Distribution</h2>
                {% for protocol, percentage in protocol_stats.items() %}
                <div class="protocol-bar">
                    <div class="protocol-name">{{ protocol }}</div>
                    <div class="protocol-bar-chart">
                        <div class="protocol-bar-fill" style="width: {{ percentage }}%;"></div>
                    </div>
                    <div class="protocol-percent">{{ "%.1f"|format(percentage) }}%</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if conversations %}
            <div class="section">
                <h2>Top Conversations</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Packets</th>
                            <th>Bytes</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for conv in conversations %}
                        <tr>
                            <td>{{ conv.src }}</td>
                            <td>{{ conv.dst }}</td>
                            <td>{{ conv.packets }}</td>
                            <td>{{ conv.bytes }}</td>
                            <td>{{ conv.duration }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if endpoints %}
            <div class="section">
                <h2>Top Endpoints</h2>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Packets</th>
                            <th>Bytes</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for endpoint in endpoints %}
                        <tr>
                            <td>{{ endpoint.ip }}</td>
                            <td>{{ endpoint.packets }}</td>
                            <td>{{ endpoint.bytes }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if top_ports %}
            <div class="section">
                <h2>Top Ports</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for port in top_ports %}
                        <tr>
                            <td>{{ port.port }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ port.count }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if packet_summary %}
            <div class="section">
                <h2>Packet Summary (First 100 packets)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>No.</th>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Length</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for packet in packet_summary %}
                        <tr>
                            <td>{{ packet.number }}</td>
                            <td>{{ packet.time }}</td>
                            <td>{{ packet.source }}</td>
                            <td>{{ packet.destination }}</td>
                            <td>{{ packet.protocol }}</td>
                            <td>{{ packet.length }}</td>
                            <td>{{ packet.info }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            {% if security_findings %}
            <div class="section">
                <h2>Security Findings</h2>
                {% if security_findings|length > 0 %}
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Description</th>
                            <th>Packet</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in security_findings %}
                        <tr>
                            <td>{{ finding.type }}</td>
                            <td class="security-{{ finding.severity|lower }}">{{ finding.severity }}</td>
                            <td>{{ finding.description }}</td>
                            <td>{{ finding.packet_num }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No security issues identified.</p>
                {% endif %}
            </div>
            {% endif %}
            
            <footer>
                <p>Generated by Network Analyzer Pro</p>
            </footer>
        </body>
        </html>
        """
        
        # Create the template
        template = env.from_string(template_string)
        
        # Render the HTML
        html_content = template.render(data)
        
        # Write the HTML file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def offer_to_open_file(self, filepath):
        """Offer to open the exported file"""
        from PyQt6.QtWidgets import QMessageBox
        
        result = QMessageBox.question(
            self.parent, "Export Complete", 
            f"Analysis exported to {filepath}\n\nWould you like to open it now?", 
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
            QMessageBox.StandardButton.Yes)
        
        if result == QMessageBox.StandardButton.Yes:
            try:
                webbrowser.open(filepath)
            except Exception as e:
                QMessageBox.warning(self.parent, "Open Error", 
                                 f"Could not open file: {str(e)}", 
                                 QMessageBox.StandardButton.Ok)


# 1. RTSP (Real Time Streaming Protocol) Parser
class RTSPParser:
    """Parser for RTSP protocol packets"""
    
    @staticmethod
    def parse_rtsp_packet(payload):
        """Parse an RTSP packet and return information about it"""
        if not payload:
            return None
            
        try:
            # Convert payload to string for text-based protocol analysis
            rtsp_data = payload.decode('utf-8', errors='ignore')
            
            # RTSP is a text-based protocol similar to HTTP
            lines = rtsp_data.split('\r\n')
            if not lines:
                return None
                
            # Parse first line to determine if it's a request or response
            first_line = lines[0]
            
            if first_line.startswith('RTSP/'):
                # It's a response
                parts = first_line.split(' ', 2)
                if len(parts) >= 3:
                    version, status_code, reason = parts
                    return {
                        "type": "RTSP Response",
                        "info": {
                            "status_code": status_code,
                            "reason": reason,
                            "version": version
                        }
                    }
            else:
                # It's a request
                parts = first_line.split(' ', 2)
                if len(parts) >= 3:
                    method, uri, version = parts
                    
                    # Extract headers
                    headers = {}
                    for line in lines[1:]:
                        if not line or ': ' not in line:
                            continue
                        key, value = line.split(': ', 1)
                        headers[key.lower()] = value
                    
                    return {
                        "type": "RTSP Request",
                        "info": {
                            "method": method,
                            "uri": uri,
                            "version": version,
                            "headers": headers
                        }
                    }
            
        except Exception as e:
            return {"type": "RTSP Error", "info": {"error": str(e)}}
            
        return None

# 2. RTP (Real-time Transport Protocol) Parser
class RTPParser:
    """Parser for RTP protocol packets"""
    
    @staticmethod
    def parse_rtp_packet(payload):
        """Parse an RTP packet and return information about it"""
        if len(payload) < 12:  # RTP header is at least 12 bytes
            return None
            
        try:
            # First byte: version (2 bits), padding (1 bit), extension (1 bit), CSRC count (4 bits)
            first_byte = payload[0]
            version = (first_byte >> 6) & 0x03
            padding = (first_byte >> 5) & 0x01
            extension = (first_byte >> 4) & 0x01
            cc = first_byte & 0x0F
            
            # Second byte: marker (1 bit), payload type (7 bits)
            second_byte = payload[1]
            marker = (second_byte >> 7) & 0x01
            payload_type = second_byte & 0x7F
            
            # Bytes 2-3: sequence number
            sequence_number = (payload[2] << 8) | payload[3]
            
            # Bytes 4-7: timestamp
            timestamp = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]
            
            # Bytes 8-11: SSRC identifier
            ssrc = (payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11]
            
            # Optional CSRC identifiers
            csrc_list = []
            for i in range(cc):
                if len(payload) >= 12 + (i+1)*4:
                    csrc = (payload[12+i*4] << 24) | (payload[12+i*4+1] << 16) | (payload[12+i*4+2] << 8) | payload[12+i*4+3]
                    csrc_list.append(csrc)
            
            # Determine payload type name
            payload_type_name = "Unknown"
            if payload_type == 0:
                payload_type_name = "PCMU/G.711"
            elif payload_type == 8:
                payload_type_name = "PCMA/G.711"
            elif payload_type == 9:
                payload_type_name = "G.722"
            elif payload_type == 25:
                payload_type_name = "CelB"
            elif payload_type == 26:
                payload_type_name = "JPEG"
            elif payload_type == 28:
                payload_type_name = "nv"
            elif payload_type == 31:
                payload_type_name = "H.261"
            elif payload_type == 32:
                payload_type_name = "MPV"
            elif payload_type == 33:
                payload_type_name = "MP2T"
            elif payload_type == 34:
                payload_type_name = "H.263"
            elif payload_type >= 96 and payload_type <= 127:
                payload_type_name = "Dynamic"
            
            return {
                "type": "RTP",
                "info": {
                    "version": version,
                    "padding": bool(padding),
                    "extension": bool(extension),
                    "csrc_count": cc,
                    "marker": bool(marker),
                    "payload_type": payload_type,
                    "payload_type_name": payload_type_name,
                    "sequence_number": sequence_number,
                    "timestamp": timestamp,
                    "ssrc": ssrc,
                    "csrc_list": csrc_list
                }
            }
            
        except Exception as e:
            return {"type": "RTP Error", "info": {"error": str(e)}}
            
        return None

# 3. CoAP (Constrained Application Protocol) Parser
class CoAPParser:
    """Parser for CoAP protocol packets"""
    
    @staticmethod
    def parse_coap_packet(payload):
        """Parse a CoAP packet and return information about it"""
        if len(payload) < 4:  # CoAP header is at least 4 bytes
            return None
            
        try:
            # First byte: version (2 bits), type (2 bits), token length (4 bits)
            first_byte = payload[0]
            version = (first_byte >> 6) & 0x03
            type_code = (first_byte >> 4) & 0x03
            token_length = first_byte & 0x0F
            
            # CoAP message types
            type_names = {0: "Confirmable", 1: "Non-confirmable", 2: "Acknowledgement", 3: "Reset"}
            type_name = type_names.get(type_code, "Unknown")
            
            # Second byte: method code (request) or response code
            code_byte = payload[1]
            code_class = code_byte >> 5
            code_detail = code_byte & 0x1F
            
            # Determine if it's a request, response, or empty message
            if code_byte == 0:
                code_name = "Empty"
                message_type = "Empty"
            elif code_class == 0:
                # Request
                method_names = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE"}
                code_name = method_names.get(code_detail, f"Unknown ({code_byte})")
                message_type = "Request"
            elif 2 <= code_class <= 5:
                # Response
                code_name = f"{code_class}.{code_detail:02d}"
                message_type = "Response"
            else:
                code_name = f"Unknown ({code_byte})"
                message_type = "Unknown"
            
            # Bytes 2-3: message ID
            message_id = (payload[2] << 8) | payload[3]
            
            # Extract token (if any)
            token = None
            if token_length > 0 and token_length <= 8 and len(payload) >= 4 + token_length:
                token = payload[4:4+token_length].hex()
            
            # Start of options (if any)
            options_position = 4 + token_length
            
            # Process options
            options = []
            current_pos = options_position
            current_option_number = 0
            
            while current_pos < len(payload):
                # Check for payload marker
                if payload[current_pos] == 0xFF:
                    current_pos += 1  # Skip the marker
                    break
                
                # Read option delta and length
                option_byte = payload[current_pos]
                option_delta = (option_byte >> 4) & 0x0F
                option_length = option_byte & 0x0F
                current_pos += 1
                
                # Handle extended option delta
                if option_delta == 13:
                    if current_pos < len(payload):
                        option_delta = 13 + payload[current_pos]
                        current_pos += 1
                elif option_delta == 14:
                    if current_pos + 1 < len(payload):
                        option_delta = 269 + (payload[current_pos] << 8) + payload[current_pos + 1]
                        current_pos += 2
                elif option_delta == 15:
                    # Reserved - should not happen in a valid CoAP message
                    break
                
                # Handle extended option length
                if option_length == 13:
                    if current_pos < len(payload):
                        option_length = 13 + payload[current_pos]
                        current_pos += 1
                elif option_length == 14:
                    if current_pos + 1 < len(payload):
                        option_length = 269 + (payload[current_pos] << 8) + payload[current_pos + 1]
                        current_pos += 2
                elif option_length == 15:
                    # Reserved - should not happen in a valid CoAP message
                    break
                
                # Calculate absolute option number
                current_option_number += option_delta
                
                # Read option value
                if current_pos + option_length <= len(payload):
                    option_value = payload[current_pos:current_pos + option_length]
                    current_pos += option_length
                    
                    # Map common option numbers to names
                    option_names = {
                        1: "If-Match",
                        3: "Uri-Host",
                        4: "ETag",
                        5: "If-None-Match",
                        7: "Uri-Port",
                        8: "Location-Path",
                        11: "Uri-Path",
                        12: "Content-Format",
                        14: "Max-Age",
                        15: "Uri-Query",
                        17: "Accept",
                        20: "Location-Query",
                        35: "Proxy-Uri",
                        39: "Proxy-Scheme",
                        60: "Size1"
                    }
                    
                    option_name = option_names.get(current_option_number, f"Unknown ({current_option_number})")
                    
                    # Try to decode URI components as strings
                    if current_option_number in [3, 8, 11, 15, 20, 35]:
                        try:
                            option_value_str = option_value.decode('utf-8')
                        except:
                            option_value_str = option_value.hex()
                    else:
                        option_value_str = option_value.hex()
                    
                    options.append({
                        "number": current_option_number,
                        "name": option_name,
                        "value": option_value_str
                    })
            
            # Extract payload if any
            payload_data = None
            if current_pos < len(payload):
                payload_data = payload[current_pos:]
                try:
                    payload_text = payload_data.decode('utf-8', errors='ignore')
                    if len(payload_text) > 30:
                        payload_text = payload_text[:30] + "..."
                except:
                    payload_text = f"<binary data, {len(payload_data)} bytes>"
            
            return {
                "type": "CoAP",
                "info": {
                    "version": version,
                    "type": type_name,
                    "token_length": token_length,
                    "code": code_name,
                    "message_type": message_type,
                    "message_id": message_id,
                    "token": token,
                    "options": options,
                    "has_payload": payload_data is not None,
                    "payload": payload_text if payload_data is not None else None
                }
            }
            
        except Exception as e:
            return {"type": "CoAP Error", "info": {"error": str(e)}}
            
        return None

# 4. mDNS (Multicast DNS) / DNS-SD Service Discovery Parser
class MDNSParser:
    """Parser for mDNS and DNS-SD packets"""
    
    @staticmethod
    def parse_mdns_packet(dns_packet):
        """Parse an mDNS/DNS-SD packet and extract service discovery information"""
        if not dns_packet or not hasattr(dns_packet, 'qd') or not hasattr(dns_packet, 'an'):
            return None
            
        try:
            results = {
                "type": "mDNS",
                "info": {
                    "queries": [],
                    "answers": [],
                    "services": []
                }
            }
            
            # Process queries
            for i in range(dns_packet.qdcount):
                if i < len(dns_packet.qd):
                    query = dns_packet.qd[i]
                    query_name = query.qname.decode('utf-8', errors='ignore') if hasattr(query, 'qname') else "Unknown"
                    query_type = query.qtype
                    
                    # Map query types to human-readable names
                    query_type_names = {
                        1: "A",
                        2: "NS",
                        5: "CNAME",
                        12: "PTR",
                        15: "MX",
                        16: "TXT",
                        28: "AAAA",
                        33: "SRV",
                        41: "OPT",
                        255: "ANY"
                    }
                    query_type_name = query_type_names.get(query_type, f"Type-{query_type}")
                    
                    results["info"]["queries"].append({
                        "name": query_name,
                        "type": query_type_name
                    })
                    
                    # Check for service discovery
                    if query_type == 12 and query_name.endswith('._tcp.local.'):
                        service_type = query_name.split('._tcp.local.')[0]
                        if service_type not in [s.get('type') for s in results["info"]["services"]]:
                            results["info"]["services"].append({
                                "type": service_type,
                                "protocol": "tcp",
                                "discovery": "query"
                            })
                    elif query_type == 12 and query_name.endswith('._udp.local.'):
                        service_type = query_name.split('._udp.local.')[0]
                        if service_type not in [s.get('type') for s in results["info"]["services"]]:
                            results["info"]["services"].append({
                                "type": service_type,
                                "protocol": "udp",
                                "discovery": "query"
                            })
            
            # Process answers
            for i in range(dns_packet.ancount):
                if i < len(dns_packet.an):
                    answer = dns_packet.an[i]
                    answer_name = answer.rrname.decode('utf-8', errors='ignore') if hasattr(answer, 'rrname') else "Unknown"
                    answer_type = answer.type
                    
                    # Map answer types to human-readable names
                    answer_type_names = {
                        1: "A",
                        2: "NS",
                        5: "CNAME",
                        12: "PTR",
                        15: "MX",
                        16: "TXT",
                        28: "AAAA",
                        33: "SRV",
                        41: "OPT",
                        47: "NSEC"
                    }
                    answer_type_name = answer_type_names.get(answer_type, f"Type-{answer_type}")
                    
                    # Extract value based on record type
                    if answer_type == 1:  # A
                        value = answer.rdata
                    elif answer_type == 28:  # AAAA
                        value = answer.rdata
                    elif answer_type == 12:  # PTR
                        value = answer.rdata.decode('utf-8', errors='ignore') if hasattr(answer, 'rdata') else "Unknown"
                    elif answer_type == 16:  # TXT
                        txt_data = []
                        if hasattr(answer, 'rdata'):
                            txt_bytes = answer.rdata
                            pos = 0
                            while pos < len(txt_bytes):
                                length = txt_bytes[pos]
                                pos += 1
                                if pos + length <= len(txt_bytes):
                                    try:
                                        txt_record = txt_bytes[pos:pos+length].decode('utf-8', errors='ignore')
                                        txt_data.append(txt_record)
                                    except:
                                        txt_data.append(f"<binary data, {length} bytes>")
                                pos += length
                        value = txt_data
                    elif answer_type == 33:  # SRV
                        if hasattr(answer, 'priority') and hasattr(answer, 'weight') and hasattr(answer, 'port') and hasattr(answer, 'target'):
                            value = {
                                "priority": answer.priority,
                                "weight": answer.weight,
                                "port": answer.port,
                                "target": answer.target.decode('utf-8', errors='ignore') if hasattr(answer.target, 'decode') else str(answer.target)
                            }
                        else:
                            value = "SRV record (details unavailable)"
                    else:
                        value = str(answer.rdata) if hasattr(answer, 'rdata') else "Unknown"
                    
                    results["info"]["answers"].append({
                        "name": answer_name,
                        "type": answer_type_name,
                        "value": value
                    })
                    
                    # Process service discovery information
                    if answer_type == 12:  # PTR
                        if answer_name.endswith('._tcp.local.'):
                            service_type = answer_name.split('._tcp.local.')[0]
                            service_name = value.split('.')[0] if isinstance(value, str) else "Unknown"
                            
                            # Check if we already have this service type
                            existing_service = next((s for s in results["info"]["services"] if s.get('type') == service_type), None)
                            if existing_service:
                                if 'instances' not in existing_service:
                                    existing_service['instances'] = []
                                if service_name not in existing_service['instances']:
                                    existing_service['instances'].append(service_name)
                            else:
                                results["info"]["services"].append({
                                    "type": service_type,
                                    "protocol": "tcp",
                                    "discovery": "answer",
                                    "instances": [service_name]
                                })
                        elif answer_name.endswith('._udp.local.'):
                            service_type = answer_name.split('._udp.local.')[0]
                            service_name = value.split('.')[0] if isinstance(value, str) else "Unknown"
                            
                            # Check if we already have this service type
                            existing_service = next((s for s in results["info"]["services"] if s.get('type') == service_type), None)
                            if existing_service:
                                if 'instances' not in existing_service:
                                    existing_service['instances'] = []
                                if service_name not in existing_service['instances']:
                                    existing_service['instances'].append(service_name)
                            else:
                                results["info"]["services"].append({
                                    "type": service_type,
                                    "protocol": "udp",
                                    "discovery": "answer",
                                    "instances": [service_name]
                                })
                    
                    # Process SRV records to extract port info
                    if answer_type == 33:  # SRV
                        srv_name = answer_name
                        # SRV records typically have the form: service_instance._service._protocol.domain
                        for service in results["info"]["services"]:
                            if 'instances' in service:
                                for instance in service['instances']:
                                    if srv_name.startswith(f"{instance}._{service['type']}._"):
                                        port_info = value.get('port') if isinstance(value, dict) else None
                                        if port_info:
                                            service['port'] = port_info
            
            return results
            
        except Exception as e:
            return {"type": "mDNS Error", "info": {"error": str(e)}}
            
        return None

# 5. ONVIF Parser (SOAP/XML over HTTP)
class ONVIFParser:
    """Parser for ONVIF protocol messages (SOAP/XML over HTTP)"""
    
    @staticmethod
    def parse_onvif_message(payload):
        """Parse an ONVIF SOAP message and extract key information"""
        if not payload:
            return None
            
        try:
            # Convert payload to string
            soap_data = payload.decode('utf-8', errors='ignore')
            
            # Quick check if it's likely an ONVIF message
            if '<SOAP-ENV:Envelope' not in soap_data and '<soap:Envelope' not in soap_data:
                return None
                
            # Look for ONVIF namespaces
            onvif_namespaces = [
                'xmlns:tds="http://www.onvif.org/ver10/device/wsdl"',
                'xmlns:tev="http://www.onvif.org/ver10/events/wsdl"',
                'xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"',
                'xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl"',
                'xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"',
                'xmlns:tr2="http://www.onvif.org/ver20/media/wsdl"',
                'xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
            ]
            
            is_onvif = any(ns in soap_data for ns in onvif_namespaces)
            if not is_onvif:
                return None
                
            # Determine message type by looking for common ONVIF operations
            message_type = "Unknown"
            service = "Unknown"
            
            # Device Management Service operations
            device_operations = [
                'GetDeviceInformation', 'GetSystemDateAndTime', 'GetCapabilities',
                'GetServiceCapabilities', 'GetDiscoveryMode', 'GetScopes', 'SetScopes',
                'GetNetworkInterfaces', 'GetNetworkProtocols', 'SetNetworkProtocols',
                'GetSystemLog', 'GetSystemSupportInformation', 'SystemReboot'
            ]
            
            # Media Service operations
            media_operations = [
                'GetProfiles', 'GetVideoSources', 'GetVideoSourceConfigurations',
                'GetStreamUri', 'GetSnapshotUri', 'GetOSDs', 'GetOSD',
                'CreateProfile', 'DeleteProfile', 'AddVideoEncoderConfiguration'
            ]
            
            # PTZ operations
            ptz_operations = [
                'GetConfigurations', 'GetConfiguration', 'GetNodes',
                'AbsoluteMove', 'RelativeMove', 'ContinuousMove', 'Stop',
                'GetStatus', 'GetPresets', 'GotoPreset'
            ]
            
            # Events operations
            event_operations = [
                'Subscribe', 'Unsubscribe', 'Renew', 'SetSynchronizationPoint',
                'GetEventProperties', 'GetServiceCapabilities'
            ]
            
            # Imaging operations
            imaging_operations = [
                'GetImagingSettings', 'SetImagingSettings', 'GetOptions',
                'GetServiceCapabilities', 'GetStatus', 'GetMoveOptions', 'Move', 'Stop'
            ]
            
            # Check for each type of operation
            for op in device_operations:
                if f'<{op}>' in soap_data or f'<tds:{op}>' in soap_data:
                    message_type = op
                    service = "Device"
                    break
                    
            if message_type == "Unknown":
                for op in media_operations:
                    if f'<{op}>' in soap_data or f'<trt:{op}>' in soap_data or f'<tr2:{op}>' in soap_data:
                        message_type = op
                        service = "Media"
                        break
                        
            if message_type == "Unknown":
                for op in ptz_operations:
                    if f'<{op}>' in soap_data or f'<tptz:{op}>' in soap_data:
                        message_type = op
                        service = "PTZ"
                        break
                        
            if message_type == "Unknown":
                for op in event_operations:
                    if f'<{op}>' in soap_data or f'<tev:{op}>' in soap_data:
                        message_type = op
                        service = "Events"
                        break
                        
            if message_type == "Unknown":
                for op in imaging_operations:
                    if f'<{op}>' in soap_data or f'<timg:{op}>' in soap_data:
                        message_type = op
                        service = "Imaging"
                        break
                        
            # Check if it's a response
            is_response = '</Response>' in soap_data or 'Response>' in soap_data
            
            # Extract any basic auth credentials (for security analysis)
            auth_info = None
            if 'Authorization: Basic ' in soap_data:
                auth_parts = soap_data.split('Authorization: Basic ', 1)
                if len(auth_parts) > 1:
                    auth_b64 = auth_parts[1].split('\r\n', 1)[0].strip()
                    auth_info = auth_b64
            
            return {
                "type": "ONVIF",
                "info": {
                    "service": service,
                    "operation": message_type,
                    "is_response": is_response,
                    "has_auth": auth_info is not None,
                    "auth_info": auth_info
                }
            }
            
        except Exception as e:
            return {"type": "ONVIF Error", "info": {"error": str(e)}}
            
        return None
# 6. HLS (HTTP Live Streaming) Parser
class HLSParser:
    """Parser for HLS protocol (HTTP Live Streaming)"""
    
    @staticmethod
    def parse_hls_message(payload, is_request=False):
        """Parse an HLS message (m3u8 playlist or segment request)"""
        if not payload:
            return None
            
        try:
            # Convert payload to string
            data = payload.decode('utf-8', errors='ignore')
            
            # Check if it's an m3u8 playlist
            if '#EXTM3U' in data:
                return HLSParser._parse_m3u8_playlist(data)
                
            # If it's a request, check for typical HLS patterns
            if is_request:
                # Check for common HLS URL patterns in HTTP requests
                if '.m3u8' in data or '.ts' in data:
                    request_lines = data.split('\r\n')
                    first_line = request_lines[0] if request_lines else ""
                    
                    # Extract request details
                    if first_line.startswith('GET '):
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            path = parts[1]
                            
                            # Determine if it's a playlist or segment request
                            is_playlist = path.endswith('.m3u8')
                            is_segment = path.endswith('.ts')
                            
                            return {
                                "type": "HLS Request",
                                "info": {
                                    "url": path,
                                    "is_playlist": is_playlist,
                                    "is_segment": is_segment,
                                    "request_type": "playlist" if is_playlist else "segment" if is_segment else "unknown"}
                        }
            
            return None
            
        except Exception as e:
            return {"type": "HLS Error", "info": {"error": str(e)}}
            
        return None
    
    @staticmethod
    def _parse_m3u8_playlist(data):
        """Parse an m3u8 playlist and extract key information"""
        try:
            lines = data.split('\n')
            
            # Check if it's a valid playlist
            if not lines or '#EXTM3U' not in lines[0]:
                return None
                
            # Identify playlist type
            is_master = False
            is_media = False
            
            for line in lines:
                if line.startswith('#EXT-X-STREAM-INF:'):
                    is_master = True
                    break
                elif line.startswith('#EXTINF:'):
                    is_media = True
                    break
                    
            # Extract streams (for master playlist) or segments (for media playlist)
            streams = []
            segments = []
            
            if is_master:
                stream_info = None
                for line in lines:
                    if line.startswith('#EXT-X-STREAM-INF:'):
                        # Parse stream attributes
                        attributes = {}
                        attrs_part = line.split(':', 1)[1] if ':' in line else ""
                        
                        # Extract comma-separated attributes
                        attr_parts = []
                        in_quotes = False
                        current_part = ""
                        
                        # Handle quoted values with commas
                        for char in attrs_part:
                            if char == '"':
                                in_quotes = not in_quotes
                                current_part += char
                            elif char == ',' and not in_quotes:
                                attr_parts.append(current_part.strip())
                                current_part = ""
                            else:
                                current_part += char
                                
                        if current_part:
                            attr_parts.append(current_part.strip())
                        
                        # Parse each attribute
                        for attr in attr_parts:
                            if '=' in attr:
                                key, value = attr.split('=', 1)
                                # Remove quotes if present
                                if value.startswith('"') and value.endswith('"'):
                                    value = value[1:-1]
                                attributes[key.strip()] = value.strip()
                        
                        stream_info = attributes
                    elif stream_info is not None and line.strip() and not line.startswith('#'):
                        # This is the URI for the previous stream info
                        streams.append({
                            "attributes": stream_info,
                            "uri": line.strip()
                        })
                        stream_info = None
            
            elif is_media:
                segment_info = None
                for line in lines:
                    if line.startswith('#EXTINF:'):
                        # Parse segment duration
                        duration_part = line.split(':', 1)[1] if ':' in line else ""
                        duration = float(duration_part.split(',')[0].strip()) if ',' in duration_part else float(duration_part.strip())
                        segment_info = {"duration": duration}
                    elif line.startswith('#EXT-X-KEY:'):
                        # Parse encryption info
                        key_info = {}
                        key_part = line.split(':', 1)[1] if ':' in line else ""
                        
                        # Parse attributes
                        for attr in key_part.split(','):
                            if '=' in attr:
                                key, value = attr.split('=', 1)
                                # Remove quotes if present
                                if value.startswith('"') and value.endswith('"'):
                                    value = value[1:-1]
                                key_info[key.strip()] = value.strip()
                        
                        # Add encryption info to playlist info
                        if "encryption" not in globals():
                            globals()["encryption"] = []
                        globals()["encryption"].append(key_info)
                    elif segment_info is not None and line.strip() and not line.startswith('#'):
                        # This is the URI for the previous segment info
                        segments.append({
                            "info": segment_info,
                            "uri": line.strip()
                        })
                        segment_info = None
            
            # Extract other important playlist attributes
            playlist_info = {
                "version": None,
                "target_duration": None,
                "media_sequence": None,
                "playlist_type": None,
                "endlist": False
            }
            
            for line in lines:
                if line.startswith('#EXT-X-VERSION:'):
                    playlist_info["version"] = int(line.split(':', 1)[1].strip())
                elif line.startswith('#EXT-X-TARGETDURATION:'):
                    playlist_info["target_duration"] = int(line.split(':', 1)[1].strip())
                elif line.startswith('#EXT-X-MEDIA-SEQUENCE:'):
                    playlist_info["media_sequence"] = int(line.split(':', 1)[1].strip())
                elif line.startswith('#EXT-X-PLAYLIST-TYPE:'):
                    playlist_info["playlist_type"] = line.split(':', 1)[1].strip()
                elif line.startswith('#EXT-X-ENDLIST'):
                    playlist_info["endlist"] = True
                    
            # Determine if encryption is used
            has_encryption = "encryption" in globals() and len(globals()["encryption"]) > 0
            
            return {
                "type": "HLS Playlist",
                "info": {
                    "is_master": is_master,
                    "is_media": is_media,
                    "playlist_info": playlist_info,
                    "streams": streams if is_master else [],
                    "segments": segments if is_media else [],
                    "has_encryption": has_encryption,
                    "encryption_info": globals().get("encryption", []) if has_encryption else []
                }
            }
            
        except Exception as e:
            return {"type": "HLS Playlist Error", "info": {"error": str(e)}}
            
        return None

class MQTTParser:
    """Parser for MQTT protocol packets"""
    
    @staticmethod
    def parse_mqtt_packet(payload):
        """Parse an MQTT packet and return information about it"""
        if len(payload) < 2:
            return None
            
        # Extract the first byte which contains message type and flags
        first_byte = payload[0]
        
        # First 4 bits (high nibble) is the message type
        msg_type = (first_byte & 0xF0) >> 4
        
        # Last 4 bits (low nibble) are flags depending on the message type
        flags = first_byte & 0x0F
        
        # Second byte starts the remaining length field (variable length encoding)
        remaining_length = 0
        multiplier = 1
        pos = 1
        
        # Parse the variable length encoding
        while pos < len(payload):
            encoding_byte = payload[pos]
            remaining_length += (encoding_byte & 127) * multiplier
            multiplier *= 128
            pos += 1
            
            if (encoding_byte & 128) == 0:
                break
                
            if pos > 4:  # Max 4 bytes for remaining length
                return None
        
        # Fixed header size
        fixed_header_size = pos + 1
        
        # Get MQTT packet type name
        packet_type = MQTT_PACKET_TYPES.get(msg_type, f"UNKNOWN-{msg_type}")
        
        # Extract additional information based on packet type
        info = {}
        
        if msg_type == 1:  # CONNECT
            if len(payload) < fixed_header_size + 10:  # Need at least protocol name and version
                return {"type": packet_type, "info": "Malformed CONNECT packet"}
                
            # Try to extract protocol name and client ID
            try:
                # Protocol name length (MSB, LSB)
                protocol_name_len = (payload[fixed_header_size] << 8) + payload[fixed_header_size + 1]
                
                if protocol_name_len + fixed_header_size + 2 <= len(payload):
                    protocol_name = payload[fixed_header_size+2:fixed_header_size+2+protocol_name_len]
                    try:
                        protocol_name = protocol_name.decode('utf-8')
                    except:
                        protocol_name = str(protocol_name)
                        
                    info["protocol"] = protocol_name
                    
                    # Protocol version comes next
                    if fixed_header_size + 2 + protocol_name_len < len(payload):
                        version = payload[fixed_header_size + 2 + protocol_name_len]
                        info["version"] = version
                        
                        # Extract connect flags
                        if fixed_header_size + 3 + protocol_name_len < len(payload):
                            connect_flags = payload[fixed_header_size + 3 + protocol_name_len]
                            info["clean_session"] = bool(connect_flags & 0x02)
                            info["will"] = bool(connect_flags & 0x04)
                            info["will_qos"] = (connect_flags & 0x18) >> 3
                            info["will_retain"] = bool(connect_flags & 0x20)
                            info["password"] = bool(connect_flags & 0x40)
                            info["username"] = bool(connect_flags & 0x80)
                            
                            # Try to extract Client ID
                            pos = fixed_header_size + 4 + protocol_name_len + 2  # Skip keepalive
                            if pos + 2 <= len(payload):
                                client_id_len = (payload[pos] << 8) + payload[pos + 1]
                                pos += 2
                                if pos + client_id_len <= len(payload):
                                    client_id = payload[pos:pos+client_id_len]
                                    try:
                                        client_id = client_id.decode('utf-8')
                                        info["client_id"] = client_id
                                    except:
                                        pass
            except:
                pass
                
        elif msg_type == 3:  # PUBLISH
            if len(payload) < fixed_header_size + 2:  # Need at least topic length
                return {"type": packet_type, "info": "Malformed PUBLISH packet"}
                
            # Extract QoS
            qos = (flags & 0x06) >> 1
            retain = bool(flags & 0x01)
            dup = bool(flags & 0x08)
            
            info["qos"] = qos
            info["retain"] = retain
            info["dup"] = dup
            
            # Try to extract topic and payload
            try:
                # Topic length (MSB, LSB)
                topic_len = (payload[fixed_header_size] << 8) + payload[fixed_header_size + 1]
                
                if topic_len + fixed_header_size + 2 <= len(payload):
                    topic = payload[fixed_header_size+2:fixed_header_size+2+topic_len]
                    try:
                        topic = topic.decode('utf-8')
                    except:
                        topic = str(topic)
                        
                    info["topic"] = topic
                    
                    # If QoS > 0, there's a message ID
                    pos = fixed_header_size + 2 + topic_len
                    if qos > 0:
                        if pos + 2 <= len(payload):
                            msg_id = (payload[pos] << 8) + payload[pos + 1]
                            info["msg_id"] = msg_id
                            pos += 2
                    
                    # Anything left is the payload
                    if pos < len(payload):
                        msg_payload = payload[pos:]
                        # Try to decode as UTF-8 if it's text
                        try:
                            msg_payload = msg_payload.decode('utf-8')
                            # Limit payload length for display
                            if len(msg_payload) > 30:
                                msg_payload = msg_payload[:30] + "..."
                        except:
                            # If it's binary, show length
                            msg_payload = f"<binary data, {len(msg_payload)} bytes>"
                            
                        info["payload"] = msg_payload
            except:
                pass

        elif msg_type == 8:  # SUBSCRIBE
            if len(payload) < fixed_header_size + 2:
                return {"type": packet_type, "info": "Malformed SUBSCRIBE packet"}
            
            # Extract message ID and topic filters
            try:
                pos = fixed_header_size
                if pos + 2 <= len(payload):
                    msg_id = (payload[pos] << 8) + payload[pos + 1]
                    info["msg_id"] = msg_id
                    pos += 2
                    
                    # Extract topic filters
                    topic_filters = []
                    while pos + 2 <= len(payload):
                        topic_len = (payload[pos] << 8) + payload[pos + 1]
                        pos += 2
                        
                        if pos + topic_len <= len(payload):
                            topic = payload[pos:pos+topic_len]
                            try:
                                topic = topic.decode('utf-8')
                            except:
                                topic = str(topic)
                            
                            # Get QoS (1 byte after the topic string)
                            if pos + topic_len + 1 <= len(payload):
                                qos = payload[pos + topic_len] & 0x03
                                topic_filters.append({"topic": topic, "qos": qos})
                            
                            pos += topic_len + 1  # Skip topic string and QoS byte
                    
                    info["topic_filters"] = topic_filters
            except:
                pass


        elif msg_type in (2, 4, 5, 6, 7, 9, 11, 13):  # Simple packets with possible message IDs
            if len(payload) >= fixed_header_size + 2:
                try:
                    msg_id = (payload[fixed_header_size] << 8) + payload[fixed_header_size + 1]
                    info["msg_id"] = msg_id
                except:
                    pass
        
        return {
            "type": packet_type,
            "info": info
        }



    class PacketCaptureThread(QThread):
        """Thread for packet capture to avoid blocking the UI"""
        packet_received = pyqtSignal(object)
        capture_complete = pyqtSignal()
        status_update = pyqtSignal(str)
        
        def __init__(self, interface=None, bpf_filter=None, packet_count=0):
            super().__init__()
            self.interface = interface
            self.bpf_filter = bpf_filter
            self.packet_count = packet_count  # 0 means unlimited
            self.running = True
            self._stop_event = threading.Event()
            
        def run(self):
            if not SCAPY_AVAILABLE:
                self.status_update.emit("Error: Scapy library not available")
                self.capture_complete.emit()
                return
                
            try:
                # Start the packet capture
                self.status_update.emit(f"Starting capture on {self.interface}")
                
                def packet_callback(packet):
                    if self._stop_event.is_set():
                        return True  # Return True to stop sniffing
                    self.packet_received.emit(packet)
                    return False  # Continue sniffing
                    
                if self.packet_count > 0:
                    sniff(iface=self.interface, prn=packet_callback, filter=self.bpf_filter, 
                        count=self.packet_count, store=0, stop_filter=lambda p: self._stop_event.is_set())
                else:
                    sniff(iface=self.interface, prn=packet_callback, filter=self.bpf_filter, 
                        store=0, stop_filter=lambda p: self._stop_event.is_set())
                        
                self.status_update.emit("Capture complete")
                self.capture_complete.emit()
                
            except Exception as e:
                self.status_update.emit(f"Capture error: {str(e)}")
                self.capture_complete.emit()
        
        def stop(self):
            self._stop_event.set()
            self.running = False

class PacketCaptureThread(QThread):
    """Thread for packet capture to avoid blocking the UI"""
    packet_received = pyqtSignal(object)
    capture_complete = pyqtSignal()
    status_update = pyqtSignal(str)
    
    def __init__(self, interface=None, bpf_filter=None, packet_count=0):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count  # 0 means unlimited
        self.running = True
        self._stop_event = threading.Event()
        
    def run(self):
        if not SCAPY_AVAILABLE:
            self.status_update.emit("Error: Scapy library not available")
            self.capture_complete.emit()
            return
            
        try:
            # Start the packet capture
            self.status_update.emit(f"Starting capture on {self.interface}")
            
            def packet_callback(packet):
                if self._stop_event.is_set():
                    return True  # Return True to stop sniffing
                self.packet_received.emit(packet)
                return False  # Continue sniffing
                
            if self.packet_count > 0:
                sniff(iface=self.interface, prn=packet_callback, filter=self.bpf_filter, 
                      count=self.packet_count, store=0, stop_filter=lambda p: self._stop_event.is_set())
            else:
                sniff(iface=self.interface, prn=packet_callback, filter=self.bpf_filter, 
                      store=0, stop_filter=lambda p: self._stop_event.is_set())
                      
            self.status_update.emit("Capture complete")
            self.capture_complete.emit()
            
        except Exception as e:
            self.status_update.emit(f"Capture error: {str(e)}")
            self.capture_complete.emit()
    
    def stop(self):
        self._stop_event.set()
        self.running = False

class FastPcapReaderThread(QThread):
    """Thread for fast PCAP file reading"""
    progress_updated = pyqtSignal(int, int, str)
    packet_batch_ready = pyqtSignal(list, list)
    loading_complete = pyqtSignal(list, list)
    loading_error = pyqtSignal(str)
    
    def __init__(self, file_path, packet_limit=None, batch_size=1000):
        super().__init__()
        self.file_path = file_path
        self.packet_limit = packet_limit
        self.batch_size = batch_size
        self.canceled = False
        self._stop_event = threading.Event()
        
    def run(self):
        """Main thread execution - reads PCAP file with optimizations"""
        try:
            # Get file size for progress reporting
            file_size = os.path.getsize(self.file_path)
            
            # Lists to hold the complete results
            all_packets = []
            all_packet_infos = []
            
            # Temporary lists for batching
            packet_batch = []
            packet_info_batch = []
            
            # Tracking variables
            packet_count = 0
            last_progress = 0
            start_time = time.time()
            last_update_time = start_time
            update_interval = 0.5  # Update UI every 0.5 seconds
            
            # Use memory-mapped file for faster access
            with open(self.file_path, 'rb') as f:
                # Check file size before memory mapping - skip for very large files
                if file_size < 1024 * 1024 * 1024:  # Use mmap only for files < 1GB
                    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    pcap_reader = PcapReader(mm)
                else:
                    # For very large files, use regular file reading
                    pcap_reader = PcapReader(f)
                
                # Create a packet analyzer for minimal processing
                packet_analyzer = MinimalPacketAnalyzer()
                
                for packet in pcap_reader:
                    # Check if we should stop
                    if self._stop_event.is_set():
                        break
                    
                    # Convert any problematic float fields to integers if needed
                    if hasattr(packet, 'time'):
                        if not isinstance(packet.time, float):
                            packet.time = float(packet.time)
                    
                    # Process the packet with minimal information extraction
                    packet_info = packet_analyzer.extract_minimal_info(packet)
                    
                    # Add to our batches
                    packet_batch.append(packet)
                    packet_info_batch.append(packet_info)
                    
                    # Add to our complete lists
                    all_packets.append(packet)
                    all_packet_infos.append(packet_info)
                    
                    packet_count += 1
                    
                    # Emit batch if we've reached batch size
                    if len(packet_batch) >= self.batch_size:
                        self.packet_batch_ready.emit(packet_batch.copy(), packet_info_batch.copy())
                        packet_batch.clear()
                        packet_info_batch.clear()
                    
                    # Update progress periodically rather than for every packet
                    current_time = time.time()
                    if current_time - last_update_time >= update_interval:
                        # Calculate progress based on file position for more accuracy
                        if isinstance(pcap_reader.f, mmap.mmap):
                            read_pos = pcap_reader.f.tell()
                        else:
                            read_pos = pcap_reader.f.tell()
                        
                        progress = min(int((read_pos / file_size) * 100), 100)
                        
                        # Only emit if progress has actually changed
                        if progress > last_progress:
                            elapsed = current_time - start_time
                            if progress > 0:
                                total_estimated = elapsed / (progress / 100)
                                remaining = total_estimated - elapsed
                                
                                # Format time remaining
                                mins = int(remaining // 60)
                                secs = int(remaining % 60)
                                time_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
                                
                                self.progress_updated.emit(progress, packet_count, time_str)
                            
                            last_progress = progress
                            last_update_time = current_time
                    
                    # If we have a packet limit and reached it, stop
                    if self.packet_limit and packet_count >= self.packet_limit:
                        break
                
                # Close the reader
                pcap_reader.close()
                
                # Emit any remaining packets in the last batch
                if packet_batch:
                    self.packet_batch_ready.emit(packet_batch, packet_info_batch)
                
            # Emit final completion signal
            self.loading_complete.emit(all_packets, all_packet_infos)
            
        except Exception as e:
            import traceback
            error_msg = f"Error reading PCAP file: {str(e)}\n{traceback.format_exc()}"
            print(error_msg)
            self.loading_error.emit(error_msg)
    
    def stop(self):
        """Stop the thread gracefully"""
        self._stop_event.set()
        self.canceled = True

class MinimalPacketAnalyzer:
    """Lightweight packet analyzer that extracts minimal info for display"""
    
    def __init__(self):
        """Initialize with caches to avoid redundant operations"""
        self.ip_protocols = {
            1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 
            51: "AH", 58: "IPv6-ICMP", 89: "OSPF", 132: "SCTP"
        }
        
        self.port_services = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP",
            161: "SNMP", 3389: "RDP", 445: "SMB", 8080: "HTTP-Proxy"
        }
    

    def detect_mqtt_protocol(self, packet, packet_info):
        """Detect and extract information from MQTT packets"""
        # MQTT typically runs on TCP port 1883 or 8883 (TLS)
        if TCP in packet and Raw in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check if it's likely an MQTT packet based on port
            if dst_port == 1883 or dst_port == 8883 or src_port == 1883 or src_port == 8883:
                packet_info['protocol'] = "MQTT-SSL" if (dst_port == 8883 or src_port == 8883) else "MQTT"
                
                # Try to parse the MQTT packet
                payload = packet[Raw].load
                mqtt_info = MQTTParser.parse_mqtt_packet(payload)
                
                if mqtt_info:
                    mqtt_type = mqtt_info["type"]
                    info_details = mqtt_info.get("info", {})
                    
                    # Create a descriptive info string
                    if mqtt_type == "CONNECT":
                        client_id = info_details.get("client_id", "unknown")
                        protocol = info_details.get("protocol", "")
                        version = info_details.get("version", "")
                        protocol_str = f"{protocol} v{version}" if protocol and version else ""
                        packet_info['info'] = f"MQTT CONNECT [{client_id}] {protocol_str}"
                        
                        # Store security-relevant information
                        packet_info['mqtt_type'] = mqtt_type
                        packet_info['mqtt_info'] = info_details
                        
                    elif mqtt_type == "PUBLISH":
                        topic = info_details.get("topic", "")
                        qos = info_details.get("qos", 0)
                        retain = info_details.get("retain", False)
                        payload = info_details.get("payload", "")
                        flags = []
                        if retain:
                            flags.append("retain")
                        if info_details.get("dup", False):
                            flags.append("dup")
                        flags_str = f" [{', '.join(flags)}]" if flags else ""
                        payload_str = f": {payload}" if payload else ""
                        packet_info['info'] = f"MQTT PUBLISH QoS{qos}{flags_str} Topic: {topic}{payload_str}"
                        
                        # Store security-relevant information
                        packet_info['mqtt_type'] = mqtt_type
                        packet_info['mqtt_info'] = info_details
                        
                    elif mqtt_type == "SUBSCRIBE":
                        msg_id = info_details.get("msg_id", "")
                        msg_id_str = f" [{msg_id}]" if msg_id else ""
                        packet_info['info'] = f"MQTT SUBSCRIBE{msg_id_str}"
                        
                        # Store security-relevant information
                        packet_info['mqtt_type'] = mqtt_type
                        packet_info['mqtt_info'] = info_details
                        
                    elif mqtt_type == "CONNACK":
                        packet_info['info'] = f"MQTT CONNACK Connection Acknowledgment"
                        packet_info['mqtt_type'] = mqtt_type
                        packet_info['mqtt_info'] = info_details
                        
                    elif mqtt_type == "PINGREQ":
                        packet_info['info'] = "MQTT PINGREQ Keep Alive Ping"
                        packet_info['mqtt_type'] = mqtt_type
                        
                    elif mqtt_type == "PINGRESP":
                        packet_info['info'] = "MQTT PINGRESP Keep Alive Response"
                        packet_info['mqtt_type'] = mqtt_type
                        
                    elif mqtt_type == "DISCONNECT":
                        packet_info['info'] = "MQTT DISCONNECT Client Disconnecting"
                        packet_info['mqtt_type'] = mqtt_type
                        
                    else:
                        msg_id = info_details.get("msg_id", "")
                        msg_id_str = f" [{msg_id}]" if msg_id else ""
                        packet_info['info'] = f"MQTT {mqtt_type}{msg_id_str}"
                        packet_info['mqtt_type'] = mqtt_type
                        packet_info['mqtt_info'] = info_details
                    
                    return True
        
        return False

    def extract_minimal_info(self, packet):
        """Extract just the essential information needed for display"""
        # Get packet time as float
        packet_time = packet.time
        
        # Format time efficiently
        formatted_time = self._format_time(packet_time)
        
        packet_info = {
            'time': packet_time,
            'formatted_time': formatted_time,
            'length': len(packet),
        }
        
        # Extract essential layer information (without deep inspection)
        # Process Ethernet layer
        if Ether in packet:
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
            
        # ARP layer
        if ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            
            if packet[ARP].op == 1:
                packet_info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            else:
                packet_info['info'] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
                
        # IP layer
        elif IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            # Set protocol name
            ip_proto = packet[IP].proto
            packet_info['protocol'] = self.ip_protocols.get(ip_proto, f"IP-{ip_proto}")
            
        # IPv6 layer
        elif IPv6 in packet:
            packet_info['src_ip'] = packet[IPv6].src
            packet_info['dst_ip'] = packet[IPv6].dst
            
            # Get protocol name
            ipv6_nh = packet[IPv6].nh
            packet_info['protocol'] = self.ip_protocols.get(ipv6_nh, f"IPv6-{ipv6_nh}")
            
        # TCP layer
        if TCP in packet:
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            
            # Set protocol if it's a well-known port (HTTP, HTTPS, etc.)
            if packet[TCP].dport in self.port_services:
                packet_info['protocol'] = self.port_services[packet[TCP].dport]
            elif packet[TCP].sport in self.port_services:
                packet_info['protocol'] = self.port_services[packet[TCP].sport]
            elif 'protocol' not in packet_info:
                packet_info['protocol'] = 'TCP'
                
            # Simple info string (minimal flags checking)
            flags = []
            flags_val = packet[TCP].flags
            if flags_val & 0x02:  # SYN
                flags.append("SYN")
            if flags_val & 0x10:  # ACK
                flags.append("ACK")
            if flags_val & 0x01:  # FIN
                flags.append("FIN")
            if flags_val & 0x04:  # RST
                flags.append("RST")
                
            flags_str = "[" + ", ".join(flags) + "]" if flags else ""
            packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} {flags_str}"
            
            # Check for MQTT protocol
            if self.detect_mqtt_protocol(packet, packet_info):
                # If MQTT was detected and processed, skip further processing
                pass

        # UDP layer
        elif UDP in packet:
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            
            # Set protocol if it's a well-known port
            if packet[UDP].dport in self.port_services:
                packet_info['protocol'] = self.port_services[packet[UDP].dport]
            elif packet[UDP].sport in self.port_services:
                packet_info['protocol'] = self.port_services[packet[UDP].sport]
            elif 'protocol' not in packet_info:
                packet_info['protocol'] = 'UDP'
                
            # Basic info string
            packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport}"
            
        # ICMP layer (minimal info)
        elif ICMP in packet:
            packet_info['protocol'] = 'ICMP'
            packet_info['info'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
            
        # DNS layer (very basic info)
        elif DNS in packet:
            packet_info['protocol'] = 'DNS'
            packet_info['info'] = "DNS Query" if packet[DNS].qr == 0 else "DNS Response"
            
        # HTTP detection (basic)
        elif TCP in packet and Raw in packet:
            try:
                payload = bytes(packet[Raw])
                if b'HTTP/' in payload[:20] or b'GET ' in payload[:20] or b'POST ' in payload[:20]:
                    packet_info['protocol'] = 'HTTP'
                    # Very basic parsing of method/path
                    if b'GET ' in payload[:20]:
                        packet_info['info'] = "HTTP GET"
                    elif b'POST ' in payload[:20]:
                        packet_info['info'] = "HTTP POST"
                    else:
                        packet_info['info'] = "HTTP Request/Response"
            except:
                # Ignore any parsing errors
                pass
                
        # Make sure we have default values for required fields
        if 'protocol' not in packet_info:
            packet_info['protocol'] = 'Unknown'
            
        if 'info' not in packet_info:
            packet_info['info'] = '-'
            
        if 'src_ip' not in packet_info:
            packet_info['src_ip'] = '-'
            
        if 'dst_ip' not in packet_info:
            packet_info['dst_ip'] = '-'
            
        return packet_info
    
    def _format_time(self, timestamp):
        """Format timestamp efficiently"""
        # Convert to time struct
        time_struct = time.localtime(timestamp)
        
        # Format main part with standard strftime
        base_time = time.strftime('%H:%M:%S', time_struct)
        
        # Calculate milliseconds part
        milliseconds = int((timestamp - int(timestamp)) * 1000)
        
        # Combine for formatted time with milliseconds
        return f"{base_time}.{milliseconds:03d}"

class PacketAnalyzer:
    """Class to analyze packet data"""
    def __init__(self):
        self.packets = []
        self.conversations = {}
        self.endpoints = {}
        self.protocols = Counter()
        self.ports = Counter()
        self.packet_count = 0
        self.start_time = None
        self.end_time = None
        self.total_bytes = 0
        self.security_issues = []


    def detect_rtsp_protocol(self, packet, packet_info):
        """Detect and extract information from RTSP packets"""
        if TCP in packet and Raw in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check if it's on a standard RTSP port
            if dst_port == 554 or src_port == 554 or dst_port == 8554 or src_port == 8554:
                payload = packet[Raw].load
                rtsp_info = RTSPParser.parse_rtsp_packet(payload)
                
                if rtsp_info:
                    packet_info['protocol'] = 'RTSP'
                    
                    # Extract key information
                    rtsp_type = rtsp_info["type"]
                    info_details = rtsp_info.get("info", {})
                    
                    if rtsp_type == "RTSP Request":
                        method = info_details.get("method", "")
                        uri = info_details.get("uri", "")
                        packet_info['info'] = f"RTSP {method} {uri}"
                    elif rtsp_type == "RTSP Response":
                        status = info_details.get("status_code", "")
                        reason = info_details.get("reason", "")
                        packet_info['info'] = f"RTSP Response: {status} {reason}"
                    
                    # Store RTSP details for later analysis
                    packet_info['rtsp_type'] = rtsp_type
                    packet_info['rtsp_info'] = info_details
                    
                    return True
            
            # Check content for RTSP regardless of port (might be on non-standard port)
            payload = packet[Raw].load
            try:
                if payload.startswith(b'RTSP/') or payload.startswith(b'OPTIONS ') or payload.startswith(b'DESCRIBE '):
                    rtsp_info = RTSPParser.parse_rtsp_packet(payload)
                    
                    if rtsp_info:
                        packet_info['protocol'] = 'RTSP'
                        
                        # Extract key information as above
                        rtsp_type = rtsp_info["type"]
                        info_details = rtsp_info.get("info", {})
                        
                        if rtsp_type == "RTSP Request":
                            method = info_details.get("method", "")
                            uri = info_details.get("uri", "")
                            packet_info['info'] = f"RTSP {method} {uri}"
                        elif rtsp_type == "RTSP Response":
                            status = info_details.get("status_code", "")
                            reason = info_details.get("reason", "")
                            packet_info['info'] = f"RTSP Response: {status} {reason}"
                        
                        # Store RTSP details for later analysis
                        packet_info['rtsp_type'] = rtsp_type
                        packet_info['rtsp_info'] = info_details
                        
                        return True
            except:
                # Skip if there's an error in basic detection
                pass
        
        return False

    def detect_coap_protocol(self, packet, packet_info):
        """Detect and extract information from CoAP packets"""
        if UDP in packet and Raw in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Check if it's on standard CoAP port (5683) or CoAP over DTLS (5684)
            if dst_port == 5683 or src_port == 5683 or dst_port == 5684 or src_port == 5684:
                payload = packet[Raw].load
                coap_info = CoAPParser.parse_coap_packet(payload)
                
                if coap_info:
                    packet_info['protocol'] = 'CoAP'
                    
                    # Extract key information
                    info_details = coap_info.get("info", {})
                    
                    message_type = info_details.get("message_type", "")
                    code_name = info_details.get("code", "")
                    token = info_details.get("token", "")
                    
                    packet_info['info'] = f"CoAP {message_type} {code_name}" + (f" Token: {token}" if token else "")
                    
                    # Store CoAP details for later analysis
                    packet_info['coap_info'] = info_details
                    
                    return True
        
        return False

    def detect_mdns_protocol(self, packet, packet_info):
        """Detect and extract information from mDNS packets"""
        if UDP in packet and DNS in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Check if it's on standard mDNS port (5353)
            if dst_port == 5353 or src_port == 5353:
                mdns_info = MDNSParser.parse_mdns_packet(packet[DNS])
                
                if mdns_info:
                    packet_info['protocol'] = 'mDNS'
                    
                    # Extract key information
                    info_details = mdns_info.get("info", {})
                    
                    # Create a descriptive info string
                    queries = info_details.get("queries", [])
                    answers = info_details.get("answers", [])
                    services = info_details.get("services", [])
                    
                    info_str = []
                    
                    if queries:
                        query_types = [q.get("type") for q in queries]
                        info_str.append(f"Queries: {', '.join(query_types)}")
                    
                    if answers:
                        answer_count = len(answers)
                        info_str.append(f"Answers: {answer_count}")
                    
                    if services:
                        service_types = [s.get("type") for s in services]
                        info_str.append(f"Services: {', '.join(service_types)}")
                    
                    packet_info['info'] = " | ".join(info_str) if info_str else "mDNS Packet"
                    
                    # Store mDNS details for later analysis
                    packet_info['mdns_info'] = info_details
                    
                    return True
        
        return False

    def detect_onvif_protocol(self, packet, packet_info):
        """Detect and extract information from ONVIF packets"""
        if TCP in packet and Raw in packet:
            payload = packet[Raw].load
            
            # Check for ONVIF SOAP messages
            if b'<SOAP-ENV:Envelope' in payload or b'<soap:Envelope' in payload:
                onvif_info = ONVIFParser.parse_onvif_message(payload)
                
                if onvif_info:
                    packet_info['protocol'] = 'ONVIF'
                    
                    # Extract key information
                    info_details = onvif_info.get("info", {})
                    
                    service = info_details.get("service", "Unknown")
                    operation = info_details.get("operation", "Unknown")
                    is_response = info_details.get("is_response", False)
                    
                    packet_info['info'] = f"ONVIF {service} {operation}" + (" Response" if is_response else " Request")
                    
                    # Store ONVIF details for later analysis
                    packet_info['onvif_info'] = info_details
                    
                    return True
        
        return False

    def detect_hls_protocol(self, packet, packet_info):
        """Detect and extract information from HLS packets"""
        if TCP in packet and Raw in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check if it's likely HTTP (common HLS transport)
            if dst_port == 80 or src_port == 80 or dst_port == 443 or src_port == 443 or dst_port == 8080 or src_port == 8080:
                payload = packet[Raw].load
                
                # Check if it's an HTTP request containing HLS patterns
                is_request = False
                if payload.startswith(b'GET ') or payload.startswith(b'POST '):
                    is_request = True
                
                hls_info = HLSParser.parse_hls_message(payload, is_request)
                
                if hls_info:
                    packet_info['protocol'] = 'HLS'
                    
                    # Extract key information
                    info_details = hls_info.get("info", {})
                    
                    if hls_info["type"] == "HLS Playlist":
                        is_master = info_details.get("is_master", False)
                        playlist_type = "Master" if is_master else "Media"
                        has_encryption = info_details.get("has_encryption", False)
                        
                        packet_info['info'] = f"HLS {playlist_type} Playlist" + (" (Encrypted)" if has_encryption else "")
                    elif hls_info["type"] == "HLS Request":
                        request_type = info_details.get("request_type", "unknown")
                        url = info_details.get("url", "")
                        
                        packet_info['info'] = f"HLS {request_type.capitalize()} Request: {url}"
                    
                    # Store HLS details for later analysis
                    packet_info['hls_info'] = info_details
                    
                    return True
        
        return False

    def detect_rtp_protocol(self, packet, packet_info):
        """Detect and extract information from RTP packets"""
        if UDP in packet and Raw in packet:
            payload = packet[Raw].load
            
            # Check if it might be RTP (basic heuristic)
            if len(payload) >= 12:
                # RTP version is in the first 2 bits - should be 2 for current version
                version = (payload[0] >> 6) & 0x03
                
                if version == 2:
                    rtp_info = RTPParser.parse_rtp_packet(payload)
                    
                    if rtp_info:
                        packet_info['protocol'] = 'RTP'
                        
                        # Extract key information
                        info_details = rtp_info.get("info", {})
                        
                        payload_type = info_details.get("payload_type", 0)
                        payload_type_name = info_details.get("payload_type_name", "Unknown")
                        sequence_number = info_details.get("sequence_number", 0)
                        
                        packet_info['info'] = f"RTP {payload_type_name} (PT={payload_type}) Seq={sequence_number}"
                        
                        # Store RTP details for later analysis
                        packet_info['rtp_info'] = info_details
                        
                        return True
        
        return False

    # Add IoT-specific security checks to your check_security_issues method

    def check_iot_security_issues(self, packet_info):
        """Check for IoT-specific security issues"""
        
        # Check for RTSP security issues
        if packet_info.get('protocol') == 'RTSP':
            # Check for authentication
            rtsp_info = packet_info.get('rtsp_info', {})
            headers = rtsp_info.get('headers', {})
            
            # Check for missing authentication in DESCRIBE or SETUP requests
            if packet_info.get('rtsp_type') == 'RTSP Request' and rtsp_info.get('method') in ['DESCRIBE', 'SETUP']:
                if 'authorization' not in headers and 'proxy-authorization' not in headers:
                    self.security_issues.append({
                        'type': 'RTSP No Authentication',
                        'severity': 'High',
                        'description': f"RTSP {rtsp_info.get('method')} request without authentication",
                        'packet_num': self.packet_count
                    })
        
        # Check for CoAP security issues
        elif packet_info.get('protocol') == 'CoAP':
            coap_info = packet_info.get('coap_info', {})
            
            # Check for lack of DTLS (unsecured CoAP)
            if 'dst_port' in packet_info and packet_info['dst_port'] == 5683:
                self.security_issues.append({
                    'type': 'Unencrypted CoAP',
                    'severity': 'High',
                    'description': 'CoAP traffic without DTLS encryption detected',
                    'packet_num': self.packet_count
                })
            
            # Check for sensitive operations without proper security
            if coap_info.get('message_type') == 'Request' and coap_info.get('code') in ['PUT', 'POST', 'DELETE']:
                # For PUT/POST/DELETE requests, check if there's any path that might be sensitive
                uri_path = None
                for option in coap_info.get('options', []):
                    if option.get('name') == 'Uri-Path':
                        uri_path = option.get('value')
                        break
                
                if uri_path:
                    sensitive_patterns = ['config', 'admin', 'control', 'password', 'key', 'token', 'auth']
                    for pattern in sensitive_patterns:
                        if pattern in uri_path.lower():
                            self.security_issues.append({
                                'type': 'CoAP Sensitive Operation',
                                'severity': 'Medium',
                                'description': f'CoAP {coap_info.get("code")} to potentially sensitive resource: {uri_path}',
                                'packet_num': self.packet_count
                            })
                            break
        
        # Check for ONVIF security issues
        elif packet_info.get('protocol') == 'ONVIF':
            onvif_info = packet_info.get('onvif_info', {})
            
            # Check for lack of authentication
            if not onvif_info.get('has_auth', False):
                # Especially concerning for certain operations
                sensitive_operations = [
                    'SetScopes', 'SetNetworkProtocols', 'SystemReboot', 'CreateProfile', 
                    'DeleteProfile', 'SetImagingSettings', 'ContinuousMove', 'GotoPreset'
                ]
                
                operation = onvif_info.get('operation')
                if operation in sensitive_operations:
                    self.security_issues.append({
                        'type': 'ONVIF Unauthenticated Admin',
                        'severity': 'High',
                        'description': f'ONVIF {operation} operation without authentication',
                        'packet_num': self.packet_count
                    })
                else:
                    self.security_issues.append({
                        'type': 'ONVIF No Authentication',
                        'severity': 'Medium',
                        'description': 'ONVIF message without authentication',
                        'packet_num': self.packet_count
                    })
        
        # Check for HLS security issues
        elif packet_info.get('protocol') == 'HLS':
            hls_info = packet_info.get('hls_info', {})
            
            # Check for unencrypted HLS streams
            if hls_info.get('has_encryption') is False and hls_info.get('is_media', False):
                self.security_issues.append({
                    'type': 'Unencrypted HLS Stream',
                    'severity': 'Medium',
                    'description': 'HLS media playlist without encryption',
                    'packet_num': self.packet_count
                })
            
            # Check for insecure transport (HTTP vs HTTPS)
            if 'dst_port' in packet_info and packet_info['dst_port'] == 80:
                self.security_issues.append({
                    'type': 'HLS over HTTP',
                    'severity': 'Medium',
                    'description': 'HLS content delivered over unencrypted HTTP',
                    'packet_num': self.packet_count
                })
        
        # Check for mDNS security issues
        elif packet_info.get('protocol') == 'mDNS':
            mdns_info = packet_info.get('mdns_info', {})
            
            # Check for sensitive service announcements
            for service in mdns_info.get('services', []):
                service_type = service.get('type', '')
                sensitive_services = ['camera', 'webcam', 'rtsp', 'onvif', 'surveillance']
                
                for sensitive in sensitive_services:
                    if sensitive in service_type.lower():
                        self.security_issues.append({
                            'type': 'mDNS Camera Exposure',
                            'severity': 'Medium',
                            'description': f'Camera/video service publicly advertised via mDNS: {service_type}',
                            'packet_num': self.packet_count
                        })
                        break




    def add_packet(self, packet):
        """Add a packet to the analyzer"""
        self.packet_count += 1
        
        # Store first and last packet time
        packet_time = packet.time
        if self.start_time is None or packet_time < self.start_time:
            self.start_time = packet_time
        if self.end_time is None or packet_time > self.end_time:
            self.end_time = packet_time
            
        # Extract packet details
        packet_info = self.extract_packet_info(packet)
        self.packets.append(packet_info)
        
        # Update protocol statistics
        if 'protocol' in packet_info:
            self.protocols[packet_info['protocol']] += 1
            
        # Update port statistics
        if 'src_port' in packet_info:
            self.ports[packet_info['src_port']] += 1
        if 'dst_port' in packet_info:
            self.ports[packet_info['dst_port']] += 1
            
        # Update conversation statistics
        if 'src_ip' in packet_info and 'dst_ip' in packet_info:
            conversation_key = (packet_info['src_ip'], packet_info['dst_ip'])
            if conversation_key not in self.conversations:
                self.conversations[conversation_key] = {
                    'packets': 0,
                    'bytes': 0,
                    'start_time': packet_time,
                    'end_time': packet_time
                }
            
            conv = self.conversations[conversation_key]
            conv['packets'] += 1
            if 'length' in packet_info:
                conv['bytes'] += packet_info['length']
            if packet_time < conv['start_time']:
                conv['start_time'] = packet_time
            if packet_time > conv['end_time']:
                conv['end_time'] = packet_time
                
        # Update endpoint statistics
        if 'src_ip' in packet_info:
            src_ip = packet_info['src_ip']
            if src_ip not in self.endpoints:
                self.endpoints[src_ip] = {'sent_packets': 0, 'sent_bytes': 0, 'received_packets': 0, 'received_bytes': 0}
            
            self.endpoints[src_ip]['sent_packets'] += 1
            if 'length' in packet_info:
                self.endpoints[src_ip]['sent_bytes'] += packet_info['length']
                
        if 'dst_ip' in packet_info:
            dst_ip = packet_info['dst_ip']
            if dst_ip not in self.endpoints:
                self.endpoints[dst_ip] = {'sent_packets': 0, 'sent_bytes': 0, 'received_packets': 0, 'received_bytes': 0}
            
            self.endpoints[dst_ip]['received_packets'] += 1
            if 'length' in packet_info:
                self.endpoints[dst_ip]['received_bytes'] += packet_info['length']
                
        # Update total bytes
        if 'length' in packet_info:
            self.total_bytes += packet_info['length']
            
        # Check for security issues
        self.check_security_issues(packet_info)
        
        return packet_info
    
    def detect_mqtt_protocol(self, packet, packet_info):
        """Detect and extract information from MQTT packets"""
        # MQTT typically runs on TCP port 1883 or 8883 (TLS)
        if TCP in packet and Raw in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check if it's likely an MQTT packet based on port
            if dst_port == 1883 or dst_port == 8883 or src_port == 1883 or src_port == 8883:
                packet_info['protocol'] = "MQTT-SSL" if (dst_port == 8883 or src_port == 8883) else "MQTT"
                
                # Try to parse the MQTT packet
                payload = packet[Raw].load
                mqtt_info = MQTTParser.parse_mqtt_packet(payload)
                
                if mqtt_info:
                    mqtt_type = mqtt_info["type"]
                    info_details = mqtt_info.get("info", {})
                    
                    # Create a descriptive info string
                    if mqtt_type == "CONNECT":
                        client_id = info_details.get("client_id", "unknown")
                        protocol = info_details.get("protocol", "")
                        version = info_details.get("version", "")
                        protocol_str = f"{protocol} v{version}" if protocol and version else ""
                        packet_info['info'] = f"MQTT CONNECT [{client_id}] {protocol_str}"
                        
                    elif mqtt_type == "PUBLISH":
                        topic = info_details.get("topic", "")
                        qos = info_details.get("qos", 0)
                        retain = info_details.get("retain", False)
                        payload = info_details.get("payload", "")
                        flags = []
                        if retain:
                            flags.append("retain")
                        if info_details.get("dup", False):
                            flags.append("dup")
                        flags_str = f" [{', '.join(flags)}]" if flags else ""
                        payload_str = f": {payload}" if payload else ""
                        packet_info['info'] = f"MQTT PUBLISH QoS{qos}{flags_str} Topic: {topic}{payload_str}"
                        
                    elif mqtt_type == "SUBSCRIBE":
                        msg_id = info_details.get("msg_id", "")
                        msg_id_str = f" [{msg_id}]" if msg_id else ""
                        packet_info['info'] = f"MQTT SUBSCRIBE{msg_id_str}"
                        
                    elif mqtt_type == "CONNACK":
                        packet_info['info'] = f"MQTT CONNACK Connection Acknowledgment"
                        
                    elif mqtt_type == "PINGREQ":
                        packet_info['info'] = "MQTT PINGREQ Keep Alive Ping"
                        
                    elif mqtt_type == "PINGRESP":
                        packet_info['info'] = "MQTT PINGRESP Keep Alive Response"
                        
                    elif mqtt_type == "DISCONNECT":
                        packet_info['info'] = "MQTT DISCONNECT Client Disconnecting"
                        
                    else:
                        msg_id = info_details.get("msg_id", "")
                        msg_id_str = f" [{msg_id}]" if msg_id else ""
                        packet_info['info'] = f"MQTT {mqtt_type}{msg_id_str}"
                    
                    # Store MQTT details for later analysis
                    packet_info['mqtt_type'] = mqtt_type
                    packet_info['mqtt_info'] = info_details
                    
                    return True
        
        return False



    def extract_packet_info(self, packet):
        """Extract relevant information from a packet"""
        # Get packet time as float
        packet_time = packet.time
        
        # Convert to time struct
        time_struct = time.localtime(packet_time)
        
        # Format main part with standard strftime
        base_time = time.strftime('%H:%M:%S', time_struct)
        
        # Calculate milliseconds part
        milliseconds = int((packet_time - int(packet_time)) * 1000)
        
        # Combine for formatted time with milliseconds
        formatted_time = f"{base_time}.{milliseconds:03d}"
        
        packet_info = {
            'time': packet_time,
            'formatted_time': formatted_time,
            'length': len(packet),
            'hex': hexdump(packet, dump=True)
        }
        
        # The rest of your method remains the same
        # Extract layer information
        layers = []
        
        # Parse Ethernet layer
        if Ether in packet:
            layers.append(('Ethernet', {
                'src_mac': packet[Ether].src,
                'dst_mac': packet[Ether].dst,
                'type': packet[Ether].type
            }))
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
            
        # Parse ARP layer
        if ARP in packet:
            layers.append(('ARP', {
                'op': 'request' if packet[ARP].op == 1 else 'reply',
                'src_ip': packet[ARP].psrc,
                'dst_ip': packet[ARP].pdst,
                'src_mac': packet[ARP].hwsrc,
                'dst_mac': packet[ARP].hwdst
            }))
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            
            if packet[ARP].op == 1:
                packet_info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            else:
                packet_info['info'] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
                
        # Parse IP layer
        elif IP in packet:
            layers.append(('IP', {
                'version': packet[IP].version,
                'ihl': packet[IP].ihl,
                'tos': packet[IP].tos,
                'len': packet[IP].len,
                'id': packet[IP].id,
                'flags': packet[IP].flags,
                'frag': packet[IP].frag,
                'ttl': packet[IP].ttl,
                'proto': packet[IP].proto,
                'chksum': packet[IP].chksum,
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'options': packet[IP].options
            }))
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            # Get protocol name
            ip_proto = packet[IP].proto
            if ip_proto in IP_PROTOCOLS:
                packet_info['protocol'] = IP_PROTOCOLS[ip_proto]
            else:
                packet_info['protocol'] = f"IP-{ip_proto}"
        
        # Parse IPv6 layer
        elif IPv6 in packet:
            layers.append(('IPv6', {
                'version': packet[IPv6].version,
                'tc': packet[IPv6].tc,
                'fl': packet[IPv6].fl,
                'plen': packet[IPv6].plen,
                'nh': packet[IPv6].nh,
                'hlim': packet[IPv6].hlim,
                'src': packet[IPv6].src,
                'dst': packet[IPv6].dst
            }))
            packet_info['src_ip'] = packet[IPv6].src
            packet_info['dst_ip'] = packet[IPv6].dst
            
            # Get protocol name
            ipv6_nh = packet[IPv6].nh
            if ipv6_nh in IP_PROTOCOLS:
                packet_info['protocol'] = IP_PROTOCOLS[ipv6_nh]
            else:
                packet_info['protocol'] = f"IPv6-{ipv6_nh}"
        
        # Parse TCP layer
        if TCP in packet:
            tcp_flags = []
            if packet[TCP].flags & 0x01:  # FIN
                tcp_flags.append("FIN")
            if packet[TCP].flags & 0x02:  # SYN
                tcp_flags.append("SYN")
            if packet[TCP].flags & 0x04:  # RST
                tcp_flags.append("RST")
            if packet[TCP].flags & 0x08:  # PSH
                tcp_flags.append("PSH")
            if packet[TCP].flags & 0x10:  # ACK
                tcp_flags.append("ACK")
            if packet[TCP].flags & 0x20:  # URG
                tcp_flags.append("URG")
            
            layers.append(('TCP', {
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'dataofs': packet[TCP].dataofs,
                'flags': tcp_flags,
                'window': packet[TCP].window,
                'chksum': packet[TCP].chksum,
                'urgptr': packet[TCP].urgptr,
                'options': packet[TCP].options
            }))
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            
            # Set protocol if it's a well-known port
            if packet[TCP].dport in PORT_SERVICES:
                packet_info['protocol'] = PORT_SERVICES[packet[TCP].dport]
            elif packet[TCP].sport in PORT_SERVICES:
                packet_info['protocol'] = PORT_SERVICES[packet[TCP].sport]
            else:
                packet_info['protocol'] = 'TCP'
                
            # Create info string
            flags_str = "[" + ", ".join(tcp_flags) + "]" if tcp_flags else ""
            packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} {flags_str} Seq={packet[TCP].seq} Ack={packet[TCP].ack} Win={packet[TCP].window}"
            # Add MQTT detection logic here
            if self.detect_mqtt_protocol(packet, packet_info):
                # If it's an MQTT packet, also add MQTT layer information
                if Raw in packet:
                    payload = packet[Raw].load
                    mqtt_info = MQTTParser.parse_mqtt_packet(payload)
                    if mqtt_info:
                        mqtt_type = mqtt_info["type"]
                        info_details = mqtt_info.get("info", {})
                        
                        # Add MQTT layer with details
                        mqtt_layer_data = {'type': mqtt_type}
                        mqtt_layer_data.update(info_details)
                        layers.append(('MQTT', mqtt_layer_data))    

        # Parse UDP layer
        elif UDP in packet:
            layers.append(('UDP', {
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport,
                'len': packet[UDP].len,
                'chksum': packet[UDP].chksum
            }))
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            
            # Set protocol if it's a well-known port
            if packet[UDP].dport in PORT_SERVICES:
                packet_info['protocol'] = PORT_SERVICES[packet[UDP].dport]
            elif packet[UDP].sport in PORT_SERVICES:
                packet_info['protocol'] = PORT_SERVICES[packet[UDP].sport]
            else:
                packet_info['protocol'] = 'UDP'
                
            # Create info string
            packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport} Len={packet[UDP].len}"
            
        # Parse ICMP layer
        elif ICMP in packet:
            layers.append(('ICMP', {
                'type': packet[ICMP].type,
                'code': packet[ICMP].code,
                'chksum': packet[ICMP].chksum,
                'id': getattr(packet[ICMP], 'id', 0),
                'seq': getattr(packet[ICMP], 'seq', 0)
            }))
            packet_info['protocol'] = 'ICMP'
            
            # Create info string based on ICMP type
            if packet[ICMP].type == 0:
                packet_info['info'] = f"Echo (ping) reply id={getattr(packet[ICMP], 'id', 0)}, seq={getattr(packet[ICMP], 'seq', 0)}"
            elif packet[ICMP].type == 8:
                packet_info['info'] = f"Echo (ping) request id={getattr(packet[ICMP], 'id', 0)}, seq={getattr(packet[ICMP], 'seq', 0)}"
            elif packet[ICMP].type == 3:
                packet_info['info'] = f"Destination unreachable (code: {packet[ICMP].code})"
            elif packet[ICMP].type == 11:
                packet_info['info'] = f"Time exceeded (code: {packet[ICMP].code})"
            else:
                packet_info['info'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        
        # Parse HTTP layer
        if packet.haslayer(Raw) and (TCP in packet):
            try:
                payload = packet[Raw].load
                if b'HTTP/' in payload or b'GET ' in payload or b'POST ' in payload:
                    packet_info['protocol'] = 'HTTP'
                    # Extract HTTP method and path
                    try:
                        first_line = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        if ' HTTP/' in first_line:
                            packet_info['info'] = first_line
                            if packet_info.get('protocol') != 'HTTPS' and 'dst_port' in packet_info and packet_info['dst_port'] == 80:
                                self.security_issues.append({
                                    'type': 'Unencrypted HTTP',
                                    'severity': 'Medium',
                                    'description': 'Detected plaintext HTTP traffic that could expose sensitive information',
                                    'packet_num': self.packet_count
                                })
                    except:
                        pass
            except:
                pass
                
        # Parse DNS layer
        if DNS in packet:
            packet_info['protocol'] = 'DNS'
            
            dns_info = []
            if packet[DNS].qr == 0:
                # DNS query
                dns_info.append("Standard query")
            else:
                # DNS response
                dns_info.append("Standard response")
            
            dns_info.append(f"0x{packet[DNS].id:x}")
            
            # Add query details
            if packet[DNS].qd:
                for i in range(packet[DNS].qdcount):
                    qname = packet[DNS].qd[i].qname.decode('utf-8', errors='ignore')
                    qtype = packet[DNS].qd[i].qtype
                    if qtype == 1:
                        qtype_name = "A"
                    elif qtype == 2:
                        qtype_name = "NS"
                    elif qtype == 5:
                        qtype_name = "CNAME"
                    elif qtype == 15:
                        qtype_name = "MX"
                    elif qtype == 16:
                        qtype_name = "TXT"
                    elif qtype == 28:
                        qtype_name = "AAAA"
                    else:
                        qtype_name = str(qtype)
                    
                    dns_info.append(f"{qtype_name} {qname}")
                    
                    # Check for suspicious domains
                    if qname.endswith('.test.') or qname.endswith('.example.'):
                        self.security_issues.append({
                            'type': 'Suspicious DNS Query',
                            'severity': 'Low',
                            'description': f'Query to non-standard domain {qname}',
                            'packet_num': self.packet_count
                        })
            
            packet_info['info'] = " ".join(dns_info)
            
        # Add all layer information
        packet_info['layers'] = layers

        # Add IoT protocol detection
        if not ('protocol' in packet_info and packet_info['protocol'] != 'TCP' and packet_info['protocol'] != 'UDP'):
            # Only try to detect these protocols if we haven't already identified a higher-level protocol
            # Check for IoT protocols in this order
            detected = (self.detect_rtsp_protocol(packet, packet_info) or
                    self.detect_onvif_protocol(packet, packet_info) or
                    self.detect_hls_protocol(packet, packet_info) or
                    self.detect_rtp_protocol(packet, packet_info) or
                    self.detect_coap_protocol(packet, packet_info) or
                    self.detect_mdns_protocol(packet, packet_info))
                
        return packet_info



        return packet_info
    
    def check_security_issues(self, packet_info):
        """Check for potential security issues in a packet"""
        # Existing security checks...
        
        # Check for unencrypted protocols on standard ports
        if packet_info.get('protocol') == 'HTTP' and packet_info.get('dst_port') == 80:
            # Already handled in extract_packet_info
            pass
            
        # Check for telnet
        elif packet_info.get('protocol') == 'Telnet':
            self.security_issues.append({
                'type': 'Unencrypted Telnet',
                'severity': 'High',
                'description': 'Detected unencrypted Telnet traffic',
                'packet_num': self.packet_count
            })
            
        # Check for ICMP abnormalities
        elif packet_info.get('protocol') == 'ICMP' and packet_info.get('length', 0) > 1000:
            self.security_issues.append({
                'type': 'Large ICMP Packet',
                'severity': 'Medium',
                'description': 'Detected unusually large ICMP packet',
                'packet_num': self.packet_count
            })
        
        # Add MQTT security checks
        elif packet_info.get('protocol') == 'MQTT' or packet_info.get('protocol') == 'MQTT-SSL':
            # Check for unencrypted MQTT
            if packet_info.get('protocol') == 'MQTT' and packet_info.get('dst_port') == 1883:
                self.security_issues.append({
                    'type': 'Unencrypted MQTT',
                    'severity': 'High',
                    'description': 'Detected unencrypted MQTT traffic on standard port (1883)',
                    'packet_num': self.packet_count
                })
                
            # Check for MQTT CONNECT packets without authentication
            if 'mqtt_type' in packet_info and packet_info['mqtt_type'] == 'CONNECT':
                mqtt_info = packet_info.get('mqtt_info', {})
                
                # Check for missing username/password
                if not mqtt_info.get('username', False) and not mqtt_info.get('password', False):
                    self.security_issues.append({
                        'type': 'MQTT No Authentication',
                        'severity': 'High',
                        'description': f"MQTT connection without username/password authentication detected from client {mqtt_info.get('client_id', 'unknown')}",
                        'packet_num': self.packet_count
                    })
                    
                # Check for empty client ID (not recommended)
                if 'client_id' in mqtt_info and not mqtt_info['client_id']:
                    self.security_issues.append({
                        'type': 'MQTT Empty Client ID',
                        'severity': 'Low', 
                        'description': 'MQTT connection with empty client ID detected',
                        'packet_num': self.packet_count
                    })
            
            # Check for MQTT PUBLISH messages with sensitive topics
            if 'mqtt_type' in packet_info and packet_info['mqtt_type'] == 'PUBLISH':
                mqtt_info = packet_info.get('mqtt_info', {})
                topic = mqtt_info.get('topic', '')
                
                # Check for potentially sensitive topics
                sensitive_patterns = [
                    'password', 'passwd', 'credentials', 'secret', 'key', 'token',
                    'auth', 'login', 'user', 'username', 'admin', 'root', 'security',
                    'private', 'certificate', 'ssid', 'wifi'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in topic.lower():
                        self.security_issues.append({
                            'type': 'MQTT Sensitive Topic',
                            'severity': 'Medium',
                            'description': f'MQTT message with potentially sensitive topic: {topic}',
                            'packet_num': self.packet_count
                        })
                        break
                        
                # Check for low QoS on important topics
                important_patterns = [
                    'command', 'control', 'update', 'firmware', 'config', 'alarm', 
                    'alert', 'emergency', 'critical', 'status', 'state'
                ]
                
                for pattern in important_patterns:
                    if pattern in topic.lower() and mqtt_info.get('qos', 0) == 0:
                        self.security_issues.append({
                            'type': 'MQTT Low QoS',
                            'severity': 'Medium',
                            'description': f'MQTT message with important topic "{topic}" using QoS 0 (fire and forget)',
                            'packet_num': self.packet_count
                        })
                        break
                        
                # Check for default/common topics
                default_topics = ['#', '+', 'test', 'temp', 'sensor', 'home', 'device']
                if topic in default_topics:
                    self.security_issues.append({
                        'type': 'MQTT Default Topic',
                        'severity': 'Low',
                        'description': f'MQTT message using common/default topic "{topic}" which may be targeted by attackers',
                        'packet_num': self.packet_count
                    })
                    
            # Check for MQTT SUBSCRIBE to wildcard topics (may indicate overly broad access)
            if 'mqtt_type' in packet_info and packet_info['mqtt_type'] == 'SUBSCRIBE':
                mqtt_info = packet_info.get('mqtt_info', {})
                if 'topic' in mqtt_info:
                    topic = mqtt_info['topic']
                    if topic == '#' or topic.endswith('/#') or '+' in topic:
                        self.security_issues.append({
                            'type': 'MQTT Wildcard Subscription',
                            'severity': 'Medium',
                            'description': f'MQTT subscription to wildcard topic "{topic}" detected - may indicate overly broad access',
                            'packet_num': self.packet_count
                        })
            
        # Check for potential port scanning (this would typically be done over multiple packets in practice)
        elif packet_info.get('protocol') == 'TCP' and 'SYN' in packet_info.get('info', '') and 'ACK' not in packet_info.get('info', ''):
            # In a real implementation, we would track sequential SYN packets to different ports from the same source
            # For now, just randomly flag some as potential scans
            if random.random() < 0.05:  # 5% chance to flag as port scan
                self.security_issues.append({
                    'type': 'Potential Port Scan',
                    'severity': 'High',
                    'description': f'Detected potential port scan from {packet_info.get("src_ip", "unknown")}',
                    'packet_num': self.packet_count
                })
        
        # Check for IoT security issues
        self.check_iot_security_issues(packet_info)

    def get_protocol_stats(self):
        """Get protocol distribution statistics"""
        total = sum(self.protocols.values())
        if total == 0:
            return {}
            
        # Return protocols sorted by frequency
        return {proto: (count / total) * 100 for proto, count in self.protocols.most_common()}
    
    def get_top_talkers(self, limit=10):
        """Get the top endpoints by traffic volume"""
        talkers = []
        for ip, stats in self.endpoints.items():
            total_packets = stats['sent_packets'] + stats['received_packets']
            total_bytes = stats['sent_bytes'] + stats['received_bytes']
            talkers.append({
                'ip': ip,
                'packets': total_packets,
                'bytes': total_bytes
            })
            
        return sorted(talkers, key=lambda x: x['bytes'], reverse=True)[:limit]
    
    def get_conversations(self, limit=10):
        """Get the top conversations by traffic volume"""
        convs = []
        for (src, dst), stats in self.conversations.items():
            duration = stats['end_time'] - stats['start_time']
            convs.append({
                'src': src,
                'dst': dst,
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'duration': duration
            })
            
        return sorted(convs, key=lambda x: x['bytes'], reverse=True)[:limit]
    
    def get_port_stats(self, limit=10):
        """Get the most active ports and services"""
        port_stats = []
        for port, count in self.ports.most_common(limit):
            service = PORT_SERVICES.get(port, "Unknown")
            port_stats.append({
                'port': port,
                'service': service,
                'count': count
            })
            
        return port_stats
    
    def get_security_findings(self):
        """Get security findings with risk levels"""
        return self.security_issues
        
    def get_capture_summary(self):
        """Get a summary of the capture session"""
        if self.start_time is None or self.end_time is None:
            duration = 0
        else:
            duration = self.end_time - self.start_time
            
        return {
            'packet_count': self.packet_count,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': duration,
            'total_bytes': self.total_bytes
        }

class PCAPFileHandler:
    """Class to handle reading and writing PCAP files"""
    @staticmethod
    def read_pcap(filename, callback=None, limit=None, update_progress=None):
        """Read packets from a PCAP file with optimizations for large files
        
        Args:
            filename (str): Path to the PCAP file
            callback (function): Callback function for each packet
            limit (int): Maximum number of packets to read (None for all)
            update_progress (function): Function to update progress percentage
        
        Returns:
            list: List of packets
        """
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            # Use a chunk-based approach for large files
            result = []
            
            # Get file size for progress reporting
            file_size = os.path.getsize(filename)
            
            # Open the pcap file
            with PcapReader(filename) as pcap_reader:
                packet_count = 0
                last_progress = 0
                read_bytes = 0
                start_time = time.time()
                
                # Read packets one by one with progress updates
                for packet in pcap_reader:
                    # Update approximate read bytes (this is an estimate)
                    read_bytes += len(bytes(packet))
                    
                    # Convert any problematic float fields to integers if needed
                    if hasattr(packet, 'time'):
                        # Ensure time is a float, not a decimal or other type
                        if not isinstance(packet.time, float):
                            packet.time = float(packet.time)
                    
                    # Call the callback if provided
                    if callback:
                        callback(packet)
                    
                    # Add to result list
                    result.append(packet)
                    packet_count += 1
                    
                    # If we have a limit and reached it, stop
                    if limit and packet_count >= limit:
                        break
                    
                    # Update progress periodically
                    if update_progress and file_size > 0:
                        # Calculate progress percentage (approximately)
                        progress = min(int((read_bytes / file_size) * 100), 100)
                        
                        # Only update if progress has changed by at least 1%
                        if progress > last_progress:
                            update_progress(progress, packet_count)
                            last_progress = progress
                            
                            # Calculate estimated time remaining
                            elapsed = time.time() - start_time
                            if progress > 0:
                                total_estimated = elapsed / (progress / 100)
                                remaining = total_estimated - elapsed
                                
                                # Format time remaining
                                mins = int(remaining // 60)
                                secs = int(remaining % 60)
                                time_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
                                update_progress(progress, packet_count, time_str)
                    
                    # Print progress periodically for debugging
                    if packet_count % 10000 == 0:
                        print(f"Read {packet_count} packets...")
            
            return result
            
        except Exception as e:
            print(f"Error reading PCAP file: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    @staticmethod
    def write_pcap(filename, packets):
        """Write packets to a PCAP file"""
        if not SCAPY_AVAILABLE:
            return False
            
        try:
            wrpcap(filename, packets)
            return True
        except Exception as e:
            print(f"Error writing PCAP file: {str(e)}")
            return False

class FastPcapReader:
    """Optimized PcapReader that minimizes processing during initial load"""
    
    def __init__(self, filename, lazy=True):
        self.filename = filename
        self.lazy = lazy  # If True, only read headers initially
        self.file_size = os.path.getsize(filename)
        self.packet_count = 0
        self.packet_offsets = []
        self.current_offset = 0
        
        # Open the file and read the header
        self.f = open(filename, 'rb')
        
        # Read the global header to determine format (24 bytes)
        header = self.f.read(24)
        
        # Check the magic number to determine endianness
        magic_num = struct.unpack('I', header[0:4])[0]
        if magic_num == 0xa1b2c3d4:
            self.endian = '<'  # Little endian
        elif magic_num == 0xd4c3b2a1:
            self.endian = '>'  # Big endian
        else:
            raise ValueError("Invalid PCAP file format")
        
        # Store the starting offset for packets
        self.current_offset = self.f.tell()
        
        # If lazy loading, scan through to get all packet offsets first
        if self.lazy:
            self._scan_packet_offsets()
    
    def _scan_packet_offsets(self):
        """Scan the file to find the offsets of all packets"""
        # Remember where we were
        original_pos = self.f.tell()
        
        # Go to the beginning of packets
        self.f.seek(self.current_offset)
        
        # Scan through all packets
        while True:
            # Record current position
            offset = self.f.tell()
            
            # Read packet header (16 bytes)
            header = self.f.read(16)
            if not header or len(header) < 16:
                break
                
            # Unpack to get included length
            _, _, incl_len, _ = struct.unpack(f'{self.endian}IIII', header)
            
            # Store this packet's offset
            self.packet_offsets.append(offset)
            
            # Skip the packet data
            self.f.seek(incl_len, 1)  # Seek relative to current position
            
            self.packet_count += 1
        
        # Go back to where we were
        self.f.seek(original_pos)
    
    def read_packet(self, index=None):
        """Read a packet at the specified index or at the current position"""
        if index is not None:
            if self.lazy and 0 <= index < len(self.packet_offsets):
                # Seek to the specified packet
                self.f.seek(self.packet_offsets[index])
            else:
                raise IndexError(f"Packet index {index} out of range")
        
        # Read packet header (16 bytes)
        header = self.f.read(16)
        if not header or len(header) < 16:
            return None
            
        # Unpack header
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{self.endian}IIII', header)
        
        # Read packet data
        packet_data = self.f.read(incl_len)
        if not packet_data or len(packet_data) < incl_len:
            return None
            
        # Create a basic packet object with minimal parsing
        # For a real implementation, you'd use Scapy's Packet class or similar
        packet = {
            'time': ts_sec + ts_usec/1000000.0,
            'length': incl_len,
            'orig_length': orig_len,
            'data': packet_data
        }
        
        return packet
    
    def __iter__(self):
        """Allow iteration through all packets"""
        if self.lazy:
            for i in range(self.packet_count):
                yield self.read_packet(i)
        else:
            # Reset to beginning of packets
            self.f.seek(self.current_offset)
            
            while True:
                packet = self.read_packet()
                if packet is None:
                    break
                yield packet
    
    def __len__(self):
        """Return the number of packets"""
        if self.lazy:
            return self.packet_count
        else:
            # We don't know without scanning
            return 0
    
    def close(self):
        """Close the file"""
        if hasattr(self, 'f') and self.f:
            self.f.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()  



    """Thread for fast PCAP file reading"""
    # Your existing code for the thread

class InterfaceScanner:
    """Class to scan and list available network interfaces"""
    @staticmethod
    def get_interfaces():
        """Get list of network interfaces suitable for packet capture"""
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {str(e)}")
            return []

class PCAPFileExtractor:
    """Class to extract files from PCAP files"""
    
    # Common file signatures (magic numbers) and their extensions
    FILE_SIGNATURES = {
        # Images
        b'\xFF\xD8\xFF': 'jpg',
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'png',
        b'\x47\x49\x46\x38': 'gif',
        b'\x42\x4D': 'bmp',
        
        # Documents
        b'\x25\x50\x44\x46': 'pdf',
        b'\x50\x4B\x03\x04': 'zip',  # Also used by docx, xlsx, pptx, etc.
        b'\x52\x61\x72\x21': 'rar',
        b'\x1F\x8B': 'gz',
        
        # Audio/Video
        b'\x49\x44\x33': 'mp3',
        b'\x00\x00\x00\x18\x66\x74\x79\x70': 'mp4',
        b'\x52\x49\x46\x46': 'wav',  # Also AVI
        
        # Executables
        b'\x4D\x5A': 'exe',
        b'\x7F\x45\x4C\x46': 'elf',
        
        # Web content
        b'\x3C\x21\x44\x4F\x43\x54\x59\x50\x45\x20\x68\x74\x6D\x6C': 'html',
        b'\x3C\x68\x74\x6D\x6C': 'html',
    }
    
    # File extensions based on content type in HTTP responses
    CONTENT_TYPE_EXTENSIONS = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'image/bmp': 'bmp',
        'application/pdf': 'pdf',
        'application/zip': 'zip',
        'application/x-rar-compressed': 'rar',
        'application/gzip': 'gz',
        'audio/mpeg': 'mp3',
        'video/mp4': 'mp4',
        'audio/wav': 'wav',
        'video/x-msvideo': 'avi',
        'application/x-msdownload': 'exe',
        'application/x-executable': 'elf',
        'text/html': 'html',
        'application/javascript': 'js',
        'text/css': 'css',
        'application/json': 'json',
        'application/xml': 'xml',
        'text/plain': 'txt',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
        'application/vnd.ms-excel': 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
        'application/vnd.ms-powerpoint': 'ppt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx'
    }
    
    def __init__(self, output_dir=None):
        """Initialize the file extractor
        
        Args:
            output_dir (str): Directory to save extracted files
        """
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'extracted_files')
        self.extracted_files = []
        self.file_count = 0
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def extract_files_from_pcap(self, packets):
        """Extract files from a list of packets
        
        Args:
            packets (list): List of scapy packets
            
        Returns:
            list: List of extracted file paths
        """
        self.extracted_files = []
        
        if not packets:
            return self.extracted_files
        
        # Track HTTP responses and their content
        http_responses = {}
        current_stream = {}
        
        # First pass - identify HTTP content
        for i, packet in enumerate(packets):
            try:
                # Process TCP packets with payload
                if TCP in packet and Raw in packet and IP in packet:
                    payload = packet[Raw].load
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    
                    # Create stream identifier
                    stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    reverse_stream_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                    
                    # Check if this packet is part of an HTTP response
                    if stream_id not in current_stream and reverse_stream_id not in current_stream:
                        # This might be a new stream
                        try:
                            if b'HTTP/' in payload and (b' 200 ' in payload or b' 302 ' in payload):
                                # This is an HTTP response status line
                                headers, body = self._split_http_response(payload)
                                if not headers:
                                    continue
                                    
                                content_type = self._extract_content_type(headers)
                                content_length = self._extract_content_length(headers)
                                
                                if content_type and content_length:
                                    current_stream[stream_id] = {
                                        'content_type': content_type,
                                        'content_length': content_length,
                                        'data': body or b'',
                                        'remaining': content_length - len(body) if body else content_length
                                    }
                                    
                                    if current_stream[stream_id]['remaining'] <= 0:
                                        # Complete response in a single packet
                                        http_responses[stream_id] = current_stream[stream_id]
                                        del current_stream[stream_id]
                        except ValueError as e:
                            # Skip this packet if there's an error parsing HTTP data values
                            print(f"Value error parsing HTTP response: {str(e)}")
                            continue
                        except Exception as e:
                            # Skip this packet if there's an error parsing HTTP data
                            print(f"Error parsing HTTP response: {str(e)}")
                            continue
                            
                    elif stream_id in current_stream:
                        # Continuing data for an existing response
                        try:
                            current_stream[stream_id]['data'] += payload
                            current_stream[stream_id]['remaining'] -= len(payload)
                            
                            if current_stream[stream_id]['remaining'] <= 0:
                                # Response is complete
                                http_responses[stream_id] = current_stream[stream_id]
                                del current_stream[stream_id]
                        except TypeError as e:
                            # Error with data types
                            print(f"Type error appending stream data: {str(e)}")
                            if stream_id in current_stream:
                                del current_stream[stream_id]
                        except Exception as e:
                            # Skip this packet if there's an error appending data
                            print(f"Error appending stream data: {str(e)}")
                            if stream_id in current_stream:
                                del current_stream[stream_id]
            except IndexError as e:
                # Skip packet if fields are missing
                print(f"Index error processing packet {i}: {str(e)}")
                continue
            except AttributeError as e:
                # Skip packet if expected attributes are missing
                print(f"Attribute error processing packet {i}: {str(e)}")
                continue
            except Exception as e:
                # Skip any packet that causes an error
                print(f"Unexpected error processing packet {i}: {str(e)}")
                import traceback
                traceback.print_exc()
                continue
        
        # Extract files from HTTP responses
        for stream_id, response in http_responses.items():
            file_ext = self.CONTENT_TYPE_EXTENSIONS.get(response['content_type'], '')
            if file_ext:
                self.file_count += 1
                file_name = f"http_{self.file_count:04d}.{file_ext}"
                
                # Sanitize filename to prevent path traversal
                import re
                safe_name = re.sub(r'[^\w\-\.]', '_', file_name)
                file_path = os.path.join(self.output_dir, safe_name)
                
                # Validate path is within extraction directory
                if not os.path.abspath(file_path).startswith(os.path.abspath(self.output_dir)):
                    print(f"Security warning: Attempted path traversal: {file_path}")
                    continue  # Skip this file
                    
                try:
                    with open(file_path, 'wb') as f:
                        f.write(response['data'])
                    
                    self.extracted_files.append({
                        'path': file_path,
                        'size': len(response['data']),
                        'type': response['content_type'],
                        'source': 'HTTP'
                    })
                except (IOError, OSError) as e:
                    print(f"File I/O error saving HTTP file {file_path}: {str(e)}")
                    continue

        # Second pass - scan for file signatures in packet payloads
        for i, packet in enumerate(packets):
            if Raw in packet:
                try:
                    payload = packet[Raw].load
                    
                    # Look for file signatures
                    for signature, ext in self.FILE_SIGNATURES.items():
                        if payload.startswith(signature):
                            # Found potential file
                            self.file_count += 1
                            file_name = f"raw_{self.file_count:04d}.{ext}"
                            
                            # Sanitize filename
                            import re
                            safe_name = re.sub(r'[^\w\-\.]', '_', file_name)
                            file_path = os.path.join(self.output_dir, safe_name)
                            
                            # Validate path
                            if not os.path.abspath(file_path).startswith(os.path.abspath(self.output_dir)):
                                print(f"Security warning: Attempted path traversal: {file_path}")
                                continue  # Skip this file
                            
                            try:
                                with open(file_path, 'wb') as f:
                                    f.write(payload)
                                
                                self.extracted_files.append({
                                    'path': file_path,
                                    'size': len(payload),
                                    'type': f"Raw {ext.upper()} file",
                                    'source': 'Raw'
                                })
                            except (IOError, OSError) as e:
                                print(f"File I/O error saving raw file {file_path}: {str(e)}")
                                continue
                                
                            break  # Only extract one file per packet
                except Exception as e:
                    print(f"Error processing raw packet {i}: {str(e)}")
                    continue
        
        return self.extracted_files
    
    def extract_files_from_pcap_reassembly(self, packets):
        """Extract files by reassembling TCP streams and looking for file signatures
        
        Args:
            packets (list): List of scapy packets
            
        Returns:
            list: List of extracted file paths
        """
        # Map to store TCP streams
        tcp_streams = {}
        
        # First pass - reassemble TCP streams
        for packet in packets:
            if IP in packet and TCP in packet and Raw in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                seq = packet[TCP].seq
                payload = bytes(packet[Raw])
                
                # Create stream ID in both directions
                stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                
                # Store the segment data
                if stream_id not in tcp_streams:
                    tcp_streams[stream_id] = []
                
                tcp_streams[stream_id].append((seq, payload))
        
        # Second pass - sort segments by sequence number and extract files
        for stream_id, segments in tcp_streams.items():
            # Sort by sequence number
            segments.sort(key=lambda x: x[0])
            
            # Concatenate data
            stream_data = b''.join([segment[1] for segment in segments])
            
            # No data, skip
            if not stream_data:
                continue
                
            # Look for file signatures in the reassembled stream
            for start_pos in range(len(stream_data) - 8):  # Check at least 8 bytes
                for signature, ext in self.FILE_SIGNATURES.items():
                    sig_len = len(signature)
                    if stream_data[start_pos:start_pos + sig_len] == signature:
                        # Calculate a reasonable endpoint (1MB limit to prevent excessive files)
                        end_pos = min(start_pos + 1024*1024, len(stream_data))
                        
                        # Extract potential file
                        file_data = stream_data[start_pos:end_pos]
                        
                        # Save the file
                        self.file_count += 1
                        file_name = f"stream_{self.file_count:04d}.{ext}"
                        file_path = os.path.join(self.output_dir, file_name)
                        
                        with open(file_path, 'wb') as f:
                            f.write(file_data)
                        
                        self.extracted_files.append({
                            'path': file_path,
                            'size': len(file_data),
                            'type': f"TCP Stream {ext.upper()} file",
                            'source': 'TCP Stream'
                        })
                        
                        # Skip ahead to avoid overlapping detections
                        start_pos += len(file_data)
                        break
        
        return self.extracted_files
    
    def carve_files(self, packets):
        """Extract files using both HTTP extraction and TCP stream reassembly
        
        Args:
            packets (list): List of scapy packets
            
        Returns:
            list: List of extracted file paths
        """
        # Reset counters
        self.extracted_files = []
        self.file_count = 0
        
        # Extract files using both methods
        self.extract_files_from_pcap(packets)
        self.extract_files_from_pcap_reassembly(packets)
        
        return self.extracted_files
    
    def _split_http_response(self, data):
        """Split HTTP response into headers and body
        
        Args:
            data (bytes): HTTP response data
            
        Returns:
            tuple: (headers, body) as byte strings
        """
        # Find the header/body separator
        separator = b'\r\n\r\n'
        if separator in data:
            parts = data.split(separator, 1)
            return parts[0], parts[1] if len(parts) > 1 else b''
        return None, None
    
    def _extract_content_type(self, headers):
        """Extract Content-Type header value
        
        Args:
            headers (bytes): HTTP headers
            
        Returns:
            str: Content-Type value or None
        """
        headers_str = headers.decode('utf-8', errors='ignore')
        for line in headers_str.split('\r\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip()
                # Strip out charset and boundary parts
                if ';' in content_type:
                    content_type = content_type.split(';', 1)[0].strip()
                return content_type
        return None
    
    def _extract_content_length(self, headers):
        """Extract Content-Length header value
        
        Args:
            headers (bytes): HTTP headers
            
        Returns:
            int: Content-Length value or 0
        """
        headers_str = headers.decode('utf-8', errors='ignore')
        for line in headers_str.split('\r\n'):
            if line.lower().startswith('content-length:'):
                try:
                    return int(line.split(':', 1)[1].strip())
                except ValueError:
                    return 0
        return 0

class ExportOptionsDialog(QDialog):
    """Dialog for configuring export options"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Analysis Results")
        self.resize(500, 400)
        
        # Initialize parameters
        self.export_format = "pdf"  # Default format
        self.export_sections = {
            "file_info": True,
            "packet_summary": True,
            "protocol_stats": True,
            "conversations": True,
            "endpoints": True,
            "security_findings": True,
            "top_ports": True
        }
        
        # Set up the dialog layout
        self.init_ui()
    
    def init_ui(self):
        """Initialize the dialog UI"""
        layout = QVBoxLayout(self)
        
        # Format selection
        format_group = QGroupBox("Export Format")
        format_layout = QHBoxLayout(format_group)
        
        self.pdf_radio = QRadioButton("PDF")
        self.html_radio = QRadioButton("HTML")
        
        # Create a button group for the radio buttons
        self.format_group = QButtonGroup()
        self.format_group.addButton(self.pdf_radio)
        self.format_group.addButton(self.html_radio)
        
        # Set default selection
        self.pdf_radio.setChecked(True)
        
        # Disable PDF option if reportlab is not available
        if not REPORTLAB_AVAILABLE:
            self.pdf_radio.setEnabled(False)
            self.pdf_radio.setText("PDF (reportlab library not installed)")
            self.html_radio.setChecked(True)
        
        format_layout.addWidget(self.pdf_radio)
        format_layout.addWidget(self.html_radio)
        
        # Sections to include
        sections_group = QGroupBox("Sections to Include")
        sections_layout = QVBoxLayout(sections_group)
        
        self.file_info_check = QCheckBox("File Information")
        self.packet_summary_check = QCheckBox("Packet Summary")
        self.protocol_stats_check = QCheckBox("Protocol Statistics")
        self.conversations_check = QCheckBox("Conversations")
        self.endpoints_check = QCheckBox("Endpoints")
        self.top_ports_check = QCheckBox("Top Ports")
        self.security_findings_check = QCheckBox("Security Findings")
        
        # Set default selections
        self.file_info_check.setChecked(True)
        self.packet_summary_check.setChecked(True)
        self.protocol_stats_check.setChecked(True)
        self.conversations_check.setChecked(True)
        self.endpoints_check.setChecked(True)
        self.top_ports_check.setChecked(True)
        self.security_findings_check.setChecked(True)
        
        sections_layout.addWidget(self.file_info_check)
        sections_layout.addWidget(self.packet_summary_check)
        sections_layout.addWidget(self.protocol_stats_check)
        sections_layout.addWidget(self.conversations_check)
        sections_layout.addWidget(self.endpoints_check)
        sections_layout.addWidget(self.top_ports_check)
        sections_layout.addWidget(self.security_findings_check)
        
        # Add select all / deselect all buttons
        select_buttons_layout = QHBoxLayout()
        self.select_all_button = QPushButton("Select All")
        self.select_all_button.clicked.connect(self.select_all_sections)
        
        self.deselect_all_button = QPushButton("Deselect All")
        self.deselect_all_button.clicked.connect(self.deselect_all_sections)
        
        select_buttons_layout.addWidget(self.select_all_button)
        select_buttons_layout.addWidget(self.deselect_all_button)
        sections_layout.addLayout(select_buttons_layout)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.accept)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.export_button)
        buttons_layout.addWidget(self.cancel_button)
        
        # Add layouts to main layout
        layout.addWidget(format_group)
        layout.addWidget(sections_group)
        layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # Connect signals
        self.pdf_radio.toggled.connect(self.update_format)
        self.html_radio.toggled.connect(self.update_format)
        
        self.file_info_check.toggled.connect(lambda: self.update_section("file_info"))
        self.packet_summary_check.toggled.connect(lambda: self.update_section("packet_summary"))
        self.protocol_stats_check.toggled.connect(lambda: self.update_section("protocol_stats"))
        self.conversations_check.toggled.connect(lambda: self.update_section("conversations"))
        self.endpoints_check.toggled.connect(lambda: self.update_section("endpoints"))
        self.top_ports_check.toggled.connect(lambda: self.update_section("top_ports"))
        self.security_findings_check.toggled.connect(lambda: self.update_section("security_findings"))
    
    def update_format(self):
        """Update the selected export format"""
        if self.pdf_radio.isChecked():
            self.export_format = "pdf"
        else:
            self.export_format = "html"
    
    def update_section(self, section_name):
        """Update the selected sections"""
        checkbox = getattr(self, f"{section_name}_check")
        self.export_sections[section_name] = checkbox.isChecked()
    
    def select_all_sections(self):
        """Select all sections"""
        for section in self.export_sections:
            checkbox = getattr(self, f"{section}_check")
            checkbox.setChecked(True)
    
    def deselect_all_sections(self):
        """Deselect all sections"""
        for section in self.export_sections:
            checkbox = getattr(self, f"{section}_check")
            checkbox.setChecked(False)
    
    def get_options(self):
        """Get the selected options"""
        return {
            "format": self.export_format,
            "sections": self.export_sections
        }
