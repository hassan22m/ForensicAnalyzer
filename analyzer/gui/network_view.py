# forensicanalyzer/gui/network_view.py

from PyQt6.QtWidgets import (QApplication,QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,  
                            QComboBox, QTableWidget, QTableWidgetItem, QLineEdit, QFileDialog, QTextEdit,QInputDialog,
                            QTabWidget,QButtonGroup, QGridLayout, QGroupBox, QSplitter, QProgressBar, QTreeWidget,
                            QTreeWidgetItem, QHeaderView, QFrame, QMessageBox,QCheckBox, QDialog, QScrollArea,QProgressDialog,QRadioButton)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QDateTime, QTimer
from PyQt6.QtGui import QIcon, QColor, QFont, QPixmap, QImage
import os,hashlib,datetime,shutil
from datetime import time 
from PyQt6.QtGui import QIcon, QColor, QFont, QPixmap, QImage  
from scapy.all import (sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, ARP, ICMP, IPv6, DNS, Raw, PcapReader)   
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
    
# Import core analyzer
from analyzer.core.network_analyzer import (
    PacketAnalyzer, PCAPFileHandler,PCAPFileExtractor,AnalysisExporter, FastPcapReaderThread, 
    PCAPFileExtractor, PacketCaptureThread,SCAPY_AVAILABLE
)

# Define WindowModal flag
WindowModal = Qt.WindowModality.WindowModal

class NetworkAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analyzer Pro")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize backend components
        self.packet_analyzer = PacketAnalyzer()
        self._status_bar = None #123
        self.capture_thread = None
        self.current_file = None
        self.packets = []
        self.filtered_packets = []
        self.capture_start_time = None
        
        # Set up timer for updating capture time
        self.time_timer = QTimer(self)
        self.time_timer.timeout.connect(self.update_capture_time)
        
        # Initialize UI
        self.init_ui()
        
        # Check for Scapy availability
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Missing Dependency", 
                            "The Scapy library is not installed, which is required for packet capture functionality.\n\n"
                            "Please install it using: pip install scapy", 
                            QMessageBox.StandardButton.Ok)
        else:
            # Scan for available interfaces
            self.scan_interfaces()
    
    def init_ui(self):
        # Create the central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        # Create toolbar with common operations
        toolbar_layout = QHBoxLayout()
        
        # Interface selection group
        interface_group = QGroupBox("Network Interface")
        interface_layout = QHBoxLayout(interface_group)
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture)
        
        interface_layout.addWidget(QLabel("Interface:"))
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addWidget(self.start_button)
        interface_layout.addWidget(self.stop_button)
        
        # File operations group
        file_group = QGroupBox("File Operations")
        file_layout = QHBoxLayout(file_group)
        
        self.open_pcap_button = QPushButton("Open PCAP")
        self.open_pcap_button.clicked.connect(self.open_pcap)
       
        self.export_pcap_button = QPushButton("Export PCAP")
        self.export_pcap_button.clicked.connect(self.export_pcap)
     
        self.export_report_button = QPushButton("Export Report")
        self.export_report_button.clicked.connect(self.export_analysis)
        
        file_layout.addWidget(self.export_report_button)
        file_layout.addWidget(self.open_pcap_button)
        file_layout.addWidget(self.export_pcap_button)
        
        # Add groups to toolbar layout
        toolbar_layout.addWidget(interface_group)
        toolbar_layout.addWidget(file_group)
        toolbar_layout.addStretch()
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create Capture tab
        self.capture_tab = QWidget()
        self.setup_capture_tab()
        self.tab_widget.addTab(self.capture_tab, "Packet Capture")
        
        # Create Analysis tab
        self.analysis_tab = QWidget()
        self.setup_analysis_tab()
        self.tab_widget.addTab(self.analysis_tab, "Network Analysis")
        
        # Create File Extraction tab
        self.extraction_tab = self.setup_file_extraction_tab()
        self.tab_widget.addTab(self.extraction_tab, "File Extraction")
        
        # Add layouts to main layout
        main_layout.addLayout(toolbar_layout)
        main_layout.addWidget(self.tab_widget)
        
        # Connection status indicator
        status_layout = QHBoxLayout()
        
        # Create a frame to contain the status bar for better styling
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #1A1416;
                border: 1px solid #3A3436;
                border-radius: 2px;
                min-height: 20px;
                padding: 0px;
                margin: 0px;
            }
        """)
        
        status_frame_layout = QHBoxLayout(status_frame)
        status_frame_layout.setContentsMargins(10, 0, 10, 0)
        status_frame_layout.setSpacing(10)
        
        self.status_bar = QProgressBar()
        self.status_bar.setRange(0, 100)
        self.status_bar.setValue(0)
        self.status_bar.setFormat("Not capturing")
        self.status_bar.setTextVisible(True)
        self.status_bar.setStyleSheet("""
            QProgressBar {
                background-color: #2A1F1F;
                border: none;
                border-radius: 2px;
                text-align: center;
                color: #FF4D54;
                font-weight: 400;
                min-height: 13px;
            }
            QProgressBar::chunk {
                background-color: #3A1E1E;
                border-radius: 2px;
            }
        """)
    
        self.packet_count_label = QLabel("Packets: 0")
        self.packet_count_label.setStyleSheet("color: #E0E0E0; padding: 0 10px;")
        
        self.displayed_count_label = QLabel("Displayed: 0")
        self.displayed_count_label.setStyleSheet("color: #E0E0E0; padding: 0 10px;")
        
        self.capture_time_label = QLabel("00:00:00")
        self.capture_time_label.setStyleSheet("color: #E0E0E0; padding: 0 10px;")
        
        # Add widgets to the status frame layout
        status_frame_layout.addWidget(self.status_bar, 1)  # Give status bar stretch priority
        status_frame_layout.addWidget(self.packet_count_label)
        status_frame_layout.addWidget(self.displayed_count_label)
        status_frame_layout.addWidget(self.capture_time_label)
        
        # Add the status frame to the main status layout
        status_layout.addWidget(status_frame)
        
        # Add the status layout to the main layout with proper spacing
        main_layout.addLayout(status_layout)
    
    def set_case_manager(self, case_manager):
        """Set the case manager reference"""
        self.case_manager = case_manager
    
    def set_status_bar(self, status_bar):
        self._status_bar = status_bar #123

    def on_case_opened(self, case):
        """Handle case opened event"""
        self.current_case = case
        if self._status_bar:
            self._status_bar.showMessage(f"Case '{case.name}' opened")
        # You might want to clear current view or reset state
        # self.clear_packet_view()
    
    def on_case_closed(self):
        """Handle case closed event"""
        self.current_case = None
        self.statusBar().showMessage("No case open")
        
        # Clear the current view
        # self.clear_packet_view()
    
    def on_evidence_added(self, evidence_item):
        """Handle evidence added event for network evidence"""
        # Only process network evidence
        if evidence_item.evidence_type != "network":
            return
        
        # Save current evidence reference
        self.active_evidence = evidence_item
        
        # Load the PCAP file
        self.open_pcap(evidence_item.source_path)
        
        self.statusBar().showMessage(f"Loaded network evidence: {evidence_item.file_name}")
    
    def on_evidence_selected(self, evidence_item):
        """Handle evidence selected event"""
        # Only process network evidence
        if evidence_item.evidence_type != "network":
            return
        
        # Save current evidence reference
        self.active_evidence = evidence_item
        
        # Load the PCAP file
        self.open_pcap(evidence_item.source_path)
        
        self.statusBar().showMessage(f"Selected network evidence: {evidence_item.file_name}")
    
    def on_bookmark_added(self, evidence_item, bookmark):
        """Handle bookmark added event"""
        # Only process network evidence
        if evidence_item.evidence_type != "network":
            return
        
        # Check if this bookmark is for a specific packet
        data = bookmark.data
        if "packet_number" in data:
            self.select_packet(data["packet_number"])
            self.statusBar().showMessage(f"Navigated to bookmarked packet {data['packet_number']}")
    
    def add_bookmark_current_packet(self):
        """Add a bookmark for the currently selected packet"""
        # Check if we have an active case and evidence
        if not hasattr(self, 'current_case') or not self.current_case or not hasattr(self, 'active_evidence') or not self.active_evidence:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or network evidence")
            return
        
        # Get the currently selected packet
        selected_rows = self.packet_table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No packet selected")
            return
        
        packet_number = self.packet_table.model().index(selected_rows[0].row(), 0).data()
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"Packet {packet_number}")
        
        if ok and description:
            # Get packet info for a good location description
            packet_info = self.packets[selected_rows[0].row()]
            location = f"Packet {packet_number}: {packet_info.get('protocol', 'Unknown')} {packet_info.get('src_ip', '')} → {packet_info.get('dst_ip', '')}"
            
            # Create bookmark data with packet-specific information
            data = {
                "packet_number": packet_number,
                "protocol": packet_info.get('protocol', 'Unknown'),
                "src_ip": packet_info.get('src_ip', ''),
                "dst_ip": packet_info.get('dst_ip', ''),
                "time": packet_info.get('formatted_time', '')
            }
            
            # Add the bookmark through the case manager
            if hasattr(self, 'case_manager'):
                success, message, bookmark = self.case_manager.add_bookmark(
                    self.active_evidence.id, description, location, data)
                
                if success:
                    self.statusBar().showMessage(f"Added bookmark: {description}")
                else:
                    QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")
            else:
                QMessageBox.warning(self, "Bookmark Error", "Case manager not available")
    
    def select_packet(self, packet_number):
        """Select a specific packet in the table view"""
        try:
            # Find the row with this packet number
            packet_number = int(packet_number)
            
            # In your implementation, you need to find how to map packet number to row index
            # This is a simplified version assuming packet numbers match row numbers
            row = packet_number - 1  # Convert to zero-based index
            
            if 0 <= row < self.packet_table.model().rowCount():
                # Select the row
                self.packet_table.selectRow(row)
                
                # Scroll to make the row visible
                self.packet_table.scrollTo(self.packet_table.model().index(row, 0))
                
                # Trigger packet details display
                self.on_packet_selected()
        except (ValueError, TypeError) as e:
            print(f"Error selecting packet: {e}")
            
    

    def export_analysis(self):
        """Export analysis results to PDF or HTML"""
        if not self.packets:
            QMessageBox.information(self, "No Data", 
                                "There are no packets to analyze for export.", 
                                QMessageBox.StandardButton.Ok)
            return
        
        # Create an exporter and start the export process
        exporter = AnalysisExporter(self)
        exporter.export_analysis()

    def setup_file_extraction_tab(self):
        """Set up the file extraction tab"""
        extraction_tab = QWidget()
        layout = QVBoxLayout(extraction_tab)
        
        # Status and controls
        controls_layout = QHBoxLayout()
        
        self.extract_button = QPushButton("Extract Files from Packets")
        self.extract_button.clicked.connect(self.extract_files)
        
        self.open_extraction_dir_button = QPushButton("Open Extraction Directory")
        self.open_extraction_dir_button.clicked.connect(self.open_extraction_directory)
        
        controls_layout.addWidget(self.extract_button)
        controls_layout.addWidget(self.open_extraction_dir_button)
        controls_layout.addStretch()
        
        # Extraction settings
        settings_group = QGroupBox("Extraction Settings")
        settings_layout = QVBoxLayout(settings_group)
        
        # Output directory selection
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Output Directory:"))
        
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setText(os.path.join(os.getcwd(), "extracted_files"))
        
        self.browse_dir_button = QPushButton("Browse...")
        self.browse_dir_button.clicked.connect(self.browse_extraction_directory)
        
        dir_layout.addWidget(self.output_dir_input, 1)
        dir_layout.addWidget(self.browse_dir_button)
        
        # Extraction options
        options_layout = QVBoxLayout()
        
        self.extract_http_checkbox = QCheckBox("Extract files from HTTP traffic")
        self.extract_http_checkbox.setChecked(True)
        
        self.extract_streams_checkbox = QCheckBox("Extract files from TCP streams")
        self.extract_streams_checkbox.setChecked(True)
        
        self.extract_raw_checkbox = QCheckBox("Extract files from raw packets")
        self.extract_raw_checkbox.setChecked(True)
        
        options_layout.addWidget(self.extract_http_checkbox)
        options_layout.addWidget(self.extract_streams_checkbox)
        options_layout.addWidget(self.extract_raw_checkbox)
        
        settings_layout.addLayout(dir_layout)
        settings_layout.addLayout(options_layout)
        
        # Extracted files table - updated to include hash column
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(6)  # Increased from 5 to 6 columns
        self.files_table.setHorizontalHeaderLabels(["Filename", "Type", "Size", "Source", "SHA-256 Hash", "Actions"])
        
        # Set row height
        self.files_table.verticalHeader().setDefaultSectionSize(40)  # Increase row height to 40 pixels
        
        # Adjust column widths to show more of the hash - initially set all to stretch
        header = self.files_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)  # Make all columns manually resizable
        
        # Set specific column behaviors
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Filename stretches
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Hash column stretches
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Actions fits content
        
        # Set fixed widths for smaller columns
        self.files_table.setColumnWidth(1, 100)  # Type column (narrower)
        self.files_table.setColumnWidth(2, 70)   # Size column (narrower)
        self.files_table.setColumnWidth(3, 80)   # Source column (narrower)
        
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        # Results summary
        self.extraction_results_label = QLabel("No files extracted yet.")
        
        # Add widgets to layout
        layout.addLayout(controls_layout)
        layout.addWidget(settings_group)
        layout.addWidget(QLabel("Extracted Files:"))
        layout.addWidget(self.files_table)
        layout.addWidget(self.extraction_results_label)
        
        return extraction_tab

    def calculate_extracted_file_hash(self, file_path):
        """Calculate SHA-256 hash of an extracted file"""
        try:
            hash_obj = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read the file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def browse_extraction_directory(self):
        """Open a dialog to select extraction directory"""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Extraction Directory", self.output_dir_input.text())
        
        if dir_path:
            self.output_dir_input.setText(dir_path)

    def open_extraction_directory(self):
        """Open the extraction directory in file explorer"""
        dir_path = self.output_dir_input.text()
        
        if not os.path.exists(dir_path):
            QMessageBox.warning(self, "Directory Not Found", 
                            f"The directory {dir_path} does not exist.", 
                            QMessageBox.StandardButton.Ok)
            return
        
        # Open the directory using the appropriate command for the OS
        try:
            if os.name == 'nt':  # Windows
                os.startfile(dir_path)
            elif os.name == 'posix':  # macOS or Linux
                if sys.platform == 'darwin':  # macOS
                    subprocess.call(['open', dir_path])
                else:  # Linux
                    subprocess.call(['xdg-open', dir_path])
        except Exception as e:
            QMessageBox.warning(self, "Error Opening Directory", 
                            f"Failed to open directory: {str(e)}", 
                            QMessageBox.StandardButton.Ok)

    # The issue might be occurring in your extract_files method.
    # Let's modify it to ensure the os module is properly used:

    def extract_files(self):
        """Extract files from captured packets"""
        if not self.packets:
            QMessageBox.information(self, "No Packets", 
                                "There are no packets to extract files from.", 
                                QMessageBox.StandardButton.Ok)
            return
        
        # Get extraction options
        output_dir = self.output_dir_input.text()
        
        # Create a timestamped subdirectory to avoid overwriting previous extractions
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extraction_dir = os.path.join(output_dir, f"extraction_{timestamp}")
        
        # Create directory if it doesn't exist
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            os.makedirs(extraction_dir)
        except Exception as e:
            QMessageBox.critical(self, "Directory Error", 
                            f"Failed to create extraction directory: {str(e)}", 
                            QMessageBox.StandardButton.Ok)
            return
        
        # Update UI
        self.statusBar().showMessage("Extracting files...")
        self.extraction_results_label.setText("Extracting files...")
        self.extract_button.setEnabled(False)
        QApplication.processEvents()
        
        try:
            # Use PCAPFileExtractor from this file
            extractor = PCAPFileExtractor(extraction_dir)
            
            # Determine which packets to use (filtered or all)
            packets_to_process = self.filtered_packets if self.filtered_packets else self.packets
            
            # Extract files
            extracted_files = extractor.carve_files(packets_to_process)
            
            # Rest of the method...
            
            # Update UI with extraction results
            self.files_table.setRowCount(0)  # Clear the table
            
            for i, file_info in enumerate(extracted_files):
                file_path = file_info['path']
                file_name = os.path.basename(file_path)
                file_size = file_info['size']
                file_type = file_info['type']
                file_source = file_info['source']
                
                # Calculate the file hash
                file_hash = self.calculate_extracted_file_hash(file_path)
                
                row_position = self.files_table.rowCount()
                self.files_table.insertRow(row_position)
                
                # Set file info in the table
                self.files_table.setItem(row_position, 0, QTableWidgetItem(file_name))
                self.files_table.setItem(row_position, 1, QTableWidgetItem(file_type))
                self.files_table.setItem(row_position, 2, QTableWidgetItem(self.format_size(file_size)))
                self.files_table.setItem(row_position, 3, QTableWidgetItem(file_source))
                
                # Create a widget for the hash column with a copy button
                hash_widget = QWidget()
                hash_layout = QHBoxLayout(hash_widget)
                hash_layout.setContentsMargins(2, 2, 2, 2)
                
                # Create a hash label that shows more of the hash
                hash_label = QLabel(file_hash[:30] + "...")  # Show first 30 chars
                hash_label.setToolTip(file_hash)  # Full hash on hover
                hash_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                
                # Add copy button
                copy_hash_button = QPushButton("Copy")
                copy_hash_button.setFixedSize(70, 24)
                copy_hash_button.setStyleSheet("""
                    QPushButton {
                        background-color: #2A2426;
                        border: 1px solid #3A3436;
                        border-radius: 3px;
                        color: #FFFFFF;
                        padding: 4px;
                        font-size: 11px;
                        font-weight: 500;
                    }
                    QPushButton:hover {
                        background-color: #3A3436;
                        border: 1px solid #4A4446;
                    }
                    QPushButton:pressed {
                        background-color: #4A4446;
                    }
                """)
                
                # Fixed lambda - use a local variable to capture the hash value
                current_hash = file_hash  # Create a local variable to avoid closure issues
                copy_hash_button.clicked.connect(lambda checked=False, h=current_hash: self.copy_hash_to_clipboard(h))
                
                hash_layout.addWidget(hash_label, 1)  # Give the label more space
                hash_layout.addWidget(copy_hash_button)
                
                self.files_table.setCellWidget(row_position, 4, hash_widget)
                
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                actions_layout.setSpacing(4)
                
                preview_button = QPushButton("Preview")
                preview_button.setFixedSize(70, 24)
                preview_button.setStyleSheet("""
                    QPushButton {
                        background-color: #1E2A3A;
                        border: 1px solid #2E3A4A;
                        border-radius: 3px;
                        color: #FFFFFF;
                        padding: 4px;
                        font-size: 11px;
                        font-weight: 500;
                    }
                    QPushButton:hover {
                        background-color: #2E3A4A;
                        border: 1px solid #3E4A5A;
                    }
                    QPushButton:pressed {
                        background-color: #3E4A5A;
                    }
                """)
                
                open_button = QPushButton("Open")
                open_button.setFixedSize(70, 24)
                open_button.setStyleSheet("""
                    QPushButton {
                        background-color: #1E3A23;
                        border: 1px solid #2E5A33;
                        border-radius: 3px;
                        color: #FFFFFF;
                        padding: 4px;
                        font-size: 11px;
                        font-weight: 500;
                    }
                    QPushButton:hover {
                        background-color: #2E5A33;
                        border: 1px solid #3E6A43;
                    }
                    QPushButton:pressed {
                        background-color: #3E6A43;
                    }
                """)
                
                save_as_button = QPushButton("Export")  # Changed from "Save As..." to "Export"
                save_as_button.setFixedSize(70, 24)
                save_as_button.setStyleSheet("""
                    QPushButton {
                        background-color: #3A1E1E;
                        border: 1px solid #4A2E2E;
                        border-radius: 3px;
                        color: #FFFFFF;
                        padding: 4px;
                        font-size: 11px;
                        font-weight: 500;
                    }
                    QPushButton:hover {
                        background-color: #4A2E2E;
                        border: 1px solid #5A3E3E;
                    }
                    QPushButton:pressed {
                        background-color: #5A3E3E;
                    }
                """)
                
                # Connect button signals using lambda to pass the file path
                current_path = file_path  # Local variable to avoid closure issues
                preview_button.clicked.connect(lambda checked=False, path=current_path: self.preview_extracted_file(path))
                open_button.clicked.connect(lambda checked=False, path=current_path: self.open_extracted_file(path))
                save_as_button.clicked.connect(lambda checked=False, path=current_path: self.save_extracted_file(path))
                
                actions_layout.addWidget(preview_button)
                actions_layout.addWidget(open_button)
                actions_layout.addWidget(save_as_button)
                
                self.files_table.setCellWidget(row_position, 5, actions_widget)
            
            # Update results label
            if extracted_files:
                self.extraction_results_label.setText(f"Successfully extracted {len(extracted_files)} files to {extraction_dir}")
                self.statusBar().showMessage(f"Extracted {len(extracted_files)} files")
            else:
                self.extraction_results_label.setText("No files were found for extraction.")
                self.statusBar().showMessage("No files found for extraction")
            
        except Exception as e:
            import traceback
            traceback.print_exc()  # Print the full traceback for debugging
            QMessageBox.critical(self, "Extraction Error", 
                            f"Failed to extract files: {str(e)}", 
                            QMessageBox.StandardButton.Ok)
            self.extraction_results_label.setText(f"Error: {str(e)}")
            self.statusBar().showMessage("File extraction failed")
            
        finally:
            self.extract_button.setEnabled(True)
    
    def copy_hash_to_clipboard(self, hash_value):
        """Copy a hash value to the clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(hash_value)
        self.statusBar().showMessage(f"Hash copied to clipboard: {hash_value[:10]}...", 3000)

    def preview_extracted_file(self, file_path):
        """Preview an extracted file in a dialog"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", 
                                f"The file {file_path} does not exist.", 
                                QMessageBox.StandardButton.Ok)
            return
        
        # Create and show the preview dialog
        preview_dialog = FilePreviewDialog(file_path, self)
        preview_dialog.exec()

    def open_extracted_file(self, file_path):
        """Open an extracted file with the default application"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", 
                            f"The file {file_path} does not exist.", 
                            QMessageBox.StandardButton.Ok)
            return
        
        try:
            if os.name == 'nt':  # Windows
                os.startfile(file_path)
            elif os.name == 'posix':  # macOS or Linux
                if sys.platform == 'darwin':  # macOS
                    subprocess.call(['open', file_path])
                else:  # Linux
                    subprocess.call(['xdg-open', file_path])
        except Exception as e:
            QMessageBox.warning(self, "Error Opening File", 
                            f"Failed to open file: {str(e)}", 
                            QMessageBox.StandardButton.Ok)

    def save_extracted_file(self, file_path):
        """Save an extracted file to a custom location"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "File Not Found", 
                            f"The file {file_path} does not exist.", 
                            QMessageBox.StandardButton.Ok)
            return
        
        # Get original filename
        original_name = os.path.basename(file_path)
        
        # Show save dialog
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save File As", original_name, "All Files (*)")
        
        if not save_path:
            return  # User canceled
        
        try:
            # Copy the file
            shutil.copy2(file_path, save_path)
            self.statusBar().showMessage(f"File saved as {save_path}", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", 
                            f"Failed to save file: {str(e)}", 
                            QMessageBox.StandardButton.Ok)

    def setup_capture_tab(self):
        layout = QVBoxLayout(self.capture_tab)
        
        self.packet_hex = QTextEdit()
        self.packet_hex.setReadOnly(True)
        self.packet_hex.setFont(QFont("Courier New", 10))
        self.packet_hex.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.packet_hex.setStyleSheet("background-color: #1E1E1E; color: #D4D4D4;")
        
        # Filter bar
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter display filter (e.g., tcp or ip.addr == 192.168.1.1)")
        self.apply_filter_button = QPushButton("Apply Filter")
        self.apply_filter_button.clicked.connect(self.apply_filter)
        self.clear_filter_button = QPushButton("Clear")
        self.clear_filter_button.clicked.connect(self.clear_filter)
        
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_input, 1)
        filter_layout.addWidget(self.apply_filter_button)
        filter_layout.addWidget(self.clear_filter_button)
        
        # Add table with improved styling
        self.packet_table = QTableWidget()
        self.packet_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E1E;
                gridline-color: #2D2D2D;
                color: white;
                selection-background-color: #B71C1C;  /* Deep red for selection */
                selection-color: white;
            }
            QTableWidget::item:selected {
                background-color: #B71C1C;  /* Deep red for selected items */
                color: white;
            }
            QTableWidget::item:hover {
                background-color: #D32F2F;  /* Lighter red for hover */
                color: white;
            }
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #2D2D2D;
            }
            QHeaderView::section {
                background-color: #252525;
                color: white;
                padding: 5px;
                border: none;
                border-right: 1px solid #2D2D2D;
                font-weight: bold;
            }
        """)
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.packet_table.itemSelectionChanged.connect(self.packet_selected)
        
        # Packet display area with splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Packet list table
        splitter.addWidget(self.packet_table)
        
        # Details area
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        
        # Packet hierarchical view
        self.packet_tree = QTreeWidget()
        self.packet_tree.setHeaderLabels(["Protocol Details"])
        self.packet_tree.setAlternatingRowColors(True)
        
        # Raw packet data
        self.packet_hex = QTextEdit()
        self.packet_hex.setReadOnly(True)
        self.packet_hex.setFont(QFont("Courier New", 10))
        self.packet_hex.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        
        # Add a horizontal splitter for tree and hex views
        details_splitter = QSplitter(Qt.Orientation.Horizontal)
        details_splitter.addWidget(self.packet_tree)
        details_splitter.addWidget(self.packet_hex)
        details_splitter.setSizes([600, 400])
        
        details_layout.addWidget(details_splitter)
        
        # Add widgets to the main splitter
        splitter.addWidget(details_widget)
        splitter.setSizes([400, 300])
        
        # Add everything to the layout
        layout.addLayout(filter_layout)
        layout.addWidget(splitter)

    def update_capture_time(self):
        """Update the capture time display"""
        if self.capture_start_time is not None:
            elapsed = time.time() - self.capture_start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            self.capture_time_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
    
    
    def start_capture(self):
        """Start packet capture on the selected interface"""
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Missing Dependency", 
                                "The Scapy library is not installed, which is required for packet capture functionality.\n\n"
                                "Please install it using: pip install scapy", 
                                QMessageBox.StandardButton.Ok)
            return

        # Get the actual interface name (not the display name)
        if os.name == 'nt':
            # On Windows, get the actual name stored in the item data
            index = self.interface_combo.currentIndex()
            selected_interface = self.interface_combo.itemData(index)
        else:
            # On Linux/Mac, the displayed name is the actual name
            selected_interface = self.interface_combo.currentText()

        if not selected_interface or "No interfaces found" in selected_interface:
            QMessageBox.warning(self, "No Interface", "No valid network interface selected", QMessageBox.StandardButton.Ok)
            return
            
        # Clear existing packets
        self.packets = []
        self.filtered_packets = []
        self.packet_table.setRowCount(0)
        self.packet_tree.clear()
        self.packet_hex.clear()
        
        # Initialize the packet analyzer
        self.packet_analyzer = PacketAnalyzer()
        
        # Record start time
        self.capture_start_time = time.time()
        
        # Get filter (if any)
        bpf_filter = self.filter_input.text() if self.filter_input.text() else None
        
        # Start the capture thread
        self.capture_thread = PacketCaptureThread(
            interface=selected_interface,
            bpf_filter=bpf_filter
        )
        self.capture_thread.packet_received.connect(self.process_packet)
        self.capture_thread.capture_complete.connect(self.capture_finished)
        self.capture_thread.status_update.connect(self.update_status)
        self.capture_thread.start()
        
        # Update UI
        self.statusBar().showMessage(f"Capturing on {selected_interface}...")
        self.status_bar.setFormat(f"Capturing on {selected_interface}")
        self.status_bar.setValue(50)  # Indeterminate progress
        
        # Enable/disable appropriate buttons
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_combo.setEnabled(False)
        
        # Start timer for updating capture time
        self.time_timer.start(1000)  # Update every second

    def stop_capture(self):
        """Stop the currently running packet capture"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            # The capture_finished slot will be called when the thread actually finishes
            self.statusBar().showMessage("Stopping capture...")
        else:
            self.capture_finished()

    def capture_finished(self):
        """Handle completion of packet capture"""
        # Stop the timer
        self.time_timer.stop()
        
        # Update UI
        self.statusBar().showMessage("Capture stopped")
        self.status_bar.setFormat("Capture stopped")
        self.status_bar.setValue(0)
        
        # Enable/disable appropriate buttons
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        
        # Refresh the analysis tab
        self.refresh_analysis()

    def process_packet(self, packet):
        """Process a captured packet"""
        # Extract packet info using the analyzer
        packet_info = self.packet_analyzer.add_packet(packet)
        
        # Store the packet
        self.packets.append(packet)
        self.filtered_packets.append(packet)
        
        # Add to the packet table
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        
        # Set values in the table with white text color
        for col, value in enumerate([
            str(len(self.packets)),
            packet_info.get('formatted_time', ''),
            packet_info.get('src_ip', ''),
            packet_info.get('dst_ip', ''),
            packet_info.get('protocol', ''),
            str(packet_info.get('length', 0)),
            packet_info.get('info', '')
        ]):
            item = QTableWidgetItem(value)
            item.setForeground(QColor('white'))  # Set text color to white
            self.packet_table.setItem(row_position, col, item)
        
        # Color code by protocol
        protocol = packet_info.get('protocol', '')
        color = self.get_protocol_color(protocol)
        for col in range(7):
            item = self.packet_table.item(row_position, col)
            if item:
                item.setBackground(color)
        
        # Update packet count in UI
        self.packet_count_label.setText(f"Packets: {len(self.packets)}")
        self.displayed_count_label.setText(f"Displayed: {len(self.filtered_packets)}")
        
        # Auto-scroll to the latest packet if at the bottom
        if self.packet_table.rowCount() > 0 and self.packet_table.verticalScrollBar().value() == self.packet_table.verticalScrollBar().maximum():
            self.packet_table.scrollToBottom()

    def update_status(self, message):
        """Update status message from the capture thread"""
        self.statusBar().showMessage(message)

    def update_capture_time(self):
        """Update the capture time display"""
        if self.capture_start_time is not None:
            elapsed = time.time() - self.capture_start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            self.capture_time_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def apply_filter(self):
        """Apply a display filter to the packet table"""
        filter_text = self.filter_input.text().lower()
        self.statusBar().showMessage(f"Applying filter: {filter_text}")
        
        # Clear the table
        self.packet_table.setRowCount(0)
        self.filtered_packets = []
        
        # Apply filter to all packets
        for i, packet in enumerate(self.packets):
            # Get packet info from the original packet
            packet_info = self.extract_packet_info(packet)
            
            # Check if the packet matches the filter
            if self.packet_matches_filter(packet_info, filter_text):
                # Add to filtered packets
                self.filtered_packets.append(packet)
                
                # Add to table
                row_position = self.packet_table.rowCount()
                self.packet_table.insertRow(row_position)
                
                # Set values in the table with white text
                for col, value in enumerate([
                    str(i + 1),
                    packet_info.get('formatted_time', ''),
                    packet_info.get('src_ip', ''),
                    packet_info.get('dst_ip', ''),
                    packet_info.get('protocol', ''),
                    str(packet_info.get('length', 0)),
                    packet_info.get('info', '')
                ]):
                    item = QTableWidgetItem(value)
                    item.setForeground(QColor('white'))  # Set text color to white
                    self.packet_table.setItem(row_position, col, item)
                
                # Color code by protocol
                protocol = packet_info.get('protocol', '')
                color = self.get_protocol_color(protocol)
                for col in range(7):
                    item = self.packet_table.item(row_position, col)
                    if item:
                        item.setBackground(color)
        
        # Update display count
        self.displayed_count_label.setText(f"Displayed: {len(self.filtered_packets)}")

    def packet_matches_filter(self, packet_info, filter_text):
        """Check if a packet matches the given filter"""
        if not filter_text:
            return True
            
        # Simple filter implementation - check if filter text appears in any field
        for key, value in packet_info.items():
            if isinstance(value, str) and filter_text in value.lower():
                return True
                
        # Special case for IP addresses
        if 'ip.addr' in filter_text:
            ip_addr = filter_text.split('==')[1].strip() if '==' in filter_text else ''
            if ip_addr:
                return ip_addr == packet_info.get('src_ip', '') or ip_addr == packet_info.get('dst_ip', '')
                
        # Protocol filters
        if filter_text in ['tcp', 'udp', 'icmp', 'http', 'dns', 'arp']:
            return filter_text.upper() == packet_info.get('protocol', '') or filter_text == packet_info.get('protocol', '').lower()
            
        return False

    def extract_packet_info(self, packet):
        """Extract packet info for display (uses the analyzer's method)"""
        return self.packet_analyzer.extract_packet_info(packet)

    def clear_filter(self):
        """Clear the display filter and show all packets"""
        self.filter_input.clear()
        self.statusBar().showMessage("Filter cleared")
        
        # Display all packets
        self.packet_table.setRowCount(0)
        self.filtered_packets = self.packets.copy()
        
        for i, packet in enumerate(self.packets):
            # Get packet info
            packet_info = self.extract_packet_info(packet)
            
            # Add to table
            row_position = self.packet_table.rowCount()
            self.packet_table.insertRow(row_position)
            
            # Set values in the table with white text
            for col, value in enumerate([
                str(i + 1),
                packet_info.get('formatted_time', ''),
                packet_info.get('src_ip', ''),
                packet_info.get('dst_ip', ''),
                packet_info.get('protocol', ''),
                str(packet_info.get('length', 0)),
                packet_info.get('info', '')
            ]):
                item = QTableWidgetItem(value)
                item.setForeground(QColor('white'))  # Set text color to white
                self.packet_table.setItem(row_position, col, item)
            
            # Color code by protocol
            protocol = packet_info.get('protocol', '')
            color = self.get_protocol_color(protocol)
            for col in range(7):
                item = self.packet_table.item(row_position, col)
                if item:
                    item.setBackground(color)
        
        # Update display count
        self.displayed_count_label.setText(f"Displayed: {len(self.filtered_packets)}")

    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """
        Calculate the hash of a file using the specified algorithm.
        
        Args:
            file_path (str): Path to the file to hash
            algorithm (str): Hash algorithm to use (default: sha256)
        
        Returns:
            str: Hexadecimal hash string if successful, None if error occurs
        """
        try:
            hash_obj = hashlib.new(algorithm)
            file_size = os.path.getsize(file_path)
            
            # Show progress dialog for files larger than 100MB
            show_progress = file_size > 100 * 1024 * 1024
            if show_progress:
                progress = QProgressDialog("Calculating file hash...", "Cancel", 0, 100, self)
                progress.setWindowTitle("Hash Calculation")
                progress.setWindowModality(Qt.WindowModal)
                progress.setMinimumDuration(500)  # Only show for operations > 500ms
            
            with open(file_path, 'rb') as f:
                # Read file in 1MB chunks
                chunk_size = 1024 * 1024
                bytes_processed = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    hash_obj.update(chunk)
                    
                    if show_progress:
                        bytes_processed += len(chunk)
                        progress_value = int((bytes_processed / file_size) * 100)
                        progress.setValue(progress_value)
                        
                        if progress.wasCanceled():
                            self.statusBar().showMessage("Hash calculation cancelled")
                            return None
                        
            if show_progress:
                progress.setValue(100)
                
            return hash_obj.hexdigest()
            
        except (IOError, OSError) as e:
            self.statusBar().showMessage(f"Error calculating hash: {str(e)}")
            return None
        except Exception as e:
            self.statusBar().showMessage(f"Unexpected error during hash calculation")
            return None

    def update_hex_display(self, hex_text):
        """Enhanced hex display with color coding for dark mode"""
        highlighted_text = ""
        lines = hex_text.split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            parts = line.split('  ')
            if len(parts) < 3:
                highlighted_text += line + '\n'
                continue
                
            # Address part (in cyan)
            addr_part = f'<span style="color:#56BBEC;">{parts[0]}</span>'
            
            # Hex part (in green)
            hex_part = f'<span style="color:#B5CEA8;">{parts[1]}</span>'
            
            # ASCII part (in yellow/gold)
            ascii_part = f'<span style="color:#DCDCAA;">{parts[2]}</span>'
            
            highlighted_text += f"{addr_part}  {hex_part}  {ascii_part}\n"
        
        self.packet_hex.setHtml(f"<pre>{highlighted_text}</pre>")


    def packet_selected(self):
        """Handle packet selection in the table"""
        selected_rows = self.packet_table.selectedItems()
        if not selected_rows:
            return
            
        # Get the selected row
        row = selected_rows[0].row()
        
        # Get the packet index from the table (No. column)
        packet_index = int(self.packet_table.item(row, 0).text()) - 1
        
        if 0 <= packet_index < len(self.packets):
            # Get the actual packet
            packet = self.packets[packet_index]
            
            # Get packet info
            packet_info = self.extract_packet_info(packet)
            
            # Clear previous data
            self.packet_tree.clear()
            
            # Create frame item
            frame_item = QTreeWidgetItem(self.packet_tree)
            frame_item.setText(0, f"Frame {packet_index + 1}")
            
            # Add frame details
            frame_time = QTreeWidgetItem(frame_item)
            frame_time.setText(0, f"Arrival Time: {packet_info.get('formatted_time', '')}")
            
            frame_len = QTreeWidgetItem(frame_item)
            frame_len.setText(0, f"Frame Length: {packet_info.get('length', 0)} bytes")
            
            # Add layer information from the packet_info
            for layer_name, layer_data in packet_info.get('layers', []):
                layer_item = QTreeWidgetItem(self.packet_tree)
                layer_item.setText(0, layer_name)
                
                # Add fields for this layer
                for field_name, field_value in layer_data.items():
                    field_item = QTreeWidgetItem(layer_item)
                    # Format complex values
                    if isinstance(field_value, list):
                        formatted_value = ", ".join(str(x) for x in field_value)
                    else:
                        formatted_value = str(field_value)
                    field_item.setText(0, f"{field_name}: {formatted_value}")

                # Special handling for MQTT layer - show decoded values with better formatting
                if layer_name == 'MQTT':
                    # If we have mqtt_type and it's a PUBLISH and we have a topic, make it more readable
                    if layer_data.get('type') == 'PUBLISH' and 'topic' in layer_data:
                        topic_item = QTreeWidgetItem(layer_item)
                        topic_item.setText(0, f"Topic: {layer_data.get('topic', '')}")
                        
                        # If we have QoS, show it with description
                        if 'qos' in layer_data:
                            qos_item = QTreeWidgetItem(layer_item)
                            qos_desc = ""
                            if layer_data['qos'] == 0:
                                qos_desc = " (At most once delivery)"
                            elif layer_data['qos'] == 1:
                                qos_desc = " (At least once delivery)"
                            elif layer_data['qos'] == 2:
                                qos_desc = " (Exactly once delivery)"
                            qos_item.setText(0, f"QoS: {layer_data.get('qos', 0)}{qos_desc}")
                        
                        # If we have payload, show it
                        if 'payload' in layer_data:
                            payload_item = QTreeWidgetItem(layer_item)
                            payload_item.setText(0, f"Payload: {layer_data.get('payload', '')}")
                    
                    # For CONNECT packets, highlight client ID and authentication
                    if layer_data.get('type') == 'CONNECT':
                        if 'client_id' in layer_data:
                            client_id_item = QTreeWidgetItem(layer_item)
                            client_id_item.setText(0, f"Client ID: {layer_data.get('client_id', '')}")
                        
                        if 'username' in layer_data:
                            username_item = QTreeWidgetItem(layer_item)
                            username_value = "Present" if layer_data.get('username', False) else "Not present"
                            username_item.setText(0, f"Username: {username_value}")
                        
                        if 'password' in layer_data:
                            password_item = QTreeWidgetItem(layer_item)
                            password_value = "Present" if layer_data.get('password', False) else "Not present"
                            password_item.setText(0, f"Password: {password_value}")

            # Add colored hex dump from the packet
            self.update_hex_display(packet_info.get('hex', ''))
            
            # Expand all items
            self.packet_tree.expandAll()

    def get_protocol_color(self, protocol):
        """Return professional, eye-friendly colors optimized for dark mode"""
        if protocol == "TCP":
            return QColor(103, 140, 177)    # Soft blue - Easy on eyes
        elif protocol == "UDP":
            return QColor(165, 105, 189)    # Soft purple - Distinct but gentle
        elif protocol == "HTTP":
            return QColor(72, 201, 176)     # Soft teal - Clear but not harsh
        elif protocol == "HTTPS":
            return QColor(88, 214, 141)     # Soft green - Secure and gentle
        elif protocol == "DNS":
            return QColor(170, 120, 220)    # Muted purple - Rich but soft
        elif protocol == "ICMP":
            return QColor(205, 97, 85)      # Soft red - Warning without harshness
        elif protocol == "ARP":
            return QColor(244, 179, 80)     # Muted orange - Warm and visible
        elif protocol == "MQTT":
            return QColor(195, 155, 119)    # Soft brown - Distinct and warm
        elif protocol == "MQTT-SSL":
            return QColor(180, 182, 77)     # Muted olive - Secure variant
        else:
            return QColor(128, 128, 128)    # Neutral grey - Balanced background
    
    def open_pcap(self,file_path=None):
        """Open and read a PCAP file with optimized loading for large files"""
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Missing Dependency", 
                            "The Scapy library is not installed, which is required for PCAP functionality.\n\n"
                            "Please install it using: pip install scapy", 
                            QMessageBox.StandardButton.Ok)
            return
            
        if not file_path:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
            
            if not file_path:
                return  # User canceled
        
        # Clear existing data
        self.packets = []
        self.filtered_packets = []
        self.packet_table.setRowCount(0)
        self.packet_tree.clear()
        self.packet_hex.clear()
        
        # Initialize a new packet analyzer
        self.packet_analyzer = PacketAnalyzer()
        
        # Ask user if they want to limit the number of packets for large files
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        packet_limit = None
        
        if file_size_mb > 50:  # If file is larger than 50MB
            limit_msg = QMessageBox(self)
            limit_msg.setWindowTitle("Large PCAP File")
            limit_msg.setText(f"This PCAP file is {file_size_mb:.1f} MB and may contain many packets.")
            limit_msg.setInformativeText("Would you like to limit the number of packets loaded?")
            limit_msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            limit_msg.setDefaultButton(QMessageBox.StandardButton.Yes)
            
            limit_all_button = limit_msg.button(QMessageBox.StandardButton.No)
            limit_all_button.setText("Load All")
            
            limit_some_button = limit_msg.button(QMessageBox.StandardButton.Yes)
            limit_some_button.setText("Load Limited")
            
            if limit_msg.exec() == QMessageBox.StandardButton.Yes:
                # Get packet limit from user
                from PyQt6.QtWidgets import QInputDialog
                limit, ok = QInputDialog.getInt(self, "Packet Limit", 
                                            "Maximum number of packets to load:", 
                                            10000, 1000, 1000000, 5000)
                if ok:
                    packet_limit = limit
        
        # NOW create the progress dialog (after asking about packet limit)
        progress = QProgressDialog("Loading PCAP file...", "Cancel", 0, 100, self)
        progress.setWindowTitle("Loading PCAP")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)  # Show immediately
        progress.setValue(0)
        
        # Disable UI updates while loading
        self.packet_table.setUpdatesEnabled(False)
        
        # Store current file path
        self.current_file = file_path
        
        # Create the optimized PCAP reader thread
        self.pcap_reader_thread = FastPcapReaderThread(file_path, packet_limit, batch_size=1000)
        
        # Connect signals
        self.pcap_reader_thread.progress_updated.connect(
            lambda progress_pct, count, time_remaining: 
                progress.setLabelText(f"Loading PCAP file... {count} packets loaded\n"
                                    f"Estimated time remaining: {time_remaining}") or
                progress.setValue(progress_pct)
        )
        
        # Handle packet batches efficiently
        def process_packet_batch(packets, packet_infos):
            # Process a batch of packets
            start_row = len(self.packets)
            batch_size = len(packets)
            
            # Add to our main packet storage
            self.packets.extend(packets)
            self.filtered_packets.extend(packets)
            
            # Update the packet table efficiently
            current_row_count = self.packet_table.rowCount()
            new_row_count = current_row_count + batch_size
            self.packet_table.setRowCount(new_row_count)
            
            # Add the new batch to the table
            for i in range(batch_size):
                row = start_row + i
                packet_info = packet_infos[i]
                
                # Set values in the table
                self.packet_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
                self.packet_table.setItem(row, 1, QTableWidgetItem(packet_info.get('formatted_time', '')))
                self.packet_table.setItem(row, 2, QTableWidgetItem(packet_info.get('src_ip', '')))
                self.packet_table.setItem(row, 3, QTableWidgetItem(packet_info.get('dst_ip', '')))
                self.packet_table.setItem(row, 4, QTableWidgetItem(packet_info.get('protocol', '')))
                self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet_info.get('length', 0))))
                self.packet_table.setItem(row, 6, QTableWidgetItem(packet_info.get('info', '')))
                
                # Color code by protocol (optional - can be deferred for speed)
                protocol = packet_info.get('protocol', '')
                color = self.get_protocol_color(protocol)
                for col in range(7):
                    item = self.packet_table.item(row, col)
                    if item:
                        item.setBackground(color)
            
            # Update packet counts in UI
            self.packet_count_label.setText(f"Packets: {len(self.packets)}")
            self.displayed_count_label.setText(f"Displayed: {len(self.filtered_packets)}")
            
            # Process UI events to keep responsiveness
            QApplication.processEvents()
        
        # Connect batch processing signal
        self.pcap_reader_thread.packet_batch_ready.connect(process_packet_batch)
        
        # Handle loading completion
        def loading_completed(all_packets, all_packet_infos):
            # Re-enable UI updates
            self.packet_table.setUpdatesEnabled(True)
            
            # Close the progress dialog
            progress.close()
            
            # Update status
            limit_info = f" (limited to {packet_limit} packets)" if packet_limit else ""
            self.statusBar().showMessage(f"Loaded {len(self.packets)} packets from {file_path}{limit_info}")
            self.status_bar.setFormat("File loaded")
            self.status_bar.setValue(0)
            
            # Update the packet analyzer with the full packet set
            # This runs in the background so we don't block the UI
            def update_analyzer_in_background():
                # Reset analyzer to ensure clean state
                self.packet_analyzer = PacketAnalyzer()
                
                # Process packets in small batches to avoid UI freezing
                batch_size = 1000
                for i in range(0, len(all_packets), batch_size):
                    batch_end = min(i + batch_size, len(all_packets))
                    for j in range(i, batch_end):
                        self.packet_analyzer.add_packet(all_packets[j])
                    
                    # Update status periodically
                    self.statusBar().showMessage(f"Analyzing packets: {batch_end}/{len(all_packets)}")
                    QApplication.processEvents()
                
                # Refresh the analysis tab with full data
                self.statusBar().showMessage("Refreshing analysis...")
                self.refresh_analysis()
                self.statusBar().showMessage("Analysis complete")
            
            # Start the background analysis with a small delay
            QTimer.singleShot(100, update_analyzer_in_background)
        
        # Connect completion signal
        self.pcap_reader_thread.loading_complete.connect(loading_completed)
        
        # Handle loading errors
        def loading_error(error_msg):
            progress.close()
            QMessageBox.critical(self, "Error Loading PCAP", 
                            f"Failed to load PCAP file: {error_msg}", 
                            QMessageBox.StandardButton.Ok)
            self.packet_table.setUpdatesEnabled(True)
            self.statusBar().showMessage("Error loading PCAP file")
        
        # Connect error signal
        self.pcap_reader_thread.loading_error.connect(loading_error)
        
        # Connect cancel button
        progress.canceled.connect(self.pcap_reader_thread.stop)
        
        # Start the PCAP reading thread
        self.statusBar().showMessage(f"Loading PCAP file: {file_path}")
        self.status_bar.setFormat("Loading file...")
        self.status_bar.setValue(10)
        self.pcap_reader_thread.start()

    def export_pcap(self):
        """Export captured packets to a PCAP file"""
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Missing Dependency", 
                            "The Scapy library is not installed, which is required for PCAP functionality.\n\n"
                            "Please install it using: pip install scapy", 
                            QMessageBox.StandardButton.Ok)
            return
            
        if not self.packets:
            QMessageBox.information(self, "No Packets", 
                                "There are no packets to export.", 
                                QMessageBox.StandardButton.Ok)
            return
            
        # Show file dialog to choose save location
        default_filename = "capture.pcap"
        if self.current_file:
            # If we previously opened a file, suggest its name with '_exported' added
            basename = os.path.basename(self.current_file)
            base, ext = os.path.splitext(basename)
            default_filename = f"{base}_exported{ext}"
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export PCAP File", default_filename, "PCAP Files (*.pcap);;All Files (*)")
            
        if not file_path:
            return  # User canceled
            
        try:
            # Determine which packets to export
            packets_to_export = self.filtered_packets if self.filtered_packets else self.packets
            
            # Use wrpcap directly instead of PCAPFileHandler
            from scapy.all import wrpcap
            wrpcap(file_path, packets_to_export)
            
            QMessageBox.information(self, "Export Successful", 
                                f"Successfully exported {len(packets_to_export)} packets to {file_path}", 
                                QMessageBox.StandardButton.Ok)
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", 
                                f"Failed to export PCAP file: {str(e)}", 
                                QMessageBox.StandardButton.Ok)




    

    # Enhance security findings display to use colors appropriate for dark mode
    def update_security_findings(self):
        """Update security findings with dark mode friendly colors"""
        security_findings = self.packet_analyzer.get_security_findings()
        
        if security_findings:
            findings_html = "<h3>Potential Security Findings:</h3><br>"
            
            for i, finding in enumerate(security_findings, 1):
                # Color code by severity
                if finding['severity'] == 'High':
                    severity_color = "#FF5252"  # Bright red
                elif finding['severity'] == 'Medium':
                    severity_color = "#FFB74D"  # Orange
                else:
                    severity_color = "#FFEE58"  # Yellow
                    
                findings_html += f"<p><b>{i}. <span style='color:{severity_color};'>{finding['type']}</span> (Packet #{finding['packet_num']})</b><br>"
                findings_html += f"&nbsp;&nbsp;&nbsp;- Risk Level: <span style='color:{severity_color};'>{finding['severity']}</span><br>"
                findings_html += f"&nbsp;&nbsp;&nbsp;- Description: {finding['description']}</p>"
                
            self.security_findings.setHtml(findings_html)
        else:
            self.security_findings.setHtml("<p>No security issues identified.</p>")

    # Update protocol statistics to use dark mode friendly visualization
    def update_protocol_stats(self):
        """Update protocol statistics with dark mode friendly visualization"""
        protocol_stats = self.packet_analyzer.get_protocol_stats()
        
        if protocol_stats:
            # Define colors for protocols in dark mode
            protocol_colors = {
                "TCP": "#5C8DFF",      # Blue
                "UDP": "#FF9966",      # Orange
                "HTTP": "#66CC66",     # Green
                "HTTPS": "#99FF99",    # Light Green
                "DNS": "#CC99CC",      # Purple
                "ICMP": "#FF6666",     # Red
                "ARP": "#66CCCC",      # Cyan
                "Other": "#CCCCCC"     # Light Gray
            }
            
            stats_html = "<h3>Protocol Distribution</h3>"
            
            # Add a simple bar chart
            stats_html += "<table style='width:100%; border-spacing: 0 4px;'>"
            for protocol, percentage in protocol_stats.items():
                # Get color (default to gray if not found)
                color = protocol_colors.get(protocol, "#999999")
                
                # Format percentage to 1 decimal place
                pct_str = f"{percentage:.1f}%"
                
                # Create a bar with the protocol's color
                bar_width = int(max(1, percentage))  # At least 1% width for visibility
                
                stats_html += f"<tr><td style='width:20%; padding:3px;'>{protocol}</td>"
                stats_html += f"<td style='width:60%; padding:3px;'><div style='background-color:{color}; height:18px; width:{bar_width}%; border-radius:2px;'></div></td>"
                stats_html += f"<td style='width:20%; padding:3px; text-align:right;'>{pct_str}</td></tr>"
                
            stats_html += "</table>"
            
            self.protocol_stats.setHtml(stats_html)
        else:
            self.protocol_stats.setHtml("<p>No protocol data available</p>")
    
    # Update refresh_analysis method to use these new display methods
    def copy_hash_to_clipboard(self, hash_value=None):
        """Copy a hash value to the clipboard"""
        clipboard = QApplication.clipboard()
        
        # If a hash value was directly provided, use it
        if hash_value:
            clipboard.setText(hash_value)
            self.statusBar().showMessage(f"Hash copied to clipboard: {hash_value[:10]}...", 3000)
        else:
            # Extract hash from the label
            label_text = self.file_hash_label.text()
            if ":" in label_text:
                hash_value = label_text.split(":", 1)[1].strip()
                clipboard.setText(hash_value)
                self.statusBar().showMessage(f"Hash copied to clipboard: {hash_value[:10]}...", 3000)
            else:
                self.statusBar().showMessage("No hash available to copy", 3000)
        
    def refresh_analysis(self):
        """Refresh the analysis tab with current packet data"""
        self.statusBar().showMessage("Refreshing analysis...")
        
        # Only proceed if we have packets
        if not self.packets:
            self.statusBar().showMessage("No packets to analyze")
            return
        
        # Get file information (if available)
        if self.current_file:
            file_name = os.path.basename(self.current_file)
            file_size = os.path.getsize(self.current_file)  
            self.file_name_label.setText(f"Filename: {file_name}")
            self.file_size_label.setText(f"File Size: {self.format_size(file_size)}")
            
            # Update the packet count in the analysis tab
            self.analysis_pkt_count_label.setText(f"Packet Count: {len(self.packets):,}")
            
            # Calculate SHA-256 hash
            self.statusBar().showMessage("Calculating SHA-256 hash...")
            QApplication.processEvents()
            
            # For large files, show a progress dialog
            if file_size > 100 * 1024 * 1024:  # If file is larger than 100MB
                progress = QMessageBox()
                progress.setWindowTitle("Calculating Hash")
                progress.setText("Calculating SHA-256 hash, please wait...")
                progress.setStandardButtons(QMessageBox.StandardButton.NoButton)
                progress.show()
                QApplication.processEvents()
                
                file_hash = self.calculate_file_hash(self.current_file, 'sha256')
                progress.close()
            else:
                file_hash = self.calculate_file_hash(self.current_file, 'sha256')
            
            # Update the hash label
            self.file_hash_label.setText(f"SHA-256: {file_hash}")
        else:
            self.file_name_label.setText("Filename: Live Capture")
            self.file_size_label.setText("File Size: N/A")
            self.file_hash_label.setText("SHA-256: N/A for live capture")

        # Use the correct variable name here
        self.analysis_pkt_count_label.setText(f"Packet Count: {len(self.packets):,}")
        
        # Get capture duration
        summary = self.packet_analyzer.get_capture_summary()
        if summary['start_time'] is not None and summary['end_time'] is not None:
            duration = summary['duration']
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            self.capture_duration_label.setText(f"Capture Duration: {minutes} minutes {seconds} seconds")
            
            # Format date range
            start_time = datetime.fromtimestamp(summary['start_time'])
            end_time = datetime.fromtimestamp(summary['end_time'])
            self.date_range_label.setText(f"Date Range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            self.capture_duration_label.setText("Capture Duration: N/A")
            self.date_range_label.setText("Date Range: N/A")
        
        # Update protocol statistics
        protocol_stats = self.packet_analyzer.get_protocol_stats()
        protocol_text = ""
        for protocol, percentage in protocol_stats.items():
            protocol_text += f"{protocol}: {percentage:.1f}%\n"
        if not protocol_text:
            protocol_text = "No protocol data available"
        self.protocol_stats.setText(protocol_text)
        
        # Update top talkers
        top_talkers = self.packet_analyzer.get_top_talkers(limit=5)
        self.top_talkers.setRowCount(len(top_talkers))
        for row, talker in enumerate(top_talkers):
            self.top_talkers.setItem(row, 0, QTableWidgetItem(talker['ip']))
            self.top_talkers.setItem(row, 1, QTableWidgetItem(str(talker['packets'])))
            self.top_talkers.setItem(row, 2, QTableWidgetItem(self.format_size(talker['bytes'])))
        
        # Update port statistics
        port_stats = self.packet_analyzer.get_port_stats(limit=5)
        self.port_stats.setRowCount(len(port_stats))
        for row, port in enumerate(port_stats):
            self.port_stats.setItem(row, 0, QTableWidgetItem(str(port['port'])))
            self.port_stats.setItem(row, 1, QTableWidgetItem(port['service']))
            self.port_stats.setItem(row, 2, QTableWidgetItem(str(port['count'])))
        
        # Update security findings
        security_findings = self.packet_analyzer.get_security_findings()
        if security_findings:
            findings_text = "Potential Security Findings:\n\n"
            for i, finding in enumerate(security_findings, 1):
                findings_text += f"{i}. {finding['type']} (Packet #{finding['packet_num']})\n"
                findings_text += f"   - Risk Level: {finding['severity']}\n"
                findings_text += f"   - Description: {finding['description']}\n\n"
        else:
            findings_text = "No security issues identified."
        
        self.security_findings.setText(findings_text)
        self.update_protocol_stats()
        self.update_security_findings()
        self.statusBar().showMessage("Analysis complete")

    def scan_interfaces(self):
        """Scan for available network interfaces and populate the combo box"""
        self.interface_combo.clear()
        
        if not SCAPY_AVAILABLE:
            self.interface_combo.addItem("No interfaces found - Scapy not installed")
            self.start_button.setEnabled(False)
            return
        
        try:
            # On Windows, we can get more descriptive names
            if os.name == 'nt':
                from scapy.arch.windows import get_windows_if_list
                interfaces_info = get_windows_if_list()
                
                if interfaces_info:
                    for iface in interfaces_info:
                        name = iface.get('name', '')
                        description = iface.get('description', '')
                        if description:
                            display_name = f"{name} ({description})"
                        else:
                            display_name = name
                        self.interface_combo.addItem(display_name, name)  # Store actual name as item data
                    self.start_button.setEnabled(True)
                else:
                    self.interface_combo.addItem("No interfaces found")
                    self.start_button.setEnabled(False)
            else:
                # On Linux/Mac, just use standard interface list
                interfaces = get_if_list()
                if interfaces:
                    for iface in interfaces:
                        self.interface_combo.addItem(iface)
                    self.start_button.setEnabled(True)
                else:
                    self.interface_combo.addItem("No interfaces found")
                    self.start_button.setEnabled(False)
        except Exception as e:
            print(f"Error scanning interfaces: {str(e)}")
            self.interface_combo.addItem(f"Error scanning interfaces: {str(e)}")
            self.start_button.setEnabled(False)
                
        self.statusBar().showMessage("Network interfaces scanned", 3000)

    def format_size(self, size_bytes):
        """Format a size in bytes to a human-readable string"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def add_sample_analysis(self):
        """Add sample analysis data when no real data is available"""
        # Only use sample data if we have no real packets
        if self.packets:
            self.refresh_analysis()
            return
            
        # Update UI with sample data
        self.file_name_label.setText("Filename: No file loaded (Sample Data)")
        self.file_size_label.setText("File Size: N/A")
        self.analysis_pkt_count_label.setText("Packet Count: 0")
        self.capture_duration_label.setText("Capture Duration: N/A")
        self.date_range_label.setText("Date Range: N/A")
        
        # Sample protocol statistics
        self.protocol_stats.setText(
            "This is sample data.\nCapture some packets or load a PCAP file to see real statistics."
        )
        
        # Clear tables
        self.top_talkers.setRowCount(0)
        self.port_stats.setRowCount(0)
        
        # Clear security findings
        self.security_findings.setText(
            "No packets captured or loaded.\n\n"
            "Start a packet capture or load a PCAP file to perform security analysis."
        )

    def recalculate_hash(self):
        """Recalculate the SHA-256 hash of the current file"""
        if not self.current_file or not os.path.exists(self.current_file):
            return
        
        # Show calculating status
        self.statusBar().showMessage("Calculating SHA-256 hash...")
        QApplication.processEvents()
        
        # For large files, show a progress dialog
        file_size = os.path.getsize(self.current_file)
        if file_size > 100 * 1024 * 1024:  # If file is larger than 100MB
            progress = QMessageBox()
            progress.setWindowTitle("Calculating Hash")
            progress.setText("Calculating SHA-256 hash, please wait...")
            progress.setStandardButtons(QMessageBox.StandardButton.NoButton)
            progress.show()
            QApplication.processEvents()
            
            file_hash = self.calculate_file_hash(self.current_file, 'sha256')
            progress.close()
        else:
            file_hash = self.calculate_file_hash(self.current_file, 'sha256')
            
        # Update the hash label
        self.file_hash_label.setText(f"SHA-256: {file_hash}")
        self.copy_hash_button.setEnabled(True)
        
        self.statusBar().showMessage("SHA-256 hash calculation complete", 3000)

    def setup_analysis_tab(self):
        # Main layout with proper spacing
        layout = QVBoxLayout(self.analysis_tab)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Top section: File Information
        file_info_group = QGroupBox("PCAP File Information")
        file_info_layout = QGridLayout(file_info_group)
        file_info_layout.setSpacing(8)
        file_info_layout.setContentsMargins(15, 15, 15, 15)
        
        # Create labels with consistent width
        label_width = 200
        self.file_name_label = QLabel("Filename: No file loaded")
        self.file_name_label.setMinimumWidth(label_width)
        self.file_size_label = QLabel("File Size: N/A")
        self.file_size_label.setMinimumWidth(label_width)
        self.analysis_pkt_count_label = QLabel("Packet Count: 0")
        self.analysis_pkt_count_label.setMinimumWidth(label_width)
        self.capture_duration_label = QLabel("Capture Duration: N/A")
        self.capture_duration_label.setMinimumWidth(label_width)
        self.date_range_label = QLabel("Date Range: N/A")
        self.date_range_label.setMinimumWidth(label_width)
        
        # Hash section with better layout
        self.file_hash_label = QLabel("SHA-256: -")
        self.file_hash_label.setWordWrap(True)
        self.file_hash_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        # Organize file info in a grid
        file_info_layout.addWidget(self.file_name_label, 0, 0)
        file_info_layout.addWidget(self.file_size_label, 0, 1)
        file_info_layout.addWidget(self.analysis_pkt_count_label, 1, 0)
        file_info_layout.addWidget(self.capture_duration_label, 1, 1)
        file_info_layout.addWidget(self.date_range_label, 2, 0, 1, 2)
        file_info_layout.addWidget(self.file_hash_label, 3, 0, 1, 2)
        
        # Middle section: Traffic Statistics with tabs
        traffic_stats_group = QGroupBox("Traffic Statistics")
        traffic_stats_layout = QVBoxLayout(traffic_stats_group)
        traffic_stats_layout.setSpacing(0)
        traffic_stats_layout.setContentsMargins(5, 15, 5, 5)
        
        # Create tab widget for traffic statistics
        stats_tab_widget = QTabWidget()
        stats_tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3A3436;
                background: #1A1416;
                border-radius: 3px;
            }
            QTabBar::tab {
                background: #2A2426;
                color: #CCCCCC;
                padding: 8px 15px;
                border: 1px solid #3A3436;
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                min-width: 120px;
            }
            QTabBar::tab:selected {
                background: #B71C1C;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background: #3A3436;
            }
        """)
        
        # Protocol Distribution Tab
        protocol_tab = QWidget()
        protocol_layout = QVBoxLayout(protocol_tab)
        protocol_layout.setContentsMargins(10, 10, 10, 10)
        
        # Add scroll area for protocol stats
        protocol_scroll = QScrollArea()
        protocol_scroll.setWidgetResizable(True)
        protocol_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        protocol_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        protocol_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #1E1E1E;
            }
            QScrollBar:vertical {
                border: none;
                background: #2A2426;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #4A4446;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5A5456;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QScrollBar:horizontal {
                border: none;
                background: #2A2426;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #4A4446;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #5A5456;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
        """)
        
        protocol_container = QWidget()
        protocol_container_layout = QVBoxLayout(protocol_container)
        protocol_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.protocol_stats = QTextEdit()
        self.protocol_stats.setReadOnly(True)
        self.protocol_stats.setMinimumHeight(250)
        self.protocol_stats.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #3A3436;
                border-radius: 3px;
                padding: 5px;
            }
        """)
        protocol_container_layout.addWidget(self.protocol_stats)
        protocol_scroll.setWidget(protocol_container)
        protocol_layout.addWidget(protocol_scroll)
        
        # Top Talkers Tab with scroll area
        talkers_tab = QWidget()
        talkers_layout = QVBoxLayout(talkers_tab)
        talkers_layout.setContentsMargins(10, 10, 10, 10)
        
        talkers_scroll = QScrollArea()
        talkers_scroll.setWidgetResizable(True)
        talkers_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        talkers_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        talkers_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #1E1E1E;
            }
            QScrollBar:vertical {
                border: none;
                background: #2A2426;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #4A4446;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5A5456;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QScrollBar:horizontal {
                border: none;
                background: #2A2426;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #4A4446;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #5A5456;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
        """)
        
        talkers_container = QWidget()
        talkers_container_layout = QVBoxLayout(talkers_container)
        talkers_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.top_talkers = QTableWidget()
        self.top_talkers.setColumnCount(3)
        self.top_talkers.setHorizontalHeaderLabels(["IP Address", "Packets", "Bytes"])
        self.top_talkers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.top_talkers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.top_talkers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.top_talkers.setColumnWidth(1, 100)
        self.top_talkers.setColumnWidth(2, 100)
        self.top_talkers.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.top_talkers.setAlternatingRowColors(True)
        self.top_talkers.setMinimumHeight(250)
        self.top_talkers.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E1E;
                color: #FFFFFF;
                gridline-color: #3A3436;
                border: 1px solid #3A3436;
                border-radius: 3px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #2A2426;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #3A3436;
            }
            QTableWidget::item:selected {
                background-color: #B71C1C;
            }
        """)
        talkers_container_layout.addWidget(self.top_talkers)
        talkers_scroll.setWidget(talkers_container)
        talkers_layout.addWidget(talkers_scroll)
        
        # Port Statistics Tab with scroll area
        ports_tab = QWidget()
        ports_layout = QVBoxLayout(ports_tab)
        ports_layout.setContentsMargins(10, 10, 10, 10)
        
        ports_scroll = QScrollArea()
        ports_scroll.setWidgetResizable(True)
        ports_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        ports_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        ports_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #1E1E1E;
            }
            QScrollBar:vertical {
                border: none;
                background: #2A2426;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #4A4446;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5A5456;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QScrollBar:horizontal {
                border: none;
                background: #2A2426;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #4A4446;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #5A5456;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
        """)
        
        ports_container = QWidget()
        ports_container_layout = QVBoxLayout(ports_container)
        ports_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.port_stats = QTableWidget()
        self.port_stats.setColumnCount(3)
        self.port_stats.setHorizontalHeaderLabels(["Port", "Service", "Count"])
        self.port_stats.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.port_stats.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.port_stats.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.port_stats.setColumnWidth(0, 100)
        self.port_stats.setColumnWidth(2, 100)
        self.port_stats.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.port_stats.setAlternatingRowColors(True)
        self.port_stats.setMinimumHeight(250)
        self.port_stats.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E1E;
                color: #FFFFFF;
                gridline-color: #3A3436;
                border: 1px solid #3A3436;
                border-radius: 3px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #2A2426;
                color: #FFFFFF;
                padding: 5px;
                border: 1px solid #3A3436;
            }
            QTableWidget::item:selected {
                background-color: #B71C1C;
            }
        """)
        ports_container_layout.addWidget(self.port_stats)
        ports_scroll.setWidget(ports_container)
        ports_layout.addWidget(ports_scroll)
        
        # Add tabs to tab widget
        stats_tab_widget.addTab(protocol_tab, "Protocol Distribution")
        stats_tab_widget.addTab(talkers_tab, "Top Talkers")
        stats_tab_widget.addTab(ports_tab, "Port Statistics")
        
        # Add tab widget to traffic stats layout
        traffic_stats_layout.addWidget(stats_tab_widget)
        
        # Bottom section: Security Analysis
        security_group = QGroupBox("Security Analysis")
        security_layout = QVBoxLayout(security_group)
        security_layout.setSpacing(10)
        security_layout.setContentsMargins(15, 15, 15, 15)
        
        self.security_findings = QTextEdit()
        self.security_findings.setReadOnly(True)
        self.security_findings.setMinimumHeight(150)
        self.security_findings.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #3A3436;
                border-radius: 3px;
                padding: 5px;
            }
        """)
        security_layout.addWidget(self.security_findings)
        
        # Refresh button with proper alignment
        button_layout = QHBoxLayout()
        self.refresh_analysis_button = QPushButton("Refresh Analysis")
        self.refresh_analysis_button.setFixedWidth(120)
        self.refresh_analysis_button.clicked.connect(self.refresh_analysis)
        self.refresh_analysis_button.setStyleSheet("""
            QPushButton {
                background-color: #B71C1C;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
            QPushButton:pressed {
                background-color: #931515;
            }
        """)
        button_layout.addStretch()
        button_layout.addWidget(self.refresh_analysis_button)
        
        # Add all sections to main layout with proper spacing
        layout.addWidget(file_info_group)
        layout.addWidget(traffic_stats_group)
        layout.addWidget(security_group)
        layout.addLayout(button_layout)
        
        # Initialize with sample data
        self.add_sample_analysis()



class FilePreviewDialog(QDialog):
    """Dialog for previewing files extracted from PCAP"""
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.file_ext = os.path.splitext(file_path)[1].lower()
        
        # Set up the dialog
        self.setWindowTitle(f"Preview: {self.file_name}")
        self.setMinimumSize(640, 480)
        self.resize(800, 600)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Create preview area
        self.preview_scroll = QScrollArea()
        self.preview_scroll.setWidgetResizable(True)
        
        # Load and display the file based on its type
        self.preview_content = QWidget()
        self.preview_layout = QVBoxLayout(self.preview_content)
        
        # Attempt to display the file
        self.display_file()
        
        self.preview_scroll.setWidget(self.preview_content)
        layout.addWidget(self.preview_scroll)
        
        # Add buttons at the bottom
        button_layout = QHBoxLayout()
        
        # Save button
        self.save_button = QPushButton("Save As...")
        self.save_button.clicked.connect(self.save_file)
        
        # Close button
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        
        button_layout.addWidget(self.save_button)
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
    
    def display_file(self):
        """Display the file content based on its type"""
        # Clear any existing content
        for i in reversed(range(self.preview_layout.count())):
            self.preview_layout.itemAt(i).widget().setParent(None)
        
        # Image files
        if self.file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            try:
                # Create image label
                image_label = QLabel()
                image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
                # Load the image with QPixmap
                pixmap = QPixmap(self.file_path)
                
                # Scale pixmap if it's larger than the dialog
                if pixmap.width() > 780 or pixmap.height() > 580:
                    pixmap = pixmap.scaled(780, 580, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                
                # Set the pixmap
                image_label.setPixmap(pixmap)
                
                # Add info label
                info_label = QLabel(f"Image: {self.file_name} ({pixmap.width()}x{pixmap.height()})")
                info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
                # Add to layout
                self.preview_layout.addWidget(info_label)
                self.preview_layout.addWidget(image_label)
                self.preview_layout.addStretch()
                
            except Exception as e:
                # If there's an error loading the image, show error message
                error_label = QLabel(f"Error displaying image: {str(e)}")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self.preview_layout.addWidget(error_label)
        
        # Text-based files
        elif self.file_ext in ['.txt', '.html', '.xml', '.json', '.csv', '.js', '.css']:
            try:
                # Read the file content
                with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                
                # Create text display
                text_display = QTextEdit()
                text_display.setReadOnly(True)
                
                # Syntax highlighting for certain file types
                if self.file_ext == '.html':
                    text_display.setHtml(content)
                elif self.file_ext in ['.json', '.js']:
                    # Basic syntax highlighting for JSON/JS
                    text_display.setPlainText(content)
                    # Set a monospace font
                    font = QFont("Courier New", 10)
                    text_display.setFont(font)
                else:
                    text_display.setPlainText(content)
                
                # Add info label
                info_label = QLabel(f"Text file: {self.file_name} ({len(content)} characters)")
                info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
                # Add to layout
                self.preview_layout.addWidget(info_label)
                self.preview_layout.addWidget(text_display)
                
            except Exception as e:
                # If there's an error loading the file, show error message
                error_label = QLabel(f"Error displaying text file: {str(e)}")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self.preview_layout.addWidget(error_label)
        
        # PDF files - show a message that they can't be previewed directly
        elif self.file_ext == '.pdf':
            info_label = QLabel(f"PDF File: {self.file_name}")
            info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            message_label = QLabel("PDF files cannot be previewed directly. Please use 'Save As...' to save the file and open it in a PDF viewer.")
            message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            message_label.setWordWrap(True)
            
            self.preview_layout.addWidget(info_label)
            self.preview_layout.addWidget(message_label)
        
        # Binary files and other unsupported formats
        else:
            # Show a hex viewer for binary files
            try:
                # Read the file as binary
                with open(self.file_path, 'rb') as f:
                    content = f.read()
                
                # Create a hex display (simplified)
                hex_display = QTextEdit()
                hex_display.setReadOnly(True)
                hex_display.setFont(QFont("Courier New", 10))
                
                # Format as hex dump
                hex_text = self.format_hex_dump(content)
                hex_display.setPlainText(hex_text)
                
                # Add info label
                info_label = QLabel(f"Binary file: {self.file_name} ({len(content)} bytes)")
                info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
                message_label = QLabel("This file type cannot be previewed directly. Showing hex representation.")
                message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                message_label.setWordWrap(True)
                
                # Add to layout
                self.preview_layout.addWidget(info_label)
                self.preview_layout.addWidget(message_label)
                self.preview_layout.addWidget(hex_display)
                
            except Exception as e:
                # If there's an error loading the file, show error message
                error_label = QLabel(f"Error displaying file: {str(e)}")
                error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self.preview_layout.addWidget(error_label)
    
    def format_hex_dump(self, data, bytes_per_line=16):
        """Format binary data as a hex dump"""
        result = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            # Address
            line = f"{i:08x}:  "
            
            # Hex values
            hex_values = ' '.join(f"{b:02x}" for b in chunk)
            line += f"{hex_values:<{bytes_per_line*3}}  "
            
            # ASCII representation
            ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            line += ascii_values
            
            result.append(line)
        
        return '\n'.join(result)
    
    def save_file(self):
        """Save the file to a user-selected location"""
        file_name = os.path.basename(self.file_path)
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save File As", file_name, "All Files (*)")
        
        if not save_path:
            return  # User canceled
        
        try:
            # Copy the file
            shutil.copy2(self.file_path, save_path)
            QMessageBox.information(self, "File Saved", 
                                 f"File saved successfully to {save_path}", 
                                 QMessageBox.StandardButton.Ok)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", 
                              f"Failed to save file: {str(e)}", 
                              QMessageBox.StandardButton.Ok)
            


