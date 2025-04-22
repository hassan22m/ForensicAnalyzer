# CRTL + I to open copilot
import sys
import os
import subprocess
import hashlib
import datetime
import pytsk3
import glob
import json,time 
import tempfile  
import argparse
import re, csv
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                            QHBoxLayout, QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit, 
                            QPushButton, QFileDialog, QLabel, QLineEdit, QComboBox,QScrollArea,QMenu,
                            QProgressBar, QMessageBox, QTableWidget, QTableWidgetItem, QStyle,
                            QHeaderView, QPlainTextEdit, QDialog, QFormLayout, QStatusBar,QListWidget,
                            QGridLayout, QGroupBox, QCheckBox, QSpinBox, QInputDialog,QDateTimeEdit,QProgressDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QByteArray, QBuffer, QIODevice,QTimer
from PyQt6.QtGui import QFont, QTextCursor, QPixmap, QIcon, QTextCharFormat, QColor

from analyzer.core.storage_analyzer import ( SparseImageCaptureDialog, LogicalAcquisitionDialog, 
                                           ForensicImage, AddBookmarkDialog, EnhancedExportOptionsDialog, 
                                           ReportGenerator, ImageCaptureDialog, FileTypeAnalyzer, StringSearcher)

from analyzer.core.case_manager import  EvidenceItem

class StorageAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forensic Storage Analyzer")
        self.resize(1200, 800)
        
        self.case_manager = None # now we will use the integrated case manager 
        self._status_bar = None
        self.current_image = None
        self.current_evidence_id = None
        # keep track of the current case and evidence
        self.current_case = None
        self.active_evidence = None
        
        self.file_tree = None
        self.hex_view = None
        self.integrated_browser = None
        self.file_type_widget = None
        self.search_widget = None
        
        # Setup signals
        self.bookmark_added = pyqtSignal(object, object)  # (evidence_item, bookmark)
        
        self.init_ui()
        
        # Apply dark theme
        #self.apply_dark_theme()
        
        # Connect tab change signal
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
    def init_ui(self):
        # Initialize attributes to None to avoid attribute errors
        self.file_tree = None
        self.hex_view = None

        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Tab widget with modern styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)  # More modern look for tabs
        
        # Create tabs
        self.create_evidence_tab()
        self.create_integrated_browser_tab()
        self.add_analysis_tabs()
        self.create_report_tab()
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        self.add_dashboard()
        self.update_dashboard()

    def apply_dark_theme(self):
        """Apply dark theme styling to the application"""
        self.setStyleSheet("""
            QMainWindow, QDialog, QWidget {
                background-color: #2d2d2d;
                color: #f0f0f0;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #3d3d3d;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #f0f0f0;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #3d3d3d;
                border: 1px solid #555555;
                border-bottom-color: #3d3d3d;
            }
            QPushButton {
                background-color: #0d47a1;
                color: white;
                padding: 6px 12px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:pressed {
                background-color: #0a3d87;
            }
            QTreeWidget, QTableWidget {
                border: 1px solid #555555;
                background-color: #3d3d3d;
                color: #f0f0f0;
                alternate-background-color: #353535;
            }
            QHeaderView::section {
                background-color: #2d2d2d;
                color: #f0f0f0;
                padding: 4px;
                border: 1px solid #555555;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #555555;
                border-radius: 4px;
                margin-top: 1ex;
                padding-top: 10px;
                color: #f0f0f0;
            }
            QLineEdit, QTextEdit, QPlainTextEdit {
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 4px;
                background-color: #2d2d2d;
                color: #f0f0f0;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 4px;
                text-align: center;
                color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: #0d47a1;
                width: 10px;
            }
            QCheckBox, QRadioButton, QLabel {
                color: #f0f0f0;
            }
            QMenu {
                background-color: #2d2d2d;
                color: #f0f0f0;
            }
            QMenu::item:selected {
                background-color: #0d47a1;
            }
            QMenuBar {
                background-color: #2d2d2d;
                color: #f0f0f0;
            }
            QMenuBar::item:selected {
                background-color: #3d3d3d;
            }
            QComboBox {
                background-color: #2d2d2d;
                color: #f0f0f0;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 4px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 15px;
                border-left-width: 1px;
                border-left-color: #555555;
                border-left-style: solid;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: #f0f0f0;
                selection-background-color: #0d47a1;
            }
            QDateTimeEdit {
                background-color: #2d2d2d;
                color: #f0f0f0;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 4px;
            }
            QScrollBar {
                background-color: #2d2d2d;
                border: 1px solid #555555;
            }
            QScrollBar::handle {
                background-color: #3d3d3d;
            }
            QScrollBar::handle:hover {
                background-color: #4d4d4d;
            }
        """)

    def set_case_manager(self, case_manager):
        """Set the case manager reference and update components"""
        self.case_manager = case_manager
        # Connect signals from case manager
        if hasattr(case_manager, 'case_opened_signal'):
            case_manager.case_opened_signal.connect(self.on_case_opened)
        if hasattr(case_manager, 'case_closed_signal'):
            case_manager.case_closed_signal.connect(self.on_case_closed)
        if hasattr(case_manager, 'evidence_added_signal'):
            case_manager.evidence_added_signal.connect(self.on_evidence_added)
        
        # Update integrated browser with case manager
        if self.integrated_browser:
            self.integrated_browser.case_manager = case_manager
            
        # Check if there's an open case already and handle it
        if case_manager and case_manager.current_case:
            self.on_case_opened(case_manager.current_case)
    
    def set_status_bar(self, status_bar: QStatusBar):
        self._status_bar = status_bar

    def on_case_opened(self, case):
        """Handle case opened event"""
        self.current_case = case
        if self._status_bar:
            self._status_bar.showMessage(f"Case '{case.name}' opened")
        
        # Update evidence table
        self.update_evidence_table()
        
        # Update dashboard
        if hasattr(self, 'update_dashboard'):
            self.update_dashboard()
    
    def on_case_closed(self):
        """Handle case closed event"""
        self.current_case = None
        self.active_evidence = None
        # Clear any open images
        self.current_image = None
        self.current_evidence_id = None
        
        if self._status_bar:
            self._status_bar.showMessage("No case open")
        
        # Update dashboard
        if hasattr(self, 'update_dashboard'):
            self.update_dashboard()
        
    def on_evidence_added(self, evidence_item):
        """Handle evidence added event for storage evidence"""
        print(f"Storage analyzer received evidence added event: {evidence_item}")
        
        try:
            # Handle different evidence item formats
            evidence_type = None
            source_path = None
            evidence_id = None
            
            if hasattr(evidence_item, 'evidence_type'):
                # It's an EvidenceItem object
                evidence_type = evidence_item.evidence_type
                source_path = evidence_item.source_path if hasattr(evidence_item, 'source_path') else None
                evidence_id = evidence_item.id if hasattr(evidence_item, 'id') else None
                print(f"Processing evidence as object: type={evidence_type}, path={source_path}, id={evidence_id}")
            elif isinstance(evidence_item, dict):
                # It's a dictionary
                evidence_type = evidence_item.get('type')
                source_path = evidence_item.get('path')
                evidence_id = evidence_item.get('id')
                print(f"Processing evidence as dict: type={evidence_type}, path={source_path}, id={evidence_id}")
            else:
                print(f"Unknown evidence format: {type(evidence_item)}")
                return
                    
            # Only process storage evidence
            if evidence_type not in [EvidenceItem.TYPE_STORAGE, 'Disk Image', 'storage']:
                print(f"Not processing non-storage evidence of type: {evidence_type}")
                return
            
            # Save current evidence reference
            self.active_evidence = evidence_item
            
            # Load the disk image
            if source_path and os.path.exists(source_path):
                print(f"Loading disk image: {source_path}")
                success = self.load_disk_image(source_path, evidence_id)
                
                if success:
                    # Update UI to show image is loaded
                    if self._status_bar:
                        self._status_bar.showMessage(f"Loaded storage evidence: {os.path.basename(source_path)}")
                    else:
                        self.statusBar.showMessage(f"Loaded storage evidence: {os.path.basename(source_path)}")
                    
                    # Switch to the integrated browser tab automatically
                    self.switch_to_integrated_browser_tab()
                else:
                    if self._status_bar:
                        self._status_bar.showMessage(f"Failed to load storage evidence: {os.path.basename(source_path)}")
                    else:
                        self.statusBar.showMessage(f"Failed to load storage evidence: {os.path.basename(source_path)}")
            else:
                msg = f"Warning: Evidence file not found at {source_path}"
                print(msg)
                if self._status_bar:
                    self._status_bar.showMessage(msg)
                else:
                    self.statusBar.showMessage(msg)
        except Exception as e:
            error_msg = f"Error processing evidence: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            if self._status_bar:
                self._status_bar.showMessage(error_msg)
            else:
                self.statusBar.showMessage(error_msg)
                
    def switch_to_integrated_browser_tab(self):
        """Switch to the integrated browser tab"""
        try:
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Integrated Browser":
                    self.tab_widget.setCurrentIndex(i)
                    break
        except Exception as e:
            print(f"Error switching to integrated browser tab: {e}")
    
    def on_evidence_selected(self, evidence_item):
        """Handle evidence selected event"""
        # Only process storage evidence
        if not evidence_item or not hasattr(evidence_item, 'evidence_type') or evidence_item.evidence_type != EvidenceItem.TYPE_STORAGE:
            return
        
        # Save current evidence reference
        self.active_evidence = evidence_item
        
        # Load the disk image
        source_path = evidence_item.source_path if hasattr(evidence_item, 'source_path') else ""
        evidence_id = evidence_item.id if hasattr(evidence_item, 'id') else None
        
        if source_path and os.path.exists(source_path):
            self.load_disk_image(source_path, evidence_id)
            
            if self._status_bar:
                self._status_bar.showMessage(f"Selected storage evidence: {os.path.basename(source_path)}")
        else:
            if self._status_bar:
                self._status_bar.showMessage(f"Warning: Evidence file not found at {source_path}")
            print(f"Warning: Evidence file not found at {source_path}")
    
    def on_bookmark_added(self, evidence_item, bookmark):
        """Handle bookmark added event"""
        # Only process storage evidence
        if evidence_item.evidence_type != EvidenceItem.TYPE_STORAGE:
            return
        
        # Check if this bookmark is for a specific file or location
        data = bookmark.data
        if "file_path" in data:
            self.navigate_to_file(data["file_path"])
            if self._status_bar:
                self._status_bar.showMessage(f"Navigated to bookmarked file: {data['file_path']}")
        elif "offset" in data:
            # If it's a bookmark for a specific disk offset
            self.navigate_to_offset(data["offset"])
            if self._status_bar:
                self._status_bar.showMessage(f"Navigated to bookmarked offset: {data['offset']}")
    
    def add_bookmark_current_file(self):
        """Add a bookmark for the currently selected file"""
        # Check if we have an active case and evidence
        if not self.case_manager or not self.case_manager.current_case or not self.active_evidence:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or storage evidence")
            return
        
        # Get the currently selected file path
        selected_file = self.get_selected_file_path()
        if not selected_file:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No file selected")
            return
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"File: {os.path.basename(selected_file)}")
        
        if ok and description:
            # Create a good location description
            location = f"File: {selected_file}"
            
            # Create bookmark data with file-specific information
            data = {
                "file_path": selected_file,
                "file_name": os.path.basename(selected_file),
                "directory": os.path.dirname(selected_file)
            }
            
            # Add file metadata if available
            file_info = self.get_file_metadata(selected_file)
            if file_info:
                data.update(file_info)
            
            # Add the bookmark through the case manager
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data)
            
            if success:
                # Update status
                if self._status_bar:
                    self._status_bar.showMessage(f"Added bookmark: {description}")
                
                # Force immediate UI updates
                self.update_bookmarks_table()
                self.update_dashboard()
                
                # Make sure the bookmark is reflected in all components
                if hasattr(self.case_manager, 'synchronize_bookmarks'):
                    self.case_manager.synchronize_bookmarks()
                
                # Save case to persist changes
                self.case_manager.save_case()
                
                # Important: Emit signal to notify other components
                self.bookmark_added.emit(self.active_evidence, bookmark)
            else:
                QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")
    
    def add_bookmark_disk_offset(self, offset=None):
        """Add a bookmark for a specific disk offset"""
        # Check if we have an active case and evidence
        if not hasattr(self, 'current_case') or not self.current_case or not hasattr(self, 'active_evidence') or not self.active_evidence:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or storage evidence")
            return
        
        # If no offset provided, use the current position in hex view
        if offset is None:
            offset = self.get_current_offset()
            if offset is None:
                QMessageBox.warning(self, "Cannot Add Bookmark", "No valid disk offset selected")
                return
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"Offset: 0x{offset:08x}")
        
        if ok and description:
            # Create a good location description
            location = f"Disk Offset: 0x{offset:08x}"
            
            # Create bookmark data with offset-specific information
            data = {
                "offset": offset,
                "offset_hex": f"0x{offset:08x}",
                "sector": offset // 512
            }
            
            # Add any additional context like hex view around the offset
            hex_view = self.get_hex_view_at_offset(offset)
            if hex_view:
                data["hex_view"] = hex_view
            
            # Add the bookmark through the case manager
            if hasattr(self, 'case_manager'):
                success, message, bookmark = self.case_manager.add_bookmark(
                    self.active_evidence.id, description, location, data)
                
                if success:
                    self._status_bar.showMessage(f"Added bookmark: {description}")
                else:
                    QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")
            else:
                QMessageBox.warning(self, "Bookmark Error", "Case manager not available")
    
    def get_selected_file_path(self):
        """Get the path of the currently selected file"""
        # This method should be implemented based on your specific UI structure
        # Example:
        selected_items = self.file_tree.selectedItems()
        if selected_items:
            # Assuming you store the file path as data in the tree item
            return selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        return None
    
    def get_file_metadata(self, file_path):
        """Get metadata for a file"""
        # This method should be implemented based on your specific file system parsing
        # Example:
        try:
            # Get basic file information
            return {
                "size": 0,  # Replace with actual size
                "created": "",  # Replace with actual creation time
                "modified": "",  # Replace with actual modification time
                "accessed": "",  # Replace with actual access time
                "is_directory": False  # Replace with actual type
            }
        except Exception as e:
            print(f"Error getting file metadata: {e}")
            return None
    
    def get_current_offset(self):
        """Get the current offset in the hex view"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Get the current position from hex editor
            return 0  # Replace with actual offset
        except Exception as e:
            print(f"Error getting current offset: {e}")
            return None
    
    def get_hex_view_at_offset(self, offset):
        """Get a hex representation of data at an offset"""
        # This method should be implemented based on your specific hex viewing code
        # Example:
        try:
            # Get a small window of bytes around the offset
            # Replace with actual hex view code
            return "00 00 00 00 00 00 00 00"
        except Exception as e:
            print(f"Error getting hex view: {e}")
            return None
    
    def navigate_to_file(self, file_path):
        """Navigate to a specific file in the file explorer"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Find and select the file in your file tree
            # This is just a placeholder - you need to implement the actual selection logic
            print(f"Navigating to file: {file_path}")
            
            # Select the file in the tree
            self.select_file_in_tree(file_path)
            
            # Display the file content or properties
            self.display_file_content(file_path)
        except Exception as e:
            print(f"Error navigating to file: {e}")
    
    def navigate_to_offset(self, offset):
        """Navigate to a specific offset in the hex view"""
        # This method should be implemented based on your specific hex viewing code
        # Example:
        try:
            # Navigate to the offset in your hex editor
            # This is just a placeholder - you need to implement the actual navigation logic
            print(f"Navigating to offset: 0x{offset:08x}")
            
            # Set the cursor position in the hex editor
            self.set_hex_editor_offset(offset)
        except Exception as e:
            print(f"Error navigating to offset: {e}")
    
    def load_disk_image(self, file_path, evidence_id=None):
        """Load a disk image file"""
        try:
            print(f"Attempting to load disk image: {file_path}")
            
            # Validate file path
            if not os.path.exists(file_path):
                print(f"ERROR: File not found: {file_path}")
                return False
                
            # Create and open the forensic image
            print("Creating ForensicImage object")
            self.current_image = ForensicImage(file_path)
            
            print("Opening ForensicImage")
            success = self.current_image.open()
            
            if not success:
                print("Failed to open disk image using ForensicImage")
                self.current_image = None
                return False
                    
            self.current_evidence_id = evidence_id
            
            # Update integrated browser if available
            if hasattr(self, 'integrated_browser') and self.integrated_browser:
                print("Updating integrated browser")
                self.integrated_browser.set_image(self.current_image, evidence_id)
                
            print("Successfully loaded disk image")
            return True
        except Exception as e:
            import traceback
            print(f"Exception in load_disk_image: {e}")
            traceback.print_exc()
            self.current_image = None
            return False
    
    # Placeholder methods that should be implemented according to your specific UI
    def select_file_in_tree(self, file_path):
        """Select a file in the file tree"""
        pass
    
    def display_file_content(self, file_path):
        """Display file content"""
        pass
    
    def set_hex_editor_offset(self, offset):
        """Set the cursor position in the hex editor"""
        pass

    def update_analysis_components_with_image(self, forensic_image, evidence_id):
        """Update all analysis components when an image is opened in any tab"""
        # Store the image reference for other parts of the application
        self.current_image = forensic_image
        self.current_evidence_id = evidence_id
        
        # Update analysis tabs
        if hasattr(self, 'file_type_widget'):
            self.file_type_widget.set_image(forensic_image)
        if hasattr(self, 'search_widget'):
            self.search_widget.set_image(forensic_image)
        
        self.statusBar.showMessage(f"Forensic image loaded in all components")

    def show_sparse_capture_dialog(self):
        """Show dialog for capturing sparse disk image"""
        dialog = SparseImageCaptureDialog(self)
        result = dialog.exec()
        
        if result == QDialog.DialogCode.Accepted:
            # If we have an open case, ask to add the image as evidence
            if self.case_manager.case_directory:
                reply = QMessageBox.question(self, "Add as Evidence", 
                                        "Do you want to add the captured image as evidence to the current case?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    evidence_path = dialog.output_edit.text()
                    evidence_type = "Sparse Disk Image"
                    description = f"Sparse image from {dialog.source_edit.text()}"
                    
                    self.case_manager.add_evidence(evidence_path, evidence_type, description)
                    self.update_evidence_table()
                    self.update_dashboard()

    def show_logical_acquisition_dialog(self):
        """Show the logical acquisition dialog"""
        dialog = LogicalAcquisitionDialog(self)
        result = dialog.exec()
        
        if result == QDialog.DialogCode.Accepted:
            # If we have an open case, ask to add the acquisition as evidence
            if self.case_manager.case_directory:
                reply = QMessageBox.question(self, "Add as Evidence", 
                                        "Do you want to add the logical acquisition as evidence to the current case?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    # Get the output path from the dialog
                    evidence_path = dialog.output_edit.text()
                    if os.path.isdir(evidence_path):
                        evidence_path = os.path.join(evidence_path, 
                                                os.path.basename(dialog.path_edit.text() or "root"))
                    
                    evidence_type = "Logical Evidence"
                    description = f"Logical acquisition from {dialog.device_edit.text()}"
                    
                    self.case_manager.add_evidence(evidence_path, evidence_type, description)
                    self.update_evidence_table()
                    self.update_dashboard()

    def create_evidence_tab(self):
        evidence_tab = QWidget()
        layout = QVBoxLayout()
        
        # Evidence table
        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(5)
        self.evidence_table.setHorizontalHeaderLabels(["ID", "Type", "Path", "Description", "Added Date"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.evidence_table.itemDoubleClicked.connect(self.open_evidence_item)
        layout.addWidget(self.evidence_table)
        
        # Buttons
        button_layout = QHBoxLayout()
        add_evidence_btn = QPushButton("Add Evidence")
        add_evidence_btn.clicked.connect(self.add_evidence_item)
        remove_evidence_btn = QPushButton("Remove Evidence")
        remove_evidence_btn.clicked.connect(self.remove_evidence_item)
        open_evidence_btn = QPushButton("Open Evidence")
        open_evidence_btn.clicked.connect(self.open_selected_evidence)
        button_layout.addWidget(add_evidence_btn)
        button_layout.addWidget(remove_evidence_btn)
        button_layout.addWidget(open_evidence_btn)
        layout.addLayout(button_layout)
        
        #evidence_tab.setLayout(layout)
        #self.tab_widget.addTab(evidence_tab, "Evidence Items")
        
    def create_browse_tab(self):
        browse_tab = QWidget()
        layout = QVBoxLayout()
        
        # Create splitter for file tree and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # File tree on the left
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Type"])
        
        # Get the header
        header = self.file_tree.header()
        
        # Set resize modes for each column
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name column stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)  # Changed to Interactive
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)  # Changed to Interactive
        
        # Set initial column widths - do this AFTER setting resize modes
        self.file_tree.setColumnWidth(0, 300)  # Name column - wider for file names
        self.file_tree.setColumnWidth(1, 100)  # Size column - increased width
        self.file_tree.setColumnWidth(2, 100)  # Type column - increased width
        
        # Allow user to resize columns by dragging
        header.setStretchLastSection(False)
        
        self.file_tree.itemClicked.connect(self.on_file_selected)
        splitter.addWidget(self.file_tree)
        
        # Rest of your code remains the same
        # File details on the right
        details_widget = QWidget()
        details_layout = QVBoxLayout()
        
        # Metadata area
        metadata_group = QGroupBox("File Metadata")
        metadata_layout = QFormLayout()
        self.file_name_label = QLabel("")
        self.file_size_label = QLabel("")
        self.file_created_label = QLabel("")
        self.file_modified_label = QLabel("")
        self.file_accessed_label = QLabel("")
        self.file_hash_label = QTextEdit()  # Use QTextEdit for multi-line hash display
        self.file_hash_label.setReadOnly(True)
        self.file_hash_label.setMaximumHeight(80)
        
        metadata_layout.addRow("Name:", self.file_name_label)
        metadata_layout.addRow("Size:", self.file_size_label)
        metadata_layout.addRow("Created:", self.file_created_label)
        metadata_layout.addRow("Modified:", self.file_modified_label)
        metadata_layout.addRow("Accessed:", self.file_accessed_label)
        metadata_layout.addRow("Hash Values:", self.file_hash_label)
        
        metadata_group.setLayout(metadata_layout)
        details_layout.addWidget(metadata_group)
        
        # Add button to recalculate hash with different algorithms
        hash_button_layout = QHBoxLayout()
        self.calc_hash_btn = QPushButton("Calculate Custom Hash")
        self.calc_hash_btn.clicked.connect(self.calculate_custom_hash)
        hash_button_layout.addWidget(self.calc_hash_btn)
        details_layout.addLayout(hash_button_layout)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        self.view_file_btn = QPushButton("View File")
        self.view_file_btn.clicked.connect(self.view_selected_file)
        self.export_file_btn = QPushButton("Export File")
        self.export_file_btn.clicked.connect(self.export_selected_file)
        self.add_bookmark_btn = QPushButton("Add Bookmark")
        self.add_bookmark_btn.clicked.connect(self.add_bookmark)
        buttons_layout.addWidget(self.view_file_btn)
        buttons_layout.addWidget(self.export_file_btn)
        buttons_layout.addWidget(self.add_bookmark_btn)
        details_layout.addLayout(buttons_layout)
        
        details_widget.setLayout(details_layout)
        splitter.addWidget(details_widget)
        
        # Set initial sizes
        splitter.setSizes([500, 200])
        
        layout.addWidget(splitter)
        browse_tab.setLayout(layout)
        self.tab_widget.addTab(browse_tab, "Browse Files")
        
    def create_viewer_tab(self):
        viewer_tab = QWidget()
        layout = QVBoxLayout()
        
        # View tabs for different views of the file
        self.view_tabs = QTabWidget()
        
        # Text view
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.view_tabs.addTab(self.text_view, "Text View")
        
        # Hex view
        self.hex_view = HexViewWidget()
        self.view_tabs.addTab(self.hex_view, "Hex View")
        
        # Image view (if applicable)setup_a
        self.image_view = QLabel()
        self.image_view.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_view.setScaledContents(True)
        image_scroll = QWidget()
        image_layout = QVBoxLayout()
        image_layout.addWidget(self.image_view)
        image_layout.addStretch()
        image_scroll.setLayout(image_layout)
        self.view_tabs.addTab(image_scroll, "Image View")
        
        layout.addWidget(self.view_tabs)
        
        # File info and navigation
        info_layout = QHBoxLayout()
        self.viewer_file_path = QLabel("")
        info_layout.addWidget(self.viewer_file_path)
        info_layout.addStretch()
        
        # Navigation controls for hex view
        nav_layout = QHBoxLayout()
        nav_layout.addWidget(QLabel("Offset:"))
        self.offset_edit = QLineEdit("0")
        self.offset_edit.setMaximumWidth(100)
        nav_layout.addWidget(self.offset_edit)
        
        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.go_to_offset)
        nav_layout.addWidget(self.go_btn)
        
        self.prev_btn = QPushButton("Previous")
        self.prev_btn.clicked.connect(self.go_to_prev)
        nav_layout.addWidget(self.prev_btn)
        
        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.go_to_next)
        nav_layout.addWidget(self.next_btn)
        
        info_layout.addLayout(nav_layout)
        layout.addLayout(info_layout)
        
        viewer_tab.setLayout(layout)
        self.tab_widget.addTab(viewer_tab, "File Viewer")
    
    def create_integrated_browser_tab(self):
        """Create an integrated tab that combines evidence, browse, and viewer functionality"""
        try:
            print("Creating integrated browser tab...")
            # Initialize the integrated browser with proper references
            self.integrated_browser = IntegratedForensicBrowser(self, self.case_manager)
            
            # Add it to tab widget with proper error handling
            if hasattr(self, 'tab_widget') and self.tab_widget is not None:
                self.tab_widget.addTab(self.integrated_browser, "Integrated Browser")
                    
            # Connect signals if they exist
            if hasattr(self.integrated_browser, 'image_loaded'):
                print("Connecting image_loaded signal...")
                self.integrated_browser.image_loaded.connect(self.update_analysis_components_with_image)
            
            # Log success
            print("Integrated browser tab created successfully")
            
            # If we have a current image, set it in the browser
            if hasattr(self, 'current_image') and self.current_image and hasattr(self, 'current_evidence_id'):
                print(f"Setting existing image in integrated browser, evidence ID: {self.current_evidence_id}")
                self.integrated_browser.set_image(self.current_image, self.current_evidence_id)
                
        except Exception as e:
            print(f"Error creating integrated browser tab: {e}")
            import traceback
            traceback.print_exc()

    def create_report_tab(self):
        report_tab = QWidget()
        layout = QVBoxLayout()
        
        # Case info section
        case_group = QGroupBox("Case Information")
        case_layout = QFormLayout()
        self.case_name_edit = QLineEdit()
        self.investigator_name_edit = QLineEdit()
        case_layout.addRow("Case Name:", self.case_name_edit)
        case_layout.addRow("Investigator:", self.investigator_name_edit)
        case_group.setLayout(case_layout)
        layout.addWidget(case_group)
        
        # Case notes
        notes_group = QGroupBox("Case Notes")
        notes_layout = QVBoxLayout()
        self.case_notes_edit = QTextEdit()
        notes_layout.addWidget(self.case_notes_edit)
        notes_group.setLayout(notes_layout)
        layout.addWidget(notes_group)
        
        # Bookmarks table
        bookmarks_group = QGroupBox("Bookmarks")
        bookmarks_layout = QVBoxLayout()
        self.bookmarks_table = QTableWidget()
        self.bookmarks_table.setColumnCount(4)
        self.bookmarks_table.setHorizontalHeaderLabels(["ID", "Evidence", "File Path", "Description"])
        self.bookmarks_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        bookmarks_layout.addWidget(self.bookmarks_table)
        
        # Bookmark buttons
        bookmark_buttons = QHBoxLayout()
        view_bookmark_btn = QPushButton("View Selected")
        view_bookmark_btn.clicked.connect(self.view_bookmark)
        delete_bookmark_btn = QPushButton("Delete Selected")
        delete_bookmark_btn.clicked.connect(self.delete_bookmark)
        bookmark_buttons.addWidget(view_bookmark_btn)
        bookmark_buttons.addWidget(delete_bookmark_btn)
        bookmarks_layout.addLayout(bookmark_buttons)
        
        bookmarks_group.setLayout(bookmarks_layout)
        layout.addWidget(bookmarks_group)
        
        # Report controls
        report_buttons = QHBoxLayout()
        
        export_report_btn = QPushButton("Export Report")
        export_report_btn.clicked.connect(self.export_report)
        
        report_buttons.addWidget(export_report_btn)
        layout.addLayout(report_buttons)
        
        report_tab.setLayout(layout)
        self.tab_widget.addTab(report_tab, "Report")

    def add_analysis_tabs(self):
        """Add analysis feature tabs to the application"""        
        # Create the widgets
        self.file_type_widget = FileTypeWidget()
        self.search_widget = StringSearchWidget()
        
        # Add them as tabs
        self.tab_widget.addTab(self.file_type_widget, "File Type Analysis")
        self.tab_widget.addTab(self.search_widget, "String Search")
        
        # Add menu entries
        # analysis_menu = self.menuBar().addMenu("Analysis")
        
        # file_type_action = analysis_menu.addAction("File Type Analysis")
        # file_type_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.file_type_widget))
        
        # search_action = analysis_menu.addAction("String Search")
        # search_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.search_widget))

    # i have removed the open_case new_case and save_case methods from here
   
    def add_evidence_item(self):
        """Add evidence item to the current case"""
        # Check if we have an open case
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(self, "No Case", "No case is open. Create or open a case first.")
            return
        
        # Show file dialog to select evidence file
        evidence_path = QFileDialog.getOpenFileName(self, "Select Evidence File", filter="Disk images (*.raw *.dd *.img);;All files (*)")[0]
        if not evidence_path:
            return

        # Get evidence type and description
        evidence_type = QInputDialog.getItem(self, "Evidence Type", "Select evidence type:", 
                                        ["Disk Image", "Logical Evidence File", "Other"], 0, False)[0]
        
        description, ok = QInputDialog.getText(self, "Evidence Description", "Enter a description (optional):")
        if not ok:
            description = ""
            
        # Add evidence to case
        evidence_type_const = EvidenceItem.TYPE_STORAGE
        
        success, message, evidence_item = self.case_manager.add_evidence(
            evidence_path, evidence_type_const, description)
        
        if success:
            QMessageBox.information(self, "Evidence Added", message)
            # Open the evidence automatically
            self.on_evidence_added(evidence_item)
            # Update the evidence table
            self.update_evidence_table()
            # Update dashboard
            self.update_dashboard()
        else:
            QMessageBox.warning(self, "Error", message)   
        # try:
        #     evidence_id = self.case_manager.add_evidence(evidence_path, evidence_type, description)
        #     self.update_evidence_table()
            
        #     # Update the integrated browser if it exists
        #     if hasattr(self, 'integrated_browser'):
        #         self.integrated_browser.update_tree()
                
        #     self.update_dashboard()
        #     self.statusBar.showMessage(f"Added evidence item {evidence_id}")
        # except Exception as e:
        #     QMessageBox.critical(self, "Error", f"Failed to add evidence: {str(e)}")
    
    def remove_evidence_item(self):
        selected_rows = self.evidence_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select an evidence item to remove.")
            return
            
        row = selected_rows[0].row()
        evidence_id = int(self.evidence_table.item(row, 0).text())
        
        reply = QMessageBox.question(self, "Confirm Removal", 
                                    "Are you sure you want to remove this evidence item?\nThis will also remove all bookmarks associated with it.",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
            
        # Remove the evidence from the case
        self.case_manager.evidence_items = [item for item in self.case_manager.evidence_items if item["id"] != evidence_id]
        
        # Remove associated bookmarks
        self.case_manager.bookmarks = [bookmark for bookmark in self.case_manager.bookmarks if bookmark["evidence_id"] != evidence_id]
        
        self.case_manager.save_case()
        self.update_evidence_table()
        self.update_bookmarks_table()
        
        # Update the integrated browser if it exists
        if hasattr(self, 'integrated_browser'):
            # Also close the evidence in the browser if it's open
            if hasattr(self.integrated_browser, 'current_images') and evidence_id in self.integrated_browser.current_images:
                del self.integrated_browser.current_images[evidence_id]
            self.integrated_browser.update_tree()
        
        self.update_dashboard()
        self.statusBar.showMessage(f"Removed evidence item {evidence_id}")
    
    def update_evidence_table(self):
        """Update the evidence table with current evidence items"""
        self.evidence_table.setRowCount(0)
        
        if not self.case_manager or not self.case_manager.current_case:
            return
            
        for item in self.case_manager.current_case.evidence_items:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)
            
            # Handle both dictionary and object formats
            if isinstance(item, dict):
                self.evidence_table.setItem(row, 0, QTableWidgetItem(str(item["id"])))
                self.evidence_table.setItem(row, 1, QTableWidgetItem(item["type"]))
                self.evidence_table.setItem(row, 2, QTableWidgetItem(os.path.basename(item["path"])))
                self.evidence_table.setItem(row, 3, QTableWidgetItem(item["description"]))
            else:
                self.evidence_table.setItem(row, 0, QTableWidgetItem(str(item.id)))
                self.evidence_table.setItem(row, 1, QTableWidgetItem(item.evidence_type))
                self.evidence_table.setItem(row, 2, QTableWidgetItem(os.path.basename(item.source_path)))
                self.evidence_table.setItem(row, 3, QTableWidgetItem(item.description))
        
        # Update the integrated browser if it exists
        if hasattr(self, 'integrated_browser'):
            self.integrated_browser.update_tree()

    def open_selected_evidence(self):
        selected_rows = self.evidence_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select an evidence item to open.")
            return
            
        self.open_evidence_item(selected_rows[0])
    
    def open_evidence_item(self, item):
        row = item.row()
        evidence_id = int(self.evidence_table.item(row, 0).text())
        
        # Find the evidence item
        evidence = next((item for item in self.case_manager.evidence_items if item["id"] == evidence_id), None)
        if not evidence:
            QMessageBox.warning(self, "Error", "Evidence item not found.")
            return
            
        # Check if the file exists
        if not os.path.exists(evidence["path"]):
            QMessageBox.warning(self, "Error", f"Evidence file not found: {evidence['path']}")
            return
            
        # Open the image
        self.open_disk_image(evidence["path"], evidence_id)
    
    def open_disk_image(self, image_path=None, evidence_id=None):
        if image_path is None:
            image_path = QFileDialog.getOpenFileName(self, "Open Disk Image", filter="Disk images (*.raw *.dd *.img);;All files (*)")[0]
            if not image_path:
                return
                
        try:
            # Create and open the forensic image
            self.current_image = ForensicImage(image_path)
            success = self.current_image.open()
            
            if not success:
                QMessageBox.critical(self, "Error", "Failed to open disk image.")
                self.current_image = None
                return
                
            self.current_evidence_id = evidence_id
            
            # Only attempt to clear and populate if file_tree exists
            if hasattr(self, 'file_tree') and self.file_tree is not None:
                # Clear file tree
                self.file_tree.clear()
                
                # Populate root directory
                self.populate_directory("/")
            
            # Update all analysis components with the new image
            if hasattr(self, 'file_type_widget'):
                self.file_type_widget.set_image(self.current_image)
            if hasattr(self, 'search_widget'):
                self.search_widget.set_image(self.current_image)
            
            # Also update the integrated browser if available
            if hasattr(self, 'integrated_browser') and evidence_id is not None:
                if evidence_id not in self.integrated_browser.current_images:
                    self.integrated_browser.current_images[evidence_id] = self.current_image
            
            # Switch to integrated browser tab if file_tree doesn't exist
            if hasattr(self, 'tab_widget'):
                if not hasattr(self, 'file_tree') or self.file_tree is None:
                    # Find the integrated browser tab
                    for i in range(self.tab_widget.count()):
                        if "Integrated" in self.tab_widget.tabText(i):
                            self.tab_widget.setCurrentIndex(i)
                            break
                else:
                    # Switch to browse tab
                    self.tab_widget.setCurrentIndex(1)
            
            self.statusBar.showMessage(f"Opened disk image: {os.path.basename(image_path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open disk image: {str(e)}")
            self.current_image = None
    
    def populate_directory(self, path):
        if not self.current_image:
            return
            
        items = self.current_image.list_directory(path)
        
        # If this is the root directory, add directly to the tree widget
        if path == "/":
            parent = self.file_tree
            self.file_tree.clear()
        else:
            # Find the parent item
            parent_path = os.path.dirname(path)
            if parent_path == "":
                parent_path = "/"
                
            # Find the parent item in the tree
            found_items = self.file_tree.findItems(os.path.basename(path), Qt.MatchFlag.MatchExactly | Qt.MatchFlag.MatchRecursive, 0)
            parent = None
            for item in found_items:
                if item.data(0, Qt.ItemDataRole.UserRole) == path:
                    parent = item
                    break
                    
            if not parent:
                return
        
        # Add items to the tree
        for item_info in items:
            name = item_info["name"]
            size = item_info["size"]
            is_dir = item_info["is_dir"]
            
            if path == "/":
                item = QTreeWidgetItem(self.file_tree)
            else:
                item = QTreeWidgetItem(parent)
                
            item.setText(0, name)
            item.setText(1, str(size) if not is_dir else "")
            item.setText(2, "Directory" if is_dir else "File")
            item.setData(0, Qt.ItemDataRole.UserRole, item_info["path"])
            
            # Add placeholder for directories
            if is_dir:
                QTreeWidgetItem(item).setText(0, "Loading...")
                
        # Expand root
        if path == "/":
            self.file_tree.expandItem(self.file_tree.topLevelItem(0))
    
    def on_file_selected(self, item, column):
        # Check if this is a placeholder item
        if item.text(0) == "Loading..." and item.parent():
            # Get the parent path
            parent_path = item.parent().data(0, Qt.ItemDataRole.UserRole)
            
            # Remove placeholder
            item.parent().removeChild(item)
            
            # Populate directory
            self.populate_directory(parent_path)
            return
            
        # Get the file path
        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not file_path:
            return
            
        # Check if it's a directory
        is_dir = item.text(2) == "Directory"
        
        if is_dir:
            # We'll expand/populate when clicked
            return
            
        # Get and display metadata
        if self.current_image:
            self.statusBar.showMessage("Getting file metadata and calculating hashes...")
            QApplication.processEvents()  # Update UI
            
            metadata = self.current_image.get_file_metadata(file_path)
            if metadata:
                self.file_name_label.setText(os.path.basename(file_path))
                self.file_size_label.setText(f"{metadata['size']} bytes")
                self.file_created_label.setText(metadata['create_time'])
                self.file_modified_label.setText(metadata['modify_time'])
                self.file_accessed_label.setText(metadata['access_time'])
                
                # Display hash values if available
                if 'hashes' in metadata:
                    hash_text = ""
                    for algo, hash_value in metadata['hashes'].items():
                        hash_text += f"{algo.upper()}: {hash_value}\n"
                    self.file_hash_label.setText(hash_text)
                else:
                    self.file_hash_label.setText("Not calculated")
                    
                # Enable buttons
                self.view_file_btn.setEnabled(True)
                self.export_file_btn.setEnabled(True)
                self.add_bookmark_btn.setEnabled(True)
                
                self.statusBar.showMessage("Ready")
            else:
                self.clear_metadata_display()
        else:
            self.clear_metadata_display()
      
    def clear_metadata_display(self):
        self.file_name_label.clear()
        self.file_size_label.clear()
        self.file_created_label.clear()
        self.file_modified_label.clear()
        self.file_accessed_label.clear()
        self.file_hash_label.clear()  # Clear hash information
        
        # Disable buttons
        self.view_file_btn.setEnabled(False)
        self.export_file_btn.setEnabled(False)
        self.add_bookmark_btn.setEnabled(False)
    
    def view_selected_file(self):
        """View the currently selected file in the tree view"""
        # Determine which tree widget to use
        tree = None
        if hasattr(self, 'file_tree') and self.file_tree is not None:
            tree = self.file_tree
        elif hasattr(self, 'tree_widget') and self.tree_widget is not None:
            tree = self.tree_widget
            
        if not tree:
            QMessageBox.warning(self, "Error", "No tree view available.")
            return
            
        selected_items = tree.selectedItems()
        if not selected_items:
            return
            
        # Get the file path
        file_path = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        if not file_path:
            return
            
        # Check if it's a directory
        is_dir = selected_items[0].text(2) == "Directory"
        if is_dir:
            return
            
        # Make sure we have a current image
        if not self.current_image:
            QMessageBox.warning(self, "Error", "No disk image loaded.")
            return
            
        # Read the file content
        try:
            file_data = self.current_image.read_file(file_path)
            if not file_data:
                QMessageBox.warning(self, "Error", "Failed to read file.")
                return
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to read file: {str(e)}")
            return
            
        # Update path display
        if hasattr(self, 'viewer_file_path'):
            self.viewer_file_path.setText(file_path)
        
        # Detect if it's a text file
        is_text = True
        for byte in file_data[:1000]:  # Check first 1000 bytes
            if byte < 9 or (byte > 13 and byte < 32 and byte != 27):
                # Non-printable character that isn't a control character
                is_text = False
                break
                
        # Detect if it's an image
        is_image = False
        if len(file_data) > 8:
            # Check for common image signatures
            if file_data.startswith(b'\xFF\xD8\xFF'):  # JPEG
                is_image = True
            elif file_data.startswith(b'\x89PNG\r\n\x1A\n'):  # PNG
                is_image = True
            elif file_data.startswith(b'GIF87a') or file_data.startswith(b'GIF89a'):  # GIF
                is_image = True
            elif file_data.startswith(b'BM'):  # BMP
                is_image = True
        
        # Update views if they exist
        if hasattr(self, 'text_view'):
            # Update text view
            if is_text:
                try:
                    text_content = file_data.decode('utf-8', errors='replace')
                    self.text_view.setPlainText(text_content)
                except:
                    self.text_view.setPlainText("Unable to display as text.")
            else:
                self.text_view.setPlainText("Binary file - use Hex View.")
        
        if hasattr(self, 'hex_view'):
            # Update hex view
            self.hex_view.set_data(file_data)
        
        if hasattr(self, 'image_view'):
            # Update image view
            if is_image:
                pixmap = QPixmap()
                if pixmap.loadFromData(file_data):
                    self.image_view.setPixmap(pixmap)
                    # Set initial tab to image view if view_tabs exists
                    if hasattr(self, 'view_tabs'):
                        self.view_tabs.setCurrentIndex(2)
                else:
                    self.image_view.clear()
            else:
                self.image_view.clear()
        
        # Switch to viewer tab if tab_widget exists
        if hasattr(self, 'tab_widget'):
            self.tab_widget.setCurrentIndex(2)
    
    def export_selected_file(self):
        selected_items = self.file_tree.selectedItems()
        if not selected_items:
            return
            
        # Get the file path
        file_path = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        if not file_path:
            return
            
        # Check if it's a directory
        is_dir = selected_items[0].text(2) == "Directory"
        if is_dir:
            QMessageBox.warning(self, "Error", "Cannot export directories.")
            return
            
        # Get output path
        output_path = QFileDialog.getSaveFileName(self, "Export File As", os.path.basename(file_path))[0]
        if not output_path:
            return
            
        # Extract the file
        if self.current_image.extract_file(file_path, output_path):
            self.statusBar.showMessage(f"File exported to {output_path}")
            
            # Ask if user wants to calculate hash
            reply = QMessageBox.question(self, "Calculate Hash", 
                                        "Do you want to calculate the hash of the exported file?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                hash_value = self.calculate_file_hash(output_path)
                QMessageBox.information(self, "File Hash", f"SHA-256: {hash_value}")
        else:
            QMessageBox.warning(self, "Error", "Failed to export file.")
    
    def add_bookmark(self):
        if not self.selected_file_path or not self.selected_evidence_id or not self.case_manager:
            return
        
        dialog = AddBookmarkDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
            
        description = dialog.get_description()
        
        # Add the bookmark
        success, message, bookmark = self.case_manager.add_bookmark(
            self.selected_evidence_id, 
            description,
            f"File: {self.selected_file_path}",
            {"file_path": self.selected_file_path}
        )
        
        if success:
            # Force synchronization
            self.case_manager.synchronize_bookmarks()
            
            # Update UI components
            if hasattr(self.parent(), 'update_bookmarks_table'):
                self.parent().update_bookmarks_table()
            if hasattr(self.parent(), 'update_dashboard'):
                self.parent().update_dashboard()
                
            QMessageBox.information(self, "Bookmark Added", f"Bookmark added for: {self.selected_file_path}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to add bookmark: {message}")
    
    def update_bookmarks_table(self):
        """Update bookmarks table with current bookmarks"""
        self.bookmarks_table.setRowCount(0)
        
        if not self.case_manager or not self.case_manager.current_case:
            return
            
        # Ensure case manager has synchronized bookmarks
        if hasattr(self.case_manager, 'synchronize_bookmarks'):
            self.case_manager.synchronize_bookmarks()
        
        # Now populate the table
        for bookmark in self.case_manager.bookmarks:
            row = self.bookmarks_table.rowCount()
            self.bookmarks_table.insertRow(row)
            
            # Find evidence name
            evidence_name = "Unknown"
            evidence_id = bookmark.get("evidence_id")
            evidence_item = self.case_manager.get_evidence_item(evidence_id)
            if evidence_item:
                evidence_name = os.path.basename(evidence_item.source_path)
            
            # Handle both bookmark object and dictionary formats
            bookmark_id = bookmark.get("id", "")
            
            # Handle location/file_path consistently
            location = bookmark.get("location", "")
            if "file_path" in bookmark.get("data", {}):
                location = bookmark["data"]["file_path"]
            elif location.startswith("File: "):
                location = location[6:]  # Remove "File: " prefix
            
            description = bookmark.get("description", "")
            
            # Set table items
            self.bookmarks_table.setItem(row, 0, QTableWidgetItem(str(bookmark_id)))
            self.bookmarks_table.setItem(row, 1, QTableWidgetItem(evidence_name))
            self.bookmarks_table.setItem(row, 2, QTableWidgetItem(location))
            self.bookmarks_table.setItem(row, 3, QTableWidgetItem(description))
        
        # Update the dashboard if it exists
        if hasattr(self, 'update_dashboard'):
            self.update_dashboard()
    
    def _find_item_by_path(self, current_item, target_path):
        """Helper method to recursively find an item by path"""
        if not current_item:
            return None
            
        # Check if this is the item we're looking for
        item_path = current_item.data(0, Qt.ItemDataRole.UserRole)
        if item_path == target_path:
            return current_item
            
        # Recursively check children
        for i in range(current_item.childCount()):
            found_item = self._find_item_by_path(current_item.child(i), target_path)
            if found_item:
                return found_item
                
        return None

    def view_bookmark(self):
        """View the selected bookmark"""
        current_row = self.bookmarks_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a bookmark to view.")
            return
                
        bookmark_id = int(self.bookmarks_table.item(current_row, 0).text())
        
        # Find the bookmark
        bookmark = None
        for b in self.case_manager.bookmarks:
            if b.get("id") == bookmark_id:
                bookmark = b
                break
                    
        if not bookmark:
            QMessageBox.warning(self, "Error", "Could not find bookmark")
            return
                
        # Find the evidence item
        evidence_id = bookmark.get("evidence_id")
        evidence_item = None
        for e in self.case_manager.current_case.evidence_items:
            if e.id == evidence_id:
                evidence_item = e
                break
                    
        if not evidence_item:
            QMessageBox.warning(self, "Error", "Could not find evidence item for bookmark")
            return
                
        # Get the file path from the bookmark data
        file_path = None
        
        # Try different possible locations for file path
        if isinstance(bookmark, dict):
            if "data" in bookmark and isinstance(bookmark["data"], dict) and "file_path" in bookmark["data"]:
                file_path = bookmark["data"]["file_path"]
            elif "file_path" in bookmark:
                file_path = bookmark["file_path"]
            elif "location" in bookmark and bookmark["location"].startswith("File: "):
                file_path = bookmark["location"][6:]  # Remove "File: " prefix
        else:
            # It might be an object
            if hasattr(bookmark, 'data') and hasattr(bookmark.data, 'get'):
                file_path = bookmark.data.get("file_path")
            elif hasattr(bookmark, 'file_path'):
                file_path = bookmark.file_path
            elif hasattr(bookmark, 'location') and bookmark.location.startswith("File: "):
                file_path = bookmark.location[6:]
        
        if file_path:
            # Load the evidence image if needed
            if not self.current_image or self.current_evidence_id != evidence_id:
                # Get the source path based on evidence format
                source_path = evidence_item.source_path if hasattr(evidence_item, 'source_path') else evidence_item.get("path")
                if source_path:
                    # Try to load the image
                    self.load_disk_image(source_path, evidence_id)
                else:
                    QMessageBox.warning(self, "Error", "Could not determine evidence source path.")
                    return
            
            # Check if integrated browser exists and switch to it
            if hasattr(self, 'integrated_browser') and self.integrated_browser:
                # Switch to the integrated browser tab
                for i in range(self.tab_widget.count()):
                    if self.tab_widget.tabText(i) == "Integrated Browser":
                        self.tab_widget.setCurrentIndex(i)
                        break
                        
                # Use the integrated browser to select the file
                if hasattr(self.integrated_browser, 'select_path_in_tree'):
                    full_path = f"{evidence_id}:{file_path}"
                    self.integrated_browser.select_path_in_tree(full_path)
                    QMessageBox.information(self, "Bookmark Loaded", f"Navigated to: {file_path}")
                    return
                    
            # If we couldn't use the integrated browser, try to use file_tree
            if hasattr(self, 'file_tree') and self.file_tree:
                # Try to find and select the file in the tree
                tree = self.file_tree
                
                # Look for the file
                for i in range(tree.topLevelItemCount()):
                    item = self._find_item_by_path(tree.topLevelItem(i), file_path)
                    if item:
                        tree.setCurrentItem(item)
                        if hasattr(self, 'on_file_selected'):
                            self.on_file_selected(item, 0)
                        elif hasattr(self, 'view_selected_file'):
                            self.view_selected_file()
                        QMessageBox.information(self, "Bookmark Loaded", f"Navigated to: {file_path}")
                        return
                    
                QMessageBox.warning(self, "Error", f"Could not find file: {file_path} in the tree")
            else:
                QMessageBox.warning(self, "Error", "No file browser available.")
        else:
            QMessageBox.information(self, "Bookmark Info", f"Bookmark ID: {bookmark_id}\nDescription: {bookmark.get('description', '')}")

    def find_and_select_file(self, file_path):
        """Find and select a file in either the file_tree or tree_widget"""
        # Determine which tree widget to use
        tree = None
        if hasattr(self, 'file_tree') and self.file_tree is not None:
            tree = self.file_tree
        elif hasattr(self, 'tree_widget') and self.tree_widget is not None:
            tree = self.tree_widget
            
        if not tree:
            QMessageBox.warning(self, "Error", "No tree view available.")
            return
            
        # Split path into components
        path_parts = file_path.split('/')
        if path_parts[0] == '':
            path_parts = path_parts[1:]  # Remove empty first element if path starts with /
            
        # Start at root
        current_item = tree.topLevelItem(0)
        current_path = "/"
        
        if not current_item:
            # Tree might not be populated yet
            if hasattr(self, 'populate_directory'):
                self.populate_directory("/")
                current_item = tree.topLevelItem(0)
            
        if not current_item:
            QMessageBox.warning(self, "Error", "Could not find file in tree view.")
            return
            
        # Traverse path
        for part in path_parts:
            if not current_item:
                break
                
            # Expand current node if it has children
            if current_item.childCount() > 0:
                tree.expandItem(current_item)
                
            # Check for placeholder items and populate
            if current_item.childCount() == 1 and current_item.child(0).text(0) == "Loading...":
                self.populate_directory(current_path)
                
            # Look for the next path component
            found = False
            for i in range(current_item.childCount()):
                child = current_item.child(i)
                if child.text(0) == part:
                    current_item = child
                    current_path = child.data(0, Qt.ItemDataRole.UserRole)
                    found = True
                    break
                    
            if not found:
                current_item = None
                
        # Select the file if found
        if current_item:
            tree.setCurrentItem(current_item)
        else:
            QMessageBox.warning(self, "Error", f"Could not find file: {file_path}")
    
    def delete_bookmark(self):
        """Delete the selected bookmark"""
        current_row = self.bookmarks_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a bookmark to delete.")
            return
                
        bookmark_id = int(self.bookmarks_table.item(current_row, 0).text())
        
        reply = QMessageBox.question(self, "Confirm Deletion", 
                                "Are you sure you want to delete this bookmark?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                
        if reply != QMessageBox.StandardButton.Yes:
            return
                
        # Remove the bookmark from the flat list (dictionary style bookmarks)
        self.case_manager.bookmarks = [b for b in self.case_manager.bookmarks if b.get("id", -1) != bookmark_id]
        
        # Also remove from evidence items' bookmark lists (object style bookmarks)
        for evidence in self.case_manager.current_case.evidence_items:
            if hasattr(evidence, 'bookmarks'):
                # Handle object-style bookmarks which have attributes, not dictionary keys
                evidence.bookmarks = [b for b in evidence.bookmarks if not hasattr(b, 'id') or b.id != bookmark_id]
        
        # Save the case to persist changes
        self.case_manager.save_case()
        
        # Update all relevant UI components
        self.update_bookmarks_table()
        
        # Update the evidence tree if it exists
        if hasattr(self, 'evidence_tree'):
            self.refresh_evidence_tree()
        
        # Update integrated browser if it exists
        if hasattr(self, 'integrated_browser') and self.integrated_browser:
            if hasattr(self.integrated_browser, 'update_tree'):
                self.integrated_browser.update_tree()
        
        # Update dashboard if it exists
        if hasattr(self, 'update_dashboard'):
            self.update_dashboard()
        
        # Force a refresh in the case manager's evidence view if available
        if hasattr(self.case_manager, 'refresh_evidence_view'):
            self.case_manager.refresh_evidence_view()
        
        # If there's a parent with a case manager that has its own tree
        if hasattr(self, 'parent') and callable(self.parent):
            parent = self.parent()
            if parent and hasattr(parent, 'refresh_evidence_tree'):
                parent.refresh_evidence_tree()
            
        self.statusBar.showMessage("Bookmark deleted")

    def refresh_evidence_tree(self):
        """Refresh the evidence tree widget to reflect current state"""
        if hasattr(self, 'evidence_tree') and self.evidence_tree is not None:
            # Store the current expanded state
            expanded_items = []
            for i in range(self.evidence_tree.topLevelItemCount()):
                item = self.evidence_tree.topLevelItem(i)
                if item.isExpanded():
                    expanded_items.append(item.text(0))
                    
                    # Also check second level items
                    for j in range(item.childCount()):
                        child = item.child(j)
                        if child.isExpanded():
                            expanded_items.append(f"{item.text(0)}:{child.text(0)}")
            
            # Clear and rebuild the tree
            self.evidence_tree.clear()
            
            if self.case_manager and self.case_manager.current_case:
                # Group by evidence type
                network_group = QTreeWidgetItem(self.evidence_tree, ["Network"])
                storage_group = QTreeWidgetItem(self.evidence_tree, ["Storage"])
                memory_group = QTreeWidgetItem(self.evidence_tree, ["Memory"])
                
                for item in self.case_manager.current_case.evidence_items:
                    evidence_item = QTreeWidgetItem([
                        str(item.id),
                        item.evidence_type,
                        item.file_name,
                        item.description
                    ])
                    evidence_item.setData(0, Qt.ItemDataRole.UserRole, item.id)
                    
                    # Add bookmarks as child items
                    for bookmark in item.bookmarks:
                        bookmark_item = QTreeWidgetItem([
                            str(bookmark.id),
                            "Bookmark",
                            bookmark.location,
                            bookmark.description
                        ])
                        bookmark_item.setData(0, Qt.ItemDataRole.UserRole, bookmark.id)
                        evidence_item.addChild(bookmark_item)
                    
                    # Add to appropriate group
                    if item.evidence_type == "network":
                        network_group.addChild(evidence_item)
                    elif item.evidence_type == "storage":
                        storage_group.addChild(evidence_item)
                    elif item.evidence_type == "memory":
                        memory_group.addChild(evidence_item)
            
                # Restore expanded state
                for i in range(self.evidence_tree.topLevelItemCount()):
                    item = self.evidence_tree.topLevelItem(i)
                    if item.text(0) in expanded_items:
                        self.evidence_tree.expandItem(item)
                    
                    # Also check second level items
                    for j in range(item.childCount()):
                        child = item.child(j)
                        if f"{item.text(0)}:{child.text(0)}" in expanded_items:
                            self.evidence_tree.expandItem(child)

    def go_to_offset(self):
        try:
            offset = int(self.offset_edit.text(), 0)  # 0 base allows for hex input
            
            # Get the current file path from the viewer
            file_path = self.viewer_file_path.text()
            if not file_path or not self.current_image:
                return
                
            # Read a chunk of data at the specified offset
            file_data = self.current_image.read_file(file_path, offset, 4096)
            if file_data:
                # Update hex view to show the data at the specified offset
                self.hex_view.set_data(file_data)
                
                # Switch to hex view tab
                self.view_tabs.setCurrentIndex(1)
            else:
                QMessageBox.warning(self, "Error", "Failed to read file at specified offset.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Please enter a valid decimal or hex (0x...) offset.")
    
    def go_to_prev(self):
        try:
            # Get current offset
            current_offset = int(self.offset_edit.text(), 0)
            
            # Calculate previous offset (4KB chunks)
            prev_offset = max(0, current_offset - 4096)
            
            # Update offset field
            self.offset_edit.setText(str(prev_offset))
            
            # Go to that offset
            self.go_to_offset()
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Please enter a valid decimal or hex (0x...) offset.")
    
    def go_to_next(self):
        try:
            # Get current offset
            current_offset = int(self.offset_edit.text(), 0)
            
            # Calculate next offset (4KB chunks)
            next_offset = current_offset + 4096
            
            # Update offset field
            self.offset_edit.setText(str(next_offset))
            
            # Go to that offset
            self.go_to_offset()
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Please enter a valid decimal or hex (0x...) offset.")
    
    def export_report(self):
        if not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(self, "No Case", "No case is currently open.")
            return
        
        # Force bookmark synchronization before generating report
        self.case_manager.synchronize_bookmarks()
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", "PDF Files (*.pdf);;All Files (*)"
        )
        
        if output_path:
            success, message = self.case_manager.generate_report(output_path)
            
            if success:
                QMessageBox.information(self, "Report Generated", message)
            else:
                QMessageBox.warning(self, "Error", message)

    def calculate_hash(self):
        """Prompt user to select a file and calculate its hash"""
        file_path = QFileDialog.getOpenFileName(self, "Select File to Hash")[0]
        if file_path:
            try:
                # Ask user which hash algorithm to use
                algorithms = ["md5", "sha1", "sha256", "sha512"]
                algorithm, ok = QInputDialog.getItem(self, "Select Hash Algorithm", 
                                                "Choose hash algorithm:", algorithms, 2, False)
                if not ok:
                    return
                    
                self.statusBar.showMessage(f"Calculating {algorithm} hash...")
                QApplication.processEvents()  # Update UI
                
                hash_value = self.calculate_file_hash(file_path, algorithm)
                QMessageBox.information(self, "Hash Value", f"{algorithm.upper()}: {hash_value}")
                self.statusBar.showMessage("Hash calculation complete")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error calculating hash: {str(e)}")

    def calculate_file_hash(self, file_path, algorithm='sha256'):
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def calculate_custom_hash(self):
        selected_items = self.file_tree.selectedItems()
        if not selected_items or not self.current_image:
            return
            
        file_path = selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        is_dir = selected_items[0].text(2) == "Directory"
        
        if is_dir or not file_path:
            return
            
        # Create a dialog with checkboxes for hash algorithms
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Hash Algorithms")
        dialog.setMinimumWidth(300)
        
        layout = QVBoxLayout()
        
        # Create checkboxes for each algorithm
        algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"]
        checkboxes = []
        
        for algo in algorithms:
            checkbox = QCheckBox(algo.upper())
            # Set SHA-256 checked by default
            if algo == "sha256":
                checkbox.setChecked(True)
            checkboxes.append(checkbox)
            layout.addWidget(checkbox)
        
        # Add OK and Cancel buttons
        button_box = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_box.addWidget(ok_button)
        button_box.addWidget(cancel_button)
        
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        
        # Execute dialog and get results
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        # Collect selected algorithms
        selected_algos = []
        for i, checkbox in enumerate(checkboxes):
            if checkbox.isChecked():
                selected_algos.append(algorithms[i])
        
        if not selected_algos:
            QMessageBox.warning(self, "No Selection", "Please select at least one hash algorithm.")
            return
            
        # Calculate hash values
        self.statusBar.showMessage("Calculating hash values...")
        QApplication.processEvents()  # Update UI
        
        hashes = self.current_image.calculate_file_hash(file_path, selected_algos)
        if hashes:
            hash_text = ""
            for algo, hash_value in hashes.items():
                hash_text += f"{algo.upper()}: {hash_value}\n"
            self.file_hash_label.setText(hash_text)
        else:
            self.file_hash_label.setText("Hash calculation failed")
            
        self.statusBar.showMessage("Hash calculation complete")

    def show_capture_dialog(self):
        dialog = ImageCaptureDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # If we have an open case, ask if user wants to add the captured image as evidence
            if self.case_manager.case_directory:
                reply = QMessageBox.question(self, "Add as Evidence", 
                                          "Do you want to add the captured image as evidence to the current case?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    evidence_path = dialog.output_edit.text()
                    evidence_type = "Disk Image"
                    description = f"Captured from {dialog.source_edit.text()}"
                    
                    self.case_manager.add_evidence(evidence_path, evidence_type, description)
                    self.update_evidence_table()
    
    def improve_ui_styling(self):
        """Apply modern styling to the application"""
        # Set application style sheet for a more modern look
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #e1e1e1;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border: 1px solid #cccccc;
                border-bottom-color: white;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 6px 12px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
            QPushButton:pressed {
                background-color: #0a6fc2;
            }
            QTreeWidget, QTableWidget {
                border: 1px solid #cccccc;
                background-color: white;
                alternate-background-color: #f9f9f9;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #cccccc;
                border-radius: 4px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            QLineEdit, QTextEdit, QPlainTextEdit {
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 4px;
                background-color: white;
            }
            QProgressBar {
                border: 1px solid #cccccc;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                width: 10px;
            }
        """)
        
        # Set icons for actions and buttons if available
        try:
            self.view_file_btn.setIcon(QIcon.fromTheme("document-open"))
            self.export_file_btn.setIcon(QIcon.fromTheme("document-save"))
            self.add_bookmark_btn.setIcon(QIcon.fromTheme("bookmark-new"))
        except:
            pass  # If icons aren't available, continue without them

    # Add a dark mode toggle
    def add_dark_mode_toggle(self):
        """Add dark mode capability to the application"""
        # Add to the UI in settings or view menu
        view_menu = self.menuBar().addMenu("View")
        self.dark_mode_action = view_menu.addAction("Dark Mode")
        self.dark_mode_action.setCheckable(True)
        self.dark_mode_action.triggered.connect(self.toggle_dark_mode)
        
    def toggle_dark_mode(self, enabled):
        """Toggle between light and dark modes"""
        if enabled:
            # Dark mode stylesheet
            self.setStyleSheet("""
                QMainWindow, QDialog, QWidget {
                    background-color: #2d2d2d;
                    color: #f0f0f0;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                    background-color: #3d3d3d;
                    border-radius: 4px;
                }
                QTabBar::tab {
                    background-color: #2d2d2d;
                    color: #f0f0f0;
                    padding: 8px 12px;
                    margin-right: 2px;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background-color: #3d3d3d;
                    border: 1px solid #555555;
                    border-bottom-color: #3d3d3d;
                }
                QPushButton {
                    background-color: #0d47a1;
                    color: white;
                    padding: 6px 12px;
                    border: none;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #1565c0;
                }
                QPushButton:pressed {
                    background-color: #0a3d87;
                }
                QTreeWidget, QTableWidget {
                    border: 1px solid #555555;
                    background-color: #3d3d3d;
                    color: #f0f0f0;
                    alternate-background-color: #353535;
                }
                QHeaderView::section {
                    background-color: #2d2d2d;
                    color: #f0f0f0;
                    padding: 4px;
                    border: 1px solid #555555;
                }
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #555555;
                    border-radius: 4px;
                    margin-top: 1ex;
                    padding-top: 10px;
                    color: #f0f0f0;
                }
                QLineEdit, QTextEdit, QPlainTextEdit {
                    border: 1px solid #555555;
                    border-radius: 4px;
                    padding: 4px;
                    background-color: #2d2d2d;
                    color: #f0f0f0;
                }
                QProgressBar {
                    border: 1px solid #555555;
                    border-radius: 4px;
                    text-align: center;
                    color: #f0f0f0;
                }
                QProgressBar::chunk {
                    background-color: #0d47a1;
                    width: 10px;
                }
                QCheckBox, QRadioButton, QLabel {
                    color: #f0f0f0;
                }
                QMenu {
                    background-color: #2d2d2d;
                    color: #f0f0f0;
                }
                QMenu::item:selected {
                    background-color: #0d47a1;
                }
                QMenuBar {
                    background-color: #2d2d2d;
                    color: #f0f0f0;
                }
                QMenuBar::item:selected {
                    background-color: #3d3d3d;
                }
            """)
        else:
            # Reset to light mode (call the original styling function)
            self.improve_ui_styling()

    # Add a customizable dashboard to the application
    def add_dashboard(self):
        """Add a customizable dashboard as the first tab"""
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()
        
        # Top section with case summary
        summary_group = QGroupBox("Case Summary")
        summary_layout = QGridLayout()
        
        # Case info widgets
        summary_layout.addWidget(QLabel("Case:"), 0, 0)
        self.dashboard_case_name = QLabel("No case open")
        summary_layout.addWidget(self.dashboard_case_name, 0, 1)
        
        summary_layout.addWidget(QLabel("Investigator:"), 1, 0)
        self.dashboard_investigator = QLabel("-")
        summary_layout.addWidget(self.dashboard_investigator, 1, 1)
        
        summary_layout.addWidget(QLabel("Evidence Items:"), 0, 2)
        self.dashboard_evidence_count = QLabel("0")
        summary_layout.addWidget(self.dashboard_evidence_count, 0, 3)
        
        summary_layout.addWidget(QLabel("Bookmarks:"), 1, 2)
        self.dashboard_bookmark_count = QLabel("0")
        summary_layout.addWidget(self.dashboard_bookmark_count, 1, 3)
        
        summary_group.setLayout(summary_layout)
        dashboard_layout.addWidget(summary_group)
        
        # Quick action buttons
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout()
        
       
        
        # Make sure all four image acquisition buttons are included
        capture_image_btn = QPushButton("Capture Disk Image")
        capture_image_btn.clicked.connect(self.show_capture_dialog)
        actions_layout.addWidget(capture_image_btn)
        
        sparse_btn = QPushButton("Sparse Disk Image")
        sparse_btn.clicked.connect(self.show_sparse_capture_dialog)
        actions_layout.addWidget(sparse_btn)
        
        logical_acq_btn = QPushButton("Logical Acquisition")
        logical_acq_btn.clicked.connect(self.show_logical_acquisition_dialog)
        actions_layout.addWidget(logical_acq_btn)
        
        open_image_btn = QPushButton("Open Disk Image")
        open_image_btn.clicked.connect(self.open_disk_image)
        actions_layout.addWidget(open_image_btn)
        
        #export_report_btn = QPushButton("Export Report")
        #export_report_btn.clicked.connect(self.export_report)
        #actions_layout.addWidget(export_report_btn)
        
        actions_group.setLayout(actions_layout)
        dashboard_layout.addWidget(actions_group)
        
        # Recent activity and bookmarks
        activity_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Recent evidence
        recent_evidence_group = QGroupBox("Recent Evidence")
        recent_evidence_layout = QVBoxLayout()
        self.recent_evidence_list = QTreeWidget()
        self.recent_evidence_list.setHeaderLabels(["Type", "Path", "Added Date"])
        self.recent_evidence_list.setColumnWidth(0, 100)
        self.recent_evidence_list.setColumnWidth(1, 300)
        self.recent_evidence_list.itemDoubleClicked.connect(self.on_recent_evidence_clicked)
        recent_evidence_layout.addWidget(self.recent_evidence_list)
        recent_evidence_group.setLayout(recent_evidence_layout)
        
        # Recent bookmarks
        recent_bookmarks_group = QGroupBox("Recent Bookmarks")
        recent_bookmarks_layout = QVBoxLayout()
        self.recent_bookmarks_list = QTreeWidget()
        self.recent_bookmarks_list.setHeaderLabels(["Evidence", "File Path", "Description"])
        self.recent_bookmarks_list.setColumnWidth(0, 100)
        self.recent_bookmarks_list.setColumnWidth(1, 200)
        self.recent_bookmarks_list.itemDoubleClicked.connect(self.on_recent_bookmark_clicked)
        recent_bookmarks_layout.addWidget(self.recent_bookmarks_list)
        recent_bookmarks_group.setLayout(recent_bookmarks_layout)
        
        activity_splitter.addWidget(recent_evidence_group)
        activity_splitter.addWidget(recent_bookmarks_group)
        dashboard_layout.addWidget(activity_splitter)
        
        dashboard_tab.setLayout(dashboard_layout)
        self.tab_widget.insertTab(0, dashboard_tab, "Dashboard")
        
    def update_dashboard(self):
        """Update the dashboard with current case information"""
        if not hasattr(self, 'dashboard_case_name'):
            return  # Dashboard not initialized
                
        if self.case_manager and self.case_manager.current_case:
            # Force synchronization of bookmarks first
            if hasattr(self.case_manager, 'synchronize_bookmarks'):
                self.case_manager.synchronize_bookmarks()
                
            self.dashboard_case_name.setText(self.case_manager.current_case.name)
            self.dashboard_investigator.setText(self.case_manager.current_case.investigator)
            
            # Count storage evidence items
            storage_evidence = [e for e in self.case_manager.current_case.evidence_items 
                            if e.evidence_type == "storage"]
            self.dashboard_evidence_count.setText(str(len(storage_evidence)))
            
            # Count bookmarks in storage evidence
            bookmark_count = 0
            for e in storage_evidence:
                if hasattr(e, 'bookmarks'):
                    bookmark_count += len(e.bookmarks)
                    
            self.dashboard_bookmark_count.setText(str(bookmark_count))
            
            # Update recent evidence list (showing the 5 most recent)
            self.recent_evidence_list.clear()
            sorted_evidence = sorted(storage_evidence, 
                                key=lambda x: x.added_date, reverse=True)
            
            for item in sorted_evidence[:5]:
                tree_item = QTreeWidgetItem()
                tree_item.setText(0, "Storage")
                tree_item.setText(1, os.path.basename(item.source_path))
                tree_item.setText(2, item.added_date)
                tree_item.setData(0, Qt.ItemDataRole.UserRole, item.id)
                self.recent_evidence_list.addTopLevelItem(tree_item)
                    
            # Update recent bookmarks list
            self.recent_bookmarks_list.clear()
            
            # Get all bookmarks from storage evidence
            all_bookmarks = []
            for evidence in storage_evidence:
                if hasattr(evidence, 'bookmarks'):
                    for bookmark in evidence.bookmarks:
                        all_bookmarks.append((evidence, bookmark))
            
            # Sort by date and take the 5 most recent
            sorted_bookmarks = sorted(all_bookmarks, 
                                    key=lambda x: x[1].added_date if hasattr(x[1], 'added_date') else "", 
                                    reverse=True)[:5]
            
            for evidence, bookmark in sorted_bookmarks:
                tree_item = QTreeWidgetItem()
                tree_item.setText(0, os.path.basename(evidence.source_path))
                
                # Get location or file path
                location = bookmark.location if hasattr(bookmark, 'location') else ""
                if hasattr(bookmark, 'data') and bookmark.data and 'file_path' in bookmark.data:
                    location = bookmark.data['file_path']
                    
                tree_item.setText(1, location)
                tree_item.setText(2, bookmark.description if hasattr(bookmark, 'description') else "")
                
                # Store bookmark ID for reference
                tree_item.setData(0, Qt.ItemDataRole.UserRole, bookmark.id)
                self.recent_bookmarks_list.addTopLevelItem(tree_item)
        else:
            # Reset dashboard when no case is open
            self.dashboard_case_name.setText("No case open")
            self.dashboard_investigator.setText("-")
            self.dashboard_evidence_count.setText("0")
            self.dashboard_bookmark_count.setText("0")
            self.recent_evidence_list.clear()
            self.recent_bookmarks_list.clear()

    def view_bookmark_by_id(self, bookmark_id):
        """View a bookmark by its ID rather than by selection"""
        if not self.case_manager or not self.case_manager.current_case:
            return
            
        # Find the bookmark
        bookmark = next((b for b in self.case_manager.bookmarks if b.get("id") == bookmark_id), None)
        if not bookmark:
            return
            
        # Find the evidence
        evidence_id = bookmark.get("evidence_id")
        evidence = self.case_manager.get_evidence_item(evidence_id)
        if not evidence:
            QMessageBox.warning(self, "Error", "Evidence item not found.")
            return
            
        # Get the file path from the bookmark
        file_path = None
        if "file_path" in bookmark.get("data", {}):
            file_path = bookmark["data"]["file_path"]
        elif bookmark.get("location", "").startswith("File: "):
            file_path = bookmark["location"][6:]  # Remove "File: " prefix
            
        if not file_path:
            QMessageBox.warning(self, "Error", "No file path found in bookmark.")
            return
            
        # Switch to the integrated browser tab first
        self.switch_to_integrated_browser_tab()
        
        # Check if we need to open a different image
        if not self.current_image or self.current_evidence_id != evidence_id:
            # Get the source path based on evidence format
            source_path = evidence.source_path if hasattr(evidence, 'source_path') else evidence.get("path")
            if source_path:
                # Wait for the image to be loaded before proceeding
                self.open_disk_image(source_path, evidence_id)
                # Give the tree widget time to initialize
                QApplication.processEvents()
            else:
                QMessageBox.warning(self, "Error", "Could not determine evidence source path.")
                return
            
        # Find and select the file
        self.find_and_select_file(file_path)
        
        # View the file
        self.view_selected_file()

    def on_recent_evidence_clicked(self, item, column):
        # Open evidence when clicked in dashboard
        evidence_id = item.data(0, Qt.ItemDataRole.UserRole)
        evidence = next((e for e in self.case_manager.evidence_items if e["id"] == evidence_id), None)
        if evidence:
            self.open_disk_image(evidence["path"], evidence_id)
            self.tab_widget.setCurrentIndex(1)  # Switch to Evidence tab
            
    def on_recent_bookmark_clicked(self, item, column):
        # Open bookmark when clicked in dashboard
        bookmark_id = item.data(0, Qt.ItemDataRole.UserRole)
        bookmark = next((b for b in self.case_manager.bookmarks if b["id"] == bookmark_id), None)
        if bookmark:
            self.view_bookmark_by_id(bookmark_id)

    def show_about(self):
        QMessageBox.about(self, "About Forensic Storage Analyzer", 
                         """<h1>Forensic Storage Analyzer</h1>
                         <p>A digital forensics tool for disk image analysis.</p>
                         <p>Features:</p>
                         <ul>
                         <li>Disk image capture</li>
                         <li>File system exploration</li>
                         <li>File extraction and analysis</li>
                         <li>Bookmarking and reporting</li>
                         </ul>
                         <p>Version 1.0</p>""")

    def on_tab_changed(self, index):
        """Handle tab changes to ensure data is refreshed"""
        tab_text = self.tab_widget.tabText(index)
        
        # Update dashboard when switching to dashboard tab
        if tab_text == "Dashboard":
            self.update_dashboard()
        
        # Update report when switching to report tab
        elif tab_text == "Report":
            self.update_bookmarks_table()

class IntegratedForensicBrowser(QWidget):
    """
    A unified interface that combines evidence items, file browsing, and file viewing
    in a single tab with an expandable tree structure similar to Autopsy.
    """

    image_loaded = pyqtSignal(object, int)  # (forensic_image, evidence_id)

    def __init__(self, parent=None, case_manager=None):
        super().__init__(parent)
        self.case_manager = case_manager
        self.current_images = {}  # Dictionary of evidence_id -> ForensicImage
        self.selected_file_path = None
        self.selected_evidence_id = None
        self.current_offset = 0
        self.init_ui()
        
    def init_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Main splitter to divide tree view and content view
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(self.main_splitter)
        
        # === Left panel: Tree view of evidence and files ===
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # Search bar for filtering tree items
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter files and folders...")
        self.filter_edit.textChanged.connect(self.filter_tree)
        search_layout.addWidget(self.filter_edit)
        left_layout.addLayout(search_layout)
        
        # Tree widget with improved styling
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Name", "Size", "Type"])
        
        # Set column widths
        self.tree_widget.setColumnWidth(0, 400)  # Name column
        self.tree_widget.setColumnWidth(1, 100)  # Size column
        self.tree_widget.setColumnWidth(2, 100)  # Type column
        
        # Set header resize modes
        header = self.tree_widget.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name column stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # Size column fixed
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # Type column fixed
        
        # Style the tree widget
        self.tree_widget.setStyleSheet("""
            QTreeWidget {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #3A3436;
                border-radius: 3px;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #2A2426;
            }
            QTreeWidget::item:selected {
                background-color: #2D2D2D;
                color: white;
            }
            QTreeWidget::item:hover {
                background-color: #2A2426;
            }
            QHeaderView::section {
                background-color: #2A2426;
                color: #FFFFFF;
                padding: 6px;
                border: none;
                border-right: 1px solid #3A3436;
                font-weight: bold;
            }
            QTreeWidget::branch {
                background: transparent;
            }
            QTreeWidget::branch:has-children:!has-siblings:closed,
            QTreeWidget::branch:closed:has-children:has-siblings {
                border-image: none;
                image: none;
                width: 12px;
                height: 12px;
            }
            QTreeWidget::branch:open:has-children:!has-siblings,
            QTreeWidget::branch:open:has-children:has-siblings {
                border-image: none;
                image: none;
                width: 12px;
                height: 12px;
            }
        """)
        
        # Configure tree widget properties
        self.tree_widget.setIndentation(20)
        self.tree_widget.setAnimated(True)
        self.tree_widget.setUniformRowHeights(True)
        
        # Ensure the header is visible and configure its properties
        header = self.tree_widget.header()
        header.setVisible(True)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name column
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # Size column
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # Type column
        
        # Set initial column widths
        self.tree_widget.setColumnWidth(1, 100)  # Size column
        self.tree_widget.setColumnWidth(2, 100)  # Type column
        
        self.tree_widget.itemClicked.connect(self.on_tree_item_selected)
        self.tree_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.tree_widget)
        
        # Add to main splitter
        self.main_splitter.addWidget(left_panel)
        
        # === Right panel: Content view with tabs and metadata ===
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create a splitter to divide metadata and content
        content_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Metadata section with tabs for different categories
        metadata_widget = QWidget()
        metadata_layout = QVBoxLayout(metadata_widget)
        metadata_layout.setContentsMargins(5, 5, 5, 5)
        
        # Create tabs for different metadata categories
        self.metadata_tabs = QTabWidget()
        
        # === Basic Properties Tab ===
        basic_tab = QWidget()
        basic_layout = QFormLayout(basic_tab)
        
        self.file_name_label = QLabel("")
        self.file_path_label = QLabel("")
        self.file_path_label.setWordWrap(True)
        self.file_size_label = QLabel("")
        self.file_type_label = QLabel("")
        # Add deleted status label
        self.file_deleted_label = QLabel("")
        self.file_deleted_label.setStyleSheet("color: red; font-weight: bold;")

        basic_layout.addRow("Name:", self.file_name_label)
        basic_layout.addRow("Path:", self.file_path_label)
        basic_layout.addRow("Size:", self.file_size_label)
        basic_layout.addRow("Type:", self.file_type_label)
        # Add deleted status field
        basic_layout.addRow("Deleted:", self.file_deleted_label)

        
        self.metadata_tabs.addTab(basic_tab, "Basic")
        
        # === Timestamps Tab ===
        times_tab = QWidget()
        times_layout = QFormLayout(times_tab)
        
        self.file_created_label = QLabel("")
        self.file_modified_label = QLabel("")
        self.file_accessed_label = QLabel("")
        self.file_changed_label = QLabel("")
        
        times_layout.addRow("Created:", self.file_created_label)
        times_layout.addRow("Modified:", self.file_modified_label)
        times_layout.addRow("Accessed:", self.file_accessed_label)
        times_layout.addRow("Status Changed:", self.file_changed_label)
        
        self.metadata_tabs.addTab(times_tab, "Timestamps")
        
        # === Hash Values Tab ===
        hash_tab = QWidget()
        hash_layout = QVBoxLayout(hash_tab)
        
        self.file_hash_label = QTextEdit()
        self.file_hash_label.setReadOnly(True)
        self.file_hash_label.setPlaceholderText("Hash values will appear here when calculated")
        hash_layout.addWidget(self.file_hash_label)
        
        # Add button to calculate additional hashes
        hash_btn_layout = QHBoxLayout()
        self.calc_hash_btn = QPushButton("Calculate Additional Hashes")
        self.calc_hash_btn.clicked.connect(self.calculate_additional_hashes)
        hash_btn_layout.addWidget(self.calc_hash_btn)
        hash_btn_layout.addStretch()
        hash_layout.addLayout(hash_btn_layout)
        
        self.metadata_tabs.addTab(hash_tab, "Hashes")
        
        # === Permissions Tab ===
        perm_tab = QWidget()
        perm_layout = QFormLayout(perm_tab)
        
        self.file_owner_label = QLabel("")
        self.file_group_label = QLabel("")
        self.file_perms_label = QLabel("")
        self.file_mode_label = QLabel("")
        
        perm_layout.addRow("Owner:", self.file_owner_label)
        perm_layout.addRow("Group:", self.file_group_label)
        perm_layout.addRow("Permissions:", self.file_perms_label)
        perm_layout.addRow("Mode:", self.file_mode_label)
        
        self.metadata_tabs.addTab(perm_tab, "Permissions")
        
        # === Extended Attributes Tab ===
        ext_tab = QWidget()
        ext_layout = QVBoxLayout(ext_tab)
        
        self.ext_attr_table = QTableWidget()
        self.ext_attr_table.setColumnCount(2)
        self.ext_attr_table.setHorizontalHeaderLabels(["Attribute", "Value"])
        self.ext_attr_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        ext_layout.addWidget(self.ext_attr_table)
        
        self.metadata_tabs.addTab(ext_tab, "Extended Attrs")
        
        # Add the tabs to metadata layout
        metadata_layout.addWidget(self.metadata_tabs)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.hash_btn = QPushButton("Calculate Hash")
        self.hash_btn.clicked.connect(self.calculate_hash)
        button_layout.addWidget(self.hash_btn)
        
        self.bookmark_btn = QPushButton("Add Bookmark")
        self.bookmark_btn.clicked.connect(self.add_bookmark)
        button_layout.addWidget(self.bookmark_btn)
        
        self.export_btn = QPushButton("Export File")
        self.export_btn.clicked.connect(self.export_file)
        button_layout.addWidget(self.export_btn)
        
        metadata_layout.addLayout(button_layout)
        
        # Add metadata widget to splitter
        content_splitter.addWidget(metadata_widget)
        
        # Content tabs
        self.content_tabs = QTabWidget()
        
        # Text view
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.content_tabs.addTab(self.text_view, "Text")
        
        # Hex view
        self.hex_view = HexViewWidget()
        self.content_tabs.addTab(self.hex_view, "Hex")
        
        # Image view
        image_widget = QWidget()
        image_layout = QVBoxLayout(image_widget)
        self.image_view = QLabel()
        self.image_view.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_view.setScaledContents(False)
        image_scroll = QScrollArea()
        image_scroll.setWidgetResizable(True)
        image_scroll.setWidget(self.image_view)
        image_layout.addWidget(image_scroll)
        self.content_tabs.addTab(image_widget, "Image")
        
        # Add content tabs to splitter
        content_splitter.addWidget(self.content_tabs)
        
        # Set initial splitter sizes for metadata/content
        content_splitter.setSizes([150, 450])
        
        # Navigation controls for hex view
        nav_layout = QHBoxLayout()
        nav_layout.addWidget(QLabel("Offset:"))
        
        self.offset_edit = QLineEdit("0")
        self.offset_edit.setMaximumWidth(100)
        nav_layout.addWidget(self.offset_edit)
        
        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.go_to_offset)
        nav_layout.addWidget(self.go_btn)
        
        self.prev_btn = QPushButton("Previous")
        self.prev_btn.clicked.connect(self.go_to_prev)
        nav_layout.addWidget(self.prev_btn)
        
        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.go_to_next)
        nav_layout.addWidget(self.next_btn)
        
        right_layout.addWidget(content_splitter)
        right_layout.addLayout(nav_layout)
        
        # Add to main splitter
        self.main_splitter.addWidget(right_panel)
        
        # Set initial sizes for main splitter
        self.main_splitter.setSizes([300, 700])
        
        # Disable buttons initially
        self.hash_btn.setEnabled(False)
        self.bookmark_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.go_btn.setEnabled(False)
        self.prev_btn.setEnabled(False)
        self.next_btn.setEnabled(False)
    
    def set_image(self, forensic_image, evidence_id):
        """Set the current forensic image and update UI"""
        try:
            print(f"IntegratedBrowser.set_image called with evidence_id: {evidence_id}")
            if forensic_image is not None and evidence_id is not None:
                # Store the image
                self.current_images[evidence_id] = forensic_image
                print(f"Added forensic image to current_images with key: {evidence_id}")
                
                # Emit the signal to update other components
                self.image_loaded.emit(forensic_image, evidence_id)
                print("Emitted image_loaded signal")
                
                # Update the tree with evidence
                self.update_tree()
                print("Updated tree")
                
                # Show a success message in parent's status bar if available
                parent = self.parent()
                if parent and hasattr(parent, 'statusBar'):
                    parent.statusBar.showMessage(f"Forensic image loaded successfully in integrated browser")
                elif parent and hasattr(parent, '_status_bar'):
                    parent._status_bar.showMessage(f"Forensic image loaded successfully in integrated browser")
        except Exception as e:
            print(f"Error in IntegratedForensicBrowser.set_image: {e}")
            import traceback
            traceback.print_exc()

    def update_tree(self):
        """Update the tree with all evidence items and their contents"""
        print("Updating tree in integrated browser...")
        # Save expanded state of items
        expanded_paths = self.get_expanded_paths()
        selected_path = None
        if self.tree_widget.currentItem():
            selected_path = self.tree_widget.currentItem().data(0, Qt.ItemDataRole.UserRole)
        
        # Clear current tree
        self.tree_widget.clear()
        
        # Check if we have any loaded images
        if not hasattr(self, 'current_images') or not self.current_images:
            print("No images loaded in integrated browser")
            no_items = QTreeWidgetItem(self.tree_widget)
            no_items.setText(0, "No evidence items available")
            no_items.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning))
            return
        
        print(f"Found {len(self.current_images)} loaded images in browser")
        
        # Add each loaded image to the tree
        for evidence_id, image in self.current_images.items():
            print(f"Adding evidence ID {evidence_id} to tree")
            
            # Create evidence root item
            evidence_item = QTreeWidgetItem(self.tree_widget)
            evidence_item.setText(0, f"Evidence {evidence_id}")
            evidence_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))
            evidence_item.setData(0, Qt.ItemDataRole.UserRole, f"evidence:{evidence_id}")
            
            # Try to list root directory
            try:
                print(f"Attempting to list root directory for evidence ID {evidence_id}")
                items = image.list_directory("/")
                
                if items:
                    print(f"Found {len(items)} items in root directory")
                    for item_info in items:
                        try:
                            # Skip . and .. entries
                            name = item_info["name"]
                            if name in [".", ".."]:
                                continue
                            
                            child = QTreeWidgetItem(evidence_item)
                            child.setText(0, name)
                            
                            # Set appropriate icon and data
                            if item_info["is_dir"]:
                                child.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                                child.setText(2, "Directory")
                                # Add placeholder for lazy loading
                                placeholder = QTreeWidgetItem(child)
                                placeholder.setText(0, "Loading...")
                            else:
                                child.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                                child.setText(1, self.format_size(item_info["size"]))
                                child.setText(2, "File")
                            
                            # Store full path with evidence ID
                            child.setData(0, Qt.ItemDataRole.UserRole, f"{evidence_id}:{item_info['path']}")
                        except Exception as e:
                            print(f"Error adding item to tree: {e}")
                else:
                    print("No items found in root directory")
                    child = QTreeWidgetItem(evidence_item)
                    child.setText(0, "No files found (empty filesystem or unrecognized format)")
                    child.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning))
            except Exception as e:
                print(f"Error listing root directory: {e}")
                import traceback
                traceback.print_exc()
                
                # Add error indicator
                error_item = QTreeWidgetItem(evidence_item)
                error_item.setText(0, f"Error accessing filesystem: {str(e)}")
                error_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxCritical))
        
        # Restore expanded state
        self.restore_expanded_paths(expanded_paths)
        
        # Restore selection if possible
        if selected_path:
            self.select_path_in_tree(selected_path)
    
    def get_expanded_paths(self):
        """Get all expanded items' paths for state preservation"""
        expanded_paths = []
        
        def traverse_items(item):
            if item.isExpanded():
                path = item.data(0, Qt.ItemDataRole.UserRole)
                if path:
                    expanded_paths.append(path)
                
                for i in range(item.childCount()):
                    traverse_items(item.child(i))
        
        # Check all top-level items
        for i in range(self.tree_widget.topLevelItemCount()):
            traverse_items(self.tree_widget.topLevelItem(i))
        
        return expanded_paths
    
    def restore_expanded_paths(self, expanded_paths):
        """Restore expanded state of items"""
        for path in expanded_paths:
            items = self.find_items_by_path(path)
            for item in items:
                if item:
                    self.tree_widget.expandItem(item)
                    # If this is an evidence item, load its root directory
                    if path.startswith("evidence:"):
                        self.load_evidence_root(item)
    
    def find_items_by_path(self, path):
        """Find tree items by their stored path"""
        matching_items = []
        
        def check_item(item):
            item_path = item.data(0, Qt.ItemDataRole.UserRole)
            if item_path == path:
                matching_items.append(item)
            
            for i in range(item.childCount()):
                check_item(item.child(i))
        
        # Check all top-level items
        for i in range(self.tree_widget.topLevelItemCount()):
            check_item(self.tree_widget.topLevelItem(i))
        
        return matching_items
    
    def select_path_in_tree(self, path):
        """Find and select an item by its path"""
        items = self.find_items_by_path(path)
        if items:
            self.tree_widget.setCurrentItem(items[0])
            self.on_tree_item_selected(items[0], 0)
    
    def on_tree_item_selected(self, item, column):
        """Handle selection of tree items"""
        # Get the item path
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path:
            return
        
        # Handle evidence root items
        if item_path.startswith("evidence:"):
            evidence_id = int(item_path.split(":")[1])
            
            # Check if this is the first time selecting this evidence
            if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
                self.load_evidence_root(item)
                
            # Clear file metadata display
            self.clear_file_display()
            return
            
        # Handle loading placeholders
        if item.text(0) == "Loading...":
            parent_item = item.parent()
            if parent_item:
                parent_path = parent_item.data(0, Qt.ItemDataRole.UserRole)
                
                # Check if parent is evidence root
                if parent_path and parent_path.startswith("evidence:"):
                    evidence_id = int(parent_path.split(":")[1])
                    self.load_evidence_root(parent_item)
                elif parent_path:
                    # Regular directory, extract evidence ID
                    evidence_id = self.extract_evidence_id_from_path(parent_path)
                    if evidence_id and self.load_image_if_needed(evidence_id):
                        dir_path = parent_path.split(":", 1)[1] if ":" in parent_path else parent_path
                        self.load_directory(parent_item, dir_path, evidence_id)
                
                # Select the parent after loading
                self.tree_widget.setCurrentItem(parent_item)
            return
            
        # Handle directory items
        if item.text(2) == "Directory":
            # Check if item has placeholder child
            if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
                evidence_id = self.extract_evidence_id_from_path(item_path)
                if evidence_id and self.load_image_if_needed(evidence_id):
                    dir_path = item_path.split(":", 1)[1] if ":" in item_path else item_path
                    self.load_directory(item, dir_path, evidence_id)
            
            # Clear file metadata display
            self.clear_file_display()
            return
            
        # Handle file items
        evidence_id = self.extract_evidence_id_from_path(item_path)
        if evidence_id and self.load_image_if_needed(evidence_id):
            file_path = item_path.split(":", 1)[1] if ":" in item_path else item_path
            self.display_file(file_path, evidence_id)
    
    def extract_evidence_id_from_path(self, path):
        """Extract evidence ID from a path string"""
        if path.startswith("evidence:"):
            return int(path.split(":")[1])
        elif ":" in path:
            parts = path.split(":", 1)
            if parts[0].isdigit():
                return int(parts[0])
        return None
    
    def load_evidence_root(self, evidence_item):
        """Load root directory of an evidence item"""
        item_path = evidence_item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path or not item_path.startswith("evidence:"):
            return
            
        evidence_id = int(item_path.split(":")[1])
        print(f"Loading evidence root for ID: {evidence_id}")
        
        # Find evidence data
        evidence = None
        if self.case_manager and hasattr(self.case_manager, 'evidence_items'):
            for item in self.case_manager.evidence_items:
                if item["id"] == evidence_id:
                    evidence = item
                    break
                
        if not evidence:
            print(f"Evidence ID {evidence_id} not found")
            return
        
        print(f"Found evidence: {evidence['path']}")
            
        # Load the image if not already loaded
        if not self.load_image_if_needed(evidence_id):
            print(f"Failed to load image for evidence {evidence_id}")
            return
            
        # Remove placeholder
        while evidence_item.childCount() > 0:
            evidence_item.removeChild(evidence_item.child(0))
            
        # Load root directory
        self.load_directory(evidence_item, "/", evidence_id)
    
    def load_image_if_needed(self, evidence_id):
        """Load the forensic image if not already loaded"""
        try:
            # Check if image is already loaded
            if evidence_id in self.current_images and self.current_images[evidence_id] is not None:
                print(f"Image for evidence {evidence_id} already loaded")
                return True
                
            # Find evidence data
            evidence = None
            if self.case_manager and hasattr(self.case_manager, 'evidence_items'):
                for item in self.case_manager.evidence_items:
                    if item["id"] == evidence_id:
                        evidence = item
                        break
                        
            if not evidence:
                print(f"Evidence ID {evidence_id} not found")
                return False
            
            # Verify file exists
            if not os.path.exists(evidence["path"]):
                print(f"Evidence file does not exist: {evidence['path']}")
                
                # Show in status bar
                parent = self.parent()
                if parent and hasattr(parent, 'statusBar'):
                    parent.statusBar.showMessage(f"Error: Evidence file not found: {evidence['path']}")
                
                return False
                
            print(f"Loading forensic image from: {evidence['path']}")
                
            # Create and open the forensic image
            image = ForensicImage(evidence["path"])
            success = image.open()
            
            if success:
                print(f"Successfully opened forensic image for evidence {evidence_id}")
                self.current_images[evidence_id] = image
                # Emit the signal when an image is loaded
                self.image_loaded.emit(image, evidence_id)
                
                # Update status
                parent = self.parent()
                if parent and hasattr(parent, 'statusBar'):
                    parent.statusBar.showMessage(f"Loaded image: {os.path.basename(evidence['path'])}")
                    
                return True
            else:
                print(f"Failed to open disk image: {evidence['path']}")
                
                # Show error message
                msg = f"Failed to open disk image: {evidence['path']}"
                QMessageBox.critical(self, "Error", msg)
                
                # Update status bar
                parent = self.parent()
                if parent and hasattr(parent, 'statusBar'):
                    parent.statusBar.showMessage(msg)
                    
                return False
        except Exception as e:
            print(f"Error loading image for evidence {evidence_id}: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Show error message
            msg = f"Error opening image: {str(e)}"
            QMessageBox.critical(self, "Error", msg)
            
            # Update status bar
            parent = self.parent()
            if parent and hasattr(parent, 'statusBar'):
                parent.statusBar.showMessage(msg)
                
            return False
    
    def on_tree_item_selected(self, item, column):
        """Handle selection of tree items"""
        # Get the item path
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path:
            return
        
        # Set status message to show we're working
        if hasattr(self, 'statusBar'):
            self._status_bar.showMessage("Loading...")
        elif self.parent() and hasattr(self.parent(), 'statusBar'):
            self.parent()._status_bar.showMessage("Loading...")
        
        # Process events to update the UI
        QApplication.processEvents()
        
        # Handle evidence root items
        if item_path.startswith("evidence:"):
            evidence_id = int(item_path.split(":")[1])
            
            # Check if this is the first time selecting this evidence
            if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
                self.load_evidence_root(item)
                
            # Clear file metadata display
            self.clear_file_display()
            
            # Clear status message
            if hasattr(self, 'statusBar'):
                self._status_bar.showMessage("Ready")
            elif self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent()._status_bar.showMessage("Ready")
            return
                
        # Handle loading placeholders
        if item.text(0) == "Loading...":
            parent_item = item.parent()
            if parent_item:
                parent_path = parent_item.data(0, Qt.ItemDataRole.UserRole)
                
                # Check if parent is evidence root
                if parent_path and parent_path.startswith("evidence:"):
                    evidence_id = int(parent_path.split(":")[1])
                    self.load_evidence_root(parent_item)
                elif parent_path:
                    # Regular directory, extract evidence ID
                    evidence_id = self.extract_evidence_id_from_path(parent_path)
                    if evidence_id and self.load_image_if_needed(evidence_id):
                        dir_path = parent_path.split(":", 1)[1] if ":" in parent_path else parent_path
                        self.load_directory(parent_item, dir_path, evidence_id)
                
                # Select the parent after loading
                self.tree_widget.setCurrentItem(parent_item)
            
            # Clear status message
            if hasattr(self, 'statusBar'):
                self._status_bar.showMessage("Ready")
            elif self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent()._status_bar.showMessage("Ready")
            return
                
        # Handle directory items
        if item.text(2) == "Directory":
            # Check if item has placeholder child
            if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
                evidence_id = self.extract_evidence_id_from_path(item_path)
                if evidence_id and self.load_image_if_needed(evidence_id):
                    dir_path = item_path.split(":", 1)[1] if ":" in item_path else item_path
                    self.load_directory(item, dir_path, evidence_id)
            
            # Clear file metadata display
            self.clear_file_display()
            
            # Clear status message
            if hasattr(self, 'statusBar'):
                self._status_bar.showMessage("Ready")
            elif self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent()._status_bar.showMessage("Ready")
            return
                
        # Handle file items
        evidence_id = self.extract_evidence_id_from_path(item_path)
        if evidence_id and self.load_image_if_needed(evidence_id):
            file_path = item_path.split(":", 1)[1] if ":" in item_path else item_path
            self.display_file(file_path, evidence_id)
        
        # Clear status message
        if hasattr(self, 'statusBar'):
            self._status_bar.showMessage("Ready")
        elif self.parent() and hasattr(self.parent(), 'statusBar'):
            self.parent()._status_bar.showMessage("Ready")

    def determine_file_type(self, extension, mime_type=None):
        """Determine file type based on extension"""
        # Text files
        if extension in ['.txt', '.log', '.csv', '.md', '.py', '.js', '.html', '.css', '.xml', '.json']:
            return "Text File"
        # Images
        elif extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg']:
            return "Image"
        # Documents
        elif extension in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp']:
            return "Document"
        # Executables
        elif extension in ['.exe', '.dll', '.so', '.sh', '.bat', '.com']:
            return "Executable"
        # Archives
        elif extension in ['.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz']:
            return "Archive"
        # Default
        return "Unknown"

    def load_directory(self, parent_item, dir_path, evidence_id):
        """Load directory contents into tree"""
        # Get the forensic image
        image = self.current_images.get(evidence_id)
        if not image:
            return
            
        # Clear existing children
        while parent_item.childCount() > 0:
            parent_item.removeChild(parent_item.child(0))
        
        # Show loading indicator in status bar instead of tree placeholder
        if hasattr(self, 'statusBar'):
            self._status_bar.showMessage(f"Loading directory: {dir_path}...")
        elif self.parent() and hasattr(self.parent(), 'statusBar'):
            self.parent()._status_bar.showMessage(f"Loading directory: {dir_path}...")
            
        try:
            # Get directory items
            dir_items = image.list_directory(dir_path)
            
            # Sort items: directories first, then files
            dir_items.sort(key=lambda x: (0 if x["is_dir"] else 1, x["name"]))
            
            # Add items to tree
            for item_info in dir_items:
                name = item_info["name"]
                
                # Skip . and .. entries
                if name in [".", ".."]:
                    continue
                    
                size = item_info["size"]
                is_dir = item_info["is_dir"]
                
                # Create tree item
                tree_item = QTreeWidgetItem(parent_item)
                tree_item.setText(0, name)
                tree_item.setText(1, self.format_size(size) if not is_dir else "")
                tree_item.setText(2, "Directory" if is_dir else "File")
                
                # Store path with evidence ID
                full_path = item_info["path"]
                tree_item.setData(0, Qt.ItemDataRole.UserRole, f"{evidence_id}:{full_path}")
                
                # Check if file is deleted
                is_deleted = False
                try:
                    if not is_dir:  # Only check files, not directories
                        item_metadata = image.get_file_metadata(full_path, include_hash=False)
                        if item_metadata and 'flags' in item_metadata:
                            # TSK_FS_META_FLAG_UNALLOC (0x0001) indicates a deleted file in TSK
                            is_deleted = (item_metadata['flags'] & 0x0001) == 0x0001
                except Exception as e:
                    # If there's an error checking, assume not deleted
                    is_deleted = False
                
                # Set appropriate icon
                if is_dir:
                    tree_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                    
                    # Add placeholder for lazy loading
                    placeholder = QTreeWidgetItem(tree_item)
                    placeholder.setText(0, "Loading...")
                else:
                    # Use regular file icon (regardless of deletion status)
                    icon = self.get_file_icon(name)
                    tree_item.setIcon(0, icon)
                    
                    # Only mark the deletion status, don't change the file name color
                    if is_deleted:
                        # Just set a custom tooltip instead of changing the text color
                        tree_item.setToolTip(0, "Deleted file")
                        
            # Clear status message
            if hasattr(self, 'statusBar'):
                self._status_bar.showMessage("Directory loaded")
            elif self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent()._status_bar.showMessage("Directory loaded")
                
        except Exception as e:
            # Clear status message
            if hasattr(self, 'statusBar'):
                self._status_bar.showMessage("")
            elif self.parent() and hasattr(self.parent(), 'statusBar'):
                self.parent()._status_bar.showMessage("")
                
            QMessageBox.warning(self, "Error", f"Failed to load directory: {str(e)}")
            # Add a placeholder to indicate error
            error_item = QTreeWidgetItem(parent_item)
            error_item.setText(0, f"Error: {str(e)}")
            error_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning))
    
    def display_file(self, file_path, evidence_id):
        """Display file contents and metadata"""
        # Get the forensic image
        image = self.current_images.get(evidence_id)
        if not image:
            return
            
        # Store current selection
        self.selected_file_path = file_path
        self.selected_evidence_id = evidence_id
        
        try:
            # Get file metadata
            metadata = image.get_file_metadata(file_path)
            if not metadata:
                return
            
            # Check if file is deleted (add this portion)
            is_deleted = False
            if 'flags' in metadata:
                # TSK_FS_META_FLAG_UNALLOC (0x0001) indicates a deleted file in TSK
                is_deleted = (metadata['flags'] & 0x0001) == 0x0001
            
            # Add deletion status to Basic tab (add this field)
            file_name = os.path.basename(file_path)
            self.file_name_label.setText(file_name)
            self.file_path_label.setText(file_path)
            self.file_size_label.setText(self.format_size(metadata['size']))
            self.file_type_label.setText(self.determine_file_type(os.path.splitext(file_name)[1].lower(), None))
            
            # Add deletion status field in the Basic tab (add this line)
            if hasattr(self, 'file_deleted_label'):
                self.file_deleted_label.setText("Yes" if is_deleted else "No")

            # Update metadata display
            self.file_name_label.setText(os.path.basename(file_path))
            self.file_size_label.setText(self.format_size(metadata['size']))
            self.file_created_label.setText(metadata['create_time'])
            self.file_modified_label.setText(metadata['modify_time'])
            self.file_accessed_label.setText(metadata['access_time'])
            
            # Display hash values if available
            if 'hashes' in metadata:
                hash_text = ""
                for algo, hash_value in metadata['hashes'].items():
                    hash_text += f"{algo.upper()}: {hash_value}\n"
                self.file_hash_label.setText(hash_text)
            else:
                self.file_hash_label.setText("Not calculated")
                
            # Enable file action buttons
            self.hash_btn.setEnabled(True)
            self.bookmark_btn.setEnabled(True)
            self.export_btn.setEnabled(True)
            
            # Read file content
            file_data = image.read_file(file_path)
            if not file_data:
                self.clear_content_views()
                return
                
            # Detect file type
            is_text = self.is_text_file(file_data)
            is_image = self.is_image_file(file_data)
            
            # Update text view
            if is_text:
                try:
                    text_content = file_data.decode('utf-8', errors='replace')
                    self.text_view.setPlainText(text_content)
                except:
                    self.text_view.setPlainText("Unable to display as text.")
            else:
                self.text_view.setPlainText("Binary file - use Hex View.")
            
            # Update hex view
            self.hex_view.set_data(file_data)
            self.current_offset = 0
            self.offset_edit.setText("0")
            
            # Enable hex navigation buttons
            self.go_btn.setEnabled(True)
            self.prev_btn.setEnabled(False)  # At offset 0
            self.next_btn.setEnabled(metadata['size'] > 4096)  # Enable if more data available
            
            # Update image view
            if is_image:
                pixmap = QPixmap()
                if pixmap.loadFromData(file_data):
                    self.image_view.setPixmap(pixmap)
                    # Switch to image tab
                    self.content_tabs.setCurrentIndex(2)
                else:
                    self.image_view.clear()
            else:
                self.image_view.clear()
                # Switch to appropriate tab
                self.content_tabs.setCurrentIndex(0 if is_text else 1)
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to display file: {str(e)}")
            self.clear_file_display()
    
    def clear_file_display(self):
        """Clear file metadata and content displays"""
        # Clear metadata
        self.file_name_label.clear()
        self.file_size_label.clear()
        self.file_created_label.clear()
        self.file_modified_label.clear()
        self.file_accessed_label.clear()
        self.file_hash_label.clear()
        
        # Disable buttons
        self.hash_btn.setEnabled(False)
        self.bookmark_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.go_btn.setEnabled(False)
        self.prev_btn.setEnabled(False)
        self.next_btn.setEnabled(False)
        
        # Clear content views
        self.clear_content_views()
        
        # Reset selection variables
        self.selected_file_path = None
        self.selected_evidence_id = None
    
    def clear_content_views(self):
        """Clear all content views"""
        self.text_view.clear()
        self.hex_view.clear()
        self.image_view.clear()
    
    def is_text_file(self, data, sample_size=1000):
        """Detect if file is likely a text file"""
        # Check a sample of the file
        sample = data[:min(sample_size, len(data))]
        
        # Check for binary data
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        return bool(sample) and not bool(sample.translate(None, text_chars))
    
    def is_image_file(self, data):
        """Detect if file is an image based on header signatures"""
        if len(data) < 8:
            return False
            
        # Check common image signatures
        if data.startswith(b'\xFF\xD8\xFF'):  # JPEG
            return True
        elif data.startswith(b'\x89PNG\r\n\x1A\n'):  # PNG
            return True
        elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):  # GIF
            return True
        elif data.startswith(b'BM'):  # BMP
            return True
            
        return False
    
    def format_size(self, size_in_bytes):
        """Format file size in human readable format"""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} bytes"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"
    
    def get_file_icon(self, filename):
        """Get appropriate icon for file based on extension"""
        ext = os.path.splitext(filename)[1].lower()
        
        # Text files
        if ext in ['.txt', '.log', '.csv', '.md']:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView)
        # Images
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_DirLinkIcon)
        # Documents
        elif ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_FileLinkIcon)
        # Executables
        elif ext in ['.exe', '.dll', '.so']:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_DriveFDIcon)
        # Archives
        elif ext in ['.zip', '.tar', '.gz', '.rar', '.7z']:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_DriveNetIcon)
        # Default
        else:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
    
    def determine_file_type(self, extension, mime_type=None):
        """Determine file type based on extension"""
        # Text files
        if extension in ['.txt', '.log', '.csv', '.md', '.py', '.js', '.html', '.css', '.xml', '.json']:
            return "Text File"
        # Images
        elif extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg']:
            return "Image"
        # Documents
        elif extension in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp']:
            return "Document"
        # Executables
        elif extension in ['.exe', '.dll', '.so', '.sh', '.bat', '.com']:
            return "Executable"
        # Archives
        elif extension in ['.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz']:
            return "Archive"
        # If mime_type is provided and no match found by extension
        elif mime_type:
            if mime_type.startswith('text/'):
                return "Text File"
            elif mime_type.startswith('image/'):
                return "Image"
            elif mime_type in ['application/pdf', 'application/msword', 'application/vnd.ms-excel']:
                return "Document"
            elif mime_type in ['application/x-executable', 'application/x-msdownload']:
                return "Executable"
            elif mime_type in ['application/zip', 'application/x-tar', 'application/x-rar-compressed']:
                return "Archive"
        # Default
        return "Unknown"

    def filter_tree(self):
        """Filter tree items based on search text"""
        filter_text = self.filter_edit.text().lower()
        
        if not filter_text:
            # Clear filter - show all items
            self.show_all_tree_items()
            return
            
        # Hide all items first
        self.hide_all_tree_items()
        
        # Show matching items and their parents
        matching_paths = []
        
        def check_item(item):
            # Check if the current item matches
            item_text = item.text(0).lower()
            matches = filter_text in item_text
            
            # If it's a match, add it and all parent paths
            if matches:
                path = item.data(0, Qt.ItemDataRole.UserRole)
                if path:
                    parent = item
                    while parent:
                        parent_path = parent.data(0, Qt.ItemDataRole.UserRole)
                        if parent_path and parent_path not in matching_paths:
                            matching_paths.append(parent_path)
                        parent = parent.parent()
            
            # Check children regardless
            for i in range(item.childCount()):
                check_item(item.child(i))
        
        # Start checking from top-level items
        for i in range(self.tree_widget.topLevelItemCount()):
            check_item(self.tree_widget.topLevelItem(i))
        
        # Show all items in matching paths
        for path in matching_paths:
            items = self.find_items_by_path(path)
            for item in items:
                self.show_item_and_parents(item)
    
    def show_item_and_parents(self, item):
        """Show an item and all its parent items"""
        if not item:
            return
            
        item.setHidden(False)
        
        # Show all parent items
        parent = item.parent()
        while parent:
            parent.setHidden(False)
            parent = parent.parent()
    
    def hide_all_tree_items(self):
        """Hide all tree items"""
        def hide_item(item):
            item.setHidden(True)
            for i in range(item.childCount()):
                hide_item(item.child(i))
        
        for i in range(self.tree_widget.topLevelItemCount()):
            hide_item(self.tree_widget.topLevelItem(i))
    
    def show_all_tree_items(self):
        """Show all tree items"""
        def show_item(item):
            item.setHidden(False)
            for i in range(item.childCount()):
                show_item(item.child(i))
        
        for i in range(self.tree_widget.topLevelItemCount()):
            show_item(self.tree_widget.topLevelItem(i))
            
    def show_context_menu(self, position):
        """Show context menu for tree items"""
        item = self.tree_widget.itemAt(position)
        if not item:
            return
            
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path:
            return
            
        # Create context menu
        menu = QMenu()
        
        # Add actions based on item type
        if item_path.startswith("evidence:"):
            # Evidence root item
            menu.addAction("Open Evidence", lambda: self.on_tree_item_selected(item, 0))
            menu.addSeparator()
            menu.addAction("Analyze File Types", lambda: self.analyze_file_types(item))
            menu.addAction("Search Strings", lambda: self.search_strings(item))
            menu.addAction("Update All Analysis Tabs", lambda: self.update_all_analysis_tabs(item))
        elif item.text(2) == "Directory":
            # Directory item
            menu.addAction("Open Directory", lambda: self.on_tree_item_selected(item, 0))
            menu.addAction("Add Bookmark", lambda: self.add_bookmark_for_dir(item))
            menu.addAction("Export Directory", lambda: self.export_directory(item))
        else:
            # File item
            menu.addAction("View File", lambda: self.on_tree_item_selected(item, 0))
            menu.addAction("Add Bookmark", lambda: self.add_bookmark())
            menu.addAction("Export File", lambda: self.export_file())
            menu.addAction("Calculate Hash", lambda: self.calculate_hash())
        
        # Show menu at cursor position
        menu.exec(self.tree_widget.viewport().mapToGlobal(position))

    def update_all_analysis_tabs(self, item):
        """Update all analysis tabs with the current evidence image"""
        if not item:
            return
            
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path or not item_path.startswith("evidence:"):
            return
            
        evidence_id = int(item_path.split(":")[1])
        
        # Find the image in our currently loaded images
        if evidence_id in self.current_images:
            image = self.current_images[evidence_id]
            
            # Emit the signal to update all components
            self.image_loaded.emit(image, evidence_id)
            
            QMessageBox.information(self, "Update Complete", 
                                  "All analysis tabs have been updated with this evidence image.")

    def add_bookmark(self):
        if not self.selected_file_path or not self.selected_evidence_id or not self.case_manager:
            return
        
        dialog = AddBookmarkDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
            
        description = dialog.get_description()
        
        # Add the bookmark
        success, message, bookmark = self.case_manager.add_bookmark(
            self.selected_evidence_id, 
            description,
            f"File: {self.selected_file_path}",
            {"file_path": self.selected_file_path}
        )
        
        if success:
            # Force synchronization
            self.case_manager.synchronize_bookmarks()
            
            # Update UI components
            if hasattr(self.parent(), 'update_bookmarks_table'):
                self.parent().update_bookmarks_table()
            if hasattr(self.parent(), 'update_dashboard'):
                self.parent().update_dashboard()
                
            QMessageBox.information(self, "Bookmark Added", f"Bookmark added for: {self.selected_file_path}")
        else:
            QMessageBox.warning(self, "Error", f"Failed to add bookmark: {message}")

    def add_bookmark_for_dir(self, item):
        """Add a bookmark for a directory"""
        if not item or not self.case_manager:
            return
            
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path:
            return
            
        evidence_id = self.extract_evidence_id_from_path(item_path)
        if not evidence_id:
            return
            
        dir_path = item_path.split(":", 1)[1] if ":" in item_path else item_path
        
        # Create bookmark dialog
        dialog = AddBookmarkDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
            
        description = dialog.get_description()
        
        # Add the bookmark
        self.case_manager.add_bookmark(evidence_id, dir_path, description)
        QMessageBox.information(self, "Bookmark Added", f"Bookmark added for directory: {dir_path}")

    def export_file(self):
        """Export the currently selected file"""
        if not self.selected_file_path or not self.selected_evidence_id:
            return
            
        # Get the forensic image
        image = self.current_images.get(self.selected_evidence_id)
        if not image:
            return
            
        # Get output path
        filename = os.path.basename(self.selected_file_path)
        output_path = QFileDialog.getSaveFileName(self, "Export File As", filename)[0]
        if not output_path:
            return
            
        # Create progress dialog
        progress = QProgressDialog("Exporting file...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setValue(10)
        progress.show()
        
        try:
            # Extract the file
            success = image.extract_file(self.selected_file_path, output_path)
            progress.setValue(100)
            
            if success:
                QMessageBox.information(self, "Export Successful", f"File exported to: {output_path}")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export file.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting file: {str(e)}")
        finally:
            progress.close()

    def export_directory(self, item):
        """Export a directory and its contents"""
        if not item:
            return
            
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path:
            return
            
        evidence_id = self.extract_evidence_id_from_path(item_path)
        if not evidence_id:
            return
            
        # Get the forensic image
        image = self.current_images.get(evidence_id)
        if not image:
            return
            
        dir_path = item_path.split(":", 1)[1] if ":" in item_path else item_path
        dir_name = os.path.basename(dir_path)
        if not dir_name:
            dir_name = "root"
            
        # Get output directory
        output_dir = QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if not output_dir:
            return
            
        # Create target directory
        target_dir = os.path.join(output_dir, dir_name)
        try:
            os.makedirs(target_dir, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}")
            return
            
        # Start recursive export
        self.export_directory_recursive(image, dir_path, target_dir, evidence_id)

    def export_directory_recursive(self, image, source_path, target_dir, evidence_id):
        """Recursively export a directory and its contents"""
        # Create progress dialog
        progress = QProgressDialog(f"Exporting directory: {os.path.basename(source_path)}...", 
                                "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setValue(0)
        progress.show()
        
        try:
            # Get directory contents
            items = image.list_directory(source_path)
            
            # Count total items for progress
            total_items = len(items)
            if total_items == 0:
                progress.setValue(100)
                progress.close()
                return
                
            # Process each item
            for i, item in enumerate(items):
                # Check if operation was canceled
                if progress.wasCanceled():
                    break
                    
                name = item["name"]
                # Skip . and .. entries
                if name in [".", ".."]:
                    continue
                    
                # Update progress
                progress.setValue(int((i / total_items) * 100))
                progress.setLabelText(f"Exporting: {name}")
                
                item_path = item["path"]
                target_path = os.path.join(target_dir, name)
                
                if item["is_dir"]:
                    # Create directory
                    try:
                        os.makedirs(target_path, exist_ok=True)
                        
                        # Recursively export subdirectory
                        self.export_directory_recursive(image, item_path, target_path, evidence_id)
                    except Exception as e:
                        print(f"Error creating directory {target_path}: {e}")
                else:
                    # Export file
                    try:
                        image.extract_file(item_path, target_path)
                    except Exception as e:
                        print(f"Error extracting file {item_path}: {e}")
            
            progress.setValue(100)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting directory: {str(e)}")
        finally:
            progress.close()

    def analyze_file_types(self, item):
        """Open file type analysis for an evidence item"""
        if not item:
            return
            
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path or not item_path.startswith("evidence:"):
            return
            
        evidence_id = int(item_path.split(":")[1])
        
        # Find parent widget (MainWindow)
        parent = self.parent()
        while parent and not hasattr(parent, 'file_type_widget'):
            parent = parent.parent()
            
        if parent and hasattr(parent, 'file_type_widget') and hasattr(parent, 'tab_widget'):
            # Set the evidence for file type analysis
            if self.load_image_if_needed(evidence_id):
                parent.file_type_widget.set_image(self.current_images[evidence_id])
                
                # Switch to the file type analysis tab
                for i in range(parent.tab_widget.count()):
                    if parent.tab_widget.widget(i) == parent.file_type_widget:
                        parent.tab_widget.setCurrentIndex(i)
                        break

    def search_strings(self, item):
        """Open string search for an evidence item"""
        if not item:
            return
            
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_path or not item_path.startswith("evidence:"):
            return
            
        evidence_id = int(item_path.split(":")[1])
        
        # Find parent widget (MainWindow)
        parent = self.parent()
        while parent and not hasattr(parent, 'search_widget'):
            parent = parent.parent()
            
        if parent and hasattr(parent, 'search_widget') and hasattr(parent, 'tab_widget'):
            # Set the evidence for string search
            if self.load_image_if_needed(evidence_id):
                parent.search_widget.set_image(self.current_images[evidence_id])
                
                # Switch to the string search tab
                for i in range(parent.tab_widget.count()):
                    if parent.tab_widget.widget(i) == parent.search_widget:
                        parent.tab_widget.setCurrentIndex(i)
                        break

    def go_to_offset(self):
        """Go to a specific offset in the hex view"""
        if not self.selected_file_path or not self.selected_evidence_id:
            return
            
        try:
            # Get offset
            offset = int(self.offset_edit.text(), 0)  # 0 base allows for hex input
            
            # Get the forensic image
            image = self.current_images.get(self.selected_evidence_id)
            if not image:
                return
                
            # Read file data at offset
            file_data = image.read_file(self.selected_file_path, offset, 4096)
            if not file_data:
                QMessageBox.warning(self, "Error", "Failed to read file at specified offset.")
                return
                
            # Update hex view
            self.hex_view.set_data(file_data)
            self.current_offset = offset
            
            # Update button states
            self.prev_btn.setEnabled(offset > 0)
            
            # Check if there's more data
            metadata = image.get_file_metadata(self.selected_file_path)
            if metadata:
                has_more = (offset + 4096) < metadata['size']
                self.next_btn.setEnabled(has_more)
            
            # Switch to hex tab
            self.content_tabs.setCurrentIndex(1)
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", 
                            "Please enter a valid decimal or hex (0x...) offset.")

    def calculate_additional_hashes(self):
        """Calculate additional hash algorithms for the current file"""
        if not self.selected_file_path or not self.selected_evidence_id:
            return
            
        # Create a dialog with checkboxes for hash algorithms
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Hash Algorithms")
        dialog.setMinimumWidth(300)
        
        layout = QVBoxLayout()
        
        # Create checkboxes for each algorithm
        algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"]
        checkboxes = []
        
        for algo in algorithms:
            checkbox = QCheckBox(algo.upper())
            # Set SHA-256 checked by default
            if algo == "sha256":
                checkbox.setChecked(True)
            checkboxes.append(checkbox)
            layout.addWidget(checkbox)
        
        # Add OK and Cancel buttons
        button_box = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_box.addWidget(ok_button)
        button_box.addWidget(cancel_button)
        
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        
        layout.addLayout(button_box)
        dialog.setLayout(layout)
        
        # Execute dialog and get results
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        # Collect selected algorithms
        selected_algos = []
        for i, checkbox in enumerate(checkboxes):
            if checkbox.isChecked():
                selected_algos.append(algorithms[i])
        
        if not selected_algos:
            QMessageBox.warning(self, "No Selection", "Please select at least one hash algorithm.")
            return
        
        # Get the forensic image
        image = self.current_images.get(self.selected_evidence_id)
        if not image:
            return
            
        # Calculate hash values
        try:
            hashes = image.calculate_file_hash(self.selected_file_path, selected_algos)
            if hashes:
                hash_text = ""
                for algo, hash_value in hashes.items():
                    hash_text += f"{algo.upper()}: {hash_value}\n"
                self.file_hash_label.setText(hash_text)
            else:
                self.file_hash_label.setText("Hash calculation failed")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to calculate hashes: {str(e)}")

    def calculate_hash(self):
        """Calculate hash values for the currently selected file"""
        if not self.selected_file_path or not self.selected_evidence_id:
            return
            
        # Get the forensic image
        image = self.current_images.get(self.selected_evidence_id)
        if not image:
            return
            
        try:
            # Calculate standard hashes (md5, sha1, sha256)
            hashes = image.calculate_file_hash(self.selected_file_path)
            if hashes:
                hash_text = ""
                for algo, hash_value in hashes.items():
                    hash_text += f"{algo.upper()}: {hash_value}\n"
                self.file_hash_label.setText(hash_text)
                QMessageBox.information(self, "Hash Calculation", "Hash values calculated successfully.")
            else:
                self.file_hash_label.setText("Hash calculation failed")
                QMessageBox.warning(self, "Error", "Failed to calculate hashes.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to calculate hashes: {str(e)}")

    def go_to_prev(self):
        """Go to previous chunk in hex view"""
        if not self.selected_file_path or not self.selected_evidence_id:
            return
            
        # Calculate previous offset
        prev_offset = max(0, self.current_offset - 4096)
        
        # Update offset field
        self.offset_edit.setText(str(prev_offset))
        
        # Go to that offset
        self.go_to_offset()

    def go_to_next(self):
        """Go to next chunk in hex view"""
        if not self.selected_file_path or not self.selected_evidence_id:
            return
            
        # Calculate next offset
        next_offset = self.current_offset + 4096
        
        # Update offset field
        self.offset_edit.setText(str(next_offset))
        
        # Go to that offset
        self.go_to_offset()

class FileTypeWidget(QWidget):
    """Improved UI for file type analysis"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.analysis_data = None
        self.image = None
        self.init_ui()
        
    def init_ui(self):
        main_layout = QVBoxLayout()
        
        # Create header section with title and description
        header_layout = QVBoxLayout()
        title_label = QLabel("File Type Analysis")
        title_label.setStyleSheet("font-size: 16pt; font-weight: bold; margin-bottom: 5px;")
        desc_label = QLabel("Analyze files in the forensic image by type and extension")
        desc_label.setStyleSheet("font-size: 10pt; color: #888888; margin-bottom: 10px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(desc_label)
        main_layout.addLayout(header_layout)
        
        # Create directory selection area with better styling
        dir_group = QGroupBox("Directory Selection")
        dir_layout = QHBoxLayout()
        
        dir_layout.addWidget(QLabel("Path:"))
        self.path_edit = QLineEdit("/")
        self.path_edit.setPlaceholderText("Enter directory path to analyze")
        dir_layout.addWidget(self.path_edit, 1)
        
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setMinimumWidth(120)
        self.analyze_btn.clicked.connect(self.analyze)
        dir_layout.addWidget(self.analyze_btn)
        
        dir_group.setLayout(dir_layout)
        main_layout.addWidget(dir_group)
        
        # Create progress indicator
        self.progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.progress_layout.addWidget(self.status_label)
        
        main_layout.addLayout(self.progress_layout)
        
        # Create the results area with tabs
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        self.view_tabs = QTabWidget()
        
        # File Types Tab
        types_tab = QWidget()
        types_layout = QVBoxLayout()
        
        # Summary statistics for types
        types_summary_layout = QHBoxLayout()
        self.types_count_label = QLabel("Total types: 0")
        self.types_files_label = QLabel("Total files: 0")
        self.types_size_label = QLabel("Total size: 0 bytes")
        types_summary_layout.addWidget(self.types_count_label)
        types_summary_layout.addWidget(self.types_files_label)
        types_summary_layout.addWidget(self.types_size_label)
        types_layout.addLayout(types_summary_layout)
        
        # Search/filter for types
        types_filter_layout = QHBoxLayout()
        types_filter_layout.addWidget(QLabel("Filter:"))
        self.types_filter = QLineEdit()
        self.types_filter.setPlaceholderText("Filter by file type...")
        self.types_filter.textChanged.connect(self.filter_types_table)
        types_filter_layout.addWidget(self.types_filter)
        types_layout.addLayout(types_filter_layout)
        
        # Types table
        self.types_table = QTableWidget()
        self.types_table.setColumnCount(4)
        self.types_table.setHorizontalHeaderLabels(["File Type", "Count", "Total Size", "Percentage"])
        self.types_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.types_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.types_table.setAlternatingRowColors(True)
        self.types_table.setSortingEnabled(True)
        self.types_table.itemClicked.connect(self.on_type_selected)
        types_layout.addWidget(self.types_table)
        
        types_tab.setLayout(types_layout)
        self.view_tabs.addTab(types_tab, "By File Type")
        
        # Extensions Tab
        extensions_tab = QWidget()
        extensions_layout = QVBoxLayout()
        
        # Summary statistics for extensions
        ext_summary_layout = QHBoxLayout()
        self.ext_count_label = QLabel("Total extensions: 0")
        self.ext_files_label = QLabel("Total files: 0")
        self.ext_size_label = QLabel("Total size: 0 bytes")
        ext_summary_layout.addWidget(self.ext_count_label)
        ext_summary_layout.addWidget(self.ext_files_label)
        ext_summary_layout.addWidget(self.ext_size_label)
        extensions_layout.addLayout(ext_summary_layout)
        
        # Search/filter for extensions
        ext_filter_layout = QHBoxLayout()
        ext_filter_layout.addWidget(QLabel("Filter:"))
        self.ext_filter = QLineEdit()
        self.ext_filter.setPlaceholderText("Filter by extension...")
        self.ext_filter.textChanged.connect(self.filter_extensions_table)
        ext_filter_layout.addWidget(self.ext_filter)
        extensions_layout.addLayout(ext_filter_layout)
        
        # Extensions table
        self.extensions_table = QTableWidget()
        self.extensions_table.setColumnCount(4)
        self.extensions_table.setHorizontalHeaderLabels(["Extension", "Count", "Total Size", "Percentage"])
        self.extensions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.extensions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.extensions_table.setAlternatingRowColors(True)
        self.extensions_table.setSortingEnabled(True)
        extensions_layout.addWidget(self.extensions_table)
        
        extensions_tab.setLayout(extensions_layout)
        self.view_tabs.addTab(extensions_tab, "By Extension")
        
        # Files Tab
        files_tab = QWidget()
        files_layout = QVBoxLayout()
        
        # Header for files list
        files_header = QLabel("Files List")
        files_header.setStyleSheet("font-weight: bold;")
        files_layout.addWidget(files_header)
        
        # Search/filter for files
        files_filter_layout = QHBoxLayout()
        files_filter_layout.addWidget(QLabel("Filter:"))
        self.files_filter = QLineEdit()
        self.files_filter.setPlaceholderText("Filter by file name/path...")
        self.files_filter.textChanged.connect(self.filter_files_table)
        files_filter_layout.addWidget(self.files_filter)
        files_layout.addLayout(files_filter_layout)
        
        # Files table
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(3)
        self.files_table.setHorizontalHeaderLabels(["File Path", "Size", "Type"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setAlternatingRowColors(True)
        files_layout.addWidget(self.files_table)
        
        # Add file action buttons
        files_buttons_layout = QHBoxLayout()
        self.view_file_btn = QPushButton("View Selected")
        self.view_file_btn.setEnabled(False)
        self.view_file_btn.clicked.connect(self.view_selected_file)
        
        self.export_file_btn = QPushButton("Export Selected")
        self.export_file_btn.setEnabled(False)
        self.export_file_btn.clicked.connect(self.export_selected_file)
        
        files_buttons_layout.addWidget(self.view_file_btn)
        files_buttons_layout.addWidget(self.export_file_btn)
        files_layout.addLayout(files_buttons_layout)
        
        files_tab.setLayout(files_layout)
        self.view_tabs.addTab(files_tab, "Files")
        
        results_layout.addWidget(self.view_tabs)
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group, 1)  # Give it stretch
        
        # Bottom actions section
        actions_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("Export Analysis")
        self.export_btn.setMinimumWidth(150)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_analysis)
        
        self.bookmark_btn = QPushButton("Bookmark Selection")
        self.bookmark_btn.setMinimumWidth(150)
        self.bookmark_btn.setEnabled(False)
        # This would need to be connected to bookmarking functionality
        
        actions_layout.addWidget(self.export_btn)
        actions_layout.addWidget(self.bookmark_btn)
        actions_layout.addStretch()
        
        main_layout.addLayout(actions_layout)
        
        self.setLayout(main_layout)
        
        # Connect signals for files table selection changed
        self.files_table.itemSelectionChanged.connect(self.on_files_selection_changed)
        
    def set_image(self, forensic_image):
        """Set the forensic image to analyze"""
        self.image = forensic_image
        self.analysis_data = None
        self.status_label.setText("Ready")
        
        # Clear tables
        self.types_table.setRowCount(0)
        self.extensions_table.setRowCount(0)
        self.files_table.setRowCount(0)
        
        # Reset summary stats
        self.types_count_label.setText("Total types: 0")
        self.types_files_label.setText("Total files: 0")
        self.types_size_label.setText("Total size: 0 bytes")
        self.ext_count_label.setText("Total extensions: 0")
        self.ext_files_label.setText("Total files: 0")
        self.ext_size_label.setText("Total size: 0 bytes")
        
        # Disable buttons
        self.export_btn.setEnabled(False)
        self.bookmark_btn.setEnabled(False)
        self.view_file_btn.setEnabled(False)
        self.export_file_btn.setEnabled(False)
    
    def format_size(self, size_in_bytes):
        """Format file size in human readable format"""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} bytes"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

    def analyze(self):
        """Analyze the file types"""
        if not self.image:
            QMessageBox.warning(self, "No Image", "No forensic image is open.")
            return
            
        path = self.path_edit.text() or "/"
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(10)
        self.status_label.setText("Analyzing...")
        self.analyze_btn.setEnabled(False)
        QApplication.processEvents()

    

        try:
            # Create progress dialog for better feedback
            progress = QProgressDialog("Analyzing file types...", "Cancel", 0, 100, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setValue(10)
            progress.show()
            
            analyzer = FileTypeAnalyzer(self.image)
            self.analysis_data = analyzer.analyze_directory(path)
            
            progress.setValue(70)
            self.update_tables()
            progress.setValue(100)
            progress.close()
            
            # Update status
            total_types = len(self.analysis_data['by_type'])
            total_files = sum(d['count'] for d in self.analysis_data['by_type'].values())
            total_size = sum(d['size'] for d in self.analysis_data['by_type'].values())
            
            self.status_label.setText(f"Analysis complete: {total_files} files analyzed")
            self.progress_bar.setValue(100)
            self.analyze_btn.setEnabled(True)
            self.export_btn.setEnabled(True)
            
            # Show success message
            QMessageBox.information(self, "Analysis Complete", 
                                  f"Analysis completed successfully.\n"
                                  f"Found {total_types} file types across {total_files} files.")
            
        except Exception as e:
            progress.close()
            self.status_label.setText("Analysis failed")
            self.progress_bar.setValue(0)
            self.analyze_btn.setEnabled(True)
            QMessageBox.critical(self, "Analysis Error", f"Error analyzing file types: {str(e)}")
        finally:
            # Hide progress bar after a delay
            QTimer.singleShot(3000, lambda: self.progress_bar.setVisible(False))
        
    def update_tables(self):
        """Update the tables with analysis data"""
        if not self.analysis_data:
            return
        
        # Calculate totals for percentages
        total_size = sum(data['size'] for data in self.analysis_data['by_type'].values())
        total_count = sum(data['count'] for data in self.analysis_data['by_type'].values())
        
        # Sort types by count (descending)
        sorted_types = sorted(self.analysis_data['by_type'].items(), 
                             key=lambda x: x[1]['count'], reverse=True)
            
        # Update types table
        self.types_table.setSortingEnabled(False)  # Disable sorting during update
        self.types_table.setRowCount(0)
        for file_type, data in sorted_types:
            row = self.types_table.rowCount()
            self.types_table.insertRow(row)
            
            percentage = (data['size'] / total_size * 100) if total_size > 0 else 0
            
            self.types_table.setItem(row, 0, QTableWidgetItem(file_type))
            self.types_table.setItem(row, 1, QTableWidgetItem(str(data['count'])))
            self.types_table.setItem(row, 2, QTableWidgetItem(self.format_size(data['size'])))
            self.types_table.setItem(row, 3, QTableWidgetItem(f"{percentage:.2f}%"))
        
        self.types_table.setSortingEnabled(True)  # Re-enable sorting
            
        # Update extensions table
        ext_total_size = sum(data['size'] for data in self.analysis_data['by_extension'].values())
        ext_total_count = sum(data['count'] for data in self.analysis_data['by_extension'].values())
        
        # Sort extensions by count (descending)
        sorted_extensions = sorted(self.analysis_data['by_extension'].items(), 
                                  key=lambda x: x[1]['count'], reverse=True)
        
        self.extensions_table.setSortingEnabled(False)  # Disable sorting during update
        self.extensions_table.setRowCount(0)
        for ext, data in sorted_extensions:
            row = self.extensions_table.rowCount()
            self.extensions_table.insertRow(row)
            
            percentage = (data['size'] / ext_total_size * 100) if ext_total_size > 0 else 0
            
            self.extensions_table.setItem(row, 0, QTableWidgetItem(ext))
            self.extensions_table.setItem(row, 1, QTableWidgetItem(str(data['count'])))
            self.extensions_table.setItem(row, 2, QTableWidgetItem(self.format_size(data['size'])))
            self.extensions_table.setItem(row, 3, QTableWidgetItem(f"{percentage:.2f}%"))
            
        self.extensions_table.setSortingEnabled(True)  # Re-enable sorting
        
        # Update summary statistics
        self.types_count_label.setText(f"Total types: {len(self.analysis_data['by_type'])}")
        self.types_files_label.setText(f"Total files: {total_count}")
        self.types_size_label.setText(f"Total size: {self.format_size(total_size)}")
        
        self.ext_count_label.setText(f"Total extensions: {len(self.analysis_data['by_extension'])}")
        self.ext_files_label.setText(f"Total files: {ext_total_count}")
        self.ext_size_label.setText(f"Total size: {self.format_size(ext_total_size)}")
            
    def on_type_selected(self, item):
        """Display files of selected type"""
        if not self.analysis_data:
            return
            
        # Get selected type
        row = item.row()
        file_type = self.types_table.item(row, 0).text()
        
        # Update files table
        self.files_table.setRowCount(0)
        if file_type in self.analysis_data['by_type']:
            for file_path in self.analysis_data['by_type'][file_type]['files']:
                # Find file size if available
                file_size = 0
                for item in self.image.list_directory(os.path.dirname(file_path)):
                    if item['path'] == file_path:
                        file_size = item['size']
                        break
                
                row = self.files_table.rowCount()
                self.files_table.insertRow(row)
                self.files_table.setItem(row, 0, QTableWidgetItem(file_path))
                self.files_table.setItem(row, 1, QTableWidgetItem(self.format_size(file_size)))
                self.files_table.setItem(row, 2, QTableWidgetItem(file_type))
                
        # Switch to files tab and clear filter
        self.view_tabs.setCurrentIndex(2)
        self.files_filter.clear()
        
    def on_files_selection_changed(self):
        """Enable/disable file action buttons based on selection"""
        has_selection = len(self.files_table.selectedItems()) > 0
        self.view_file_btn.setEnabled(has_selection)
        self.export_file_btn.setEnabled(has_selection)
        self.bookmark_btn.setEnabled(has_selection)
        
    def view_selected_file(self):
        """View the selected file"""
        selected_items = self.files_table.selectedItems()
        if not selected_items:
            return
            
        # Get the file path from the first column
        row = selected_items[0].row()
        file_path = self.files_table.item(row, 0).text()
        
        # This would need to be connected to the main application's file viewer
        # For now, we'll just show a message
        QMessageBox.information(self, "View File", f"Viewing file: {file_path}")
        
    def export_selected_file(self):
        """Export the selected file"""
        selected_items = self.files_table.selectedItems()
        if not selected_items:
            return
            
        # Get the file path from the first column
        row = selected_items[0].row()
        file_path = self.files_table.item(row, 0).text()
        
        # Get output path
        output_path = QFileDialog.getSaveFileName(self, "Export File As", os.path.basename(file_path))[0]
        if not output_path:
            return
            
        # Extract the file
        try:
            if self.image.extract_file(file_path, output_path):
                self.status_label.setText(f"File exported to {output_path}")
                QMessageBox.information(self, "Export Success", f"File exported to {output_path}")
            else:
                QMessageBox.warning(self, "Export Error", "Failed to export file.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting file: {str(e)}")
        
    def filter_types_table(self):
        """Filter the types table based on search text"""
        filter_text = self.types_filter.text().lower()
        
        for row in range(self.types_table.rowCount()):
            file_type = self.types_table.item(row, 0).text().lower()
            match = filter_text in file_type
            self.types_table.setRowHidden(row, not match)
            
    def filter_extensions_table(self):
        """Filter the extensions table based on search text"""
        filter_text = self.ext_filter.text().lower()
        
        for row in range(self.extensions_table.rowCount()):
            ext = self.extensions_table.item(row, 0).text().lower()
            match = filter_text in ext
            self.extensions_table.setRowHidden(row, not match)
    
    def filter_files_table(self):
        """Filter the files table based on search text"""
        filter_text = self.files_filter.text().lower()
        
        for row in range(self.files_table.rowCount()):
            file_path = self.files_table.item(row, 0).text().lower()
            file_type = self.files_table.item(row, 2).text().lower()
            match = filter_text in file_path or filter_text in file_type
            self.files_table.setRowHidden(row, not match)
        
    def export_analysis(self):
        """Export analysis results to a file"""
        if not self.analysis_data:
            QMessageBox.warning(self, "No Data", "No analysis data to export.")
            return
            
        path, _ = QFileDialog.getSaveFileName(self, "Export Analysis", "", 
                                           "CSV Files (*.csv);;HTML Files (*.html)")
        if not path:
            return
            
        try:
            if path.lower().endswith('.csv'):
                self.export_to_csv(path)
            elif path.lower().endswith('.html'):
                self.export_to_html(path)
            else:
                # Default to CSV if no extension
                path += '.csv'
                self.export_to_csv(path)
            
            self.status_label.setText(f"Analysis exported to {path}")
            QMessageBox.information(self, "Export Complete", f"Analysis exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export analysis: {str(e)}")
        
    def export_to_csv(self, path):
        """Export analysis data to CSV"""
        with open(path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Add header with summary info
            writer.writerow(["File Type Analysis Report"])
            writer.writerow(["Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow([])
            
            # Calculate totals
            total_size = sum(data['size'] for data in self.analysis_data['by_type'].values())
            total_count = sum(data['count'] for data in self.analysis_data['by_type'].values())
            
            writer.writerow(["Summary"])
            writer.writerow(["Total File Types", len(self.analysis_data['by_type'])])
            writer.writerow(["Total Files", total_count])
            writer.writerow(["Total Size", self.format_size(total_size)])
            writer.writerow([])
            
            # Write file types
            writer.writerow(["File Types Analysis"])
            writer.writerow(["Type", "Count", "Total Size", "Percentage"])
            
            # Sort types by count (descending)
            sorted_types = sorted(self.analysis_data['by_type'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)
            
            for file_type, data in sorted_types:
                percentage = (data['size'] / total_size * 100) if total_size > 0 else 0
                writer.writerow([
                    file_type, 
                    data['count'], 
                    self.format_size(data['size']),
                    f"{percentage:.2f}%"
                ])
                
            writer.writerow([])  # Empty row as separator
            
            # Write extensions
            writer.writerow(["Extensions Analysis"])
            writer.writerow(["Extension", "Count", "Total Size", "Percentage"])
            
            # Sort extensions by count (descending)
            sorted_extensions = sorted(self.analysis_data['by_extension'].items(), 
                                     key=lambda x: x[1]['count'], reverse=True)
            
            ext_total_size = sum(data['size'] for data in self.analysis_data['by_extension'].values())
            
            for ext, data in sorted_extensions:
                percentage = (data['size'] / ext_total_size * 100) if ext_total_size > 0 else 0
                writer.writerow([
                    ext, 
                    data['count'], 
                    self.format_size(data['size']),
                    f"{percentage:.2f}%"
                ])
                
    def export_to_html(self, path):
        """Export analysis data to HTML with tables"""
        try:
            # Calculate totals
            total_size = sum(data['size'] for data in self.analysis_data['by_type'].values())
            total_count = sum(data['count'] for data in self.analysis_data['by_type'].values())
            
            # Sort by count
            sorted_types = sorted(self.analysis_data['by_type'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)
            
            sorted_extensions = sorted(self.analysis_data['by_extension'].items(), 
                                     key=lambda x: x[1]['count'], reverse=True)
            
            # Generate HTML content
            html_content = f"""<!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>File Type Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #2d2d2d; color: #f0f0f0; }}
                    h1 {{ color: #e0e0e0; border-bottom: 2px solid #555; padding-bottom: 10px; }}
                    h2 {{ color: #e0e0e0; margin-top: 20px; border-bottom: 1px solid #555; padding-bottom: 5px; }}
                    .summary {{ background-color: #3d3d3d; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                    .summary p {{ margin: 5px 0; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }}
                    th {{ background-color: #444; padding: 10px; text-align: left; color: #fff; }}
                    td {{ padding: 8px; border: 1px solid #555; }}
                    tr:nth-child(even) {{ background-color: #3d3d3d; }}
                    tr:nth-child(odd) {{ background-color: #333; }}
                    .date {{ color: #aaa; font-style: italic; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <h1>File Type Analysis Report</h1>
                <div class="date">Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <p><strong>Total File Types:</strong> {len(self.analysis_data['by_type'])}</p>
                    <p><strong>Total Files:</strong> {total_count}</p>
                    <p><strong>Total Size:</strong> {self.format_size(total_size)}</p>
                </div>
                
                <h2>File Types Analysis</h2>
                <table>
                    <tr>
                        <th>File Type</th>
                        <th>Count</th>
                        <th>Total Size</th>
                        <th>Percentage</th>
                    </tr>
            """
            
            # Add file types data
            for file_type, data in sorted_types:
                percentage = (data['size'] / total_size * 100) if total_size > 0 else 0
                html_content += f"""
                    <tr>
                        <td>{file_type}</td>
                        <td>{data['count']}</td>
                        <td>{self.format_size(data['size'])}</td>
                        <td>{percentage:.2f}%</td>
                    </tr>
                """
                
            html_content += """
                </table>
                
                <h2>Extensions Analysis</h2>
                <table>
                    <tr>
                        <th>Extension</th>
                        <th>Count</th>
                        <th>Total Size</th>
                        <th>Percentage</th>
                    </tr>
            """
            
            # Calculate extension totals
            ext_total_size = sum(data['size'] for data in self.analysis_data['by_extension'].values())
            
            # Add extensions data
            for ext, data in sorted_extensions:
                percentage = (data['size'] / ext_total_size * 100) if ext_total_size > 0 else 0
                html_content += f"""
                    <tr>
                        <td>{ext}</td>
                        <td>{data['count']}</td>
                        <td>{self.format_size(data['size'])}</td>
                        <td>{percentage:.2f}%</td>
                    </tr>
                """
                
            html_content += """
                </table>
            </body>
            </html>
            """
            
            # Write HTML to file
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            return True
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return False

class StringSearchWidget(QWidget):
    """UI for string search"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.forensic_image = None
        self.search_results = []
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Search controls
        search_layout = QHBoxLayout()
        
        # Search input field
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search term...")
        self.search_input.returnPressed.connect(self.perform_search)
        
        # Search options
        options_layout = QHBoxLayout()
        
        # Case sensitive checkbox
        self.case_sensitive = QCheckBox("Case Sensitive")
        self.case_sensitive.setChecked(False)
        
        # Regex search checkbox
        self.regex_search = QCheckBox("Use Regex")
        self.regex_search.setChecked(False)
        
        # Search path input
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Search Path:"))
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("/ (root directory)")
        path_layout.addWidget(self.path_edit)
        
        # Search button
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.perform_search)
        
        # Add widgets to search layout
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.case_sensitive)
        search_layout.addWidget(self.regex_search)
        search_layout.addWidget(search_button)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["File", "Offset", "Context", "Status"])
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.results_table.itemSelectionChanged.connect(self.on_result_selected)
        
        # Preview area
        preview_group = QGroupBox("Preview")
        preview_layout = QVBoxLayout()
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        preview_layout.addWidget(self.preview_text)
        preview_group.setLayout(preview_layout)
        
        # Export button
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        
        # Add all layouts and widgets to main layout
        layout.addLayout(search_layout)
        layout.addLayout(path_layout)
        layout.addWidget(self.results_table)
        layout.addWidget(preview_group)
        layout.addWidget(self.export_button)
        
        self.setLayout(layout)
        
    def perform_search(self):
        if not self.forensic_image:
            QMessageBox.warning(self, "Warning", "No image loaded")
            return
            
        search_term = self.search_input.text()
        if not search_term:
            QMessageBox.warning(self, "Warning", "Please enter a search term")
            return
            
        try:
            # Get search options
            case_sensitive = self.case_sensitive.isChecked()
            use_regex = self.regex_search.isChecked()
            search_path = self.path_edit.text().strip() or "/"
            
            # Clear previous results
            self.search_results = []
            self.results_table.setRowCount(0)
            self.preview_text.clear()
            
            # Prepare the search pattern
            if use_regex:
                try:
                    pattern = re.compile(search_term, flags=0 if case_sensitive else re.IGNORECASE)
                except re.error as e:
                    QMessageBox.warning(self, "Invalid Regex", f"Invalid regular expression: {str(e)}")
                    return
            else:
                pattern = re.compile(re.escape(search_term), flags=0 if case_sensitive else re.IGNORECASE)
            
            # Start the search
            self.setCursor(Qt.CursorShape.WaitCursor)
            
            def search_directory(current_path):
                try:
                    # List contents of current directory
                    items = self.forensic_image.list_directory(current_path)
                    
                    for item in items:
                        if item['name'] in ['.', '..']:
                            continue
                            
                        file_path = item['path']
                        
                        # Process files
                        if not item['is_dir']:
                            try:
                                # Read file content
                                file_data = self.forensic_image.read_file(file_path)
                                if not file_data:
                                    continue
                                    
                                # Process the file in chunks
                                chunk_size = 4096
                                offset = 0
                                
                                while offset < len(file_data):
                                    chunk = file_data[offset:offset + chunk_size]
                                    try:
                                        # Try to decode as text
                                        text = chunk.decode('utf-8', errors='ignore')
                                        
                                        # Find all matches in this chunk
                                        for match in pattern.finditer(text):
                                            start_pos = max(0, match.start() - 50)
                                            end_pos = min(len(text), match.end() + 50)
                                            context = text[start_pos:end_pos]
                                            
                                            # Add to results
                                            self.search_results.append({
                                                'file': file_path,
                                                'offset': offset + match.start(),
                                                'context': context,
                                                'status': 'Found'
                                            })
                                            
                                    except UnicodeDecodeError:
                                        # Skip binary content
                                        pass
                                        
                                    offset += chunk_size
                                    
                                    # Update UI periodically
                                    QApplication.processEvents()
                                    
                            except Exception as e:
                                print(f"Error searching file {file_path}: {str(e)}")
                        
                        # Recursively search subdirectories
                        elif item['is_dir']:
                            search_directory(file_path)
                            
                except Exception as e:
                    print(f"Error searching directory {current_path}: {str(e)}")
            
            try:
                # Start recursive search from the specified path
                search_directory(search_path)
            finally:
                self.setCursor(Qt.CursorShape.ArrowCursor)
            
            # Update the results table
            self.update_results_table()
            
            # Show search summary
            QMessageBox.information(
                self,
                "Search Complete",
                f"Found {len(self.search_results)} matches"
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Search failed: {str(e)}")
            
    def update_results_table(self):
        self.results_table.setRowCount(len(self.search_results))
        for row, result in enumerate(self.search_results):
            self.results_table.setItem(row, 0, QTableWidgetItem(result.get('file', '')))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(result.get('offset', ''))))
            self.results_table.setItem(row, 2, QTableWidgetItem(result.get('context', '')))
            self.results_table.setItem(row, 3, QTableWidgetItem(result.get('status', '')))
            
    def highlight_search_term(self, text, search_term):
        if not search_term:
            return text
            
        try:
            if self.regex_search.isChecked():
                pattern = re.compile(f'({re.escape(search_term)})', 
                                  flags=re.IGNORECASE if not self.case_sensitive.isChecked() else 0)
                return pattern.sub(r'<span style="background-color: #FFD700">\1</span>', text)
            else:
                if not self.case_sensitive.isChecked():
                    pattern = re.compile(re.escape(search_term), re.IGNORECASE)
                else:
                    pattern = re.compile(re.escape(search_term))
                return pattern.sub(lambda m: f'<span style="background-color: #FFD700">{m.group()}</span>', text)
        except re.error:
            return text
            
    def on_result_selected(self):
        selected_items = self.results_table.selectedItems()
        if not selected_items:
            self.preview_text.clear()
            return
            
        row = selected_items[0].row()
        if row < len(self.search_results):
            result = self.search_results[row]
            context = result.get('context', '')
            if context:
                highlighted_text = self.highlight_search_term(context, self.search_input.text())
                self.preview_text.setHtml(highlighted_text)
            else:
                self.preview_text.clear()
                
    def export_results(self):
        if not self.search_results:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Search Results",
            "",
            "CSV files (*.csv);;Text files (*.txt)"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["File", "Offset", "Context", "Status"])
                for result in self.search_results:
                    writer.writerow([
                        result.get('file', ''),
                        result.get('offset', ''),
                        result.get('context', ''),
                        result.get('status', '')
                    ])
            QMessageBox.information(self, "Success", "Results exported successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
            
    def set_image(self, forensic_image):
        self.forensic_image = forensic_image
        self.search_results = []
        self.results_table.setRowCount(0)
        self.preview_text.clear()

class HexViewWidget(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        font = QFont("Courier New")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        
    def set_data(self, data):
        self.clear()
        hex_text = ""
        ascii_text = ""
        line_address = 0
        
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            # Address part
            hex_text += f"{line_address:08x}: "
            
            # Hex part
            hex_part = ""
            for j in range(16):
                if j < len(chunk):
                    hex_part += f"{chunk[j]:02x} "
                else:
                    hex_part += "   "
                if j == 7:  # Add extra space in the middle
                    hex_part += " "
            
            # ASCII part
            ascii_part = ""
            for byte in chunk:
                if 32 <= byte <= 126:  # Printable ASCII
                    ascii_part += chr(byte)
                else:
                    ascii_part += "."
            
            hex_text += f"{hex_part} |{ascii_part}|\n"
            line_address += 16
        
        self.setPlainText(hex_text)

