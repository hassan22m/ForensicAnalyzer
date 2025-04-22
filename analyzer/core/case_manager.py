# forensicanalyzer/core/case_manager.py

import os
import json
import datetime
import hashlib
import shutil
from PyQt6.QtWidgets import (QApplication,QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                            QLineEdit, QTextEdit, QFileDialog, QMessageBox, QTreeWidget, 
                            QTreeWidgetItem, QTabWidget, QGroupBox, QFormLayout, QComboBox,
                            QDialog, QDialogButtonBox)
from PyQt6.QtCore import Qt, pyqtSignal

class EvidenceItem:
    """Class representing a single evidence item"""
    
    TYPE_NETWORK = "network"
    TYPE_STORAGE = "storage"
    TYPE_MEMORY = "memory"
    
    def __init__(self, id=None, source_path="", evidence_type="", description="", md5=""):
        self.id = id
        self.source_path = source_path
        self.evidence_type = evidence_type
        self.description = description
        self.md5 = md5
        self.added_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.file_name = os.path.basename(source_path) if source_path else ""
        self.bookmarks = []
        
    def to_dict(self):
        """Convert evidence item to dictionary for serialization"""
        return {
            "id": self.id,
            "source_path": self.source_path,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "md5": self.md5,
            "added_date": self.added_date,
            "file_name": self.file_name,
            "bookmarks": [b.to_dict() for b in self.bookmarks]
        }
    
    @staticmethod
    def from_dict(data):
        """Create evidence item from dictionary"""
        item = EvidenceItem(
            id=data.get("id"),
            source_path=data.get("source_path", ""),
            evidence_type=data.get("evidence_type", ""),
            description=data.get("description", ""),
            md5=data.get("md5", "")
        )
        item.added_date = data.get("added_date", item.added_date)
        item.file_name = data.get("file_name", os.path.basename(item.source_path))
        
        # Load bookmarks
        for bookmark_data in data.get("bookmarks", []):
            bookmark = Bookmark.from_dict(bookmark_data)
            item.bookmarks.append(bookmark)
            
        return item

class Bookmark:
    """Class representing a bookmark within an evidence item"""
    
    def __init__(self, id=None, description="", location="", data=None):
        self.id = id
        self.description = description
        self.location = location  # Could be an offset, timestamp, or other location identifier
        self.data = data or {}    # Additional data specific to the bookmark type
        self.added_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def to_dict(self):
        """Convert bookmark to dictionary for serialization"""
        return {
            "id": self.id,
            "description": self.description,
            "location": self.location,
            "data": self.data,
            "added_date": self.added_date
        }
    
    @staticmethod
    def from_dict(data):
        """Create bookmark from dictionary"""
        bookmark = Bookmark(
            id=data.get("id"),
            description=data.get("description", ""),
            location=data.get("location", ""),
            data=data.get("data", {})
        )
        bookmark.added_date = data.get("added_date", bookmark.added_date)
        return bookmark

class Case:
    """Class representing a forensic case"""
    
    def __init__(self, name="", directory="", investigator=""):
        self.name = name
        self.directory = directory
        self.investigator = investigator
        self.creation_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.last_modified = self.creation_date
        self.notes = ""
        self.evidence_items = []
        self.next_evidence_id = 1
        self.next_bookmark_id = 1
    
    def to_dict(self):
        """Convert case to dictionary for serialization"""
        return {
            "name": self.name,
            "directory": self.directory,
            "investigator": self.investigator,
            "creation_date": self.creation_date,
            "last_modified": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "notes": self.notes,
            "evidence_items": [item.to_dict() for item in self.evidence_items],
            "next_evidence_id": self.next_evidence_id,
            "next_bookmark_id": self.next_bookmark_id
        }
    
    @staticmethod
    def from_dict(data):
        """Create case from dictionary"""
        case = Case(
            name=data.get("name", ""),
            directory=data.get("directory", ""),
            investigator=data.get("investigator", "")
        )
        case.creation_date = data.get("creation_date", case.creation_date)
        case.last_modified = data.get("last_modified", case.last_modified)
        case.notes = data.get("notes", "")
        case.next_evidence_id = data.get("next_evidence_id", 1)
        case.next_bookmark_id = data.get("next_bookmark_id", 1)
        
        # Load evidence items
        for item_data in data.get("evidence_items", []):
            item = EvidenceItem.from_dict(item_data)
            case.evidence_items.append(item)
            
        return case

class IntegratedCaseManager:
    """Unified case manager that works across all analyzers"""
    
    def __init__(self):
        self.current_case = None
        self.case_file_path = None
        self.bookmarks = []  # Initialize flat bookmarks list
    
    def synchronize_bookmarks(self):
        """Ensure the flat bookmarks list is synchronized with evidence items"""
        if not self.current_case:
            return False, "No case is currently open"
            
        # Clear the flat bookmarks list
        self.bookmarks = []
        
        # Rebuild the flat bookmarks list from evidence items
        for evidence in self.current_case.evidence_items:
            if hasattr(evidence, 'bookmarks'):
                for bookmark in evidence.bookmarks:
                    # Convert bookmark to dictionary if it's a Bookmark object
                    if isinstance(bookmark, Bookmark):
                        bookmark_dict = bookmark.to_dict()
                    else:
                        bookmark_dict = bookmark
                    
                    # Ensure evidence_id is included
                    bookmark_dict['evidence_id'] = evidence.id
                    
                    # Add file_path if it's in the data but not in the main dict
                    if 'data' in bookmark_dict and 'file_path' in bookmark_dict['data']:
                        bookmark_dict['file_path'] = bookmark_dict['data']['file_path']
                    
                    # Clean up location if it's a file path
                    if 'location' in bookmark_dict and bookmark_dict['location'].startswith('File: '):
                        bookmark_dict['file_path'] = bookmark_dict['location'][6:]  # Remove "File: " prefix
                    
                    self.bookmarks.append(bookmark_dict)
        
        # Sort bookmarks by ID to maintain consistent order
        self.bookmarks.sort(key=lambda x: x.get('id', 0))
        
        return True, "Bookmarks synchronized"

    def create_case(self, name, directory, investigator=""):
        """Create a new case with the specified details"""
        # Create case object
        self.current_case = Case(name, directory, investigator)
        
        # Create case directory structure
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        # Create subdirectories for different evidence types
        os.makedirs(os.path.join(directory, "evidence"), exist_ok=True)
        os.makedirs(os.path.join(directory, "evidence", "network"), exist_ok=True)
        os.makedirs(os.path.join(directory, "evidence", "storage"), exist_ok=True)
        os.makedirs(os.path.join(directory, "evidence", "memory"), exist_ok=True)
        os.makedirs(os.path.join(directory, "reports"), exist_ok=True)
        
        # Set case file path
        self.case_file_path = os.path.join(directory, "case.json")
        
        # Save the case
        self.save_case()
        
        return True, "Case created successfully"
    
    def open_case(self, case_file_path):
        """Open an existing case from the specified file path"""
        if not os.path.exists(case_file_path):
            return False, "Case file does not exist"
        
        try:
            with open(case_file_path, 'r') as f:
                case_data = json.load(f)
                
            self.current_case = Case.from_dict(case_data)
            self.case_file_path = case_file_path
            
            return True, "Case opened successfully"
        except Exception as e:
            return False, f"Error opening case: {str(e)}"
    
    def save_case(self):
        """Save the current case to the case file"""
        if not self.current_case or not self.case_file_path:
            return False, "No case is currently open"
        
        try:
            # Update last modified timestamp
            self.current_case.last_modified = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Convert case to dictionary
            case_data = self.current_case.to_dict()
            
            # Save to JSON file
            with open(self.case_file_path, 'w') as f:
                json.dump(case_data, f, indent=4)
                
            return True, "Case saved successfully"
        except Exception as e:
            return False, f"Error saving case: {str(e)}"
    
    def add_evidence(self, source_path, evidence_type, description=""):
        """Add evidence to the current case"""
        if not self.current_case:
            return False, "No case is currently open", None
        
        try:
            # Generate a unique evidence ID
            evidence_id = self.current_case.next_evidence_id
            self.current_case.next_evidence_id += 1
            
            # Calculate MD5 hash of the file
            md5_hash = self._calculate_file_hash(source_path)
            
            # Create evidence item
            evidence_item = EvidenceItem(
                id=evidence_id,
                source_path=source_path,
                evidence_type=evidence_type,
                description=description,
                md5=md5_hash
            )
            
            # Copy the evidence file to the case directory
            evidence_dir = os.path.join(self.current_case.directory, "evidence", evidence_type)
            destination_path = os.path.join(evidence_dir, evidence_item.file_name)
            
            # If the file already exists, add a unique identifier
            if os.path.exists(destination_path):
                base_name, ext = os.path.splitext(evidence_item.file_name)
                destination_path = os.path.join(evidence_dir, f"{base_name}_{evidence_id}{ext}")
                evidence_item.file_name = os.path.basename(destination_path)
            
            # Copy the file
            shutil.copy2(source_path, destination_path)
            
            # Update evidence source path to the copied location
            evidence_item.source_path = destination_path
            
            # Add to evidence list
            self.current_case.evidence_items.append(evidence_item)
            
            # Save the case
            self.save_case()
            
            return True, f"Evidence added with ID: {evidence_id}", evidence_item
        except Exception as e:
            return False, f"Error adding evidence: {str(e)}", None
    
    def add_bookmark(self, evidence_id, description, location, data=None):
        """Add a bookmark to a specific evidence item"""
        if not self.current_case:
            return False, "No case is currently open", None
        
        # Find the evidence item
        evidence_item = next((item for item in self.current_case.evidence_items if item.id == evidence_id), None)
        if not evidence_item:
            return False, f"Evidence with ID {evidence_id} not found", None
        
        try:
            print(f"Adding bookmark: {description} to evidence {evidence_id}")
            
            # Generate a unique bookmark ID
            bookmark_id = self.current_case.next_bookmark_id
            self.current_case.next_bookmark_id += 1
            
            # Create bookmark
            bookmark = Bookmark(
                id=bookmark_id,
                description=description,
                location=location,
                data=data or {}
            )
            
            # Initialize bookmarks list if it doesn't exist
            if not hasattr(evidence_item, 'bookmarks'):
                evidence_item.bookmarks = []
            
            # Add to evidence item
            evidence_item.bookmarks.append(bookmark)
            
            # Add to flat bookmarks list
            bookmark_dict = bookmark.to_dict()
            bookmark_dict['evidence_id'] = evidence_id
            self.bookmarks.append(bookmark_dict)
            
            print(f"Bookmark added with ID: {bookmark.id}")
            print(f"Total evidence bookmarks: {len(evidence_item.bookmarks)}")
            print(f"Total case manager bookmarks: {len(self.bookmarks)}")
            
            # Save the case to persist changes
            self.save_case()
            
            return True, f"Bookmark added with ID: {bookmark_id}", bookmark
        except Exception as e:
            return False, f"Error adding bookmark: {str(e)}", None
    
    def update_case_notes(self, notes):
        """Update the case notes"""
        if not self.current_case:
            return False, "No case is currently open"
        
        self.current_case.notes = notes
        self.save_case()
        
        return True, "Case notes updated"
    
    def get_evidence_item(self, evidence_id):
        """Get an evidence item by ID"""
        if not self.current_case:
            return None
        
        return next((item for item in self.current_case.evidence_items if item.id == evidence_id), None)
    
    def close_case(self):
        """Close the current case"""
        self.current_case = None
        self.case_file_path = None
        
        return True, "Case closed"
    
    def _calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def generate_report(self, output_path, include_evidence=True, include_bookmarks=True, include_notes=True):
        """Generate a report of the current case"""
        if not self.current_case:
            return False, "No case is currently open"
        
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            
            # Create the PDF
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = styles["Heading1"]
            elements.append(Paragraph(f"Forensic Analysis Report: {self.current_case.name}", title_style))
            elements.append(Spacer(1, 12))
            
            # Case Information
            elements.append(Paragraph("Case Information", styles["Heading2"]))
            elements.append(Spacer(1, 6))
            
            case_info = [
                ["Case Name:", self.current_case.name],
                ["Investigator:", self.current_case.investigator],
                ["Created Date:", self.current_case.creation_date],
                ["Last Modified:", self.current_case.last_modified]
            ]
            
            t = Table(case_info, colWidths=[100, 400])
            t.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
            ]))
            elements.append(t)
            elements.append(Spacer(1, 12))
            
            # Evidence Items
            if include_evidence and self.current_case.evidence_items:
                elements.append(Paragraph("Evidence Items", styles["Heading2"]))
                elements.append(Spacer(1, 6))
                
                evidence_data = [["ID", "Type", "Filename", "MD5 Hash", "Added Date", "Description"]]
                for item in self.current_case.evidence_items:
                    evidence_data.append([
                        str(item.id),
                        item.evidence_type,
                        item.file_name,
                        item.md5,
                        item.added_date,
                        item.description
                    ])
                
                t = Table(evidence_data, colWidths=[30, 60, 100, 130, 80, 100])
                t.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
                ]))
                elements.append(t)
                elements.append(Spacer(1, 12))
                
                # Bookmarks (grouped by evidence item)
                if include_bookmarks:
                    has_bookmarks = any(item.bookmarks for item in self.current_case.evidence_items)
                    if has_bookmarks:
                        elements.append(Paragraph("Bookmarks", styles["Heading2"]))
                        elements.append(Spacer(1, 6))
                        
                        for item in self.current_case.evidence_items:
                            if item.bookmarks:
                                elements.append(Paragraph(f"Evidence ID {item.id}: {item.file_name}", styles["Heading3"]))
                                elements.append(Spacer(1, 3))
                                
                                bookmark_data = [["ID", "Description", "Location", "Added Date"]]
                                for bookmark in item.bookmarks:
                                    bookmark_data.append([
                                        str(bookmark.id),
                                        bookmark.description,
                                        bookmark.location,
                                        bookmark.added_date
                                    ])
                                
                                t = Table(bookmark_data, colWidths=[30, 180, 180, 100])
                                t.setStyle(TableStyle([
                                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
                                ]))
                                elements.append(t)
                                elements.append(Spacer(1, 6))
            
            # Notes
            if include_notes and self.current_case.notes:
                elements.append(Paragraph("Case Notes", styles["Heading2"]))
                elements.append(Spacer(1, 6))
                elements.append(Paragraph(self.current_case.notes, styles["Normal"]))
                elements.append(Spacer(1, 12))
            
            # Build the PDF
            doc.build(elements)
            
            return True, f"Report generated successfully at {output_path}"
        except Exception as e:
            return False, f"Error generating report: {str(e)}"

class CaseManagerGUI(QWidget):
    """GUI widget for the integrated case manager"""
    
    # Signals
    case_opened = pyqtSignal(object)  # Signal emitted when a case is opened (case object)
    case_closed = pyqtSignal()  # Signal emitted when a case is closed
    evidence_added = pyqtSignal(object)  # Signal emitted when evidence is added (evidence item)
    evidence_selected = pyqtSignal(object)  # Signal emitted when evidence is selected (evidence item)
    bookmark_added = pyqtSignal(object, object)  # Signal emitted when a bookmark is added (evidence item, bookmark)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.case_manager = IntegratedCaseManager()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components"""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        
        # Case controls group
        case_group = QGroupBox("Case Management")
        case_layout = QVBoxLayout(case_group)
        case_layout.setContentsMargins(5, 15, 5, 5)
        case_layout.setSpacing(5)
        
        # Create a dark container for the buttons
        button_container = QWidget()
        button_container.setStyleSheet("""
            QWidget {
                background-color: #1A1416;
                border-radius: 4px;
                padding: 6px;
            }
            QPushButton {
                min-width: 85px;
                max-width: 85px;
                height: 28px;
                background-color: #1E1B1C;
                border: 1px solid #3A3436;
                border-radius: 4px;
                color: #E0E0E0;
                font-size: 12px;
                padding: 4px 8px;
                margin: 2px 4px;
            }
            QPushButton:hover {
                background-color: #2A2426;
                border: 1px solid #4A4446;
            }
            QPushButton:pressed {
                background-color: #C41016;
                border: 1px solid #E31E24;
            }
            QPushButton:disabled {
                background-color: #1A1416;
                color: #787C80;
                border: 1px solid #2A2426;
            }
        """)

        # Create buttons layout with increased spacing
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(6, 6, 6, 6)
        button_layout.setSpacing(8)  # Increased spacing between buttons

        # Create buttons
        self.btn_new_case = QPushButton("New Case")
        self.btn_open_case = QPushButton("Open Case")
        self.btn_save_case = QPushButton("Save Case")
        self.btn_save_case.setEnabled(False)

        # Add buttons to layout
        button_layout.addWidget(self.btn_new_case)
        button_layout.addWidget(self.btn_open_case)
        button_layout.addWidget(self.btn_save_case)
        button_layout.addStretch()

        # Add button container to main layout
        case_layout.addWidget(button_container)

        # Current case info
        case_info_layout = QFormLayout()
        case_info_layout.setSpacing(5)
        self.lbl_case_name = QLabel("No case open")
        self.lbl_investigator = QLabel("")
        self.lbl_creation_date = QLabel("")
        case_info_layout.addRow("Case:", self.lbl_case_name)
        case_info_layout.addRow("Investigator:", self.lbl_investigator)
        case_info_layout.addRow("Created:", self.lbl_creation_date)
        
        case_layout.addLayout(case_info_layout)
        case_group.setLayout(case_layout)
        main_layout.addWidget(case_group)
        
        # Evidence group
        evidence_group = QGroupBox("Evidence Items")
        evidence_layout = QVBoxLayout()
        
        # Evidence tree widget
        self.evidence_tree = QTreeWidget()
        self.evidence_tree.setHeaderLabels(["ID", "Type", "Filename", "Description"])
        self.evidence_tree.setColumnWidth(0, 40)
        self.evidence_tree.setColumnWidth(1, 70)
        self.evidence_tree.setColumnWidth(2, 120)
        
        evidence_layout.addWidget(self.evidence_tree)
        
        # Evidence buttons
        evidence_buttons_layout = QHBoxLayout()
        self.btn_add_evidence = QPushButton("Add Evidence")
        #self.btn_add_bookmark = QPushButton("Add Bookmark")
        self.btn_view_details = QPushButton("View Details")
        
        evidence_buttons_layout.addWidget(self.btn_add_evidence)
        #evidence_buttons_layout.addWidget(self.btn_add_bookmark)
        evidence_buttons_layout.addWidget(self.btn_view_details)
        
        evidence_layout.addLayout(evidence_buttons_layout)
        evidence_group.setLayout(evidence_layout)
        main_layout.addWidget(evidence_group)
        
        # Notes group
        notes_group = QGroupBox("Case Notes")
        notes_layout = QVBoxLayout()
        
        self.txt_notes = QTextEdit()
        self.btn_save_notes = QPushButton("Save Notes")
        
        notes_layout.addWidget(self.txt_notes)
        notes_layout.addWidget(self.btn_save_notes)
        
        notes_group.setLayout(notes_layout)
        main_layout.addWidget(notes_group)
        
        # Report group
        report_group = QGroupBox("Report Generation")
        report_layout = QHBoxLayout()
        
        self.btn_generate_report = QPushButton("Generate Report")
        report_layout.addWidget(self.btn_generate_report)
        
        report_group.setLayout(report_layout)
        main_layout.addWidget(report_group)
        
        # Connect signals and slots
        self.btn_new_case.clicked.connect(self.on_new_case)
        self.btn_open_case.clicked.connect(self.on_open_case)
        self.btn_save_case.clicked.connect(self.on_save_case)
        self.btn_add_evidence.clicked.connect(self.on_add_evidence)
        #self.btn_add_bookmark.clicked.connect(self.on_add_bookmark)
        self.btn_view_details.clicked.connect(self.on_view_details)
        self.btn_save_notes.clicked.connect(self.on_save_notes)
        self.btn_generate_report.clicked.connect(self.on_generate_report)
        self.evidence_tree.itemSelectionChanged.connect(self.on_evidence_selection_changed)
        
        self.evidence_tree.itemClicked.connect(self.on_evidence_tree_clicked)
        # Initial state: disable buttons that require an open case
        self.update_ui_case_closed()
    
    def on_evidence_tree_clicked(self, item, column):
        """Handle click on evidence item in the tree"""
        # Get the evidence ID from the tree item
        evidence_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not evidence_id:
            return
            
        # Find the evidence item
        evidence_item = self.case_manager.get_evidence_item(evidence_id)
        if evidence_item:
            # Emit signal to notify other components
            self.evidence_selected.emit(evidence_item)

    def notify_bookmark_added(self, evidence_item, bookmark):
        """Notify all components that a bookmark has been added"""
        # Ensure bookmarks are synchronized across all data structures
        self.synchronize_bookmarks()
        
        # Emit signal if available
        if hasattr(self, 'bookmark_added_signal'):
            self.bookmark_added_signal.emit(evidence_item, bookmark)
        
        # Update all relevant GUI components
        # (This is a fallback in case signals don't work)
        main_window = QApplication.instance().activeWindow()
        if main_window:
            # Try to find and update any evidence tree widgets
            for widget in main_window.findChildren(QTreeWidget):
                if widget.objectName() == "evidence_tree" or "evidence" in widget.objectName().lower():
                    # Found a likely evidence tree widget
                    # Force a refresh by calling appropriate methods
                    parent = widget.parent()
                    while parent:
                        if hasattr(parent, 'refresh_evidence_tree'):
                            parent.refresh_evidence_tree()
                            break
                        elif hasattr(parent, 'update_evidence_table'):
                            parent.update_evidence_table()
                            break
                        parent = parent.parent()

    def update_ui_case_open(self):
        """Update UI for open case state"""
        self.btn_save_case.setEnabled(True)
        self.btn_add_evidence.setEnabled(True)
        self.btn_generate_report.setEnabled(True)
        self.txt_notes.setEnabled(True)
        self.btn_save_notes.setEnabled(True)
        
        # Update case info
        if self.case_manager.current_case:
            self.lbl_case_name.setText(self.case_manager.current_case.name)
            self.lbl_investigator.setText(self.case_manager.current_case.investigator)
            self.lbl_creation_date.setText(self.case_manager.current_case.creation_date)
            self.txt_notes.setText(self.case_manager.current_case.notes)
    
    def update_ui_case_closed(self):
        """Update UI for closed case state"""
        self.btn_save_case.setEnabled(False)
        self.btn_add_evidence.setEnabled(False)
        #self.btn_add_bookmark.setEnabled(False)
        self.btn_view_details.setEnabled(False)
        self.btn_generate_report.setEnabled(False)
        self.txt_notes.setEnabled(False)
        self.btn_save_notes.setEnabled(False)
        
        # Clear case info
        self.lbl_case_name.setText("No case open")
        self.lbl_investigator.setText("")
        self.lbl_creation_date.setText("")
        self.txt_notes.clear()
        self.evidence_tree.clear()
    
    def refresh_evidence_tree(self):
        """Refresh the evidence tree widget"""
        self.evidence_tree.clear()
        
        if not self.case_manager.current_case:
            return
        
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
            
            # # Add bookmarks as child items
            # for bookmark in item.bookmarks:
            #     bookmark_item = QTreeWidgetItem([
            #         str(bookmark.id),
            #         "Bookmark",
            #         bookmark.location,
            #         bookmark.description
            #     ])
            #     bookmark_item.setData(0, Qt.ItemDataRole.UserRole, bookmark.id)
            #     evidence_item.addChild(bookmark_item)
            
            # Add to appropriate group
            if item.evidence_type == EvidenceItem.TYPE_NETWORK:
                network_group.addChild(evidence_item)
            elif item.evidence_type == EvidenceItem.TYPE_STORAGE:
                storage_group.addChild(evidence_item)
            elif item.evidence_type == EvidenceItem.TYPE_MEMORY:
                memory_group.addChild(evidence_item)
        
        # Expand all groups
        self.evidence_tree.expandAll()
    
    def on_new_case(self):
        """Handle new case button click"""
        dialog = NewCaseDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            case_name = dialog.get_case_name()
            case_directory = dialog.get_case_directory()
            investigator = dialog.get_investigator()
            
            success, message = self.case_manager.create_case(case_name, case_directory, investigator)
            
            if success:
                QMessageBox.information(self, "Case Created", message)
                self.update_ui_case_open()
                self.case_opened.emit(self.case_manager.current_case)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def on_open_case(self):
        """Handle open case button click"""
        case_file, _ = QFileDialog.getOpenFileName(
            self, "Open Case", "", "Case Files (*.json);;All Files (*)"
        )
        
        if case_file:
            success, message = self.case_manager.open_case(case_file)
            
            if success:
                QMessageBox.information(self, "Case Opened", message)
                self.update_ui_case_open()
                self.refresh_evidence_tree()
                self.case_opened.emit(self.case_manager.current_case)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def on_save_case(self):
        """Handle save case button click"""
        if self.case_manager.current_case:
            success, message = self.case_manager.save_case()
            
            if success:
                QMessageBox.information(self, "Case Saved", message)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def on_add_evidence(self):
        """Handle add evidence button click"""
        if not self.case_manager.current_case:
            QMessageBox.warning(self, "No Case", "No case is open. Create or open a case first.")
            return
        
        dialog = AddEvidenceDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            source_path = dialog.get_source_path()
            evidence_type = dialog.get_evidence_type()
            description = dialog.get_description()
            
            success, message, evidence_item = self.case_manager.add_evidence(
                source_path, evidence_type, description
            )
            
            if success:
                QMessageBox.information(self, "Evidence Added", message)
                self.refresh_evidence_tree()
                
                print(f"Emitting evidence_added signal with item: {evidence_item}")
                self.evidence_added.emit(evidence_item)  # This line is crucial
            else:
                QMessageBox.warning(self, "Error", message)
    
    def on_add_bookmark(self):
        """Handle add bookmark button click"""
        # Get selected evidence item
        selected_items = self.evidence_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "Please select an evidence item first")
            return
        
        selected_item = selected_items[0]
        
        # Make sure it's an evidence item (not a bookmark)
        if selected_item.parent() is not None:
            QMessageBox.warning(self, "Error", "Please select an evidence item (not a bookmark)")
            return
        
        # Get evidence ID
        evidence_id = selected_item.data(0, Qt.ItemDataRole.UserRole)
        if not evidence_id:
            return
        
        dialog = AddBookmarkDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            description = dialog.get_description()
            location = dialog.get_location()
            
            success, message, bookmark = self.case_manager.add_bookmark(
                evidence_id, description, location
            )
            
            if success:
                QMessageBox.information(self, "Bookmark Added", message)
                self.refresh_evidence_tree()
                
                # Get the evidence item
                evidence_item = self.case_manager.get_evidence_item(evidence_id)
                if evidence_item:
                    self.bookmark_added.emit(evidence_item, bookmark)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def on_view_details(self):
        """Handle view details button click"""
        # Get selected evidence item
        selected_items = self.evidence_tree.selectedItems()
        if not selected_items:
            return
        
        selected_item = selected_items[0]
        
        # Check if it's a top-level item (evidence group)
        if selected_item.parent() is None and selected_item.childCount() > 0:
            return
            
        # Get evidence or bookmark ID
        item_id = selected_item.data(0, Qt.ItemDataRole.UserRole)
        if not item_id:
            return
        
        # If it's a bookmark (has a parent)
        if selected_item.parent() and selected_item.parent().parent() is not None:
            # Get evidence ID from parent
            evidence_id = selected_item.parent().data(0, Qt.ItemDataRole.UserRole)
            evidence_item = self.case_manager.get_evidence_item(evidence_id)
            
            if evidence_item:
                # Find the bookmark
                bookmark = next((b for b in evidence_item.bookmarks if b.id == item_id), None)
                if bookmark:
                    # Display bookmark details
                    dialog = BookmarkDetailsDialog(self, evidence_item, bookmark)
                    dialog.exec()
        else:
            # It's an evidence item
            evidence_item = self.case_manager.get_evidence_item(item_id)
            if evidence_item:
                # Display evidence details
                dialog = EvidenceDetailsDialog(self, evidence_item)
                dialog.exec()
                
                # Emit evidence selected signal
                self.evidence_selected.emit(evidence_item)
    
    def on_save_notes(self):
        """Handle save notes button click"""
        if not self.case_manager.current_case:
            return
        
        notes = self.txt_notes.toPlainText()
        success, message = self.case_manager.update_case_notes(notes)
        
        if success:
            QMessageBox.information(self, "Notes Saved", message)
        else:
            QMessageBox.warning(self, "Error", message)
    
    def on_generate_report(self):
        """Handle generate report button click"""
        if not self.case_manager.current_case:
            return
        
        # Get output file path
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", "PDF Files (*.pdf);;All Files (*)"
        )
        
        if output_path:
            success, message = self.case_manager.generate_report(output_path)
            
            if success:
                QMessageBox.information(self, "Report Generated", message)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def on_evidence_selection_changed(self):
        """Handle evidence selection change"""
        selected_items = self.evidence_tree.selectedItems()
        
        if selected_items:
            selected_item = selected_items[0]
            
            # Enable/disable buttons based on selection
            if selected_item.parent() is None and selected_item.childCount() > 0:
                # It's a group item (Network, Storage, Memory)
                #self.btn_add_bookmark.setEnabled(False)
                self.btn_view_details.setEnabled(False)
            elif selected_item.parent() is not None and selected_item.parent().parent() is not None:
                # It's a bookmark item
                #self.btn_add_bookmark.setEnabled(False)
                self.btn_view_details.setEnabled(True)
            else:
                # It's an evidence item
                #self.btn_add_bookmark.setEnabled(True)
                self.btn_view_details.setEnabled(True)
        else:
            #self.btn_add_bookmark.setEnabled(False)
            self.btn_view_details.setEnabled(False)

class NewCaseDialog(QDialog):
    """Dialog for creating a new case"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Case")
        self.setMinimumWidth(400)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        
        # Form layout for inputs
        form_layout = QFormLayout()
        
        self.txt_case_name = QLineEdit()
        self.txt_investigator = QLineEdit()
        self.txt_case_directory = QLineEdit()
        self.btn_browse_directory = QPushButton("Browse...")
        
        # Directory selection layout
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(self.txt_case_directory)
        dir_layout.addWidget(self.btn_browse_directory)
        
        form_layout.addRow("Case Name:", self.txt_case_name)
        form_layout.addRow("Investigator:", self.txt_investigator)
        form_layout.addRow("Case Directory:", dir_layout)
        
        layout.addLayout(form_layout)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)
        
        # Connect signals
        self.btn_browse_directory.clicked.connect(self.browse_directory)
    
    def browse_directory(self):
        """Open directory selection dialog"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Case Directory", ""
        )
        
        if directory:
            self.txt_case_directory.setText(directory)
    
    def get_case_name(self):
        """Get the entered case name"""
        return self.txt_case_name.text()
    
    def get_case_directory(self):
        """Get the selected case directory"""
        return self.txt_case_directory.text()
    
    def get_investigator(self):
        """Get the entered investigator name"""
        return self.txt_investigator.text()

class AddEvidenceDialog(QDialog):
    """Dialog for adding evidence to a case"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Evidence")
        self.setMinimumWidth(400)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        
        # Form layout for inputs
        form_layout = QFormLayout()
        
        self.txt_source_path = QLineEdit()
        self.btn_browse_file = QPushButton("Browse...")
        
        # File selection layout
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.txt_source_path)
        file_layout.addWidget(self.btn_browse_file)
        
        self.cmb_evidence_type = QComboBox()
        self.cmb_evidence_type.addItem("Network", EvidenceItem.TYPE_NETWORK)
        self.cmb_evidence_type.addItem("Storage", EvidenceItem.TYPE_STORAGE)
        self.cmb_evidence_type.addItem("Memory", EvidenceItem.TYPE_MEMORY)
        
        self.txt_description = QTextEdit()
        self.txt_description.setMaximumHeight(100)
        
        form_layout.addRow("Source File:", file_layout)
        form_layout.addRow("Evidence Type:", self.cmb_evidence_type)
        form_layout.addRow("Description:", self.txt_description)
        
        layout.addLayout(form_layout)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)
        
        # Connect signals
        self.btn_browse_file.clicked.connect(self.browse_file)
    
    def browse_file(self):
        """Open file selection dialog"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Evidence File", "", "All Files (*)"
        )
        
        if file_path:
            self.txt_source_path.setText(file_path)
    
    def get_source_path(self):
        """Get the selected source file path"""
        return self.txt_source_path.text()
    
    def get_evidence_type(self):
        """Get the selected evidence type"""
        return self.cmb_evidence_type.currentData()
    
    def get_description(self):
        """Get the entered description"""
        return self.txt_description.toPlainText()

class AddBookmarkDialog(QDialog):
    """Dialog for adding a bookmark to evidence"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Bookmark")
        self.setMinimumWidth(400)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        
        # Form layout for inputs
        form_layout = QFormLayout()
        
        self.txt_location = QLineEdit()
        self.txt_description = QTextEdit()
        self.txt_description.setMaximumHeight(100)
        
        form_layout.addRow("Location:", self.txt_location)
        form_layout.addRow("Description:", self.txt_description)
        
        layout.addLayout(form_layout)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)
    
    def get_location(self):
        """Get the entered location"""
        return self.txt_location.text()
    
    def get_description(self):
        """Get the entered description"""
        return self.txt_description.toPlainText()

class EvidenceDetailsDialog(QDialog):
    """Dialog for viewing evidence details"""
    
    def __init__(self, parent=None, evidence_item=None):
        super().__init__(parent)
        self.evidence_item = evidence_item
        self.setWindowTitle("Evidence Details")
        self.setMinimumWidth(500)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        
        if not self.evidence_item:
            layout.addWidget(QLabel("No evidence item selected"))
            return
        
        # Create tabs
        tab_widget = QTabWidget()
        
        # Details tab
        details_widget = QWidget()
        details_layout = QFormLayout(details_widget)
        
        details_layout.addRow("ID:", QLabel(str(self.evidence_item.id)))
        details_layout.addRow("Type:", QLabel(self.evidence_item.evidence_type))
        details_layout.addRow("Filename:", QLabel(self.evidence_item.file_name))
        details_layout.addRow("Path:", QLabel(self.evidence_item.source_path))
        details_layout.addRow("MD5 Hash:", QLabel(self.evidence_item.md5))
        details_layout.addRow("Added Date:", QLabel(self.evidence_item.added_date))
        
        # Description
        description_label = QLabel(self.evidence_item.description)
        description_label.setWordWrap(True)
        details_layout.addRow("Description:", description_label)
        
        tab_widget.addTab(details_widget, "Details")
        
        # Bookmarks tab
        bookmarks_widget = QWidget()
        bookmarks_layout = QVBoxLayout(bookmarks_widget)
        
        if self.evidence_item.bookmarks:
            bookmarks_tree = QTreeWidget()
            bookmarks_tree.setHeaderLabels(["ID", "Location", "Description", "Added Date"])
            
            for bookmark in self.evidence_item.bookmarks:
                bookmark_item = QTreeWidgetItem([
                    str(bookmark.id),
                    bookmark.location,
                    bookmark.description,
                    bookmark.added_date
                ])
                bookmarks_tree.addTopLevelItem(bookmark_item)
            
            bookmarks_layout.addWidget(bookmarks_tree)
        else:
            bookmarks_layout.addWidget(QLabel("No bookmarks for this evidence item"))
        
        tab_widget.addTab(bookmarks_widget, "Bookmarks")
        
        layout.addWidget(tab_widget)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)

class BookmarkDetailsDialog(QDialog):
    """Dialog for viewing bookmark details"""
    
    def __init__(self, parent=None, evidence_item=None, bookmark=None):
        super().__init__(parent)
        self.evidence_item = evidence_item
        self.bookmark = bookmark
        self.setWindowTitle("Bookmark Details")
        self.setMinimumWidth(400)
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout(self)
        
        if not self.evidence_item or not self.bookmark:
            layout.addWidget(QLabel("No bookmark selected"))
            return
        
        # Form layout for details
        form_layout = QFormLayout()
        
        form_layout.addRow("Bookmark ID:", QLabel(str(self.bookmark.id)))
        form_layout.addRow("Evidence ID:", QLabel(str(self.evidence_item.id)))
        form_layout.addRow("Evidence File:", QLabel(self.evidence_item.file_name))
        form_layout.addRow("Location:", QLabel(self.bookmark.location))
        form_layout.addRow("Added Date:", QLabel(self.bookmark.added_date))
        
        # Description
        description_label = QLabel(self.bookmark.description)
        description_label.setWordWrap(True)
        form_layout.addRow("Description:", description_label)
        
        layout.addLayout(form_layout)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)