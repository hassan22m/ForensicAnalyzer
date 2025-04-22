# forensicanalyzer/gui/main_window.py

from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, QWidget, QGroupBox,
            QGridLayout, QPushButton, QHBoxLayout, QLabel, QListWidget, QSplitter,
            QMessageBox, QMenu, QMenuBar, QStatusBar, QToolBar, QFileDialog)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QIcon
import os 
from analyzer.gui.network_view import NetworkAnalyzerGUI
from analyzer.gui.storage_view import StorageAnalyzerGUI
from analyzer.gui.memory_view import LinuxMemoryForensicsApp
from analyzer.core.case_manager import CaseManagerGUI, IntegratedCaseManager, EvidenceItem

class MainWindow(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forensic Analyzer")
        self.setGeometry(100, 100, 1200, 800)

        # Create main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Use horizontal layout for main layout
        self.main_layout = QHBoxLayout(self.central_widget)
        
        # Create a splitter for case manager and tabs
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Create the case manager first
        self.setup_case_manager()
        
        # Create analyzers and connect them to the case manager
        self.create_analyzers()
        
        # Create the tab widget in a vertical layout
        tab_container = QWidget()
        tab_layout = QVBoxLayout(tab_container)
        self.tab_widget = QTabWidget()
        
        # Add the analyzers to tabs
        self.tab_widget.addTab(self.network_analyzer, "Network Analysis")
        self.tab_widget.addTab(self.storage_analyzer, "Storage Analysis")
        self.tab_widget.addTab(self.memory_analyzer, "Memory Analysis")
        
        tab_layout.addWidget(self.tab_widget)
        
        # Add widgets to splitter
        self.splitter.addWidget(self.case_manager_gui)
        self.splitter.addWidget(tab_container)
        
        # Set initial sizes
        self.splitter.setSizes([300, 900])
        
        # Add splitter to main layout
        self.main_layout.addWidget(self.splitter)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        # Set up timer for auto-save
        self.setup_autosave_timer()
        
    def setup_case_manager(self):
        """Create and set up the case manager"""
        # Create the case manager backend
        self.case_manager = IntegratedCaseManager()
        
        # Create the case manager UI
        self.case_manager_gui = CaseManagerGUI()
        self.case_manager_gui.setMinimumWidth(300)
        self.case_manager_gui.setMaximumWidth(400)
        
        # Set the case manager backend in the GUI
        self.case_manager_gui.case_manager = self.case_manager  # Add this line
        
        # Connect case manager signals
        self.case_manager_gui.case_opened.connect(self.on_case_opened)
        self.case_manager_gui.case_closed.connect(self.on_case_closed)
        self.case_manager_gui.evidence_added.connect(self.on_evidence_added)
        self.case_manager_gui.evidence_selected.connect(self.on_evidence_selected)
        self.case_manager_gui.bookmark_added.connect(self.on_bookmark_added)
        
    def create_analyzers(self):
        """Create all analyzer instances and connect them to the case manager"""
        # Create network analyzer
        self.network_analyzer = NetworkAnalyzerGUI()
        self.network_analyzer.set_case_manager(self.case_manager)
        
        self.network_analyzer.set_status_bar(self.statusBar())
       
        # Create storage analyzer
        self.storage_analyzer = StorageAnalyzerGUI()
        self.storage_analyzer.set_case_manager(self.case_manager)
        
        self.storage_analyzer.set_status_bar(self.statusBar())

        # Create memory analyzer
        self.memory_analyzer = LinuxMemoryForensicsApp()
        self.memory_analyzer.set_case_manager(self.case_manager)
        self.memory_analyzer.set_status_bar(self.statusBar())

    def create_menu_bar(self):
        """Create the application menu bar"""
        # Create menu bar
        menu_bar = self.menuBar()
        
        # File menu
        file_menu = menu_bar.addMenu("&File")
        
        # Case management menu items
        case_menu = file_menu.addMenu("&Case")
        
        new_case_action = QAction("&New Case", self)
        new_case_action.triggered.connect(self.on_new_case)
        case_menu.addAction(new_case_action)
        
        open_case_action = QAction("&Open Case", self)
        open_case_action.triggered.connect(self.on_open_case)
        case_menu.addAction(open_case_action)
        
        save_case_action = QAction("&Save Case", self)
        save_case_action.triggered.connect(self.on_save_case)
        case_menu.addAction(save_case_action)
        
        close_case_action = QAction("&Close Case", self)
        close_case_action.triggered.connect(self.on_close_case)
        case_menu.addAction(close_case_action)
        
        # Evidence management menu items
        evidence_menu = file_menu.addMenu("&Evidence")
        
        add_evidence_action = QAction("&Add Evidence", self)
        add_evidence_action.triggered.connect(self.on_add_evidence)
        evidence_menu.addAction(add_evidence_action)
        
        # Report menu items
        file_menu.addSeparator()
        
        generate_report_action = QAction("&Generate Report", self)
        generate_report_action.triggered.connect(self.on_generate_report)
        file_menu.addAction(generate_report_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menu_bar.addMenu("&Edit")
        
        add_bookmark_action = QAction("Add &Bookmark", self)
        add_bookmark_action.triggered.connect(self.on_add_bookmark)
        edit_menu.addAction(add_bookmark_action)
        
        # View menu
        view_menu = menu_bar.addMenu("&View")
        
        show_case_manager_action = QAction("Show Case &Manager", self)
        show_case_manager_action.setCheckable(True)
        show_case_manager_action.setChecked(True)
        show_case_manager_action.triggered.connect(self.toggle_case_manager)
        view_menu.addAction(show_case_manager_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
        
    def setup_autosave_timer(self):
        """Set up a timer for auto-saving the case"""
        from PyQt6.QtCore import QTimer
        
        self.autosave_timer = QTimer(self)
        self.autosave_timer.timeout.connect(self.auto_save_case)
        self.autosave_timer.start(300000)  # Auto-save every 5 minutes (300,000 ms)
        
    def auto_save_case(self):
        """Auto-save the current case if one is open"""
        if self.case_manager.current_case:
            success, message = self.case_manager.save_case()
            if success:
                self.statusBar().showMessage("Case auto-saved", 3000)
        
    # Menu action handlers
    def on_new_case(self):
        """Handle new case action"""
        self.case_manager_gui.on_new_case()
        
    def on_open_case(self):
        """Handle open case action"""
        self.case_manager_gui.on_open_case()
        
    def on_save_case(self):
        """Handle save case action"""
        self.case_manager_gui.on_save_case()
        
    def on_close_case(self):
        """Handle close case action"""
        self.case_manager_gui.on_close_case()
        
    def on_add_evidence(self):
        """Handle add evidence action"""
        self.case_manager_gui.on_add_evidence()
        
    def on_add_bookmark(self):
        """Handle add bookmark action"""
        # Determine which analyzer is active and call its bookmark method
        current_tab_index = self.tab_widget.currentIndex()
        
        if current_tab_index == 0:  # Network analyzer
            self.network_analyzer.add_bookmark_current_packet()
        elif current_tab_index == 1:  # Storage analyzer
            self.storage_analyzer.add_bookmark_current_file()
        elif current_tab_index == 2:  # Memory analyzer
            # Show a menu to choose what to bookmark (process, memory region, or search result)
            bookmark_menu = QMenu(self)
            
            process_action = bookmark_menu.addAction("Bookmark Current Process")
            process_action.triggered.connect(self.memory_analyzer.add_bookmark_process)
            
            memory_action = bookmark_menu.addAction("Bookmark Memory Region")
            memory_action.triggered.connect(self.memory_analyzer.add_bookmark_memory_region)
            
            # Show the menu at the cursor position
            bookmark_menu.exec(self.cursor().pos())
        
    def on_generate_report(self):
        """Handle generate report action"""
        if not self.case_manager.current_case:
            QMessageBox.warning(self, "No Case Open", "Please open a case before generating a report")
            return
            
        # Show a dialog to select the report output path
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", "PDF Files (*.pdf);;All Files (*)"
        )
        
        if output_path:
            success, message = self.case_manager.generate_report(output_path)
            
            if success:
                QMessageBox.information(self, "Report Generated", message)
            else:
                QMessageBox.warning(self, "Error", message)
                
    def toggle_case_manager(self, checked):
        """Show or hide the case manager panel"""
        if checked:
            self.case_manager_gui.show()
            # Restore previous sizes
            sizes = self.splitter.sizes()
            if sizes[0] == 0:
                self.splitter.setSizes([300, sizes[1] - 300])
        else:
            self.case_manager_gui.hide()
            
    def show_about_dialog(self):
        """Show the about dialog"""
        QMessageBox.about(self, "About Forensic Analyzer", 
                       "Forensic Analyzer\n\nVersion 1.0\n\nA comprehensive tool for forensic analysis of network traffic, storage devices, and memory dumps.")
    
    # Case manager event handlers
    def on_case_opened(self, case):
        """Handle case opened event"""
        # Notify each analyzer about the opened case
        self.network_analyzer.on_case_opened(case)
        self.storage_analyzer.on_case_opened(case)
        self.memory_analyzer.on_case_opened(case)
        
        self.statusBar().showMessage(f"Case '{case.name}' opened")
        
        # Enable case-specific actions
        self.update_ui_for_case_state(True)
    
    def on_case_closed(self):
        """Handle case closed event"""
        # Notify each analyzer about the closed case
        self.network_analyzer.on_case_closed()
        self.storage_analyzer.on_case_closed()
        self.memory_analyzer.on_case_closed()
        
        self.statusBar().showMessage("Case closed")
        
        # Disable case-specific actions
        self.update_ui_for_case_state(False)
    
    def on_evidence_added(self, evidence_item):
        """Handle evidence added event"""
        # Check if the case manager has the case
        if not self.case_manager.current_case:
            print("WARNING: Case manager has no current case when handling evidence_added signal")
            return
            
        print(f"MainWindow received evidence_added signal: {evidence_item}")
        
        # Switch to the appropriate tab based on evidence type
        if hasattr(evidence_item, 'evidence_type'):
            evidence_type = evidence_item.evidence_type
        elif isinstance(evidence_item, dict):
            evidence_type = evidence_item.get('type')
        else:
            print(f"Unknown evidence format in MainWindow.on_evidence_added: {type(evidence_item)}")
            return
            
        if evidence_type == EvidenceItem.TYPE_NETWORK:
            self.tab_widget.setCurrentIndex(0)  # Network tab
            self.network_analyzer.on_evidence_added(evidence_item)
        elif evidence_type == EvidenceItem.TYPE_STORAGE:
            self.tab_widget.setCurrentIndex(1)  # Storage tab
            self.storage_analyzer.on_evidence_added(evidence_item)
        elif evidence_type == EvidenceItem.TYPE_MEMORY:
            self.tab_widget.setCurrentIndex(2)  # Memory tab
            self.memory_analyzer.on_evidence_added(evidence_item)
    
    
    def on_evidence_selected(self, evidence_item):
        """Handle evidence selected event"""
        print(f"MainWindow.on_evidence_selected: {evidence_item}")
        
        try:
            # Find the evidence type
            if hasattr(evidence_item, 'evidence_type'):
                evidence_type = evidence_item.evidence_type
            elif isinstance(evidence_item, dict):
                evidence_type = evidence_item.get('type')
            else:
                print(f"Unknown evidence format in MainWindow.on_evidence_selected: {type(evidence_item)}")
                return
                
            # Switch to the appropriate tab based on evidence type
            if evidence_type == EvidenceItem.TYPE_NETWORK:
                self.tab_widget.setCurrentIndex(0)  # Network tab
                self.network_analyzer.on_evidence_selected(evidence_item)
            elif evidence_type == EvidenceItem.TYPE_STORAGE:
                self.tab_widget.setCurrentIndex(1)  # Storage tab
                
                # Make sure the storage analyzer gets the evidence
                self.storage_analyzer.on_evidence_selected(evidence_item)
                
                # Direct access to integrated browser
                if hasattr(self.storage_analyzer, 'integrated_browser') and self.storage_analyzer.integrated_browser:
                    try:
                        # Get the source path
                        source_path = None
                        if hasattr(evidence_item, 'source_path'):
                            source_path = evidence_item.source_path
                        elif isinstance(evidence_item, dict):
                            source_path = evidence_item.get('path')
                        
                        # Get the evidence ID
                        evidence_id = None
                        if hasattr(evidence_item, 'id'):
                            evidence_id = evidence_item.id
                        elif isinstance(evidence_item, dict):
                            evidence_id = evidence_item.get('id')
                        
                        if source_path and evidence_id:
                            # Load the image if it exists
                            if os.path.exists(source_path):
                                # Use the load_disk_image method from storage_analyzer which already has ForensicImage
                                success = self.storage_analyzer.load_disk_image(source_path, evidence_id)
                                
                                # If successful, the storage_analyzer will have updated its integrated_browser
                                if success:
                                    print(f"Successfully loaded image into storage analyzer")
                        
                    except Exception as e:
                        print(f"Error directly setting image in integrated browser: {e}")
                
            elif evidence_type == EvidenceItem.TYPE_MEMORY:
                self.tab_widget.setCurrentIndex(2)  # Memory tab
                self.memory_analyzer.on_evidence_selected(evidence_item)
                
        except Exception as e:
            print(f"Error in MainWindow.on_evidence_selected: {e}")
            import traceback
            traceback.print_exc()
    
    def on_bookmark_added(self, evidence_item, bookmark):
        """Handle bookmark added event"""
        # Pass the bookmark to the appropriate analyzer
        if evidence_item.evidence_type == EvidenceItem.TYPE_NETWORK:
            self.network_analyzer.on_bookmark_added(evidence_item, bookmark)
        elif evidence_item.evidence_type == EvidenceItem.TYPE_STORAGE:
            self.storage_analyzer.on_bookmark_added(evidence_item, bookmark)
        elif evidence_item.evidence_type == EvidenceItem.TYPE_MEMORY:
            self.memory_analyzer.on_bookmark_added(evidence_item, bookmark)
    
    def update_ui_for_case_state(self, case_open):
        """Update UI elements based on whether a case is open"""
        # Update menu and toolbar actions
        for action in self.findChildren(QAction):
            if action.text() in ["&Save Case", "&Close Case", "&Add Evidence", "Save Case", "Close Case", "Add Evidence", "Add &Bookmark", "Add Bookmark", "&Generate Report", "Generate Report"]:
                action.setEnabled(case_open)