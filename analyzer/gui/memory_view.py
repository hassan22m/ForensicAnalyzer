import logging,re,csv,datetime,subprocess,os,json,tempfile
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                           QHBoxLayout, QSplitter, QTextEdit, QRadioButton,QDialogButtonBox,
                           QPushButton, QFileDialog, QLabel, QLineEdit, QComboBox,
                           QProgressBar, QMessageBox, QTableWidget, QTableWidgetItem,
                           QHeaderView, QPlainTextEdit, QDialog, QFormLayout, QStatusBar,
                           QGridLayout, QGroupBox, QCheckBox, QInputDialog,QMenu)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont,QColor

#setup logger 
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('linux_memory_forensics')

from analyzer.core.memory_analyzer import VolatilityRunnerThread,LinuxMemoryParser
from analyzer.core.case_manager import CaseManagerGUI,NewCaseDialog,EvidenceItem
                                              

class LinuxMemoryForensicsApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize with null case manager
        self.case_manager = None
        self.case_manager_gui = None
        self._status_bar = None
        self.current_memory_file = None
        self.current_evidence_id = None
        # Keep track of the current case and evidence
        self.current_case = None
        self.active_evidence = None
        
        # Set up the UI
        self.init_ui()
        
    def init_ui(self):
        # Set window properties
        self.setWindowTitle("Linux Memory Forensics Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        # Create main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        
        # Initialize case manager GUI component
        self.case_manager_gui = CaseManagerGUI(self)
        # Initialize actual case manager from the GUI component
        self.case_manager = self.case_manager_gui.case_manager
        
        # Create tab widget for different functionalities
        self.tab_widget = QTabWidget()
        
        # Add case manager as first tab for easy access
        # self.tab_widget.addTab(self.case_manager_gui, "Case Manager") no need for this one 
        
        # Create Dashboard tab 
        self.create_dashboard_tab()
        
        # Add tabs
        self.memory_capture_widget = MemoryCaptureWidget(self, self.case_manager)
        self.tab_widget.addTab(self.memory_capture_widget, "Memory Capture")
        
        self.memory_analyzer_widget = LinuxMemoryAnalyzerWidget(self, self.case_manager)
        self.tab_widget.addTab(self.memory_analyzer_widget, "Memory Analyzer")
        
        # Add Volatility tab if available
        try:
            self.add_volatility_tab()
        except Exception as e:
            print(f"Could not initialize Volatility tab: {e}")
            
        # Connect the open_memory_dump signal from the capture widget if available
        if hasattr(self.memory_capture_widget, 'open_memory_dump'):
            self.memory_capture_widget.open_memory_dump.connect(self.memory_analyzer_widget.open_memory_dump)
        
        # Connect the case manager signals to the main window
        self.case_manager_gui.case_opened.connect(self.on_case_opened)
        self.case_manager_gui.case_closed.connect(self.on_case_closed)
        self.case_manager_gui.evidence_added.connect(self.on_evidence_added)
        self.case_manager_gui.evidence_selected.connect(self.on_evidence_selected)
        self.case_manager_gui.bookmark_added.connect(self.on_bookmark_added)

        main_layout.addWidget(self.tab_widget)
        
        # Set the main widget
        self.setCentralWidget(main_widget)
        
        # Set Dashboard (index 1) as the default active tab
        self.tab_widget.setCurrentIndex(1)

    def set_case_manager(self, case_manager):
        """Set the case manager reference and update components"""
        self.case_manager = case_manager
        
        # Update any other components that need the case manager
        if hasattr(self, 'memory_capture_widget'):
            self.memory_capture_widget.case_manager = case_manager
        if hasattr(self, 'memory_analyzer_widget'):
            self.memory_analyzer_widget.case_manager = case_manager
        if hasattr(self, 'volatility_widget'):
            self.volatility_widget.case_manager = case_manager
        
        # Check if there's an open case already and handle it
        if case_manager and case_manager.current_case:
            self.on_case_opened(case_manager.current_case)

    def set_status_bar(self, status_bar):
        self._status_bar = status_bar

    def on_case_opened(self, case):
        """Handle case opened event"""
        self.current_case = case
        self.statusBar.showMessage(f"Case '{case.name}' opened")
        
        # Update dashboard info
        self.update_dashboard_info()
        
        # You might want to clear current view or reset state
        # self.clear_memory_view()

    def on_case_closed(self):
        """Handle case closed event"""
        self.current_case = None
        self.statusBar.showMessage("No case open")
        
        # Update dashboard info
        self.update_dashboard_info()
        
        # Clear any loaded memory dump
        if hasattr(self, 'memory_parser') and self.memory_parser:
            self.memory_parser.close()
            self.memory_parser = None
        
        # Clear the current view
        # self.clear_memory_view()

    def on_evidence_added(self, evidence_item):
        """Handle evidence added event for memory evidence"""
        # Only process memory evidence
        if evidence_item.evidence_type != "memory":
            return
        
        # Save current evidence reference
        self.active_evidence = evidence_item
        
        # Load the memory dump
        self.load_memory_dump(evidence_item.source_path)
        
        self.statusBar.showMessage(f"Loaded memory evidence: {evidence_item.file_name}")

    # Define a custom signal for evidence selection
    evidence_selected_signal = pyqtSignal(object)

    def on_evidence_selected(self, evidence_item):
        """Handle evidence selected event"""
        # Save current evidence reference
        self.active_evidence = evidence_item
        
        # Emit our own signal to inform other components
        self.evidence_selected_signal.emit(evidence_item)
        
        # If it's memory evidence, also tell the memory analyzer widget
        if evidence_item.evidence_type == "memory":
            self.memory_analyzer_widget.on_evidence_selected(evidence_item)
            
            # Switch to the memory analyzer tab 
            for i in range(self.tab_widget.count()):
                if self.tab_widget.widget(i) is self.memory_analyzer_widget:
                    self.tab_widget.setCurrentIndex(i)
                    break
                    
        self.statusBar.showMessage(f"Selected evidence: {evidence_item.file_name}")

    def on_bookmark_added(self, evidence_item, bookmark):
        """Handle bookmark added event"""
        # Only process memory evidence
        if evidence_item.evidence_type != "memory":
            return
        
        # Check what type of bookmark this is and navigate accordingly
        data = bookmark.data
        if "process_id" in data:
            # Navigate to process information
            self.navigate_to_process(data["process_id"])
            self.statusBar.showMessage(f"Navigated to bookmarked process: {data['process_id']}")
        elif "memory_address" in data:
            # Navigate to memory address
            self.navigate_to_memory_address(data["memory_address"])
            self.statusBar.showMessage(f"Navigated to bookmarked memory address: {data['memory_address']}")
        elif "string_value" in data:
            # Search for string
            self.search_for_string(data["string_value"])
            self.statusBar.showMessage(f"Searching for bookmarked string: {data['string_value']}")

    def add_bookmark_process(self):
        """Add a bookmark for the currently selected process"""
        # Check if we have an active case and evidence
        if not self.case_manager.current_case or not hasattr(self, 'active_evidence'):
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
        
        # Get the currently selected process
        process = self.get_selected_process()
        if not process:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No process selected")
            return
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"Process: {process.get('name', '')} (PID: {process.get('pid', '')})")
        
        if ok and description:
            # Create a good location description
            location = f"Process: {process.get('name', '')} (PID: {process.get('pid', '')})"
            
            # Create bookmark data with process-specific information
            data = {
                "process_id": process.get('pid', ''),
                "process_name": process.get('name', ''),
                "process_state": process.get('state', ''),
                "process_uid": process.get('uid', '')
            }
            
            # Add the bookmark through the case manager
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data)
            
            if success:
                self.statusBar.showMessage(f"Added bookmark: {description}")
            else:
                QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    def add_bookmark_memory_region(self):
        """Add a bookmark for the currently selected memory region"""
        # Check if we have an active case and evidence
        if not self.case_manager.current_case or not hasattr(self, 'active_evidence'):
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
        
        # Get the currently selected memory region
        memory_region = self.get_selected_memory_region()
        if not memory_region:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No memory region selected")
            return
        
        # Open a dialog to get bookmark description
        address_str = f"0x{memory_region.get('address', 0):08x}"
        size_str = f"0x{memory_region.get('size', 0):x}"
        
        description, ok = QInputDialog.getText(
            self, "Add Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"Memory: {address_str} (Size: {size_str})")
        
        if ok and description:
            # Create a good location description
            location = f"Memory Address: {address_str} (Size: {size_str})"
            
            # Create bookmark data with memory-specific information
            data = {
                "memory_address": memory_region.get('address', 0),
                "memory_size": memory_region.get('size', 0),
                "memory_type": memory_region.get('type', ''),
                "memory_permissions": memory_region.get('permissions', '')
            }
            
            # Add the bookmark through the case manager
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data)
            
            if success:
                self.statusBar.showMessage(f"Added bookmark: {description}")
            else:
                QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    def add_bookmark_search_result(self, search_result):
        """Add a bookmark for a specific search result"""
        # Check if we have an active case and evidence
        if not self.case_manager.current_case or not hasattr(self, 'active_evidence'):
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
        
        if not search_result:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No search result provided")
            return
        
        # Extract search result information
        search_string = search_result.get('match', '')
        offset = search_result.get('offset', 0)
        context = search_result.get('context', '')
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"String: {search_string}")
        
        if ok and description:
            # Create a good location description
            location = f"Memory Offset: 0x{offset:08x} - String: {search_string}"
            
            # Create bookmark data with search result information
            data = {
                "string_value": search_string,
                "offset": offset,
                "context": context
            }
            
            # Add the bookmark through the case manager
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data)
            
            if success:
                self.statusBar.showMessage(f"Added bookmark: {description}")
            else:
                QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    def get_selected_process(self):
        """Get the currently selected process"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Get the selected process from your process list
            selected_items = self.process_list.selectedItems()
            if selected_items:
                # Assuming you store the process data in the item
                return selected_items[0].data(Qt.ItemDataRole.UserRole)
            return None
        except Exception as e:
            print(f"Error getting selected process: {e}")
            return None
    
    def get_selected_memory_region(self):
        """Get the currently selected memory region"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Get the selected memory region from your memory regions list
            selected_items = self.memory_regions_list.selectedItems()
            if selected_items:
                # Assuming you store the memory region data in the item
                return selected_items[0].data(Qt.ItemDataRole.UserRole)
            return None
        except Exception as e:
            print(f"Error getting selected memory region: {e}")
            return None
    
    def navigate_to_process(self, process_id):
        """Navigate to a specific process by ID"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Find and select the process in your process list
            process_id = int(process_id)  # Ensure it's an integer
            
            # Iterate through items in the process list
            for i in range(self.process_list.count()):
                item = self.process_list.item(i)
                process = item.data(Qt.ItemDataRole.UserRole)
                
                if process and process.get('pid') == process_id:
                    # Select this process
                    self.process_list.setCurrentItem(item)
                    
                    # Trigger any process selection handlers
                    self.on_process_selected(item)
                    return True
            
            # Process not found
            print(f"Process {process_id} not found")
            return False
        except Exception as e:
            print(f"Error navigating to process: {e}")
            return False
    
    def navigate_to_memory_address(self, memory_address):
        """Navigate to a specific memory address"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Navigate to the memory address in your memory viewer
            memory_address = int(memory_address)  # Ensure it's an integer
            
            # Find which memory region contains this address
            for i in range(self.memory_regions_list.count()):
                item = self.memory_regions_list.item(i)
                region = item.data(Qt.ItemDataRole.UserRole)
                
                start_address = region.get('address', 0)
                end_address = start_address + region.get('size', 0)
                
                if start_address <= memory_address < end_address:
                    # Select this memory region
                    self.memory_regions_list.setCurrentItem(item)
                    
                    # Set the offset within the region
                    offset = memory_address - start_address
                    self.memory_viewer.go_to_offset(offset)
                    
                    # Trigger any selection handlers
                    self.on_memory_region_selected(item)
                    return True
            
            # Address not found in any region
            print(f"Memory address 0x{memory_address:08x} not found in any region")
            return False
        except Exception as e:
            print(f"Error navigating to memory address: {e}")
            return False
    
    def search_for_string(self, string_value):
        """Search for a string in memory"""
        # This method should be implemented based on your specific UI structure
        # Example:
        try:
            # Search for the string in memory
            self.search_text.setText(string_value)
            
            # Trigger the search action
            self.on_search_button_clicked()
            
            return True
        except Exception as e:
            print(f"Error searching for string: {e}")
            return False
    
    def load_memory_dump(self, file_path):
        """Load a memory dump file"""
        # This should call your existing code to load a memory dump
        # Example:
        try:
            # Reset the UI
            self.reset_ui()
            
            # Initialize memory parser
            self.memory_parser = LinuxMemoryParser(file_path)
            if not self.memory_parser.open():
                QMessageBox.critical(self, "Error", f"Failed to open memory dump file: {file_path}")
                return False
            
            # Extract kernel information
            kernel_info = self.memory_parser.extract_kernel_info()
            self.update_kernel_info(kernel_info)
            
            # Extract processes
            processes = self.memory_parser.extract_detailed_processes()
            self.update_process_list(processes)
            
            # Update UI status
            self.statusBar.showMessage(f"Loaded memory dump: {file_path}")
            
            # Enable analysis features
            self.enable_analysis_features()
            
            return True
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load memory dump: {str(e)}")
            return False
    # Placeholder methods that should be implemented according to your specific UI
    def reset_ui(self):
        """Reset the UI to a clean state"""
        pass
    
    def update_kernel_info(self, kernel_info):
        """Update the kernel information display"""
        pass
    
    def update_process_list(self, processes):
        """Update the process list display"""
        pass
    
    def enable_analysis_features(self):
        """Enable analysis features after loading a memory dump"""
        pass
    
    def on_process_selected(self, item):
        """Handle process selection event"""
        pass
    
    def on_memory_region_selected(self, item):
        """Handle memory region selection event"""
        pass
    
    def on_search_button_clicked(self):
        """Handle search button click event"""
        pass

    def create_dashboard_tab(self):
        """Create a Dashboard tab with all the functionality from the menu bar"""
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        # Welcome section
        welcome_group = QGroupBox("Linux Memory Forensics Tool")
        welcome_layout = QVBoxLayout()
        welcome_text = QLabel("Welcome to the Linux Memory Forensics Tool!")
        welcome_text.setStyleSheet("font-size: 16pt; font-weight: bold;")
        welcome_desc = QLabel("A specialized tool for analyzing Linux memory dumps")
        welcome_desc.setStyleSheet("font-size: 10pt;")
        welcome_layout.addWidget(welcome_text)
        welcome_layout.addWidget(welcome_desc)
        welcome_group.setLayout(welcome_layout)
        layout.addWidget(welcome_group)
        
        # Case management section
        case_group = QGroupBox("Case Management")
        case_layout = QHBoxLayout()
        
        new_case_btn = QPushButton("New Case")
        new_case_btn.clicked.connect(self.create_new_case)
        case_layout.addWidget(new_case_btn)
        
        open_case_btn = QPushButton("Open Case")
        open_case_btn.clicked.connect(self.open_existing_case)
        case_layout.addWidget(open_case_btn)
        
        save_case_btn = QPushButton("Save Case")
        save_case_btn.clicked.connect(self.save_case)
        case_layout.addWidget(save_case_btn)
        
        close_case_btn = QPushButton("Close Case")
        close_case_btn.clicked.connect(self.close_case)
        case_layout.addWidget(close_case_btn)
        
        case_group.setLayout(case_layout)
        layout.addWidget(case_group)
        
        # Tools section
        tools_group = QGroupBox("Memory Analysis Tools")
        tools_layout = QGridLayout()
        
        capture_btn = QPushButton("Capture Memory")
        capture_btn.clicked.connect(lambda: self.tab_widget.setCurrentWidget(self.memory_capture_widget))
        tools_layout.addWidget(capture_btn, 0, 0)
        
        analyze_btn = QPushButton("Analyze Memory")
        analyze_btn.clicked.connect(lambda: self.tab_widget.setCurrentWidget(self.memory_analyzer_widget))
        tools_layout.addWidget(analyze_btn, 0, 1)
        
        # Linux tools section
        lime_btn = QPushButton("Install LiME Module")
        lime_btn.clicked.connect(self.install_lime_module)
        tools_layout.addWidget(lime_btn, 1, 0)
        
        check_source_btn = QPushButton("Check Memory Source")
        check_source_btn.clicked.connect(self.check_memory_source)
        tools_layout.addWidget(check_source_btn, 1, 1)
        
        prepare_btn = QPushButton("Prepare System for Analysis")
        prepare_btn.clicked.connect(self.prepare_system_analysis)
        tools_layout.addWidget(prepare_btn, 2, 0)
        
        # Add Volatility specific buttons if available
        if hasattr(self, 'volatility_widget'):
            vol_btn = QPushButton("Volatility Analysis")
            vol_btn.clicked.connect(lambda: self.tab_widget.setCurrentWidget(self.volatility_widget))
            tools_layout.addWidget(vol_btn, 2, 1)
        
        tools_group.setLayout(tools_layout)
        layout.addWidget(tools_group)
        
        # Help section
        help_group = QGroupBox("Help and Documentation")
        help_layout = QHBoxLayout()
        
        about_btn = QPushButton("About")
        about_btn.clicked.connect(self.show_about_dialog)
        help_layout.addWidget(about_btn)
        
        docs_btn = QPushButton("Documentation")
        docs_btn.clicked.connect(self.show_documentation)
        help_layout.addWidget(docs_btn)
        
        exit_btn = QPushButton("Exit")
        exit_btn.clicked.connect(self.close)
        help_layout.addWidget(exit_btn)
        
        help_group.setLayout(help_layout)
        layout.addWidget(help_group)
        
        # Add current case info section (will be updated when a case is loaded)
        self.case_info_group = QGroupBox("Current Case")
        case_info_layout = QFormLayout()
        
        self.current_case_name = QLabel("No case open")
        case_info_layout.addRow("Case:", self.current_case_name)
        
        self.current_case_path = QLabel("")
        case_info_layout.addRow("Location:", self.current_case_path)
        
        self.current_case_investigator = QLabel("")
        case_info_layout.addRow("Investigator:", self.current_case_investigator)
        
        self.current_evidence_count = QLabel("0")
        case_info_layout.addRow("Evidence Items:", self.current_evidence_count)
        
        self.case_info_group.setLayout(case_info_layout)
        layout.addWidget(self.case_info_group)
        
        # Add stretch to push everything up
        layout.addStretch(1)
        
        self.tab_widget.addTab(dashboard_tab, "Dashboard")

    def update_dashboard_info(self):
        """Update the dashboard with current case information"""
        if self.case_manager and self.case_manager.current_case:
            self.current_case_name.setText(self.case_manager.current_case.name)
            self.current_case_path.setText(self.case_manager.current_case.directory)
            self.current_case_investigator.setText(self.case_manager.current_case.investigator)
            self.current_evidence_count.setText(str(len(self.case_manager.current_case.evidence_items)))
        else:
            self.current_case_name.setText("No case open")
            self.current_case_path.setText("")
            self.current_case_investigator.setText("")
            self.current_evidence_count.setText("0")

    def finalize_create_case(self, dialog, case_name, case_directory):
        """Create the case with the provided information"""
        if not case_name:
            QMessageBox.warning(dialog, "Missing Information", "Please enter a case name.")
            return
            
        if not case_directory:
            QMessageBox.warning(dialog, "Missing Information", "Please select a case directory.")
            return
            
        # Create the case
        success, message = self.case_manager.create_case(case_name, case_directory)
        
        if success:
            QMessageBox.information(dialog, "Success", message)
            self.statusBar.showMessage(f"Case '{case_name}' created at {case_directory}")
            self.update_dashboard_info()  # Update dashboard
            dialog.accept()
        else:
            QMessageBox.critical(dialog, "Error", message)

    def open_existing_case(self):
        """Open an existing case"""
        directory = QFileDialog.getExistingDirectory(self, "Select Case Directory")
        if directory:
            success, message = self.case_manager.open_case(directory)
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.statusBar.showMessage(f"Case '{self.case_manager.case_name}' opened from {directory}")
                self.update_dashboard_info()  # Update dashboard
            else:
                QMessageBox.critical(self, "Error", message)

    def add_volatility_tab(self):
        """Add the Volatility integration tab to the main application with improved case integration"""
        try:
            # Check if volatility is installed
            try:
                result = subprocess.run(['vol', '--help'], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    check=False,
                                    timeout=2)
                volatility_available = result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError):
                # Try alternative command names
                try:
                    result = subprocess.run(['volatility3', '--help'], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        check=False,
                                        timeout=2)
                    volatility_available = result.returncode == 0
                except (subprocess.SubprocessError, FileNotFoundError):
                    volatility_available = False
            
            if not volatility_available:
                print("Volatility command not found")
                # Add a placeholder tab with installation instructions
                placeholder_widget = QWidget()
                placeholder_layout = QVBoxLayout(placeholder_widget)
                placeholder_text = QLabel(
                    "Volatility 3 is not installed or not in your PATH.\n\n"
                    "Please install Volatility 3 to use this feature:\n"
                    "1. Install using pip: pip install volatility3\n"
                    "2. Or download from: https://github.com/volatilityfoundation/volatility3\n\n"
                    "After installation, restart the application."
                )
                placeholder_text.setWordWrap(True)
                placeholder_layout.addWidget(placeholder_text)
                
                install_btn = QPushButton("Installation Instructions")
                install_btn.clicked.connect(self.show_volatility_install_instructions)
                placeholder_layout.addWidget(install_btn)
                
                self.tab_widget.addTab(placeholder_widget, "Volatility (Not Available)")
                return
            
            # Create the Volatility integration widget
            self.volatility_widget = VolatilityIntegrationWidget(self, self.case_manager)
            
            # Add it as a tab
            self.tab_widget.addTab(self.volatility_widget, "Volatility Analysis")
            
            # Connect to evidence_selected_signal from case manager GUI
            if hasattr(self.case_manager_gui, 'evidence_selected'):
                self.case_manager_gui.evidence_selected.connect(self.on_evidence_selected_for_volatility)
                
            # Connect to our own evidence_selected_signal
            if hasattr(self, 'evidence_selected_signal'):
                self.evidence_selected_signal.connect(self.on_evidence_selected_for_volatility)
            
        except Exception as e:
            print(f"Could not initialize Volatility tab: {e}")
            import traceback
            traceback.print_exc()

    def on_evidence_selected_for_volatility(self, evidence_item):
        """Handle evidence selection for Volatility tab"""
        # Only process if Volatility widget exists and evidence is memory type
        if hasattr(self, 'volatility_widget') and evidence_item.evidence_type == "memory":
            # Set the evidence in Volatility widget
            self.volatility_widget.set_evidence(evidence_item)
            
            # Optionally switch to Volatility tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.widget(i) is self.volatility_widget:
                    self.tab_widget.setCurrentIndex(i)
                    break

    def show_volatility_install_instructions(self):
        """Show detailed instructions for installing Volatility"""
        instructions = """
        <h2>Installing Volatility 3</h2>
        
        <h3>Method 1: Install via pip</h3>
        <p>The simplest way to install Volatility 3 is through pip:</p>
        <pre>python3 -m pip install volatility3</pre>
        
        <h3>Method 2: Install from GitHub</h3>
        <ol>
            <li>Clone the repository:
                <pre>git clone https://github.com/volatilityfoundation/volatility3.git</pre>
            </li>
            <li>Install the package:
                <pre>cd volatility3
    python3 setup.py install</pre>
            </li>
        </ol>
        
        <h3>Verify Installation</h3>
        <p>Test that Volatility is working with:</p>
        <pre>vol -h</pre>
        <p>or</p>
        <pre>volatility3 -h</pre>
        
        <h3>Symbol Tables</h3>
        <p>For Linux analysis, you may need to generate or download symbol tables for your specific kernel versions.</p>
        <p>See the Volatility 3 documentation for more details on working with Linux memory dumps.</p>
        
        <h3>After Installation</h3>
        <p>Restart this application after installing Volatility 3.</p>
        """
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Volatility Installation Instructions")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        text_browser = QTextEdit()
        text_browser.setReadOnly(True)
        text_browser.setHtml(instructions)
        
        layout.addWidget(text_browser)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)
        
        dialog.exec()

    def create_menu_bar(self):
        # Create menu bar
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        # New Case action
        new_case_action = file_menu.addAction("New Case")
        new_case_action.triggered.connect(self.create_new_case)
        
        # Open Case action
        open_case_action = file_menu.addAction("Open Case")
        open_case_action.triggered.connect(self.open_existing_case)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        # Capture Memory action
        capture_memory_action = tools_menu.addAction("Capture Memory")
        capture_memory_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.memory_capture_widget))
        
        # Analyze Memory action
        analyze_memory_action = tools_menu.addAction("Analyze Memory")
        analyze_memory_action.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.memory_analyzer_widget))
        
        # Add Volatility submenu if available
        try:
            volatility_menu = QMenu("Volatility", self)
            tools_menu.addMenu(volatility_menu)
            
            if hasattr(self, 'volatility_widget'):
                check_vol_action = volatility_menu.addAction("Check Volatility Installation")
                check_vol_action.triggered.connect(lambda: self.volatility_widget.check_volatility_installation())
                
                show_log_action = volatility_menu.addAction("Show Error Log")
                show_log_action.triggered.connect(lambda: self.volatility_widget.show_error_log())
                
                vol_help_action = volatility_menu.addAction("Volatility Help")
                vol_help_action.triggered.connect(lambda: self.volatility_widget.show_help())
        except:
            pass
            
        # Linux tools submenu
        linux_menu = QMenu("Linux Tools", self)
        tools_menu.addMenu(linux_menu)
        
        # Add Linux-specific tools
        linux_specific_actions = [
            ("Install LiME Module", self.install_lime_module),
            ("Check Memory Source", self.check_memory_source),
            ("Prepare System for Analysis", self.prepare_system_analysis)
        ]
        
        for name, handler in linux_specific_actions:
            action = linux_menu.addAction(name)
            action.triggered.connect(handler)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        # About action
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about_dialog)
        
        # Documentation action
        docs_action = help_menu.addAction("Documentation")
        docs_action.triggered.connect(self.show_documentation)
    
    def save_case(self):
        """Save the current case"""
        if self.case_manager.current_case:
            success, message = self.case_manager.save_case()
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.statusBar.showMessage("Case saved successfully")
            else:
                QMessageBox.critical(self, "Error", message)
        else:
            QMessageBox.warning(self, "No Case Open", "No case is currently open.")

    def close_case(self):
        """Close the current case"""
        if self.case_manager.current_case:
            success, message = self.case_manager.close_case()
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.statusBar.showMessage("Case closed")
                self.update_dashboard_info()  # Update dashboard
            else:
                QMessageBox.critical(self, "Error", message)
        else:
            QMessageBox.warning(self, "No Case Open", "No case is currently open.")

    def create_new_case(self):
        """Create a new case dialog"""
        dialog = NewCaseDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            case_name = dialog.get_case_name()
            case_directory = dialog.get_case_directory()
            investigator = dialog.get_investigator()
            
            success, message = self.case_manager.create_case(case_name, case_directory, investigator)
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.statusBar.showMessage(f"Case '{case_name}' created at {case_directory}")
                self.update_dashboard_info()  # Update dashboard
            else:
                QMessageBox.critical(self, "Error", message)

    def browse_case_directory(self, line_edit):
        """Browse for case directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Case Directory")
        if directory:
            line_edit.setText(directory)
    
    def finalize_create_case(self, dialog, case_name, case_directory):
        """Create the case with the provided information"""
        if not case_name:
            QMessageBox.warning(dialog, "Missing Information", "Please enter a case name.")
            return
            
        if not case_directory:
            QMessageBox.warning(dialog, "Missing Information", "Please select a case directory.")
            return
            
        # Create the case
        success, message = self.case_manager.create_case(case_name, case_directory)
        
        if success:
            QMessageBox.information(dialog, "Success", message)
            self.statusBar.showMessage(f"Case '{case_name}' created at {case_directory}")
            dialog.accept()
        else:
            QMessageBox.critical(dialog, "Error", message)
    
    def open_existing_case(self):
        """Open an existing case"""
        case_file, _ = QFileDialog.getOpenFileName(
            self, "Open Case", "", "Case Files (*.json);;All Files (*)"
        )
        
        if case_file:
            success, message = self.case_manager.open_case(case_file)
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.statusBar.showMessage(f"Case '{self.case_manager.current_case.name}' opened")
                self.update_dashboard_info()  # Update dashboard
            else:
                QMessageBox.critical(self, "Error", message)
    
    def install_lime_module(self):
        """Instructions for installing LiME kernel module"""
        instructions = """
        <h3>Installing Linux Memory Extractor (LiME)</h3>
        
        <p>LiME is a Loadable Kernel Module (LKM) that allows acquisition of volatile memory from Linux systems.</p>
        
        <h4>Prerequisites:</h4>
        <ul>
            <li>Linux system with kernel headers installed</li>
            <li>Git</li>
            <li>Build tools (make, gcc)</li>
        </ul>
        
        <h4>Installation Steps:</h4>
        <ol>
            <li>Clone the LiME repository:
                <pre>git clone https://github.com/504ensicsLabs/LiME.git</pre>
            </li>
            <li>Compile LiME:
                <pre>cd LiME/src
make</pre>
            </li>
            <li>This will create a kernel module (lime-[kernel version].ko)</li>
            <li>Copy the module to /lib/modules/ for system-wide access</li>
        </ol>
        
        <h4>Usage with this tool:</h4>
        <p>Once installed, the Memory Capture tab can use LiME to acquire memory dumps.</p>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("LiME Installation Instructions")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(instructions)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
    
    def check_memory_source(self):
        """Check memory source availability on the system"""
        try:
            # Check /proc/kcore
            kcore_available = os.path.exists("/proc/kcore") and os.access("/proc/kcore", os.R_OK)
            
            # Check /dev/mem
            mem_available = os.path.exists("/dev/mem") and os.access("/dev/mem", os.R_OK)
            
            # Check if LiME is installed
            lime_available = False
            try:
                result = subprocess.run(["modinfo", "lime"], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     check=False)
                lime_available = result.returncode == 0
            except FileNotFoundError:
                lime_available = False
            
            # Format results
            result_text = "<h3>Memory Source Availability:</h3><ul>"
            
            if kcore_available:
                result_text += "<li><b>/proc/kcore</b>: <span style='color:green'>Available</span></li>"
            else:
                result_text += "<li><b>/proc/kcore</b>: <span style='color:red'>Not available</span> (requires root access)</li>"
                
            if mem_available:
                result_text += "<li><b>/dev/mem</b>: <span style='color:green'>Available</span></li>"
            else:
                result_text += "<li><b>/dev/mem</b>: <span style='color:red'>Not available</span> (requires root access)</li>"
                
            if lime_available:
                result_text += "<li><b>LiME Module</b>: <span style='color:green'>Installed</span></li>"
            else:
                result_text += "<li><b>LiME Module</b>: <span style='color:red'>Not installed</span></li>"
                
            result_text += "</ul>"
            
            if not (kcore_available or mem_available or lime_available):
                result_text += """
                <p><b>No memory sources are available.</b></p>
                <p>To capture memory, you need one of the following:</p>
                <ul>
                    <li>Root access to access /proc/kcore or /dev/mem</li>
                    <li>Install LiME kernel module (recommended)</li>
                </ul>
                """
            
            # Show results
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Memory Source Check")
            msg_box.setTextFormat(Qt.TextFormat.RichText)
            msg_box.setText(result_text)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error checking memory sources: {str(e)}")
    
    def prepare_system_analysis(self):
        """Prepare system for memory analysis"""
        instructions = """
        <h3>Preparing a Linux System for Memory Analysis</h3>
        
        <p>Follow these steps to prepare a Linux system for forensic memory analysis:</p>
        
        <h4>1. Install Required Tools</h4>
        <p>For Debian/Ubuntu systems:</p>
        <pre>sudo apt-get update
sudo apt-get install build-essential git dwarfdump linux-headers-$(uname -r)</pre>
        
        <p>For Red Hat/CentOS/Fedora systems:</p>
        <pre>sudo yum install git make gcc kernel-devel dwarfdump</pre>
        
        <h4>2. Install LiME for Memory Acquisition</h4>
        <pre>git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make</pre>
        
        <h4>3. Install Volatility (Optional)</h4>
        <pre>git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -e .</pre>
        
        <h4>4. Configure System for Analysis</h4>
        <ul>
            <li>Ensure system has enough disk space for memory dumps</li>
            <li>Optionally disable swap to prevent sensitive data spillover:
                <pre>sudo swapoff -a</pre>
            </li>
            <li>Consider setting Linux to not overwrite freed memory:
                <pre>echo 1 | sudo tee /proc/sys/vm/compact_memory</pre>
            </li>
        </ul>
        
        <p>After these steps, you can use the Memory Capture tab to acquire memory.</p>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("System Preparation Instructions")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(instructions)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
    
    def show_about_dialog(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Linux Memory Forensics Tool",
                        """<h2>Linux Memory Forensics Tool</h2>
                        <p>Version 1.0</p>
                        <p>A specialized tool for capturing and analyzing Linux memory dumps for forensic investigation.</p>
                        <p>Features:</p>
                        <ul>
                            <li>Memory capture from local and remote Linux systems</li>
                            <li>Specialized Linux memory analysis</li>
                            <li>Process extraction and analysis</li>
                            <li>Network connection information retrieval</li>
                            <li>Command history recovery</li>
                            <li>User account information extraction</li>
                            <li>File path recovery</li>
                            <li>String search capabilities</li>
                            <li>Hex viewer with structure analysis</li>
                        </ul>""")
                        
    def show_documentation(self):
        """Show documentation dialog"""
        documentation = """
        <h2>Linux Memory Forensics Tool Documentation</h2>
        
        <h3>Overview</h3>
        <p>This tool is designed for capturing and analyzing memory dumps from Linux systems for 
        forensic investigation purposes. It provides a GUI interface for various memory forensic 
        techniques specifically tailored to Linux systems.</p>
        
        <h3>Memory Capture Tab</h3>
        <p>Allows capturing memory from local or remote Linux systems using various methods:</p>
        <ul>
            <li><b>DD (Raw)</b>: Uses dd to capture from /proc/kcore or /dev/mem</li>
            <li><b>LiME</b>: Uses the Linux Memory Extractor kernel module (recommended)</li>
            <li><b>SSH</b>: Captures memory from a remote system via SSH</li>
        </ul>
        
        <h3>Memory Analyzer Tab</h3>
        <p>Provides tools for analyzing Linux memory dumps:</p>
        <ul>
            <li><b>Process Analysis</b>: Extract and examine process information</li>
            <li><b>Network Analysis</b>: View network connections</li>
            <li><b>Command History</b>: Recover executed commands</li>
            <li><b>User Information</b>: Extract user account details</li>
            <li><b>File Analysis</b>: Recover file paths from memory</li>
            <li><b>String Search</b>: Search for specific strings in memory</li>
            <li><b>Hex View</b>: View and analyze raw memory contents</li>
        </ul>
        
        <h3>Volatility Integration</h3>
        <p>If Volatility 3 is installed, the tool provides integration for running Volatility plugins.</p>
        
        <h3>Case Management</h3>
        <p>Organize your forensic investigation:</p>
        <ul>
            <li>Create and manage cases</li>
            <li>Add evidence to cases</li>
            <li>Export findings as reports</li>
        </ul>
        
        <h3>System Requirements</h3>
        <ul>
            <li>Linux operating system</li>
            <li>Python 3.6 or later</li>
            <li>PyQt6</li>
            <li>Root/sudo access for memory capture</li>
        </ul>
        """
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Documentation")
        dialog.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(dialog)
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setHtml(documentation)
        layout.addWidget(text_edit)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec()

class MemoryCaptureWidget(QWidget):
    """Widget for memory capture functionality"""
    
    # Signal to notify when a memory dump should be opened in the analyzer
    open_memory_dump = pyqtSignal(str)
    
    def __init__(self, parent=None, case_manager=None):
        super().__init__(parent)
        self.case_manager = case_manager
        self.capture_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create header section with title and description
        header_layout = QVBoxLayout()
        title_label = QLabel("Linux Memory Capture")
        title_label.setStyleSheet("font-size: 16pt; font-weight: bold; margin-bottom: 5px;")
        desc_label = QLabel("Capture memory dumps from local or remote Linux systems")
        desc_label.setStyleSheet("font-size: 10pt; color: #888888; margin-bottom: 10px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(desc_label)
        layout.addLayout(header_layout)
        
        # System selection
        system_group = QGroupBox("System Selection")
        system_layout = QFormLayout()
        
        self.system_type_combo = QComboBox()
        self.system_type_combo.addItems(["Local System", "Remote System (SSH)"])
        system_layout.addRow("System Type:", self.system_type_combo)
        
        # Remote system options
        self.remote_host_edit = QLineEdit()
        self.remote_host_edit.setPlaceholderText("hostname or IP address")
        system_layout.addRow("Remote Host:", self.remote_host_edit)
        
        self.remote_user_edit = QLineEdit()
        self.remote_user_edit.setPlaceholderText("username")
        system_layout.addRow("Remote User:", self.remote_user_edit)
        
        system_group.setLayout(system_layout)
        layout.addWidget(system_group)
        
        # Capture options
        options_group = QGroupBox("Capture Options")
        options_layout = QFormLayout()
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["DD (Raw)", "LiME (Linux Memory Extractor)"])
        options_layout.addRow("Capture Method:", self.method_combo)
        
        self.compression_check = QCheckBox("Compress memory dump")
        options_layout.addRow("", self.compression_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Output selection
        output_group = QGroupBox("Output Options")
        output_layout = QHBoxLayout()
        
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Select output file path")
        output_layout.addWidget(self.output_edit, 1)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_output)
        output_layout.addWidget(self.browse_btn)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Progress indicator
        self.progress_layout = QVBoxLayout()
        self.status_label = QLabel("Ready")
        self.progress_layout.addWidget(self.status_label)
        layout.addLayout(self.progress_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.capture_btn = QPushButton("Start Capture")
        self.capture_btn.clicked.connect(self.start_capture)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_capture)
        self.cancel_btn.setEnabled(False)
        
        button_layout.addWidget(self.capture_btn)
        button_layout.addWidget(self.cancel_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        layout.addStretch()
    
    def browse_output(self):
        """Open file dialog to select output file path"""
        if self.case_manager and self.case_manager.current_case:
            # If we have a case, use the evidence directory
            default_dir = os.path.join(self.case_manager.case_directory, "evidence")
        else:
            default_dir = ""
            
        # Get current date/time for default filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"memory_dump_{timestamp}.raw"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Memory Dump As", 
            os.path.join(default_dir, default_filename),
            "Raw Memory Dumps (*.raw);;All Files (*)"
        )
        
        if file_path:
            self.output_edit.setText(file_path)
    
    def start_capture(self):
        """Start the memory capture process"""
        # Basic implementation - you would expand this with actual capture logic
        self.status_label.setText("Starting capture...")
        output_path = self.output_edit.text()
        if not output_path:
            QMessageBox.warning(self, "Missing Output", "Please specify an output file path.")
            return
        
        # Your capture logic would go here
        # For now, just simulate a capture with a message
        QMessageBox.information(self, "Capture", "Memory capture functionality not implemented in this version.")
        
    def cancel_capture(self):
        """Cancel the memory capture process"""
        self.status_label.setText("Capture cancelled")

class VolatilityIntegrationWidget(QWidget):
    """Widget for Volatility integration, focused on Linux memory dumps"""
    
    def __init__(self, parent=None, case_manager=None):
        super().__init__(parent)
        self.case_manager = case_manager
        self.memory_file = None
        self.current_evidence_id = None  # Track the current evidence ID
        self.vol_path = 'vol'  # Default command name for Volatility 3
        self.runner_thread = None
        self.active_evidence = None  # Reference to the current evidence item
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Memory dump selection
        file_group = QGroupBox("Memory Dump Selection")
        file_layout = QHBoxLayout()
        
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Select Linux memory dump file")
        file_layout.addWidget(self.file_edit, 1)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Plugin selection
        plugin_group = QGroupBox("Volatility Plugin Selection")
        plugin_layout = QVBoxLayout()
        
        self.linux_plugins_combo = QComboBox()
        self.populate_linux_plugins()
        plugin_layout.addWidget(QLabel("Select Linux Plugin:"))
        plugin_layout.addWidget(self.linux_plugins_combo)
        
        # Plugin options (if needed)
        self.options_group = QGroupBox("Plugin Options")
        self.options_layout = QFormLayout(self.options_group)
        self.options_widgets = {}  # Store option widgets
        
        plugin_layout.addWidget(self.options_group)
        self.options_group.setVisible(False)  # Hide initially
        
        # Run button
        self.run_btn = QPushButton("Run Plugin")
        self.run_btn.clicked.connect(self.run_volatility)
        plugin_layout.addWidget(self.run_btn)
        
        plugin_group.setLayout(plugin_layout)
        layout.addWidget(plugin_group)
        
        # Progress indicator
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_label = QLabel("Ready")
        
        progress_layout = QVBoxLayout()
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        layout.addLayout(progress_layout)
        
        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_tabs = QTabWidget()
        
        # Table view for structured results
        self.table_view = QTableWidget()
        self.results_tabs.addTab(self.table_view, "Table View")
        
        # Raw text view for unstructured results
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.results_tabs.addTab(self.text_view, "Raw Output")
        
        results_layout.addWidget(self.results_tabs)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        
        # Export button
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setEnabled(False)
        buttons_layout.addWidget(self.export_btn)
        
        # Add bookmark button (new)
        self.bookmark_btn = QPushButton("Add Bookmark")
        self.bookmark_btn.clicked.connect(self.add_bookmark)
        self.bookmark_btn.setEnabled(False)
        buttons_layout.addWidget(self.bookmark_btn)
        
        results_layout.addLayout(buttons_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group, 1)  # Give it stretch factor

    def populate_linux_plugins(self):
        """Populate the plugin combo box with Linux-specific Volatility plugins"""
        # Common Linux plugins in Volatility 3
        linux_plugins = [
            "banner",                       # extract kernel information 
            "linux.bash.Bash",              # Recover bash command history
            "linux.check_afinfo.Check_afinfo", # Check network protocols
            "linux.check_creds.Check_creds",   # Check credentials
            "linux.check_idt.Check_idt",       # Check interrupt descriptor table
            "linux.check_modules.Check_modules", # Check kernel modules
            "linux.check_syscall.Check_syscall", # Check syscall table
            "linux.elfs.Elfs",              # List ELF binaries
            "linux.lsmod.Lsmod",            # List loaded kernel modules
            "linux.lsof.Lsof",              # List open files
            "linux.malfind.Malfind",        # Find injected code
            "linux.proc.Maps",              # Process memory maps
            "linux.psaux.PsAux",            # Process listing with arguments
            "linux.psscan.PsScan",          # Process scanner
            "linux.tty_check.tty_check"     # Check TTY devices
        ]
        
        self.linux_plugins_combo.clear()
        for plugin in linux_plugins:
            self.linux_plugins_combo.addItem(plugin)
        
        # Connect signal for when plugin selection changes
        self.linux_plugins_combo.currentIndexChanged.connect(self.plugin_changed)
    
    def plugin_changed(self):
        """Handle plugin selection changes"""
        selected_plugin = self.linux_plugins_combo.currentText()
        
        # Clear current options
        for i in reversed(range(self.options_layout.count())): 
            self.options_layout.itemAt(i).widget().setParent(None)
        self.options_widgets = {}
        
        # Add plugin-specific options (as an example for pslist)
        if selected_plugin == "linux.psaux.PsAux" or selected_plugin == "linux.psscan.PsScan":
            # Add PID filter option
            pid_label = QLabel("PID Filter (optional):")
            pid_edit = QLineEdit()
            pid_edit.setPlaceholderText("Enter PID to filter")
            self.options_layout.addRow(pid_label, pid_edit)
            self.options_widgets['pid'] = pid_edit
            
            # Show the options group
            self.options_group.setVisible(True)
        elif selected_plugin == "linux.malfind.Malfind":
            # Add dump option
            dump_check = QCheckBox("Dump suspicious sections")
            self.options_layout.addRow("Options:", dump_check)
            self.options_widgets['dump'] = dump_check
            
            # Show the options group
            self.options_group.setVisible(True)
        else:
            # Hide the options group if no options needed
            self.options_group.setVisible(False)

    def set_evidence(self, evidence_item):
        """Set the current evidence item"""
        if evidence_item and evidence_item.evidence_type == EvidenceItem.TYPE_MEMORY:
            self.active_evidence = evidence_item
            self.current_evidence_id = evidence_item.id
            self.memory_file = evidence_item.source_path
            self.file_edit.setText(evidence_item.source_path)
            
            # Update status
            self.progress_label.setText(f"Memory dump loaded: {evidence_item.file_name}")
            
            # Enable the plugin selection and run button
            self.run_btn.setEnabled(True)
            
            # Return success
            return True
        return False
    
    def browse_file(self):
        """Open file dialog to select memory dump file"""
        if self.case_manager and self.case_manager.current_case:
            # If we have a case, use the evidence directory
            default_dir = os.path.join(self.case_manager.current_case.directory, "evidence")
        else:
            default_dir = ""
            
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Linux Memory Dump", default_dir,
            "Memory Dumps (*.raw *.lime *.mem *.vmem);;All Files (*)"
        )
        
        if file_path:
            self.file_edit.setText(file_path)
            self.memory_file = file_path
            
            # If we have a case manager, ask if the user wants to add this as evidence
            if self.case_manager and self.case_manager.current_case:
                # Check if it's already in evidence
                is_evidence = False
                for item in self.case_manager.current_case.evidence_items:
                    if item.source_path == file_path:
                        # It's already evidence, so set it as active
                        self.set_evidence(item)
                        is_evidence = True
                        break
                
                if not is_evidence:
                    # Ask if they want to add it
                    reply = QMessageBox.question(self, "Add Evidence", 
                                             "Do you want to add this memory dump to the current case?",
                                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    
                    if reply == QMessageBox.StandardButton.Yes:
                        # Get description
                        description, ok = QInputDialog.getText(self, "Evidence Description", 
                                                           "Enter a description for this memory dump:")
                        
                        if ok:
                            # Add it as evidence
                            success, message, evidence_item = self.case_manager.add_evidence(
                                file_path, EvidenceItem.TYPE_MEMORY, description
                            )
                            
                            if success and evidence_item:
                                self.set_evidence(evidence_item)
                                QMessageBox.information(self, "Evidence Added", message)
                            else:
                                QMessageBox.warning(self, "Error", message)

    def run_volatility(self):
        """Run the selected Volatility plugin"""
        if not self.file_edit.text():
            QMessageBox.warning(self, "Missing File", "Please select a memory dump file first.")
            return
        
        self.memory_file = self.file_edit.text()
        if not os.path.exists(self.memory_file):
            QMessageBox.warning(self, "Invalid File", "The selected memory dump file does not exist.")
            return
        
        # Check if we need the VMSS file for VMware memory dumps
        if self.memory_file.lower().endswith('.vmem'):
            base_path = os.path.splitext(self.memory_file)[0]
            vmss_path = base_path + '.vmss'
            vmsn_path = base_path + '.vmsn'
            
            if not os.path.exists(vmss_path) and not os.path.exists(vmsn_path):
                # Fix for PyQt6 vs PyQt5 compatibility
                try:
                    # PyQt5 style
                    yes_button = QMessageBox.Yes
                    no_button = QMessageBox.No
                    default_button = QMessageBox.No
                except AttributeError:
                    # PyQt6 style
                    yes_button = QMessageBox.StandardButton.Yes
                    no_button = QMessageBox.StandardButton.No
                    default_button = QMessageBox.StandardButton.No
                    
                response = QMessageBox.question(
                    self, 
                    "VMware Memory File",
                    "This appears to be a VMware memory file (.vmem). Volatility may require the corresponding .vmss or .vmsn file in the same directory. Continue anyway?",
                    yes_button | no_button,
                    default_button
                )
                
                try:
                    # PyQt5 check
                    if response == QMessageBox.No:
                        return
                except AttributeError:
                    # PyQt6 check
                    if response == QMessageBox.StandardButton.No:
                        return
        
        # Get the selected plugin
        plugin_name = self.linux_plugins_combo.currentText()
        
        # Collect plugin-specific arguments
        args = {}
        for key, widget in self.options_widgets.items():
            if isinstance(widget, QLineEdit) and widget.text():
                args[key] = widget.text()
            elif isinstance(widget, QCheckBox):
                args[key] = widget.isChecked()
        
        # Update UI
        self.progress_bar.setValue(0)
        self.progress_label.setText(f"Running {plugin_name}...")
        self.run_btn.setEnabled(False)
        
        # Clear previous results
        self.table_view.clear()
        self.table_view.setRowCount(0)
        self.table_view.setColumnCount(0)
        self.text_view.clear()
        
        # Create and start the runner thread
        self.runner_thread = VolatilityRunnerThread(self.memory_file, plugin_name, args, self.vol_path)
        self.runner_thread.progress_update.connect(self.update_progress)
        self.runner_thread.operation_complete.connect(self.process_results)
        self.runner_thread.start()

    def update_progress(self, value, message):
        """Update the progress bar and status message"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)

    def process_results(self, success, message, results):
        """Process the results from Volatility with improved table view handling"""
        # Set progress to 100% to indicate completion
        self.progress_bar.setValue(100)
        self.run_btn.setEnabled(True)
        
        if not success:
            self.progress_label.setText(f"Error: {message}")
            QMessageBox.critical(self, "Error", message)
            return
        
        self.progress_label.setText(message)
        self.export_btn.setEnabled(True)
        self.bookmark_btn.setEnabled(True)  # Enable bookmark button on success
        
        # Always update the text view
        raw_text = ""
        if isinstance(results, dict):
            if "data" in results and isinstance(results["data"], dict) and "output" in results["data"]:
                raw_text = results["data"]["output"]
            else:
                raw_text = json.dumps(results, indent=2)
        else:
            raw_text = str(results)
        
        self.text_view.setText(raw_text)
        
        # Get the plugin name for specific handling
        plugin_name = self.linux_plugins_combo.currentText()
        
        # Handle table-based results
        if isinstance(results, dict) and "data" in results and "columns" in results["data"] and "rows" in results["data"]:
            columns = results["data"]["columns"]
            rows = results["data"]["rows"]
            self.display_table_results(columns, rows)
            return
        
        # Try to extract structured data from JSON
        table_data = None
        try:
            # Find the first [ and last ] to extract the potential list
            if isinstance(raw_text, str):
                start_bracket = raw_text.find("[")
                end_bracket = raw_text.rfind("]")
                
                if start_bracket >= 0 and end_bracket > start_bracket:
                    potential_list_str = raw_text[start_bracket:end_bracket+1]
                    # Use ast.literal_eval to safely evaluate the string as a Python literal
                    import ast
                    table_data = ast.literal_eval(potential_list_str)
                    if table_data and isinstance(table_data, list) and isinstance(table_data[0], dict):
                        self.display_table_from_data(table_data)
                        return
        except (SyntaxError, ValueError, AttributeError) as e:
            print(f"Data parsing failed: {str(e)}")
            
        # If parsing as structured data failed, try plugin-specific parsers
        if "linux.psaux" in plugin_name or "linux.psscan" in plugin_name:
            table_data = self._extract_table_from_process_listing(raw_text)
            if table_data:
                self.display_table_from_data(table_data)
                return
        elif "linux.lsmod" in plugin_name:
            table_data = self._extract_table_from_lsmod(raw_text)
            if table_data:
                self.display_table_from_data(table_data)
                return
        
        # If all parsing fails, just show the raw text
        self.results_tabs.setCurrentIndex(1)  # Switch to raw text view

    def add_bookmark(self):
        """Add a bookmark for the current result"""
        if not self.active_evidence or not self.case_manager or not self.case_manager.current_case:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
        
        # Get the current plugin and result information
        plugin_name = self.linux_plugins_combo.currentText()
        
        # Get bookmark description from user
        description, ok = QInputDialog.getText(self, "Add Bookmark", 
                                          "Enter a description for this Volatility result:",
                                          QLineEdit.EchoMode.Normal, 
                                          f"Volatility {plugin_name} result")
        
        if not ok or not description:
            return
            
        # Create bookmark location string
        location = f"Volatility Plugin: {plugin_name}"
        
        # Create data object with additional information
        data = {
            "plugin": plugin_name,
            "memory_file": self.memory_file,
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Try to include some of the actual result data
        current_tab_index = self.results_tabs.currentIndex()
        if current_tab_index == 0:  # Table view
            # Get selected row data
            selected_items = self.table_view.selectedItems()
            selected_data = {}
            
            if selected_items:
                row = selected_items[0].row()
                for col in range(self.table_view.columnCount()):
                    header_item = self.table_view.horizontalHeaderItem(col)
                    if header_item:
                        col_name = header_item.text()
                        item = self.table_view.item(row, col)
                        if item:
                            selected_data[col_name] = item.text()
                
                if selected_data:
                    data["selected_row"] = selected_data
                    location += f" - Selected: {', '.join([f'{k}={v}' for k, v in selected_data.items()[:2]])}"
        else:  # Text view
            # Include a snippet of the text view content
            text_content = self.text_view.toPlainText()
            if text_content:
                # Take the first 100 characters
                snippet = text_content[:100].replace('\n', ' ')
                data["text_snippet"] = snippet
        
        # Add the bookmark through the case manager
        success, message, bookmark = self.case_manager.add_bookmark(
            self.active_evidence.id, description, location, data
        )
        
        if success:
            QMessageBox.information(self, "Bookmark Added", message)
            # Try to emit the bookmark_added signal if parent has it
            parent = self.parent()
            if parent and hasattr(parent, 'bookmark_added'):
                parent.bookmark_added.emit(self.active_evidence, bookmark)
        else:
            QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    def _extract_table_from_lsmod(self, raw_text):
        """Extract table data from lsmod output"""
        lines = raw_text.strip().split('\n')
        
        # Look for the header line
        for i, line in enumerate(lines):
            if ("Address" in line and "Name" in line and "Size" in line) or "Module" in line:
                header_line = line.strip()
                header_index = i
                
                # Extract header columns
                headers = [h.strip() for h in re.split(r'\s{2,}|\t+', header_line) if h.strip()]
                
                # Process data rows
                rows = []
                for j in range(header_index + 1, len(lines)):
                    row_text = lines[j].strip()
                    if not row_text:
                        continue
                    
                    # Split by whitespace
                    parts = re.split(r'\s{2,}|\t+', row_text)
                    if len(parts) >= len(headers) - 1:  # Allow for "Used by" to be empty
                        row_data = {}
                        for k, header in enumerate(headers):
                            if k < len(parts):
                                row_data[header] = parts[k].strip()
                            else:
                                row_data[header] = ""
                        
                        rows.append(row_data)
                
                if rows:
                    return rows
        
        return None

    def _extract_table_from_process_listing(self, raw_text):
        """Extract table data from process listing text"""
        # Try different approaches to parse the text
        lines = raw_text.strip().split('\n')
        
        # Look for a line containing typical process table headers
        for i, line in enumerate(lines):
            # Check for process table headers
            if (("PID" in line and "PPID" in line) or 
                ("OFFSET" in line and "PID" in line and "COMM" in line) or
                ("Command" in line and "PID" in line)):
                
                # Found a potential header line
                header_line = line.strip()
                header_index = i
                
                # Extract column headers
                # Use regex to split by multiple spaces or tabs
                headers = [h.strip() for h in re.split(r'\s{2,}|\t+', header_line) if h.strip()]
                
                # Process rows below the header
                rows = []
                for j in range(header_index + 1, len(lines)):
                    row_text = lines[j].strip()
                    if not row_text:  # Skip empty lines
                        continue
                    
                    # Try different approaches to split the row
                    row_data = {}
                    
                    # Approach 1: Split by whitespace and map to headers
                    parts = re.split(r'\s{2,}|\t+', row_text)
                    if len(parts) >= len(headers):
                        for k, header in enumerate(headers):
                            if k < len(parts):
                                row_data[header] = parts[k].strip()
                            else:
                                row_data[header] = ""
                        
                        rows.append(row_data)
                        continue
                    
                    # Approach 2: Try to match column positions from header line
                    col_positions = []
                    for match in re.finditer(r'\S+\s*', header_line):
                        col_positions.append(match.start())
                    
                    if col_positions and len(row_text) >= col_positions[-1]:
                        for k in range(len(headers)):
                            start = col_positions[k]
                            end = col_positions[k+1] if k+1 < len(col_positions) else len(row_text)
                            
                            if start < len(row_text):
                                value = row_text[start:end].strip()
                                row_data[headers[k]] = value
                        
                        if row_data:
                            rows.append(row_data)
                
                if rows:
                    return rows
        
        return None
    
    def display_table_from_data(self, table_data):
        """Display data in the table view from a list of dictionaries"""
        if not table_data or not isinstance(table_data, list) or not table_data[0]:
            return False
        
        # Get all columns from all items (some rows might have different keys)
        all_columns = set()
        for row in table_data:
            all_columns.update(row.keys())
        
        # Prioritize important columns
        priority_columns = ['Command', 'COMM', 'PID', 'PPID', 'EXIT_STATE', 'OFFSET (P)', 'OFFSET', 'TID']
        columns = []
        
        # Add priority columns first
        for col in priority_columns:
            if col in all_columns:
                columns.append(col)
                all_columns.remove(col)
        
        # Add remaining columns in alphabetical order
        columns.extend(sorted(all_columns))
        
        # Format column names for display
        display_columns = []
        for col in columns:
            display_name = col.replace('_', ' ').replace('(P)', '').strip()
            if col == "COMM":
                display_name = "Command"
            elif col == "PPID":
                display_name = "Parent PID"
            elif col == "OFFSET (P)" or col == "OFFSET":
                display_name = "Offset"
            elif col == "EXIT_STATE":
                display_name = "Exit State"
            elif col == "__children":
                display_name = "Children"
            display_columns.append(display_name)
        
        # Clear and set up the table
        self.table_view.clear()
        self.table_view.setRowCount(len(table_data))
        self.table_view.setColumnCount(len(columns))
        self.table_view.setHorizontalHeaderLabels(display_columns)
        
        # Fill the table with data
        for row_idx, row_data in enumerate(table_data):
            for col_idx, column in enumerate(columns):
                value = row_data.get(column, "")
                
                # Special case for __children - format it better
                if column == "__children" and isinstance(value, list):
                    if not value:
                        value = ""
                    else:
                        value = f"{len(value)} items"
                
                item = QTableWidgetItem(str(value) if value is not None else "")
                self.table_view.setItem(row_idx, col_idx, item)
        
        # Adjust column widths
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        
        # Enable sorting
        self.table_view.setSortingEnabled(True)
        
        # Switch to table view
        self.results_tabs.setCurrentIndex(0)
        return True
    
    def display_table_results(self, columns, rows):
        """Display results in the table view"""
        # Clear previous content
        self.table_view.clear()
        self.table_view.setRowCount(0)
        self.table_view.setColumnCount(0)
        
        # Set new dimensions
        self.table_view.setRowCount(len(rows))
        self.table_view.setColumnCount(len(columns))
        
        # Set column headers
        self.table_view.setHorizontalHeaderLabels(columns)
        
        # Fill the table with data
        for row_idx, row_data in enumerate(rows):
            for col_idx, cell_data in enumerate(row_data):
                if col_idx < len(columns):  # Ensure we don't exceed column count
                    item = QTableWidgetItem(str(cell_data))
                    self.table_view.setItem(row_idx, col_idx, item)
        
        # Adjust column widths
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        
        # Enable sorting
        self.table_view.setSortingEnabled(True)
        
        # Switch to table view
        self.results_tabs.setCurrentIndex(0)
    
    def export_results(self):
        """Export the results to a CSV, JSON, or HTML report"""
        # Get the current results
        current_plugin = self.linux_plugins_combo.currentText()
        file_name = os.path.basename(self.memory_file) if self.memory_file else "volatility_results"
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"{file_name}_{current_plugin.replace('.', '_')}_{timestamp}"
        
        # Create export dialog
        export_dialog = QDialog(self)
        export_dialog.setWindowTitle("Export Results")
        export_dialog.setMinimumSize(500, 300)
        
        dialog_layout = QVBoxLayout(export_dialog)
        
        # Export format selection
        format_group = QGroupBox("Export Format")
        format_layout = QVBoxLayout()
        
        csv_radio = QRadioButton("CSV (Table data only)")
        json_radio = QRadioButton("JSON (Raw data)")
        html_radio = QRadioButton("HTML Report (Recommended)")
        html_radio.setChecked(True)  # Default to HTML
        
        format_layout.addWidget(csv_radio)
        format_layout.addWidget(json_radio)
        format_layout.addWidget(html_radio)
        format_group.setLayout(format_layout)
        dialog_layout.addWidget(format_group)
        
        # Options group
        options_group = QGroupBox("Options")
        options_layout = QFormLayout()
        
        filename_edit = QLineEdit(default_filename)
        filename_label = QLabel("Filename (without extension):")
        options_layout.addRow(filename_label, filename_edit)
        
        # HTML report options (only shown when HTML is selected)
        html_options = QWidget()
        html_layout = QFormLayout(html_options)
        
        include_raw_check = QCheckBox("Include raw output")
        include_raw_check.setChecked(True)
        include_meta_check = QCheckBox("Include metadata")
        include_meta_check.setChecked(True)
        theme_combo = QComboBox()
        theme_combo.addItems(["Light", "Dark", "Blue"])
        
        html_layout.addRow("Include raw output:", include_raw_check)
        html_layout.addRow("Include metadata:", include_meta_check)
        html_layout.addRow("Theme:", theme_combo)
        
        options_layout.addRow(html_options)
        
        # Add option to save to case (if we have a case open)
        save_to_case_check = None
        if self.case_manager and self.case_manager.current_case:
            save_to_case_check = QCheckBox("Save as report in current case")
            save_to_case_check.setChecked(True)
            options_layout.addRow("", save_to_case_check)
        
        options_group.setLayout(options_layout)
        dialog_layout.addWidget(options_group)
        
        # Show/hide HTML options based on radio selection
        def update_options():
            html_options.setVisible(html_radio.isChecked())
            export_dialog.adjustSize()
        
        csv_radio.toggled.connect(update_options)
        json_radio.toggled.connect(update_options)
        html_radio.toggled.connect(update_options)
        update_options()  # Initial state
        
        # Button box
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(export_dialog.accept)
        button_box.rejected.connect(export_dialog.reject)
        dialog_layout.addWidget(button_box)
        
        # Show dialog
        if export_dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        # Get the selected format and options
        export_format = ""
        if csv_radio.isChecked():
            export_format = "csv"
        elif json_radio.isChecked():
            export_format = "json"
        else:
            export_format = "html"
        
        filename = filename_edit.text().strip()
        if not filename:
            filename = default_filename
        
        # Set file filter based on format
        if export_format == "csv":
            file_filter = "CSV Files (*.csv)"
            default_ext = ".csv"
        elif export_format == "json":
            file_filter = "JSON Files (*.json)"
            default_ext = ".json"
        else:
            file_filter = "HTML Files (*.html)"
            default_ext = ".html"
        
        # Handle saving to case or external file
        save_to_case = save_to_case_check and save_to_case_check.isChecked()
        
        file_path = ""
        if save_to_case and self.case_manager and self.case_manager.current_case:
            # Save to case directory (in reports folder)
            reports_dir = os.path.join(self.case_manager.current_case.directory, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            file_path = os.path.join(reports_dir, filename + default_ext)
        else:
            # Get save location from user
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save As", filename + default_ext, 
                f"{file_filter};;All Files (*)"
            )
        
        if not file_path:
            return
        
        try:
            # Export based on format
            if export_format == "csv" and self.table_view.columnCount() > 0:
                self._export_to_csv(file_path)
            elif export_format == "json":
                self._export_to_json(file_path)
            else:  # HTML
                include_raw = include_raw_check.isChecked()
                include_meta = include_meta_check.isChecked()
                theme = theme_combo.currentText().lower()
                self._export_to_html(file_path, include_raw, include_meta, theme)
            
            if save_to_case and self.case_manager and self.case_manager.current_case:
                # Add a note to the case about the export
                current_notes = self.case_manager.current_case.notes
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                new_note = f"\n[{timestamp}] Volatility {current_plugin} analysis report exported to {os.path.basename(file_path)}"
                self.case_manager.update_case_notes(current_notes + new_note)
                
                QMessageBox.information(self, "Export Successful", 
                                    f"Results exported to case reports folder: {os.path.basename(file_path)}")
            else:
                QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")

    def _export_to_csv(self, file_path):
        """Export table data to CSV"""
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            header = []
            for col in range(self.table_view.columnCount()):
                header.append(self.table_view.horizontalHeaderItem(col).text())
            writer.writerow(header)
            
            # Write data
            for row in range(self.table_view.rowCount()):
                row_data = []
                for col in range(self.table_view.columnCount()):
                    item = self.table_view.item(row, col)
                    if item:
                        row_data.append(item.text())
                    else:
                        row_data.append("")
                writer.writerow(row_data)

    def _export_to_json(self, file_path):
        """Export raw data to JSON file"""
        # Get the current results data
        raw_text = self.text_view.toPlainText()
        
        # Try to parse as JSON first
        try:
            data = json.loads(raw_text)
            # It's valid JSON, write it prettified
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            return
        except json.JSONDecodeError:
            # Not valid JSON, continue
            pass
        
        # If it's not JSON, create a simple JSON structure from table data if available
        if self.table_view.columnCount() > 0:
            data = []
            headers = []
            
            for col in range(self.table_view.columnCount()):
                headers.append(self.table_view.horizontalHeaderItem(col).text())
            
            for row in range(self.table_view.rowCount()):
                row_dict = {}
                for col in range(self.table_view.columnCount()):
                    item = self.table_view.item(row, col)
                    if item:
                        row_dict[headers[col]] = item.text()
                    else:
                        row_dict[headers[col]] = ""
                data.append(row_dict)
            
            # Write the JSON data
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            # Fallback to text output wrapped in JSON
            data = {
                "plugin": self.linux_plugins_combo.currentText(),
                "timestamp": datetime.datetime.now().isoformat(),
                "raw_output": raw_text
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

    def _export_to_html(self, file_path, include_raw=True, include_meta=True, theme="light"):
        """Export results to an HTML report that directly converts JSON to table format using ast.literal_eval"""
        import ast  # Import at the top of the function
        
        plugin_name = self.linux_plugins_combo.currentText()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Prepare CSS for different themes (CSS remains the same)
        css_themes = {
            "light": """
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                h1, h2, h3 { color: #444; }
                .metadata { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #007bff; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                th { background-color: #007bff; color: white; text-align: left; padding: 12px; }
                td { padding: 10px; border-bottom: 1px solid #ddd; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                tr:hover { background-color: #e9f5ff; }
                .raw-output { background: #f5f5f5; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace; max-height: 500px; overflow: auto; border: 1px solid #ddd; }
                .footer { margin-top: 30px; text-align: center; font-size: 0.8em; color: #666; }
                .empty-cell { color: #999; font-style: italic; }
            """,
            # Dark and blue themes remain the same
            "dark": """
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #2d2d2d; color: #e0e0e0; }
                .container { max-width: 1200px; margin: 0 auto; background: #1e1e1e; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.3); }
                h1, h2, h3 { color: #cccccc; }
                .metadata { background: #2c2c2c; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #0066cc; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
                th { background-color: #0066cc; color: white; text-align: left; padding: 12px; }
                td { padding: 10px; border-bottom: 1px solid #444; }
                tr:nth-child(even) { background-color: #2a2a2a; }
                tr:hover { background-color: #353535; }
                .raw-output { background: #252525; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace; max-height: 500px; overflow: auto; border: 1px solid #444; color: #e0e0e0; }
                .footer { margin-top: 30px; text-align: center; font-size: 0.8em; color: #888; }
                .empty-cell { color: #777; font-style: italic; }
            """,
            "blue": """
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #e8f0fe; color: #333; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                h1, h2, h3 { color: #0066cc; }
                .metadata { background: #f0f7ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #0066cc; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                th { background-color: #0066cc; color: white; text-align: left; padding: 12px; }
                td { padding: 10px; border-bottom: 1px solid #ddd; }
                tr:nth-child(even) { background-color: #f0f7ff; }
                tr:hover { background-color: #e0f0ff; }
                .raw-output { background: #f5f9ff; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-family: monospace; max-height: 500px; overflow: auto; border: 1px solid #cce0ff; }
                .footer { margin-top: 30px; text-align: center; font-size: 0.8em; color: #666; }
                .empty-cell { color: #999; font-style: italic; }
            """
        }
        
        # Begin building HTML content
        html_content = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Volatility Analysis Results - {plugin_name}</title>
        <style>
            {css_themes.get(theme, css_themes["light"])}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Volatility Analysis Results</h1>
    """
        
        # Add metadata section if requested
        if include_meta:
            memory_file = os.path.basename(self.memory_file) if self.memory_file else "Unknown"
            html_content += f"""
            <div class="metadata">
                <h2>Analysis Metadata</h2>
                <p><strong>Plugin:</strong> {plugin_name}</p>
                <p><strong>Memory Dump:</strong> {memory_file}</p>
                <p><strong>Date/Time:</strong> {timestamp}</p>
                <p><strong>Volatility Path:</strong> {self.vol_path}</p>
            </div>
    """
        
        # Get the raw text from the text view
        raw_text = self.text_view.toPlainText()
        
        # Initialize table_data
        table_data = None
        
        # First try: Use ast.literal_eval to parse Python-style list of dictionaries
        try:
            # Find the first [ and last ] to extract the potential list
            start_bracket = raw_text.find("[")
            end_bracket = raw_text.rfind("]")
            
            if start_bracket >= 0 and end_bracket > start_bracket:
                potential_list_str = raw_text[start_bracket:end_bracket+1]
                # Use ast.literal_eval to safely evaluate the string as a Python literal
                table_data = ast.literal_eval(potential_list_str)
                print(f"Successfully parsed data with ast.literal_eval: {len(table_data)} items")
        except (SyntaxError, ValueError) as e:
            print(f"ast.literal_eval failed: {str(e)}")
            table_data = None
        
        # Second try: If ast.literal_eval failed, try JSON parsing
        if table_data is None:
            try:
                # Try to parse as JSON directly
                json_data = json.loads(raw_text)
                
                # Check if it's a list of dictionaries
                if isinstance(json_data, list) and len(json_data) > 0 and isinstance(json_data[0], dict):
                    table_data = json_data
                # Check if it's a dictionary with a key that contains a list
                elif isinstance(json_data, dict):
                    # Look for any key that has a list value with dictionaries
                    for key, value in json_data.items():
                        if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                            table_data = value
                            break
                    
                    # Check for 'data' key with 'rows' and 'columns'
                    if table_data is None and 'data' in json_data and isinstance(json_data['data'], dict):
                        data = json_data['data']
                        if 'rows' in data and 'columns' in data:
                            # Convert to list of dictionaries
                            table_data = []
                            for row in data['rows']:
                                row_dict = {}
                                for i, col in enumerate(data['columns']):
                                    if i < len(row):
                                        row_dict[col] = row[i]
                                    else:
                                        row_dict[col] = ""
                                table_data.append(row_dict)
            except json.JSONDecodeError:
                print("JSON parsing failed")
                table_data = None
        
        # Third try: Fall back to the table view if available
        if table_data is None and self.table_view.columnCount() > 0:
            table_data = []
            headers = []
            
            for col in range(self.table_view.columnCount()):
                header_item = self.table_view.horizontalHeaderItem(col)
                headers.append(header_item.text() if header_item else f"Column {col}")
            
            for row in range(self.table_view.rowCount()):
                row_data = {}
                for col in range(self.table_view.columnCount()):
                    item = self.table_view.item(row, col)
                    row_data[headers[col]] = item.text() if item else ""
                table_data.append(row_data)
        
        # Generate the table HTML if we have data
        if table_data and len(table_data) > 0:
            # Get all columns from the data
            all_columns = set()
            for row in table_data:
                all_columns.update(row.keys())
            
            # Prioritize important columns
            priority_columns = ['Command', 'COMM', 'PID', 'PPID', 'EXIT_STATE', 'OFFSET (P)', 'TID']
            columns = []
            
            # Add priority columns first
            for col in priority_columns:
                if col in all_columns:
                    columns.append(col)
                    all_columns.remove(col)
            
            # Add remaining columns in alphabetical order
            columns.extend(sorted(all_columns))
            
            # Build the table HTML
            html_content += """
            <h2>Analysis Results</h2>
            <table>
                <thead>
                    <tr>
    """
            
            # Add table headers
            for col in columns:
                # Format the header nicely for display
                display_name = col.replace('_', ' ').replace('(P)', '').strip().title()
                if col == "COMM":
                    display_name = "Command"
                elif col == "PID":
                    display_name = "PID"
                elif col == "PPID":
                    display_name = "Parent PID"
                elif col == "TID":
                    display_name = "TID"
                elif col == "OFFSET (P)":
                    display_name = "Offset"
                elif col == "EXIT_STATE":
                    display_name = "Exit State"
                html_content += f"                    <th>{display_name}</th>\n"
            
            html_content += """                </tr>
                </thead>
                <tbody>
    """
            
            # Add table rows
            for row_data in table_data:
                html_content += "                <tr>\n"
                for col in columns:
                    # Get cell value, handle missing keys
                    cell_value = row_data.get(col, "")
                    
                    # Special case for __children - format it better
                    if col == "__children" and isinstance(cell_value, list):
                        if not cell_value:
                            cell_value = ""
                        else:
                            cell_value = f"{len(cell_value)} items"
                    
                    if cell_value == "" or cell_value is None or (isinstance(cell_value, list) and not cell_value):
                        html_content += f'                    <td class="empty-cell">-</td>\n'
                    else:
                        # Escape HTML special characters
                        cell_value = str(cell_value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        html_content += f"                    <td>{cell_value}</td>\n"
                html_content += "                </tr>\n"
            
            html_content += """            </tbody>
            </table>
    """
        else:
            # No structured data
            html_content += """
            <h2>Analysis Results</h2>
            <p>No structured data available to display in table format.</p>
    """
        
        # Add raw output if requested
        if include_raw and raw_text:
            # Escape HTML special characters
            escaped_raw = raw_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            
            html_content += f"""
            <h2>Raw Output</h2>
            <div class="raw-output">
    {escaped_raw}
            </div>
    """
        
        # Add footer and close tags
        html_content += f"""
            <div class="footer">
                <p>Generated by Volatility Integration Tool on {timestamp}</p>
            </div>
        </div>
    </body>
    </html>
    """
        
        # Write the HTML file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _parse_text_for_table_format(self, text):
        """Parse raw text looking for table-like structures"""
        lines = text.strip().split('\n')
        
        # Look for lines that might be table headers (spaced words with uppercase)
        for i, line in enumerate(lines):
            if i + 5 >= len(lines):  # Need at least a few lines to make a table
                continue
                
            # Check if this might be a header line
            if ("OFFSET" in line and "PID" in line) or ("Command" in line and "PID" in line):
                # This could be a header line
                header_line = line.strip()
                
                # Try to extract column positions and names
                column_info = []
                current_pos = 0
                
                # Regular expression to find word boundaries
                matches = re.finditer(r'\b\w+(?:\s+\w+)*\b', header_line)
                for match in matches:
                    start, end = match.span()
                    col_name = match.group()
                    column_info.append((start, col_name))
                    current_pos = end
                
                if not column_info:
                    continue
                    
                # Add end position for the last column
                column_info.append((len(header_line), None))
                
                # Extract data from subsequent lines
                table_data = []
                for j in range(i + 1, min(i + 30, len(lines))):  # Look at next 30 lines max
                    data_line = lines[j].strip()
                    if not data_line or len(data_line) < column_info[0][0]:
                        continue
                        
                    row_data = {}
                    for k in range(len(column_info) - 1):
                        start = column_info[k][0]
                        col_name = column_info[k][1]
                        end = column_info[k+1][0]
                        
                        # Ensure line is long enough
                        if start < len(data_line):
                            if end <= len(data_line):
                                value = data_line[start:end].strip()
                            else:
                                value = data_line[start:].strip()
                            
                            row_data[col_name] = value
                    
                    if row_data:
                        table_data.append(row_data)
                
                if table_data:
                    return table_data
        
        # Try another approach - splitting by whitespace
        for i, line in enumerate(lines):
            words = line.strip().split()
            if len(words) >= 3 and "PID" in words:
                # This could be a header row
                headers = words
                
                table_data = []
                for j in range(i + 1, min(i + 30, len(lines))):
                    data_line = lines[j].strip()
                    if not data_line:
                        continue
                        
                    # Split into words
                    values = data_line.split()
                    if len(values) >= len(headers):
                        row_data = {}
                        for k in range(len(headers)):
                            row_data[headers[k]] = values[k]
                        
                        table_data.append(row_data)
                
                if table_data:
                    return table_data
        
        return None

    def process_results(self, success, message, results):
        """Process the results from Volatility with improved table view handling"""
        
        # Set progress to 100% to indicate completion
        self.progress_bar.setValue(100)
        self.run_btn.setEnabled(True)
        
        if not success:
            self.progress_label.setText(f"Error: {message}")
            QMessageBox.critical(self, "Error", message)
            return
        
        self.progress_label.setText(message)
        self.export_btn.setEnabled(True)
        
        # Debug print only to console for developer eyes
        print(f"Results type: {type(results)}")
        if isinstance(results, dict):
            print(f"Results keys: {list(results.keys())}")
        
        # Extract the raw text from the results
        raw_text = ""
        if isinstance(results, dict):
            if "data" in results and isinstance(results["data"], dict) and "output" in results["data"]:
                raw_text = results["data"]["output"]
            else:
                raw_text = json.dumps(results, indent=2)
        else:
            raw_text = str(results)
        
        # Always update the text view
        self.text_view.setText(raw_text)
        
        # Get the plugin name for specific handling
        plugin_name = self.linux_plugins_combo.currentText()
        
        # Try to parse the data using ast.literal_eval
        table_data = None
        try:
            # Find the first [ and last ] to extract the potential list
            start_bracket = raw_text.find("[")
            end_bracket = raw_text.rfind("]")
            
            if start_bracket >= 0 and end_bracket > start_bracket:
                potential_list_str = raw_text[start_bracket:end_bracket+1]
                # Use ast.literal_eval to safely evaluate the string as a Python literal
                import ast
                table_data = ast.literal_eval(potential_list_str)
                print(f"Successfully parsed data with ast.literal_eval: {len(table_data)} items")
        except (SyntaxError, ValueError) as e:
            print(f"ast.literal_eval failed: {str(e)}")
            table_data = None
        
        # If ast.literal_eval parsing worked, process the data
        if table_data and isinstance(table_data, list) and len(table_data) > 0 and isinstance(table_data[0], dict):
            # Get all unique columns from the data
            all_columns = set()
            for row in table_data:
                all_columns.update(row.keys())
            
            # Prioritize important columns
            priority_columns = ['Command', 'COMM', 'PID', 'PPID', 'EXIT_STATE', 'OFFSET (P)', 'TID']
            columns = []
            
            # Add priority columns first
            for col in priority_columns:
                if col in all_columns:
                    columns.append(col)
                    all_columns.remove(col)
            
            # Add remaining columns in alphabetical order
            columns.extend(sorted(all_columns))
            
            # Format display names for headers
            display_columns = []
            for col in columns:
                # Format the header nicely for display
                display_name = col.replace('_', ' ').replace('(P)', '').strip()
                if col == "COMM":
                    display_name = "Command"
                elif col == "PID":
                    display_name = "PID"
                elif col == "PPID":
                    display_name = "Parent PID"
                elif col == "TID":
                    display_name = "TID"
                elif col == "OFFSET (P)":
                    display_name = "Offset"
                elif col == "EXIT_STATE":
                    display_name = "Exit State"
                elif col == "__children":
                    display_name = "Children"
                display_columns.append(display_name)
            
            # Set up the table with the columns
            self.table_view.clear()
            self.table_view.setRowCount(len(table_data))
            self.table_view.setColumnCount(len(columns))
            self.table_view.setHorizontalHeaderLabels(display_columns)
            
            # Fill the table with data
            for row_idx, row_data in enumerate(table_data):
                for col_idx, col in enumerate(columns):
                    # Get cell value, handle missing keys
                    cell_value = row_data.get(col, "")
                    
                    # Special case for __children - format it better
                    if col == "__children" and isinstance(cell_value, list):
                        if not cell_value:
                            cell_value = ""
                        else:
                            cell_value = f"{len(cell_value)} items"
                    
                    item = QTableWidgetItem(str(cell_value) if cell_value is not None else "")
                    self.table_view.setItem(row_idx, col_idx, item)
            
            # Adjust column widths
            self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            self.table_view.horizontalHeader().setStretchLastSection(True)
            
            # Enable sorting
            self.table_view.setSortingEnabled(True)
            
            # Switch to table view
            self.results_tabs.setCurrentIndex(0)
            return
        
        # If ast.literal_eval failed, try JSON parsing
        try:
            json_data = json.loads(raw_text)
            
            # If it's a dictionary with a data key that has columns and rows
            if isinstance(json_data, dict) and "data" in json_data and isinstance(json_data["data"], dict):
                data = json_data["data"]
                if "columns" in data and "rows" in data:
                    self.display_table_results(data["columns"], data["rows"])
                    return
            
            # If it's a list of dictionaries
            if isinstance(json_data, list) and len(json_data) > 0 and isinstance(json_data[0], dict):
                # Extract columns from the first item
                columns = list(json_data[0].keys())
                rows = []
                for item in json_data:
                    row = [str(item.get(col, "")) for col in columns]
                    rows.append(row)
                self.display_table_results(columns, rows)
                return
            
            # If it's a dictionary with a key that contains a list of dictionaries
            if isinstance(json_data, dict):
                for key, value in json_data.items():
                    if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                        columns = list(value[0].keys())
                        rows = []
                        for item in value:
                            row = [str(item.get(col, "")) for col in columns]
                            rows.append(row)
                        self.display_table_results(columns, rows)
                        return
        except json.JSONDecodeError:
            # Not valid JSON, continue with other approaches
            pass
        
        # For specific plugins, try parsing format directly from text
        if "linux.psscan" in plugin_name or "linux.psaux" in plugin_name:
            table_data = self._extract_table_from_process_listing(raw_text)
            if table_data:
                self.display_table_from_data(table_data)
                return
        elif "linux.lsmod" in plugin_name:
            table_data = self._extract_table_from_lsmod(raw_text)
            if table_data:
                self.display_table_from_data(table_data)
                return
        
        # Try general table extraction as a last resort
        table_data = self._extract_general_table(raw_text)
        if table_data:
            self.display_table_from_data(table_data)
            return
        
        # If all else fails, just show in text view
        self.results_tabs.setCurrentIndex(1)
   
    def _extract_table_from_text(self, text):
        """Try to extract table data from text by finding header patterns"""
        lines = text.strip().split('\n')
        
        # Look for lines that have multiple words separated by whitespace
        # that could be table headers
        for i, line in enumerate(lines):
            # Skip very short lines
            if len(line.strip()) < 10:
                continue
                
            # Check if line has multiple uppercase words and looks like a header
            words = line.split()
            if len(words) >= 3 and any(word.isupper() for word in words[:3]):
                # This could be a header line
                header_line = line
                columns = []
                
                # Extract column names, trying to be smart about it
                in_column = False
                current_column = ""
                for char in header_line:
                    if char.isalnum() or char in "()_":
                        in_column = True
                        current_column += char
                    elif in_column and char.isspace():
                        if current_column:
                            columns.append(current_column)
                            current_column = ""
                        in_column = False
                
                # Add the last column if there is one
                if current_column:
                    columns.append(current_column)
                
                # If we found reasonable column names, try to extract rows
                if len(columns) >= 2:
                    # Extract rows
                    rows = []
                    for j in range(i + 1, min(i + 100, len(lines))):  # Look at next 100 lines max
                        line = lines[j].strip()
                        if not line:
                            continue
                            
                        # Check if this line matches our column pattern
                        parts = line.split()
                        if len(parts) >= len(columns):
                            row_data = []
                            # Take first N-1 columns as is
                            for k in range(len(columns) - 1):
                                if k < len(parts):
                                    row_data.append(parts[k])
                                else:
                                    row_data.append("")
                            
                            # Last column gets the rest
                            last_col = ' '.join(parts[len(columns) - 1:])
                            row_data.append(last_col)
                            
                            rows.append(row_data)
                    
                    # If we found rows, return the table data
                    if rows:
                        return {"columns": columns, "rows": rows}
        
        # If we couldn't find a pattern, return None
        return None

    def _extract_general_table(self, raw_text):
        """Try to extract a table from general output text or JSON"""
        # Try to find table-like structure in text
        lines = raw_text.strip().split('\n')
        
        # Look for lines with potential headers (uppercase words with spaces between)
        for i, line in enumerate(lines):
            if i + 3 >= len(lines):  # Need at least a few lines of data
                continue
            
            # Check if this line has multiple words with capital letters (potential header)
            words = [w.strip() for w in re.split(r'\s{2,}|\t+', line) if w.strip()]
            if len(words) >= 2 and any(w[0].isupper() for w in words if w):
                headers = words
                
                # Process rows below this potential header
                rows = []
                for j in range(i + 1, min(i + 30, len(lines))):
                    row_text = lines[j].strip()
                    if not row_text:
                        continue
                    
                    # Try to split into columns using the same pattern
                    parts = [p.strip() for p in re.split(r'\s{2,}|\t+', row_text) if p.strip()]
                    if len(parts) >= len(headers) - 1:  # Allow one column to be missing
                        row_data = {}
                        for k, header in enumerate(headers):
                            if k < len(parts):
                                row_data[header] = parts[k]
                            else:
                                row_data[header] = ""
                        
                        rows.append(row_data)
                
                # If we found several rows, this is probably a table
                if len(rows) >= 2:
                    return rows
        
        return None

    def parse_volatility_raw_output(self, raw_text, plugin_name):
        """Parse raw output from volatility commands into tabular data"""
        # Process linux.psaux.PsAux and linux.psscan.PsScan output
        if "linux.psaux" in plugin_name or "linux.psscan" in plugin_name:
            try:
                # Extract data from the raw text
                lines = raw_text.strip().split('\n')
                
                # Look for a line containing process headers
                header_idx = -1
                for idx, line in enumerate(lines):
                    if ("PID" in line and "PPID" in line) or ("OFFSET" in line and "PID" in line and "COMM" in line):
                        header_idx = idx
                        break
                
                if header_idx >= 0:
                    header_line = lines[header_idx]
                    
                    # Try to determine column positions
                    # For linux.psscan.PsScan, output looks like:
                    # OFFSET (P)     PID     PPID    COMM
                    # For linux.psaux.PsAux, output looks like:
                    # PID     PPID    COMM    ARGS
                    
                    column_positions = []
                    column_names = []
                    
                    # Find position of each header column
                    for match in re.finditer(r'\S+\s*', header_line):
                        start, end = match.span()
                        name = match.group().strip()
                        column_positions.append((start, end))
                        column_names.append(name)
                    
                    # Extract row data based on column positions
                    rows = []
                    for i in range(header_idx + 1, len(lines)):
                        if lines[i].strip():
                            row = {}
                            line = lines[i]
                            
                            # Handle special case where the line might be too short
                            if len(line) < column_positions[-1][0]:
                                continue
                                
                            for idx, (start, end) in enumerate(column_positions):
                                col_name = column_names[idx]
                                
                                # For the last column, take the rest of the line
                                if idx == len(column_positions) - 1:
                                    value = line[start:].strip()
                                else:
                                    # For other columns, take up to the next column start
                                    value = line[start:column_positions[idx+1][0]].strip()
                                    
                                row[col_name] = value
                                
                            rows.append(row)
                    
                    # Only return if we have rows
                    if rows:
                        return rows
                
                # Try another approach if the above fails
                # Look for a line with a consistent pattern
                for idx, line in enumerate(lines):
                    if re.search(r'\d+\s+\d+\s+\S+', line):
                        # This line may have PID PPID COMM pattern
                        
                        # Estimate column positions
                        tokens = re.findall(r'\S+\s*', line)
                        if len(tokens) >= 3:
                            # Assume first 3 tokens are PID, PPID, COMM
                            rows = []
                            
                            for i in range(idx, len(lines)):
                                line_tokens = re.findall(r'\S+\s*', lines[i])
                                if len(line_tokens) >= 3:
                                    row = {
                                        "PID": line_tokens[0].strip(),
                                        "PPID": line_tokens[1].strip(),
                                        "COMM": line_tokens[2].strip()
                                    }
                                    rows.append(row)
                            
                            if rows:
                                return rows
                
                return None
                    
            except Exception as e:
                print(f"Error parsing process list output: {str(e)}")
                return None
        
        # Process linux.lsmod.Lsmod output
        elif "linux.lsmod" in plugin_name:
            try:
                lines = raw_text.strip().split('\n')
                
                # Look for the header line
                header_idx = -1
                for idx, line in enumerate(lines):
                    if "Address" in line and "Name" in line and "Size" in line:
                        header_idx = idx
                        break
                
                if header_idx >= 0:
                    header_line = lines[header_idx]
                    
                    # Find column positions
                    column_positions = []
                    column_names = []
                    
                    for match in re.finditer(r'\S+\s*', header_line):
                        start, end = match.span()
                        name = match.group().strip()
                        column_positions.append((start, end))
                        column_names.append(name)
                    
                    # Extract data rows
                    rows = []
                    for i in range(header_idx + 1, len(lines)):
                        if lines[i].strip():
                            row = {}
                            line = lines[i]
                            
                            # Skip if line is too short
                            if len(line) < column_positions[-1][0]:
                                continue
                                
                            for idx, (start, end) in enumerate(column_positions):
                                col_name = column_names[idx]
                                
                                # For the last column, take the rest of the line
                                if idx == len(column_positions) - 1:
                                    value = line[start:].strip()
                                else:
                                    # For other columns, take up to the next column start
                                    value = line[start:column_positions[idx+1][0]].strip()
                                    
                                row[col_name] = value
                                
                            rows.append(row)
                    
                    if rows:
                        return rows
                
                return None
                    
            except Exception as e:
                print(f"Error parsing lsmod output: {str(e)}")
                return None
        
        # For other plugins, try a more generic approach
        else:
            try:
                # First try to parse as JSON
                try:
                    data = json.loads(raw_text)
                    
                    # If it's a list of dictionaries, return directly
                    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                        return data
                    
                    # If it's a dictionary with a list inside, extract that
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                                return value
                except json.JSONDecodeError:
                    pass  # Not valid JSON, continue with text parsing
                
                # Try to find a table structure in the text
                lines = raw_text.strip().split('\n')
                
                # Look for a header line with multiple columns
                for idx, line in enumerate(lines[:10]):  # Check first 10 lines for header
                    # Check if line has multiple words separated by whitespace
                    tokens = re.findall(r'\S+\s*', line)
                    if len(tokens) >= 3:  # At least 3 columns
                        # Try to use this as a header
                        column_names = [token.strip() for token in tokens]
                        
                        # Check if the following lines follow a similar pattern
                        rows = []
                        for i in range(idx + 1, min(idx + 11, len(lines))):  # Check next 10 lines
                            if lines[i].strip():
                                line_tokens = re.findall(r'\S+\s*', lines[i])
                                if len(line_tokens) >= len(column_names):
                                    row = {column_names[j]: line_tokens[j].strip() 
                                        for j in range(len(column_names))}
                                    rows.append(row)
                        
                        if len(rows) >= 2:  # Need at least 2 rows to confirm it's a table
                            # Extract all rows using this pattern
                            all_rows = []
                            for i in range(idx + 1, len(lines)):
                                if lines[i].strip():
                                    line_tokens = re.findall(r'\S+\s*', lines[i])
                                    if len(line_tokens) >= len(column_names):
                                        row = {column_names[j]: line_tokens[j].strip() 
                                            for j in range(len(column_names))}
                                        all_rows.append(row)
                            
                            return all_rows
                
                return None
                    
            except Exception as e:
                print(f"Error parsing generic output: {str(e)}")
                return None

    def _update_text_view_from_table(self):
        """Update the text view with a formatted version of the table data"""
        columns = []
        for col_idx in range(self.table_view.columnCount()):
            header_item = self.table_view.horizontalHeaderItem(col_idx)
            if header_item:
                columns.append(header_item.text())
            else:
                columns.append(f"Column {col_idx}")
        
        # Determine the maximum width for each column for proper alignment
        col_widths = [len(col) for col in columns]
        
        for row_idx in range(self.table_view.rowCount()):
            for col_idx in range(self.table_view.columnCount()):
                item = self.table_view.item(row_idx, col_idx)
                if item:
                    col_widths[col_idx] = max(col_widths[col_idx], len(item.text()))
        
        # Format header
        header = " | ".join(f"{col:{col_widths[idx]}}" for idx, col in enumerate(columns))
        separator = "-" * (sum(col_widths) + 3 * (len(columns) - 1))
        
        rows = [header, separator]
        
        # Format rows
        for row_idx in range(self.table_view.rowCount()):
            row_data = []
            for col_idx in range(self.table_view.columnCount()):
                item = self.table_view.item(row_idx, col_idx)
                if item:
                    row_data.append(f"{item.text():{col_widths[col_idx]}}")
                else:
                    row_data.append(" " * col_widths[col_idx])
            rows.append(" | ".join(row_data))
        
        # Update text view
        self.text_view.setText("\n".join(rows))
    
    def _extract_table_from_json_output(self, output_text):
        """Extract table data from JSON output text for linux.psscan or similar plugins"""
        try:
            # Try to parse the output as JSON
            parsed_data = json.loads(output_text)
            
            # Check different formats of Volatility JSON output
            
            # Format 1: Data directly as a list of dicts
            if isinstance(parsed_data, list) and parsed_data and isinstance(parsed_data[0], dict):
                columns = list(parsed_data[0].keys())
                rows = []
                for item in parsed_data:
                    row = [str(item.get(col, "")) for col in columns]
                    rows.append(row)
                return columns, rows
            
            # Format 2: Data in 'data' field
            if isinstance(parsed_data, dict) and 'data' in parsed_data:
                data = parsed_data['data']
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    columns = list(data[0].keys())
                    rows = []
                    for item in data:
                        row = [str(item.get(col, "")) for col in columns]
                        rows.append(row)
                    return columns, rows
            
            # Format 3: Volatility 3 format with plugin-specific structure
            if isinstance(parsed_data, dict) and any(key.startswith('volatility3') for key in parsed_data.keys()):
                # Find the plugin result key
                for key in parsed_data.keys():
                    if key.startswith('volatility3'):
                        plugin_data = parsed_data[key]
                        if isinstance(plugin_data, list) and plugin_data and isinstance(plugin_data[0], dict):
                            columns = list(plugin_data[0].keys())
                            rows = []
                            for item in plugin_data:
                                row = [str(item.get(col, "")) for col in columns]
                                rows.append(row)
                            return columns, rows
            
            # Handle psscan data in PsActiveProcessHead format
            if isinstance(parsed_data, dict) and 'PsActiveProcessHead' in parsed_data:
                processes = parsed_data['PsActiveProcessHead']
                if processes:
                    # Find first non-empty item to get keys
                    first_proc = None
                    for proc in processes:
                        if proc:
                            first_proc = proc
                            break
                    
                    if first_proc:
                        columns = list(first_proc.keys())
                        rows = []
                        for proc in processes:
                            if proc:  # Skip any None/empty items
                                row = [str(proc.get(col, "")) for col in columns]
                                rows.append(row)
                        return columns, rows
            
            return None, None
        except json.JSONDecodeError:
            return None, None
        except Exception as e:
            logger.error(f"Error parsing JSON output: {str(e)}")
            return None, None

    def display_text_results(self, text):
        """Display results as text in a formatted, readable way"""
        # Set monospaced font for better formatting
        font = QFont("Courier New", 10)
        self.text_view.setFont(font)
        
        # First check if this is a process listing output (linux.psscan.PsScan output)
        if "OFFSET (P)" in text and "PID" in text and "COMM" in text:
            # This looks like process listing output
            try:
                # Format into a readable table
                lines = text.split('\n')
                formatted_lines = []
                
                # Find the header line
                header_index = -1
                for i, line in enumerate(lines):
                    if "OFFSET (P)" in line and "PID" in line:
                        header_index = i
                        break
                
                if header_index >= 0:
                    # Add a separator before the header
                    formatted_lines.append("-" * 100)
                    formatted_lines.append(lines[header_index])
                    formatted_lines.append("-" * 100)
                    
                    # Add the data rows with some formatting
                    for i in range(header_index + 1, len(lines)):
                        if lines[i].strip():
                            formatted_lines.append(lines[i])
                    
                    self.text_view.setText('\n'.join(formatted_lines))
                    self.results_tabs.setCurrentIndex(1)  # Switch to raw output
                    return
            except:
                # If parsing fails, continue to other formats
                pass
        
        # Check if we're dealing with JSON data that's been converted to a string
        if text.strip().startswith('[') and text.strip().endswith(']'):
            try:
                # Try to parse as JSON to format it better
                data = json.loads(text)
                formatted_text = ""
                
                # Format banner output similar to command line
                if isinstance(data, list) and all(isinstance(item, dict) and 'Banner' in item for item in data):
                    formatted_text = "Offset       Banner\n" + "-" * 80 + "\n"
                    for item in data:
                        offset = item.get('Offset', 'Unknown')
                        banner = item.get('Banner', '')
                        formatted_text += f"{offset}    {banner}\n"
                
                # Format bash history output similar to command line
                elif isinstance(data, list) and all(isinstance(item, dict) and 'Command' in item for item in data):
                    formatted_text = "PID      Process CommandTime                Command\n" + "-" * 80 + "\n"
                    for item in data:
                        pid = item.get('PID', 'N/A')
                        process = item.get('Process', 'N/A')
                        cmd_time = item.get('CommandTime', 'N/A')
                        command = item.get('Command', 'N/A')
                        formatted_text += f"{pid:<8} {process:<7} {cmd_time} {command}\n"
                
                # Other plugin-specific formatting can be added here
                
                else:
                    # For other types of data, try to present it in a more structured way
                    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                        # Try to identify common fields and format them as columns
                        fields = set()
                        for item in data:
                            fields.update(item.keys())
                        
                        fields = sorted(list(fields))
                        if len(fields) < 5:  # Only do this for reasonably sized data
                            formatted_text = " | ".join(f"{field}" for field in fields) + "\n"
                            formatted_text += "-" * 80 + "\n"
                            
                            for item in data:
                                row = " | ".join(f"{str(item.get(field, ''))}" for field in fields)
                                formatted_text += row + "\n"
                        else:
                            # Too many fields, use pretty JSON instead
                            formatted_text = json.dumps(data, indent=2)
                    else:
                        # Just use pretty JSON
                        formatted_text = json.dumps(data, indent=2)
                        
                self.text_view.setText(formatted_text)
            except json.JSONDecodeError:
                # If parsing fails, try the next approach
                pass
        
        # Check if it's another JSON format
        elif text.strip().startswith('{') and text.strip().endswith('}'):
            try:
                json_data = json.loads(text)
                formatted_json = json.dumps(json_data, indent=2)
                self.text_view.setText(formatted_json)
                return
            except json.JSONDecodeError:
                # Not JSON, continue to text formatting
                pass
        
        # For non-JSON text, try to format command output
        lines = text.split('\n')
        formatted_lines = []
        
        # Process the output to make it more readable
        in_data_section = False
        
        for line in lines:
            # Add some spacing and formatting
            if "Volatility 3 Framework" in line:
                formatted_lines.append("\n" + line)
            elif line.startswith('Progress:'):
                formatted_lines.append("\n" + line)
            elif line.startswith('WARNING') or line.startswith('ERROR'):
                formatted_lines.append("\n" + line + "\n")
            elif line.strip() == "PID      Process CommandTime                Command":
                in_data_section = True
                formatted_lines.append("\n" + "-" * 80)
                formatted_lines.append(line)
                formatted_lines.append("-" * 80)
            elif line.strip() == "Offset    Banner":
                in_data_section = True
                formatted_lines.append("\n" + "-" * 80)
                formatted_lines.append(line)
                formatted_lines.append("-" * 80)
            elif line.strip() and ":" in line and not line.startswith(' ') and not in_data_section:
                # Add a newline before section headers
                formatted_lines.append("\n" + line)
            else:
                formatted_lines.append(line)
                    
        self.text_view.setText('\n'.join(formatted_lines))
        
        # Switch to text view
        self.results_tabs.setCurrentIndex(1)
    
    def check_volatility_installation(self):
        """Check if Volatility is installed and configured"""
        try:
            # Try different possible command names
            commands = ["vol", "vol.py", "volatility3"]
            
            for cmd in commands:
                try:
                    result = subprocess.run([cmd, "--help"], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        check=False,
                                        timeout=2)
                    if result.returncode == 0:
                        self.vol_path = cmd
                        version_info = result.stdout.decode('utf-8', errors='replace')
                        QMessageBox.information(self, "Volatility Available", 
                                              f"Found Volatility using command '{cmd}'.\n\n{version_info[:200]}...")
                        return True
                except (subprocess.SubprocessError, FileNotFoundError):
                    continue
            
            QMessageBox.warning(self, "Volatility Not Found", 
                              "Volatility was not found on your system. Please install Volatility 3 and make sure it's in your PATH.")
            return False
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error checking Volatility installation: {str(e)}")
            return False
    
    def show_error_log(self):
        """Show error log dialog"""
        log_file = os.path.join(tempfile.gettempdir(), "volatility_errors.log")
        
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                
                dialog = QDialog(self)
                dialog.setWindowTitle("Volatility Error Log")
                dialog.setMinimumSize(700, 500)
                
                layout = QVBoxLayout(dialog)
                
                log_view = QTextEdit()
                log_view.setReadOnly(True)
                log_view.setPlainText(log_content)
                layout.addWidget(log_view)
                
                close_btn = QPushButton("Close")
                close_btn.clicked.connect(dialog.accept)
                layout.addWidget(close_btn)
                
                dialog.exec()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error reading log file: {str(e)}")
        else:
            QMessageBox.information(self, "No Log", "No error log file found.")
    
    def show_help(self):
        """Show help information for Volatility"""
        help_text = """
        <h2>Volatility Integration Help</h2>
        
        <h3>Overview</h3>
        <p>This tab allows you to run Volatility 3 plugins on Linux memory dumps to extract various forensic artifacts.</p>
        
        <h3>Getting Started</h3>
        <ol>
            <li>Select a Linux memory dump file using the browse button</li>
            <li>Choose a Volatility plugin from the dropdown list</li>
            <li>Configure any plugin-specific options if needed</li>
            <li>Click "Run Plugin" to start the analysis</li>
        </ol>
        
        <h3>Linux-Specific Plugins</h3>
        <ul>
            <li><b>linux.bash.Bash</b> - Recover bash command history</li>
            <li><b>linux.psaux.PsAux</b> - List processes with arguments</li>
            <li><b>linux.psscan.PsScan</b> - Scan for processes that might be hidden</li>
            <li><b>linux.lsof.Lsof</b> - List open files</li>
            <li><b>linux.lsmod.Lsmod</b> - List loaded kernel modules</li>
            <li><b>linux.malfind.Malfind</b> - Find potentially malicious code injections</li>
        </ul>
        
        <h3>Troubleshooting</h3>
        <p>If you encounter issues:</p>
        <ul>
            <li>Make sure Volatility 3 is installed and accessible from your PATH</li>
            <li>Verify that the memory dump is from a supported Linux kernel version</li>
            <li>Check that you have proper symbols for the Linux kernel in question</li>
            <li>Review the error log for detailed error messages</li>
        </ul>
        """
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Volatility Help")
        dialog.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(dialog)
        
        help_view = QTextEdit()
        help_view.setReadOnly(True)
        help_view.setHtml(help_text)
        layout.addWidget(help_view)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec()

class LinuxMemoryAnalyzerWidget(QWidget):
    """Widget for memory analysis functionality specifically for Linux memory dumps"""
    
    def __init__(self, parent=None, case_manager=None):
        super().__init__(parent)
        self.case_manager = case_manager
        self.memory_parser = None
        self.current_memory_file = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create header section with title and description
        header_layout = QVBoxLayout()
        title_label = QLabel("Linux Memory Analyzer")
        title_label.setStyleSheet("font-size: 16pt; font-weight: bold; margin-bottom: 5px;")
        desc_label = QLabel("Analyze Linux memory dumps for forensic investigation")
        desc_label.setStyleSheet("font-size: 10pt; color: #888888; margin-bottom: 10px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(desc_label)
        layout.addLayout(header_layout)
        
        # Memory dump selection
        file_group = QGroupBox("Memory Dump Selection")
        file_layout = QHBoxLayout()
        
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Select Linux memory dump file")
        file_layout.addWidget(self.file_edit, 1)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        
        self.open_btn = QPushButton("Open")
        self.open_btn.clicked.connect(self.open_memory_dump)
        file_layout.addWidget(self.open_btn)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Main analysis area with tabs
        self.analysis_tabs = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout()
        
        # Memory dump information
        info_group = QGroupBox("Memory Dump Information")
        info_layout = QFormLayout()
        
        self.file_path_label = QLabel("-")
        info_layout.addRow("File Path:", self.file_path_label)
        
        self.file_size_label = QLabel("-")
        info_layout.addRow("Size:", self.file_size_label)
        
        self.format_label = QLabel("-")
        info_layout.addRow("Format:", self.format_label)
        
        self.kernel_version_label = QLabel("-")
        info_layout.addRow("Kernel Version:", self.kernel_version_label)
        
        info_group.setLayout(info_layout)
        overview_layout.addWidget(info_group)
        
        # Quick analysis buttons
        analysis_group = QGroupBox("Quick Analysis")
        analysis_buttons = QGridLayout()
        
        self.processes_btn = QPushButton("Extract Processes")
        self.processes_btn.clicked.connect(self.extract_processes)
        self.processes_btn.setEnabled(False)
        analysis_buttons.addWidget(self.processes_btn, 0, 0)
        
        self.network_btn = QPushButton("Network Connections")
        self.network_btn.clicked.connect(self.extract_network_connections)
        self.network_btn.setEnabled(False)
        analysis_buttons.addWidget(self.network_btn, 0, 1)
        
        self.commands_btn = QPushButton("Command History")
        self.commands_btn.clicked.connect(self.extract_commands)
        self.commands_btn.setEnabled(False)
        analysis_buttons.addWidget(self.commands_btn, 1, 0)
        
        self.users_btn = QPushButton("User Information")
        self.users_btn.clicked.connect(self.extract_users)
        self.users_btn.setEnabled(False)
        analysis_buttons.addWidget(self.users_btn, 1, 1)
        
        self.files_btn = QPushButton("File Paths")
        self.files_btn.clicked.connect(self.extract_file_listing)
        self.files_btn.setEnabled(False)
        analysis_buttons.addWidget(self.files_btn, 2, 0)
        
        self.strings_btn = QPushButton("String Search")
        self.strings_btn.clicked.connect(self.show_string_search)
        self.strings_btn.setEnabled(False)
        analysis_buttons.addWidget(self.strings_btn, 2, 1)
        
        analysis_group.setLayout(analysis_buttons)
        overview_layout.addWidget(analysis_group)
        
        # Kernel info section
        self.kernel_info_group = QGroupBox("Kernel Information")
        kernel_layout = QVBoxLayout()
        
        self.kernel_info_text = QTextEdit()
        self.kernel_info_text.setReadOnly(True)
        kernel_layout.addWidget(self.kernel_info_text)
        
        self.kernel_info_group.setLayout(kernel_layout)
        overview_layout.addWidget(self.kernel_info_group, 1)  # Give it stretch factor
        
        overview_tab.setLayout(overview_layout)
        self.analysis_tabs.addTab(overview_tab, "Overview")
        
        # Processes tab
        processes_tab = QWidget()
        processes_layout = QVBoxLayout()
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("Filter by name or PID...")
        self.process_filter.textChanged.connect(lambda: self.apply_filter(self.processes_table, 
                                                                       self.process_filter.text(), 
                                                                       [0, 1]))  # Filter on PID and Name columns
        filter_layout.addWidget(self.process_filter, 1)
        
        processes_layout.addLayout(filter_layout)
        
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(6)
        self.processes_table.setHorizontalHeaderLabels(["PID", "Name", "PPID", "State", "UID", "Memory Offset"])
        self.processes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.processes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.processes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.processes_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.processes_table.customContextMenuRequested.connect(
            lambda pos: self.show_context_menu(self.processes_table, pos))
        self.processes_table.doubleClicked.connect(self.view_process_memory)
        
        processes_layout.addWidget(self.processes_table)
        
        processes_btn_layout = QHBoxLayout()
        refresh_processes_btn = QPushButton("Refresh")
        refresh_processes_btn.clicked.connect(self.extract_processes)
        processes_btn_layout.addWidget(refresh_processes_btn)
        
        export_processes_btn = QPushButton("Export")
        export_processes_btn.clicked.connect(lambda: self.export_table_data(self.processes_table, "processes"))
        processes_btn_layout.addWidget(export_processes_btn)
        
        processes_btn_layout.addStretch()
        
        processes_layout.addLayout(processes_btn_layout)
        processes_tab.setLayout(processes_layout)
        self.analysis_tabs.addTab(processes_tab, "Processes")
        
        # Network tab
        network_tab = QWidget()
        network_layout = QVBoxLayout()
        
        filter_layout = QHBoxLayout()
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.network_filter = QLineEdit()
        self.network_filter.setPlaceholderText("Filter by IP or port...")
        self.network_filter.textChanged.connect(lambda: self.apply_filter(self.network_table, 
                                                                    self.network_filter.text(), 
                                                                    [0, 1, 2, 3]))  # Filter on IP and port columns
        filter_layout.addWidget(self.network_filter, 1)
        
        network_layout.addLayout(filter_layout)
        
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(6)
        self.network_table.setHorizontalHeaderLabels(["Local IP", "Local Port", "Remote IP", "Remote Port", "Protocol", "Memory Offset"])
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.network_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.network_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.network_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.network_table.customContextMenuRequested.connect(
            lambda pos: self.show_context_menu(self.network_table, pos))
        self.network_table.doubleClicked.connect(self.view_network_memory)
        
        network_layout.addWidget(self.network_table)
        
        network_btn_layout = QHBoxLayout()
        refresh_network_btn = QPushButton("Refresh")
        refresh_network_btn.clicked.connect(self.extract_network_connections)
        network_btn_layout.addWidget(refresh_network_btn)
        
        export_network_btn = QPushButton("Export")
        export_network_btn.clicked.connect(lambda: self.export_table_data(self.network_table, "network"))
        network_btn_layout.addWidget(export_network_btn)
        
        network_btn_layout.addStretch()
        
        network_layout.addLayout(network_btn_layout)
        network_tab.setLayout(network_layout)
        self.analysis_tabs.addTab(network_tab, "Network")
        
        # Commands tab
        commands_tab = QWidget()
        commands_layout = QVBoxLayout()
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.commands_filter = QLineEdit()
        self.commands_filter.setPlaceholderText("Filter commands...")
        self.commands_filter.textChanged.connect(lambda: self.apply_filter(self.commands_table, 
                                                                    self.commands_filter.text(), 
                                                                    [0]))  # Filter on command column
        filter_layout.addWidget(self.commands_filter, 1)
        
        commands_layout.addLayout(filter_layout)
        
        self.commands_table = QTableWidget()
        self.commands_table.setColumnCount(2)
        self.commands_table.setHorizontalHeaderLabels(["Command", "Memory Offset"])
        self.commands_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.commands_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.commands_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.commands_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.commands_table.customContextMenuRequested.connect(
            lambda pos: self.show_context_menu(self.commands_table, pos))
        
        commands_layout.addWidget(self.commands_table)
        
        commands_btn_layout = QHBoxLayout()
        refresh_commands_btn = QPushButton("Refresh")
        refresh_commands_btn.clicked.connect(self.extract_commands)
        commands_btn_layout.addWidget(refresh_commands_btn)
        
        export_commands_btn = QPushButton("Export")
        export_commands_btn.clicked.connect(lambda: self.export_table_data(self.commands_table, "commands"))
        commands_btn_layout.addWidget(export_commands_btn)
        
        commands_btn_layout.addStretch()
        
        commands_layout.addLayout(commands_btn_layout)
        commands_tab.setLayout(commands_layout)
        self.analysis_tabs.addTab(commands_tab, "Commands")
        
        # Users tab
        users_tab = QWidget()
        users_layout = QVBoxLayout()
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(5)
        self.users_table.setHorizontalHeaderLabels(["Username", "UID", "GID", "Home Directory", "Shell"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.users_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.users_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        users_layout.addWidget(self.users_table)
        
        users_btn_layout = QHBoxLayout()
        refresh_users_btn = QPushButton("Refresh")
        refresh_users_btn.clicked.connect(self.extract_users)
        users_btn_layout.addWidget(refresh_users_btn)
        
        export_users_btn = QPushButton("Export")
        export_users_btn.clicked.connect(lambda: self.export_table_data(self.users_table, "users"))
        users_btn_layout.addWidget(export_users_btn)
        
        users_btn_layout.addStretch()
        
        users_layout.addLayout(users_btn_layout)
        users_tab.setLayout(users_layout)
        self.analysis_tabs.addTab(users_tab, "Users")
        
        # Files tab
        files_tab = QWidget()
        files_layout = QVBoxLayout()
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.files_filter = QLineEdit()
        self.files_filter.setPlaceholderText("Filter by path...")
        self.files_filter.textChanged.connect(lambda: self.apply_filter(self.files_table, 
                                                                    self.files_filter.text(), 
                                                                    [0]))  # Filter on path column
        filter_layout.addWidget(self.files_filter, 1)
        
        files_layout.addLayout(filter_layout)
        
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(2)
        self.files_table.setHorizontalHeaderLabels(["File Path", "Memory Offset"])
        self.files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(
            lambda pos: self.show_context_menu(self.files_table, pos))
        
        files_layout.addWidget(self.files_table)
        
        files_btn_layout = QHBoxLayout()
        refresh_files_btn = QPushButton("Refresh")
        refresh_files_btn.clicked.connect(self.extract_file_listing)
        files_btn_layout.addWidget(refresh_files_btn)
        
        export_files_btn = QPushButton("Export")
        export_files_btn.clicked.connect(lambda: self.export_table_data(self.files_table, "files"))
        files_btn_layout.addWidget(export_files_btn)
        
        files_btn_layout.addStretch()
        
        files_layout.addLayout(files_btn_layout)
        files_tab.setLayout(files_layout)
        self.analysis_tabs.addTab(files_tab, "Files")
        
        # Strings search tab
        strings_tab = QWidget()
        strings_layout = QVBoxLayout()
        
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search for:"))
        self.search_text = QLineEdit()
        self.search_text.setPlaceholderText("Enter string to search for...")
        search_layout.addWidget(self.search_text, 1)
        
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.search_strings)
        search_layout.addWidget(self.search_btn)
        
        predefined_layout = QHBoxLayout()
        predefined_layout.addWidget(QLabel("Common searches:"))
        
        # Add buttons for common searches in Linux memory
        password_btn = QPushButton("Passwords")
        password_btn.clicked.connect(lambda: self.predefined_search("password"))
        predefined_layout.addWidget(password_btn)
        
        keys_btn = QPushButton("Keys/Tokens")
        keys_btn.clicked.connect(lambda: self.predefined_search("key|token|secret"))
        predefined_layout.addWidget(keys_btn)
        
        ip_btn = QPushButton("IP Addresses")
        ip_btn.clicked.connect(lambda: self.predefined_search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
        predefined_layout.addWidget(ip_btn)
        
        url_btn = QPushButton("URLs")
        url_btn.clicked.connect(lambda: self.predefined_search("http|https"))
        predefined_layout.addWidget(url_btn)
        
        predefined_layout.addStretch()
        
        strings_layout.addLayout(search_layout)
        strings_layout.addLayout(predefined_layout)
        
        self.strings_table = QTableWidget()
        self.strings_table.setColumnCount(3)
        self.strings_table.setHorizontalHeaderLabels(["Memory Offset", "Match", "Context"])
        self.strings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.strings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.strings_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.strings_table.customContextMenuRequested.connect(
            lambda pos: self.show_context_menu(self.strings_table, pos))
        self.strings_table.doubleClicked.connect(self.view_string_memory)
        
        strings_layout.addWidget(self.strings_table)
        
        # Export button for strings results
        strings_btn_layout = QHBoxLayout()
        export_strings_btn = QPushButton("Export Results")
        export_strings_btn.clicked.connect(lambda: self.export_table_data(self.strings_table, "strings_search"))
        strings_btn_layout.addWidget(export_strings_btn)
        strings_btn_layout.addStretch()
        
        strings_layout.addLayout(strings_btn_layout)
        strings_tab.setLayout(strings_layout)
        self.analysis_tabs.addTab(strings_tab, "Strings")
        
        # Hex view tab
        hex_tab = QWidget()
        hex_layout = QVBoxLayout()
        
        navigation_layout = QHBoxLayout()
        navigation_layout.addWidget(QLabel("Go to offset:"))
        self.offset_edit = QLineEdit()
        self.offset_edit.setPlaceholderText("Enter offset (decimal or hex with 0x prefix)")
        navigation_layout.addWidget(self.offset_edit)
        
        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.go_to_offset)
        navigation_layout.addWidget(self.go_btn)
        
        self.prev_btn = QPushButton("Previous")
        self.prev_btn.clicked.connect(self.go_to_prev)
        navigation_layout.addWidget(self.prev_btn)
        
        self.next_btn = QPushButton("Next")
        self.next_btn.clicked.connect(self.go_to_next)
        navigation_layout.addWidget(self.next_btn)
        
        hex_layout.addLayout(navigation_layout)
        
        # Add bookmark functionality for important offsets
        bookmark_layout = QHBoxLayout()
        bookmark_layout.addWidget(QLabel("Bookmarks:"))
        
        self.bookmark_combo = QComboBox()
        self.bookmark_combo.setEditable(False)
        self.bookmark_combo.setMinimumWidth(250)
        bookmark_layout.addWidget(self.bookmark_combo, 1)
        
        self.add_bookmark_btn = QPushButton("Add")
        self.add_bookmark_btn.clicked.connect(self.add_offset_bookmark)
        bookmark_layout.addWidget(self.add_bookmark_btn)
        
        self.goto_bookmark_btn = QPushButton("Go To")
        self.goto_bookmark_btn.clicked.connect(self.goto_bookmark)
        bookmark_layout.addWidget(self.goto_bookmark_btn)
        
        self.remove_bookmark_btn = QPushButton("Remove")
        self.remove_bookmark_btn.clicked.connect(self.remove_bookmark)
        bookmark_layout.addWidget(self.remove_bookmark_btn)
        
        hex_layout.addLayout(bookmark_layout)
        
        # Create a splitter with hex view and ASCII representation
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Hex view
        self.hex_view = HexViewWidget()
        splitter.addWidget(self.hex_view)
        
        # Add analysis panel below hex view
        analysis_panel = QWidget()
        analysis_panel_layout = QVBoxLayout(analysis_panel)
        
        analysis_panel_layout.addWidget(QLabel("Data Analysis:"))
        
        # Tabs for different analysis views
        analysis_tabs = QTabWidget()
        
        # Data structures tab
        data_structures_tab = QWidget()
        data_structures_layout = QVBoxLayout(data_structures_tab)
        
        # Add Linux-specific structure detection
        structures_layout = QHBoxLayout()
        structures_layout.addWidget(QLabel("Detect:"))
        
        # Add buttons for common Linux structures
        task_struct_btn = QPushButton("task_struct")
        task_struct_btn.clicked.connect(lambda: self.detect_structure("task_struct"))
        structures_layout.addWidget(task_struct_btn)
        
        mm_struct_btn = QPushButton("mm_struct")
        mm_struct_btn.clicked.connect(lambda: self.detect_structure("mm_struct"))
        structures_layout.addWidget(mm_struct_btn)
        
        files_struct_btn = QPushButton("files_struct")
        files_struct_btn.clicked.connect(lambda: self.detect_structure("files_struct"))
        structures_layout.addWidget(files_struct_btn)
        
        socket_btn = QPushButton("socket")
        socket_btn.clicked.connect(lambda: self.detect_structure("socket"))
        structures_layout.addWidget(socket_btn)
        
        data_structures_layout.addLayout(structures_layout)
        
        # Add structure view
        self.structure_view = QTextEdit()
        self.structure_view.setReadOnly(True)
        self.structure_view.setFont(QFont("Courier New", 10))
        data_structures_layout.addWidget(self.structure_view)
        
        analysis_tabs.addTab(data_structures_tab, "Data Structures")
        
        # Interpretation tab
        interpretation_tab = QWidget()
        interpretation_layout = QVBoxLayout(interpretation_tab)
        
        interpret_layout = QHBoxLayout()
        interpret_layout.addWidget(QLabel("Interpret as:"))
        
        # Add buttons for different data interpretations
        int32_btn = QPushButton("int32")
        int32_btn.clicked.connect(lambda: self.interpret_data("int32"))
        interpret_layout.addWidget(int32_btn)
        
        int64_btn = QPushButton("int64")
        int64_btn.clicked.connect(lambda: self.interpret_data("int64"))
        interpret_layout.addWidget(int64_btn)
        
        float_btn = QPushButton("float")
        float_btn.clicked.connect(lambda: self.interpret_data("float"))
        interpret_layout.addWidget(float_btn)
        
        string_btn = QPushButton("string")
        string_btn.clicked.connect(lambda: self.interpret_data("string"))
        interpret_layout.addWidget(string_btn)
        
        time_btn = QPushButton("timestamp")
        time_btn.clicked.connect(lambda: self.interpret_data("timestamp"))
        interpret_layout.addWidget(time_btn)
        
        interpretation_layout.addLayout(interpret_layout)
        
        # Add interpretation view
        self.interpretation_view = QTextEdit()
        self.interpretation_view.setReadOnly(True)
        interpretation_layout.addWidget(self.interpretation_view)
        
        analysis_tabs.addTab(interpretation_tab, "Interpretation")
        
        # Notes tab
        notes_tab = QWidget()
        notes_layout = QVBoxLayout(notes_tab)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Add your analysis notes here...")
        notes_layout.addWidget(self.notes_edit)
        
        save_notes_btn = QPushButton("Save Notes")
        save_notes_btn.clicked.connect(self.save_analysis_notes)
        notes_layout.addWidget(save_notes_btn)
        
        analysis_tabs.addTab(notes_tab, "Notes")
        
        analysis_panel_layout.addWidget(analysis_tabs)
        
        splitter.addWidget(analysis_panel)
        
        # Set initial splitter sizes (70% hex view, 30% analysis panel)
        splitter.setSizes([700, 300])
        
        hex_layout.addWidget(splitter)
        
        hex_tab.setLayout(hex_layout)
        self.analysis_tabs.addTab(hex_tab, "Hex View")
        
        layout.addWidget(self.analysis_tabs, 1)  # Give it stretch factor
        
        # Status bar at bottom
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def open_memory_dump(self, file_path=None):
        """Enhanced open_memory_dump method that integrates with case management"""
        # If file_path is provided, use it; otherwise get from the text field
        if not file_path:
            file_path = self.file_edit.text()
            
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Invalid File", "Please select a valid memory dump file.")
            return
        
        # Update the file path in the UI if it came from an external call
        if file_path != self.file_edit.text():
            self.file_edit.setText(file_path)
        
        self.status_label.setText(f"Opening memory dump: {file_path}")
        QApplication.processEvents()  # Update the UI
        
        # Close any previously opened memory file
        if self.memory_parser:
            self.memory_parser.close()
        
        # Create a new memory parser instance
        self.memory_parser = LinuxMemoryParser(file_path)
        
        # Try to open the memory dump
        if not self.memory_parser.open():
            QMessageBox.critical(self, "Error", f"Failed to open memory dump file: {file_path}")
            self.memory_parser = None
            self.status_label.setText("Failed to open memory dump")
            return
        
        # Update the current memory file
        self.current_memory_file = file_path
        
        # Update memory dump information in the UI
        self.file_path_label.setText(file_path)
        self.file_size_label.setText(f"{os.path.getsize(file_path) / (1024*1024):.2f} MB")
        self.format_label.setText(self.memory_parser.format.upper())
        self.kernel_version_label.setText(self.memory_parser.kernel_version or "Unknown")
        
        # Extract kernel information
        kernel_info = self.memory_parser.extract_kernel_info()
        
        # Format kernel info for display
        kernel_text = "Kernel Information:\n\n"
        kernel_text += f"Version: {kernel_info.get('version', 'Unknown')}\n"
        kernel_text += f"Boot Time: {kernel_info.get('boot_time', 'Unknown')}\n"
        kernel_text += f"Hostname: {kernel_info.get('hostname', 'Unknown')}\n"
        kernel_text += f"Command Line: {kernel_info.get('command_line', 'Unknown')}\n\n"
        
        if kernel_info.get('modules'):
            kernel_text += "Loaded Modules:\n"
            for module in kernel_info.get('modules', []):
                kernel_text += f"- {module}\n"
        
        self.kernel_info_text.setText(kernel_text)
        
        # Enable analysis buttons now that we have an open memory dump
        self.processes_btn.setEnabled(True)
        self.network_btn.setEnabled(True)
        self.commands_btn.setEnabled(True)
        self.users_btn.setEnabled(True)
        self.files_btn.setEnabled(True)
        self.strings_btn.setEnabled(True)
        
        # Reset the tables
        self.processes_table.setRowCount(0)
        self.network_table.setRowCount(0)
        self.commands_table.setRowCount(0)
        self.users_table.setRowCount(0)
        self.files_table.setRowCount(0)
        self.strings_table.setRowCount(0)
        
        # Update status
        self.status_label.setText(f"Memory dump opened: {file_path}")
        
        # If we have a case manager and this file isn't already evidence, offer to add it
        if self.case_manager and self.case_manager.current_case:
            # Check if this file is already in the evidence
            is_evidence = any(
                e.source_path == file_path for e in self.case_manager.current_case.evidence_items
            )
            
            if not is_evidence and not hasattr(self, 'active_evidence'):
                # Ask user if they want to add it
                reply = QMessageBox.question(self, "Add Evidence", 
                                        "Do you want to add this memory dump to the current case?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                
                if reply == QMessageBox.StandardButton.Yes:
                    # Show dialog to get evidence description
                    description, ok = QInputDialog.getText(self, "Evidence Description", 
                                                    "Enter a description for this evidence:")
                    
                    if ok:
                        success, message, evidence_item = self.case_manager.add_evidence(
                            file_path, EvidenceItem.TYPE_MEMORY, description)
                        
                        if success:
                            self.active_evidence = evidence_item
                            self.current_evidence_id = evidence_item.id
                            self.enable_bookmark_features(True)
                            
                            # Update status
                            self.status_label.setText(f"Added as evidence and opened: {file_path}")
                            
                            # Notify the parent application
                            parent = self.parent()
                            if parent and hasattr(parent, 'evidence_added'):
                                parent.evidence_added.emit(evidence_item)
                        else:
                            QMessageBox.warning(self, "Error", message)

    def browse_file(self):
        """Open file dialog to select memory dump file"""
        default_dir = ""
        
        # Fix for case_directory access
        if self.case_manager and self.case_manager.current_case:
            # If we have a case, use the evidence directory
            default_dir = os.path.join(self.case_manager.current_case.directory, "evidence")
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Linux Memory Dump", default_dir,
            "Memory Dumps (*.raw *.lime *.mem *.vmem);;All Files (*)"
        )
        
        if file_path:
            self.file_edit.setText(file_path)
            self.memory_file = file_path
            
            # If we have a case manager, ask if the user wants to add this as evidence
            if self.case_manager and self.case_manager.current_case:
                # Check if it's already in evidence
                is_evidence = False
                for item in self.case_manager.current_case.evidence_items:
                    if item.source_path == file_path:
                        # It's already evidence, so set it as active
                        self.set_evidence(item)
                        is_evidence = True
                        break
                
                if not is_evidence:
                    # Ask if they want to add it
                    reply = QMessageBox.question(self, "Add Evidence", 
                                            "Do you want to add this memory dump to the current case?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    
                    if reply == QMessageBox.StandardButton.Yes:
                        # Get description
                        description, ok = QInputDialog.getText(self, "Evidence Description", 
                                                        "Enter a description for this memory dump:")
                        
                        if ok:
                            # Add it as evidence
                            success, message, evidence_item = self.case_manager.add_evidence(
                                file_path, EvidenceItem.TYPE_MEMORY, description
                            )
                            
                            if success and evidence_item:
                                self.set_evidence(evidence_item)
                                QMessageBox.information(self, "Evidence Added", message)
                            else:
                                QMessageBox.warning(self, "Error", message)

    def on_evidence_selected(self, evidence_item):
        """Improved handler for when evidence is selected in the case manager"""
        if evidence_item.evidence_type != "memory":
            return
        
        # Set active evidence reference
        self.active_evidence = evidence_item
        self.current_evidence_id = evidence_item.id
        
        # Open the memory file directly from the evidence item
        self.open_memory_dump(evidence_item.source_path)
        
        # Update status message
        self.status_label.setText(f"Memory evidence loaded: {evidence_item.file_name}")
        
        # Enable bookmarking functionality
        self.enable_bookmark_features(True)

    def enable_bookmark_features(self, enabled=True):
        """Enable or disable bookmark-related features"""
        # Check if we have these buttons/controls
        if hasattr(self, 'add_bookmark_btn'):
            self.add_bookmark_btn.setEnabled(enabled)
        
        if hasattr(self, 'bookmark_combo'):
            self.bookmark_combo.setEnabled(enabled)
            self.goto_bookmark_btn.setEnabled(enabled and self.bookmark_combo.count() > 0)
            self.remove_bookmark_btn.setEnabled(enabled and self.bookmark_combo.count() > 0)

    def create_bookmark_at_current_offset(self, description=None):
        """Enhanced bookmark creation with case manager integration"""
        if not self.case_manager or not self.case_manager.current_case or not hasattr(self, 'active_evidence'):
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
            
        current_offset = self.hex_view.current_address
        
        # Get bookmark description from user if not provided
        if not description:
            description, ok = QInputDialog.getText(self, "Add Bookmark", 
                                            "Enter a description for this bookmark:")
            if not ok or not description:
                return
        
        # Create bookmark location
        location = f"Memory Offset: 0x{current_offset:08x}"
        
        # Create bookmark data
        data = {
            "memory_address": current_offset,
            "offset_type": "hex_view",
            "file_path": self.current_memory_file,
            # Add content glimpse to help with context
            "content_preview": self.hex_view.get_current_content_preview()
        }
        
        # Add the bookmark through the case manager
        success, message, bookmark = self.case_manager.add_bookmark(
            self.active_evidence.id, description, location, data)
        
        if success:
            self.status_label.setText(f"Added bookmark: {description} at offset 0x{current_offset:08x}")
            
            # Also add to the local bookmark combo box
            bookmark_text = f"{description} (0x{current_offset:x})"
            if self.bookmark_combo.findText(bookmark_text) == -1:
                self.bookmark_combo.addItem(bookmark_text, current_offset)
                self.goto_bookmark_btn.setEnabled(True)
                self.remove_bookmark_btn.setEnabled(True)
            
            # Emit signal if parent has it
            parent = self.parent()
            if parent and hasattr(parent, 'bookmark_added'):
                parent.bookmark_added.emit(self.active_evidence, bookmark)
        else:
            QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    def add_bookmark_process(self):
        """Enhanced process bookmarking with case manager integration"""
        # Check if we have an active case and evidence
        if not self.case_manager or not self.case_manager.current_case or not hasattr(self, 'active_evidence'):
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
        
        # Get the selected process
        selected_rows = self.processes_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No process selected")
            return

        row = selected_rows[0].row()
        pid_item = self.processes_table.item(row, 0)  # PID column
        name_item = self.processes_table.item(row, 1)  # Name column
        offset_item = self.processes_table.item(row, 5)  # Offset column
        
        if not pid_item or not name_item or not offset_item:
            QMessageBox.warning(self, "Cannot Add Bookmark", "Missing process information")
            return
        
        pid = pid_item.text()
        name = name_item.text()
        offset = offset_item.text()
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Process Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, f"Process: {name} (PID: {pid})")
        
        if ok and description:
            # Create bookmark location
            location = f"Process: {name} (PID: {pid})"
            
            # Create bookmark data with process-specific information
            data = {
                "process_id": pid,
                "process_name": name,
                "memory_offset": offset,
                "file_path": self.current_memory_file
            }
            
            # Add parent PID if available
            if self.processes_table.columnCount() > 2:
                ppid_item = self.processes_table.item(row, 2)  # PPID column
                if ppid_item:
                    data["parent_pid"] = ppid_item.text()
            
            # Add the bookmark through the case manager
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data)
            
            if success:
                self.status_label.setText(f"Added process bookmark: {description}")
                # Emit signal if parent has it
                parent = self.parent()
                if parent and hasattr(parent, 'bookmark_added'):
                    parent.bookmark_added.emit(self.active_evidence, bookmark)
            else:
                QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    def add_bookmark_network(self):
        """Add a bookmark for the selected network connection"""
        # Check if we have an active case and evidence
        if not self.case_manager or not self.case_manager.current_case or not hasattr(self, 'active_evidence'):
            QMessageBox.warning(self, "Cannot Add Bookmark", "No active case or memory evidence")
            return
        
        # Get the selected network connection
        selected_rows = self.network_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Cannot Add Bookmark", "No network connection selected")
            return

        row = selected_rows[0].row()
        local_ip = self.network_table.item(row, 0).text()  # Local IP
        local_port = self.network_table.item(row, 1).text()  # Local Port
        remote_ip = self.network_table.item(row, 2).text()  # Remote IP
        remote_port = self.network_table.item(row, 3).text()  # Remote Port
        protocol = self.network_table.item(row, 4).text()  # Protocol
        
        # Open a dialog to get bookmark description
        description, ok = QInputDialog.getText(
            self, "Add Network Bookmark", "Enter bookmark description:",
            QLineEdit.EchoMode.Normal, 
            f"{protocol} {local_ip}:{local_port} -> {remote_ip}:{remote_port}")
        
        if ok and description:
            # Create bookmark location
            location = f"Network: {local_ip}:{local_port} -> {remote_ip}:{remote_port} ({protocol})"
            
            # Create bookmark data
            data = {
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "file_path": self.current_memory_file
            }
            
            # Get offset if available
            if self.network_table.columnCount() > 5:
                offset_item = self.network_table.item(row, 5)  # Offset column
                if offset_item:
                    data["memory_offset"] = offset_item.text()
            
            # Add the bookmark through the case manager
            success, message, bookmark = self.case_manager.add_bookmark(
                self.active_evidence.id, description, location, data)
            
            if success:
                self.status_label.setText(f"Added network bookmark: {description}")
                # Emit signal if parent has it
                parent = self.parent()
                if parent and hasattr(parent, 'bookmark_added'):
                    parent.bookmark_added.emit(self.active_evidence, bookmark)
            else:
                QMessageBox.warning(self, "Bookmark Error", f"Failed to add bookmark: {message}")

    # Add this method to HexViewWidget class to support bookmark content preview
    def get_current_content_preview(self):
        """Get a preview of the content at the current address"""
        current_text = self.toPlainText()
        if not current_text:
            return "No content available"
        
        # Find the line with the current address
        address_str = f"{self.current_address:08x}: "
        
        lines = current_text.split('\n')
        for line in lines:
            if line.startswith(address_str):
                return line
        
        # If not found, just return first line
        return lines[0] if lines else "No content available"
    
    def extract_processes(self):
        """Extract process information from the memory dump and populate the table."""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return

        self.status_label.setText("Extracting process information...")
        QApplication.processEvents()

        try:
            processes = self.memory_parser.extract_detailed_processes()
        except Exception as e:
            QMessageBox.critical(self, "Extraction Error", f"Failed to extract processes:\n{str(e)}")
            self.status_label.setText("Extraction failed.")
            return

        if not processes:
            QMessageBox.information(self, "No Processes Found", "No process information was found in the memory dump.")
            self.status_label.setText("No processes found.")
            return

        # Setup table headers
        headers = ["PID", "Name", "PPID", "State", "UID", "Offset"]
        self.processes_table.setColumnCount(len(headers))
        self.processes_table.setHorizontalHeaderLabels(headers)
        self.processes_table.setRowCount(0)

        for process in processes:
            row = self.processes_table.rowCount()
            self.processes_table.insertRow(row)

            items = [
                QTableWidgetItem(str(process.get('pid', 'N/A'))),
                QTableWidgetItem(process.get('name', 'Unknown')),
                QTableWidgetItem(str(process.get('parent_pid', 'N/A'))),
                QTableWidgetItem(process.get('state', 'Unknown')),
                QTableWidgetItem(str(process.get('uid', 'N/A'))),
                QTableWidgetItem(f"0x{process.get('offset', 0):x}")
            ]

            for col, item in enumerate(items):
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)  # Make cells read-only
                self.processes_table.setItem(row, col, item)

        self.status_label.setText(f"Extracted {len(processes)} processes.")

    def extract_network_connections(self):
        """Extract network connection information from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting network connections...")
        QApplication.processEvents()  # Update the UI
        
        # Extract network connections
        connections = self.memory_parser.extract_network_connections()
        
        # Clear the table
        self.network_table.setRowCount(0)
        
        # Populate the table with connection information
        for conn in connections:
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            
            # Set Local IP
            local_ip_item = QTableWidgetItem(conn.get('local_ip', 'N/A'))
            self.network_table.setItem(row, 0, local_ip_item)
            
            # Set Local Port
            local_port_item = QTableWidgetItem(str(conn.get('local_port', 'N/A')))
            self.network_table.setItem(row, 1, local_port_item)
            
            # Set Remote IP
            remote_ip_item = QTableWidgetItem(conn.get('remote_ip', 'N/A'))
            self.network_table.setItem(row, 2, remote_ip_item)
            
            # Set Remote Port
            remote_port_item = QTableWidgetItem(str(conn.get('remote_port', 'N/A')))
            self.network_table.setItem(row, 3, remote_port_item)
            
            # Set Protocol
            protocol_item = QTableWidgetItem(conn.get('protocol', 'Unknown'))
            self.network_table.setItem(row, 4, protocol_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{conn.get('offset', 0):x}")
            self.network_table.setItem(row, 5, offset_item)
        
        self.status_label.setText(f"Extracted {len(connections)} network connections")

    def extract_commands(self):
        """Extract command history from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting command history...")
        QApplication.processEvents()  # Update the UI
        
        # Extract commands
        commands = self.memory_parser.extract_commands()
        
        # Clear the table
        self.commands_table.setRowCount(0)
        
        # Populate the table with command information
        for cmd in commands:
            row = self.commands_table.rowCount()
            self.commands_table.insertRow(row)
            
            # Set Command
            command_item = QTableWidgetItem(cmd.get('command', 'Unknown'))
            self.commands_table.setItem(row, 0, command_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{cmd.get('offset', 0):x}")
            self.commands_table.setItem(row, 1, offset_item)
        
        self.status_label.setText(f"Extracted {len(commands)} commands")

    def extract_users(self):
        """Extract user account information from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting user information...")
        QApplication.processEvents()  # Update the UI
        
        # Extract users
        users = self.memory_parser.extract_users()
        
        # Clear the table
        self.users_table.setRowCount(0)
        
        # Populate the table with user information
        for user in users:
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            
            # Set Username
            username_item = QTableWidgetItem(user.get('username', 'Unknown'))
            self.users_table.setItem(row, 0, username_item)
            
            # Set UID
            uid_item = QTableWidgetItem(str(user.get('uid', 'N/A')))
            self.users_table.setItem(row, 1, uid_item)
            
            # Set GID
            gid_item = QTableWidgetItem(str(user.get('gid', 'N/A')))
            self.users_table.setItem(row, 2, gid_item)
            
            # Set Home directory
            home_item = QTableWidgetItem(user.get('home', 'Unknown'))
            self.users_table.setItem(row, 3, home_item)
            
            # Set Shell
            shell_item = QTableWidgetItem(user.get('shell', 'Unknown'))
            self.users_table.setItem(row, 4, shell_item)
        
        self.status_label.setText(f"Extracted {len(users)} users")

    def extract_file_listing(self):
        """Extract file paths from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting file paths...")
        QApplication.processEvents()  # Update the UI
        
        # Extract files
        files = self.memory_parser.extract_file_listing()
        
        # Clear the table
        self.files_table.setRowCount(0)
        
        # Populate the table with file information
        for file_info in files:
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            
            # Set File Path
            path_item = QTableWidgetItem(file_info.get('path', 'Unknown'))
            self.files_table.setItem(row, 0, path_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{file_info.get('offset', 0):x}")
            self.files_table.setItem(row, 1, offset_item)
        
        self.status_label.setText(f"Extracted {len(files)} file paths")

    def show_string_search(self):
        """Show the string search tab"""
        # Switch to the strings tab
        for i in range(self.analysis_tabs.count()):
            if self.analysis_tabs.tabText(i) == "Strings":
                self.analysis_tabs.setCurrentIndex(i)
                break
        
        # Set focus to the search text field
        self.search_text.setFocus()

    def search_strings(self):
        """Search for strings in the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
        
        search_text = self.search_text.text()
        if not search_text:
            QMessageBox.warning(self, "Empty Search", "Please enter a string to search for.")
            return
        
        self.status_label.setText(f"Searching for '{search_text}'...")
        QApplication.processEvents()  # Update the UI
        
        # Perform the search
        results = self.memory_parser.search_string(search_text)
        
        # Clear the table
        self.strings_table.setRowCount(0)
        
        # Populate the table with search results
        for result in results:
            row = self.strings_table.rowCount()
            self.strings_table.insertRow(row)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{result.get('offset', 0):x}")
            self.strings_table.setItem(row, 0, offset_item)
            
            # Set match string
            match_item = QTableWidgetItem(result.get('match', 'Unknown'))
            self.strings_table.setItem(row, 1, match_item)
            
            # Set context
            context_item = QTableWidgetItem(result.get('context', 'Unknown'))
            self.strings_table.setItem(row, 2, context_item)
        
        self.status_label.setText(f"Found {len(results)} matches for '{search_text}'")

    def predefined_search(self, pattern):
        """Perform a predefined search"""
        self.search_text.setText(pattern)
        self.search_strings()

    def apply_filter(self, table, filter_text, columns):
        """Apply text filter to a table"""
        if not filter_text:
            # Show all rows if filter is empty
            for row in range(table.rowCount()):
                table.setRowHidden(row, False)
            return
        
        filter_text = filter_text.lower()
        
        # Hide rows that don't match the filter
        for row in range(table.rowCount()):
            match = False
            
            for col in columns:
                item = table.item(row, col)
                if item and filter_text in item.text().lower():
                    match = True
                    break
            
            table.setRowHidden(row, not match)

    def show_context_menu(self, table, pos):
        """Show context menu for a table"""
        global_pos = table.mapToGlobal(pos)
        
        # Create the context menu
        menu = QMenu()
        
        # Get the selected row's data
        selected_rows = table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Add "View in Hex" action
        view_hex_action = menu.addAction("View in Hex")
        
        # Add "Copy to Clipboard" action
        copy_action = menu.addAction("Copy to Clipboard")
        
        # Add "Export Selected" action
        export_selected_action = menu.addAction("Export Selected")
        
        # Show the menu and get the selected action
        action = menu.exec(global_pos)
        
        if action == view_hex_action:
            # Get offset from the table
            offset_col = -1
            for col in range(table.columnCount()):
                if "offset" in table.horizontalHeaderItem(col).text().lower():
                    offset_col = col
                    break
            
            if offset_col != -1:
                offset_item = table.item(selected_row, offset_col)
                if offset_item:
                    offset_text = offset_item.text()
                    try:
                        # Convert from hex string if needed
                        if offset_text.startswith("0x"):
                            offset = int(offset_text, 16)
                        else:
                            offset = int(offset_text)
                        
                        # Switch to hex view tab and go to offset
                        for i in range(self.analysis_tabs.count()):
                            if self.analysis_tabs.tabText(i) == "Hex View":
                                self.analysis_tabs.setCurrentIndex(i)
                                break
                        
                        # Set the offset in the input field and go there
                        self.offset_edit.setText(offset_text)
                        self.go_to_offset()
                    except:
                        pass
        
        elif action == copy_action:
            # Copy all cell values from the selected row
            row_data = []
            for col in range(table.columnCount()):
                item = table.item(selected_row, col)
                if item:
                    row_data.append(item.text())
            
            # Join with tabs and copy to clipboard
            QApplication.clipboard().setText("\t".join(row_data))
        
        elif action == export_selected_action:
            # Export only the selected row(s)
            rows = set()
            for index in table.selectedIndexes():
                rows.add(index.row())
            
            if rows:
                # Get the tab name for the default filename
                tab_name = "data"
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.widget(i) is table.parent():
                        tab_name = self.analysis_tabs.tabText(i).lower()
                        break
                
                self.export_selected_rows(table, rows, f"{tab_name}_selected")

    def view_process_memory(self):
        """View memory for the selected process"""
        selected_rows = self.processes_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Get offset from the Offset column (column 5)
        offset_item = self.processes_table.item(selected_row, 5)
        if offset_item:
            offset_text = offset_item.text()
            try:
                # Convert from hex string
                if offset_text.startswith("0x"):
                    offset = int(offset_text, 16)
                else:
                    offset = int(offset_text)
                
                # Switch to hex view tab and go to offset
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.tabText(i) == "Hex View":
                        self.analysis_tabs.setCurrentIndex(i)
                        break
                
                # Set the offset in the input field and go there
                self.offset_edit.setText(offset_text)
                self.go_to_offset()
            except:
                pass

    def view_network_memory(self):
        """View memory for the selected network connection"""
        selected_rows = self.network_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Get offset from the Offset column (column 5)
        offset_item = self.network_table.item(selected_row, 5)
        if offset_item:
            offset_text = offset_item.text()
            try:
                # Convert from hex string
                if offset_text.startswith("0x"):
                    offset = int(offset_text, 16)
                else:
                    offset = int(offset_text)
                
                # Switch to hex view tab and go to offset
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.tabText(i) == "Hex View":
                        self.analysis_tabs.setCurrentIndex(i)
                        break
                
                # Set the offset in the input field and go there
                self.offset_edit.setText(offset_text)
                self.go_to_offset()
            except:
                pass

    def view_string_memory(self):
        """View memory for the selected string"""
        selected_rows = self.strings_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Get offset from the Offset column (column 0)
        offset_item = self.strings_table.item(selected_row, 0)
        if offset_item:
            offset_text = offset_item.text()
            try:
                # Convert from hex string
                if offset_text.startswith("0x"):
                    offset = int(offset_text, 16)
                else:
                    offset = int(offset_text)
                
                # Switch to hex view tab and go to offset
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.tabText(i) == "Hex View":
                        self.analysis_tabs.setCurrentIndex(i)
                        break
                
                # Set the offset in the input field and go there
                self.offset_edit.setText(offset_text)
                self.go_to_offset()
            except:
                pass

    def go_to_offset(self):
        """Go to the specified offset in the hex view"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
        
        offset_text = self.offset_edit.text()
        if not offset_text:
            return
        
        try:
            # Convert from hex string if needed
            if offset_text.startswith("0x"):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
            
            # Read data from the offset
            data = self.memory_parser.read_data(offset, 1024)  # Read 1KB of data
            
            if data:
                # Set the data in the hex view
                self.hex_view.set_data(data, offset)
                self.status_label.setText(f"Viewing memory at offset: {offset_text}")
            else:
                QMessageBox.warning(self, "Error", "Could not read data from the specified offset.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Please enter a valid integer offset.")

    def go_to_prev(self):
        """Go to the previous page in the hex view"""
        if not self.memory_parser:
            return
        
        # Calculate new offset (1KB back)
        current_offset = self.hex_view.current_address
        new_offset = max(0, current_offset - 1024)
        
        # Update the offset field
        self.offset_edit.setText(f"0x{new_offset:x}")
        
        # Go to the new offset
        self.go_to_offset()

    def go_to_next(self):
        """Go to the next page in the hex view"""
        if not self.memory_parser:
            return
        
        # Calculate new offset (1KB forward)
        current_offset = self.hex_view.current_address
        new_offset = current_offset + 1024
        
        # Make sure we don't go past the end of the file
        if new_offset < self.memory_parser.size:
            # Update the offset field
            self.offset_edit.setText(f"0x{new_offset:x}")
            
            # Go to the new offset
            self.go_to_offset()

    def add_offset_bookmark(self):
        """Add a bookmark for the current offset"""
        if not self.memory_parser:
            return
        
        current_offset = self.hex_view.current_address
        
        # Prompt for bookmark name
        name, ok = QInputDialog.getText(self, "Add Bookmark", 
                                    "Enter a name for this bookmark:")
        
        if ok and name:
            # Create bookmark text (name + offset)
            bookmark_text = f"{name} (0x{current_offset:x})"
            
            # Add to combo box if not already present
            if self.bookmark_combo.findText(bookmark_text) == -1:
                self.bookmark_combo.addItem(bookmark_text, current_offset)
                self.status_label.setText(f"Bookmark added: {bookmark_text}")

    def goto_bookmark(self):
        """Go to the selected bookmark offset"""
        if self.bookmark_combo.currentIndex() == -1:
            return
        
        # Get the stored offset
        offset = self.bookmark_combo.currentData()
        
        # Update the offset field
        self.offset_edit.setText(f"0x{offset:x}")
        
        # Go to the offset
        self.go_to_offset()

    def remove_bookmark(self):
        """Remove the selected bookmark"""
        current_index = self.bookmark_combo.currentIndex()
        if current_index == -1:
            return
        
        self.bookmark_combo.removeItem(current_index)
        self.status_label.setText("Bookmark removed")

    def detect_structure(self, structure_type):
        """Detect a Linux data structure at the current offset"""
        if not self.memory_parser:
            return
        
        current_offset = self.hex_view.current_address
        
        # This is a placeholder for actual structure detection logic
        # In a real implementation, you would analyze the memory at the current offset
        # and try to interpret it as the specified Linux kernel structure
        
        self.structure_view.setText(f"Analyzing for {structure_type} structure at offset 0x{current_offset:x}...\n\n"
                                f"Structure detection not implemented in this version.")
        
    def interpret_data(self, data_type):
        """Interpret data at current offset as the specified type"""
        if not self.memory_parser:
            return
        
        current_offset = self.hex_view.current_address
        
        # Read appropriate amount of data based on data type
        if data_type == "int32":
            size = 4
        elif data_type == "int64":
            size = 8
        elif data_type == "float":
            size = 4
        elif data_type == "string":
            size = 64  # Read 64 bytes for string interpretation
        elif data_type == "timestamp":
            size = 8  # Timestamps are typically 64-bit values
        else:
            size = 16  # Default
        
        data = self.memory_parser.read_data(current_offset, size)
        
        if not data:
            self.interpretation_view.setText("Could not read data from the specified offset.")
            return
        
        # Interpret the data based on type
        result = "Data Interpretation:\n\n"
        
        if data_type == "int32":
            if len(data) >= 4:
                value = int.from_bytes(data[:4], byteorder='little')
                result += f"Int32 (Little Endian): {value}\n"
                value = int.from_bytes(data[:4], byteorder='big')
                result += f"Int32 (Big Endian): {value}\n"
        
        elif data_type == "int64":
            if len(data) >= 8:
                value = int.from_bytes(data[:8], byteorder='little')
                result += f"Int64 (Little Endian): {value}\n"
                value = int.from_bytes(data[:8], byteorder='big')
                result += f"Int64 (Big Endian): {value}\n"
        
        elif data_type == "float":
            if len(data) >= 4:
                import struct
                value = struct.unpack('<f', data[:4])[0]
                result += f"Float (Little Endian): {value}\n"
                value = struct.unpack('>f', data[:4])[0]
                result += f"Float (Big Endian): {value}\n"
        
        elif data_type == "string":
            # Try various string encodings
            result += "ASCII: "
            try:
                # Find null terminator
                null_pos = data.find(b'\x00')
                if null_pos != -1:
                    result += data[:null_pos].decode('ascii', errors='replace')
                else:
                    result += data.decode('ascii', errors='replace')
            except:
                result += "[Decoding error]"
            
            result += "\n\nUTF-8: "
            try:
                null_pos = data.find(b'\x00')
                if null_pos != -1:
                    result += data[:null_pos].decode('utf-8', errors='replace')
                else:
                    result += data.decode('utf-8', errors='replace')
            except:
                result += "[Decoding error]"
            
            result += "\n\nUTF-16: "
            try:
                result += data.decode('utf-16', errors='replace')
            except:
                result += "[Decoding error]"
        
        elif data_type == "timestamp":
            if len(data) >= 8:
                import datetime
                # Try unix timestamp (seconds since epoch)
                secs = int.from_bytes(data[:8], byteorder='little')
                try:
                    dt = datetime.datetime.fromtimestamp(secs)
                    result += f"Unix timestamp (Little Endian): {dt}\n"
                except:
                    result += "Unix timestamp (Little Endian): [Invalid timestamp]\n"
                
                secs = int.from_bytes(data[:8], byteorder='big')
                try:
                    dt = datetime.datetime.fromtimestamp(secs)
                    result += f"Unix timestamp (Big Endian): {dt}\n"
                except:
                    result += "Unix timestamp (Big Endian): [Invalid timestamp]\n"
        
        self.interpretation_view.setText(result)

    def save_analysis_notes(self):
        """Save analysis notes to a file"""
        if not self.memory_parser or not self.current_memory_file:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
        
        notes_text = self.notes_edit.toPlainText()
        if not notes_text:
            QMessageBox.warning(self, "Empty Notes", "There are no notes to save.")
            return
        
        # Generate a default filename based on the memory dump
        default_filename = os.path.splitext(os.path.basename(self.current_memory_file))[0] + "_notes.txt"
        
        if self.case_manager and self.case_manager.current_case:
            default_dir = os.path.join(self.case_manager.case_directory, "reports")
        else:
            default_dir = os.path.dirname(self.current_memory_file)
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Analysis Notes", 
            os.path.join(default_dir, default_filename),
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Write header
                    f.write(f"=== Analysis Notes ===\n")
                    f.write(f"Memory Dump: {self.current_memory_file}\n")
                    f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 40 + "\n\n")
                    
                    # Write notes
                    f.write(notes_text)
                
                QMessageBox.information(self, "Notes Saved", f"Analysis notes saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save notes: {str(e)}")

    def export_table_data(self, table, name):
        """Export table data to a CSV file"""
        if table.rowCount() == 0:
            QMessageBox.warning(self, "Empty Table", "There is no data to export.")
            return
        
        # Generate a default filename
        if self.current_memory_file:
            basename = os.path.splitext(os.path.basename(self.current_memory_file))[0]
            default_filename = f"{basename}_{name}.csv"
        else:
            default_filename = f"{name}_export.csv"
        
        if self.case_manager and self.case_manager.current_case:
            default_dir = os.path.join(self.case_manager.case_directory, "reports")
        else:
            default_dir = ""
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Table Data", 
            os.path.join(default_dir, default_filename),
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header row
                    headers = []
                    for col in range(table.columnCount()):
                        headers.append(table.horizontalHeaderItem(col).text())
                    writer.writerow(headers)
                    
                    # Write data rows
                    for row in range(table.rowCount()):
                        row_data = []
                        for col in range(table.columnCount()):
                            item = table.item(row, col)
                            if item:
                                row_data.append(item.text())
                            else:
                                row_data.append("")
                        writer.writerow(row_data)
                
                QMessageBox.information(self, "Export Complete", f"Table data exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data: {str(e)}")

    def export_selected_rows(self, table, rows, name):
        """Export selected rows from a table to a CSV file"""
        if not rows:
            QMessageBox.warning(self, "No Selection", "No rows selected for export.")
            return
        
        # Generate a default filename
        if self.current_memory_file:
            basename = os.path.splitext(os.path.basename(self.current_memory_file))[0]
            default_filename = f"{basename}_{name}.csv"
        else:
            default_filename = f"{name}_export.csv"
        
        if self.case_manager and self.case_manager.current_case:
            default_dir = os.path.join(self.case_manager.case_directory, "reports")
        else:
            default_dir = ""
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Selected Rows", 
            os.path.join(default_dir, default_filename),
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header row
                    headers = []
                    for col in range(table.columnCount()):
                        headers.append(table.horizontalHeaderItem(col).text())
                    writer.writerow(headers)
                    
                    # Write selected rows
                    for row in sorted(rows):
                        row_data = []
                        for col in range(table.columnCount()):
                            item = table.item(row, col)
                            if item:
                                row_data.append(item.text())
                            else:
                                row_data.append("")
                        writer.writerow(row_data)
                
                QMessageBox.information(self, "Export Complete", f"Selected rows exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export data: {str(e)}")

    def extract_processes(self):
        """Extract process information from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting process information...")
        QApplication.processEvents()  # Update the UI
        
        # Extract processes
        processes = self.memory_parser.extract_detailed_processes()
        
        # Clear the table
        self.processes_table.setRowCount(0)
        
        # Populate the table with process information
        for process in processes:
            row = self.processes_table.rowCount()
            self.processes_table.insertRow(row)
            
            # Set PID
            pid_item = QTableWidgetItem(str(process.get('pid', 'N/A')))
            self.processes_table.setItem(row, 0, pid_item)
            
            # Set Name
            name_item = QTableWidgetItem(process.get('name', 'Unknown'))
            self.processes_table.setItem(row, 1, name_item)
            
            # Set PPID
            ppid_item = QTableWidgetItem(str(process.get('parent_pid', 'N/A')))
            self.processes_table.setItem(row, 2, ppid_item)
            
            # Set State
            state_item = QTableWidgetItem(process.get('state', 'Unknown'))
            self.processes_table.setItem(row, 3, state_item)
            
            # Set UID
            uid_item = QTableWidgetItem(str(process.get('uid', 'N/A')))
            self.processes_table.setItem(row, 4, uid_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{process.get('offset', 0):x}")
            self.processes_table.setItem(row, 5, offset_item)
        
        self.status_label.setText(f"Extracted {len(processes)} processes")

    def extract_network_connections(self):
        """Extract network connection information from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting network connections...")
        QApplication.processEvents()  # Update the UI
        
        # Extract network connections
        connections = self.memory_parser.extract_network_connections()
        
        # Clear the table
        self.network_table.setRowCount(0)
        
        # Populate the table with connection information
        for conn in connections:
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            
            # Set Local IP
            local_ip_item = QTableWidgetItem(conn.get('local_ip', 'N/A'))
            self.network_table.setItem(row, 0, local_ip_item)
            
            # Set Local Port
            local_port_item = QTableWidgetItem(str(conn.get('local_port', 'N/A')))
            self.network_table.setItem(row, 1, local_port_item)
            
            # Set Remote IP
            remote_ip_item = QTableWidgetItem(conn.get('remote_ip', 'N/A'))
            self.network_table.setItem(row, 2, remote_ip_item)
            
            # Set Remote Port
            remote_port_item = QTableWidgetItem(str(conn.get('remote_port', 'N/A')))
            self.network_table.setItem(row, 3, remote_port_item)
            
            # Set Protocol
            protocol_item = QTableWidgetItem(conn.get('protocol', 'Unknown'))
            self.network_table.setItem(row, 4, protocol_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{conn.get('offset', 0):x}")
            self.network_table.setItem(row, 5, offset_item)
        
        self.status_label.setText(f"Extracted {len(connections)} network connections")

    def extract_commands(self):
        """Extract command history from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting command history...")
        QApplication.processEvents()  # Update the UI
        
        # Extract commands
        commands = self.memory_parser.extract_commands()
        
        # Clear the table
        self.commands_table.setRowCount(0)
        
        # Populate the table with command information
        for cmd in commands:
            row = self.commands_table.rowCount()
            self.commands_table.insertRow(row)
            
            # Set Command
            command_item = QTableWidgetItem(cmd.get('command', 'Unknown'))
            self.commands_table.setItem(row, 0, command_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{cmd.get('offset', 0):x}")
            self.commands_table.setItem(row, 1, offset_item)
        
        self.status_label.setText(f"Extracted {len(commands)} commands")

    def extract_users(self):
        """Extract user account information from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting user information...")
        QApplication.processEvents()  # Update the UI
        
        # Extract users
        users = self.memory_parser.extract_users()
        
        # Clear the table
        self.users_table.setRowCount(0)
        
        # Populate the table with user information
        for user in users:
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            
            # Set Username
            username_item = QTableWidgetItem(user.get('username', 'Unknown'))
            self.users_table.setItem(row, 0, username_item)
            
            # Set UID
            uid_item = QTableWidgetItem(str(user.get('uid', 'N/A')))
            self.users_table.setItem(row, 1, uid_item)
            
            # Set GID
            gid_item = QTableWidgetItem(str(user.get('gid', 'N/A')))
            self.users_table.setItem(row, 2, gid_item)
            
            # Set Home directory
            home_item = QTableWidgetItem(user.get('home', 'Unknown'))
            self.users_table.setItem(row, 3, home_item)
            
            # Set Shell
            shell_item = QTableWidgetItem(user.get('shell', 'Unknown'))
            self.users_table.setItem(row, 4, shell_item)
        
        self.status_label.setText(f"Extracted {len(users)} users")

    def extract_file_listing(self):
        """Extract file paths from the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
            
        self.status_label.setText("Extracting file paths...")
        QApplication.processEvents()  # Update the UI
        
        # Extract files
        files = self.memory_parser.extract_file_listing()
        
        # Clear the table
        self.files_table.setRowCount(0)
        
        # Populate the table with file information
        for file_info in files:
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            
            # Set File Path
            path_item = QTableWidgetItem(file_info.get('path', 'Unknown'))
            self.files_table.setItem(row, 0, path_item)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{file_info.get('offset', 0):x}")
            self.files_table.setItem(row, 1, offset_item)
        
        self.status_label.setText(f"Extracted {len(files)} file paths")

    def show_string_search(self):
        """Show the string search tab"""
        # Switch to the strings tab
        for i in range(self.analysis_tabs.count()):
            if self.analysis_tabs.tabText(i) == "Strings":
                self.analysis_tabs.setCurrentIndex(i)
                break
        
        # Set focus to the search text field
        self.search_text.setFocus()

    def search_strings(self):
        """Search for strings in the memory dump"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
        
        search_text = self.search_text.text()
        if not search_text:
            QMessageBox.warning(self, "Empty Search", "Please enter a string to search for.")
            return
        
        self.status_label.setText(f"Searching for '{search_text}'...")
        QApplication.processEvents()  # Update the UI
        
        # Perform the search
        results = self.memory_parser.search_string(search_text)
        
        # Clear the table
        self.strings_table.setRowCount(0)
        
        # Populate the table with search results
        for result in results:
            row = self.strings_table.rowCount()
            self.strings_table.insertRow(row)
            
            # Set memory offset
            offset_item = QTableWidgetItem(f"0x{result.get('offset', 0):x}")
            self.strings_table.setItem(row, 0, offset_item)
            
            # Set match string
            match_item = QTableWidgetItem(result.get('match', 'Unknown'))
            self.strings_table.setItem(row, 1, match_item)
            
            # Set context
            context_item = QTableWidgetItem(result.get('context', 'Unknown'))
            self.strings_table.setItem(row, 2, context_item)
        
        self.status_label.setText(f"Found {len(results)} matches for '{search_text}'")

    def predefined_search(self, pattern):
        """Perform a predefined search"""
        self.search_text.setText(pattern)
        self.search_strings()

    def apply_filter(self, table, filter_text, columns):
        """Apply text filter to a table"""
        if not filter_text:
            # Show all rows if filter is empty
            for row in range(table.rowCount()):
                table.setRowHidden(row, False)
            return
        
        filter_text = filter_text.lower()
        
        # Hide rows that don't match the filter
        for row in range(table.rowCount()):
            match = False
            
            for col in columns:
                item = table.item(row, col)
                if item and filter_text in item.text().lower():
                    match = True
                    break
            
            table.setRowHidden(row, not match)

    def show_context_menu(self, table, pos):
        """Show context menu for a table"""
        global_pos = table.mapToGlobal(pos)
        
        # Create the context menu
        menu = QMenu()
        
        # Get the selected row's data
        selected_rows = table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Add "View in Hex" action
        view_hex_action = menu.addAction("View in Hex")
        
        # Add "Copy to Clipboard" action
        copy_action = menu.addAction("Copy to Clipboard")
        
        # Add "Export Selected" action
        export_selected_action = menu.addAction("Export Selected")
        
        # Show the menu and get the selected action
        action = menu.exec(global_pos)
        
        if action == view_hex_action:
            # Get offset from the table
            offset_col = -1
            for col in range(table.columnCount()):
                if "offset" in table.horizontalHeaderItem(col).text().lower():
                    offset_col = col
                    break
            
            if offset_col != -1:
                offset_item = table.item(selected_row, offset_col)
                if offset_item:
                    offset_text = offset_item.text()
                    try:
                        # Convert from hex string if needed
                        if offset_text.startswith("0x"):
                            offset = int(offset_text, 16)
                        else:
                            offset = int(offset_text)
                        
                        # Switch to hex view tab and go to offset
                        for i in range(self.analysis_tabs.count()):
                            if self.analysis_tabs.tabText(i) == "Hex View":
                                self.analysis_tabs.setCurrentIndex(i)
                                break
                        
                        # Set the offset in the input field and go there
                        self.offset_edit.setText(offset_text)
                        self.go_to_offset()
                    except:
                        pass
        
        elif action == copy_action:
            # Copy all cell values from the selected row
            row_data = []
            for col in range(table.columnCount()):
                item = table.item(selected_row, col)
                if item:
                    row_data.append(item.text())
            
            # Join with tabs and copy to clipboard
            QApplication.clipboard().setText("\t".join(row_data))
        
        elif action == export_selected_action:
            # Export only the selected row(s)
            rows = set()
            for index in table.selectedIndexes():
                rows.add(index.row())
            
            if rows:
                # Get the tab name for the default filename
                tab_name = "data"
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.widget(i) is table.parent():
                        tab_name = self.analysis_tabs.tabText(i).lower()
                        break
                
                self.export_selected_rows(table, rows, f"{tab_name}_selected")

    def view_process_memory(self):
        """View memory for the selected process"""
        selected_rows = self.processes_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Get offset from the Offset column (column 5)
        offset_item = self.processes_table.item(selected_row, 5)
        if offset_item:
            offset_text = offset_item.text()
            try:
                # Convert from hex string
                if offset_text.startswith("0x"):
                    offset = int(offset_text, 16)
                else:
                    offset = int(offset_text)
                
                # Switch to hex view tab and go to offset
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.tabText(i) == "Hex View":
                        self.analysis_tabs.setCurrentIndex(i)
                        break
                
                # Set the offset in the input field and go there
                self.offset_edit.setText(offset_text)
                self.go_to_offset()
            except:
                pass

    def view_network_memory(self):
        """View memory for the selected network connection"""
        selected_rows = self.network_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Get offset from the Offset column (column 5)
        offset_item = self.network_table.item(selected_row, 5)
        if offset_item:
            offset_text = offset_item.text()
            try:
                # Convert from hex string
                if offset_text.startswith("0x"):
                    offset = int(offset_text, 16)
                else:
                    offset = int(offset_text)
                
                # Switch to hex view tab and go to offset
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.tabText(i) == "Hex View":
                        self.analysis_tabs.setCurrentIndex(i)
                        break
                
                # Set the offset in the input field and go there
                self.offset_edit.setText(offset_text)
                self.go_to_offset()
            except:
                pass

    def view_string_memory(self):
        """View memory for the selected string"""
        selected_rows = self.strings_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        selected_row = selected_rows[0].row()
        
        # Get offset from the Offset column (column 0)
        offset_item = self.strings_table.item(selected_row, 0)
        if offset_item:
            offset_text = offset_item.text()
            try:
                # Convert from hex string
                if offset_text.startswith("0x"):
                    offset = int(offset_text, 16)
                else:
                    offset = int(offset_text)
                
                # Switch to hex view tab and go to offset
                for i in range(self.analysis_tabs.count()):
                    if self.analysis_tabs.tabText(i) == "Hex View":
                        self.analysis_tabs.setCurrentIndex(i)
                        break
                
                # Set the offset in the input field and go there
                self.offset_edit.setText(offset_text)
                self.go_to_offset()
            except:
                pass

    def go_to_offset(self):
        """Go to the specified offset in the hex view"""
        if not self.memory_parser:
            QMessageBox.warning(self, "No Memory Dump", "Please open a memory dump file first.")
            return
        
        offset_text = self.offset_edit.text()
        if not offset_text:
            return
        
        try:
            # Convert from hex string if needed
            if offset_text.startswith("0x"):
                offset = int(offset_text, 16)
            else:
                offset = int(offset_text)
            
            # Read data from the offset
            data = self.memory_parser.read_data(offset, 1024)  # Read 1KB of data
            
            if data:
                # Set the data in the hex view
                self.hex_view.set_data(data, offset)
                self.status_label.setText(f"Viewing memory at offset: {offset_text}")
            else:
                QMessageBox.warning(self, "Error", "Could not read data from the specified offset.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", "Please enter a valid integer offset.")

    def go_to_prev(self):
        """Go to the previous page in the hex view"""
        if not self.memory_parser:
            return
        
        # Calculate new offset (1KB back)
        current_offset = self.hex_view.current_address
        new_offset = max(0, current_offset - 1024)
        
        # Update the offset field
        self.offset_edit.setText(f"0x{new_offset:x}")
        
        # Go to the new offset
        self.go_to_offset()

    def go_to_next(self):
        """Go to the next page in the hex view"""
        if not self.memory_parser:
            return
        
        # Calculate new offset (1KB forward)
        current_offset = self.hex_view.current_address
        new_offset = current_offset + 1024
        
        # Make sure we don't go past the end of the file
        if new_offset < self.memory_parser.size:
            # Update the offset field
            self.offset_edit.setText(f"0x{new_offset:x}")
            
            # Go to the new offset
            self.go_to_offset()

    def add_offset_bookmark(self):
        """Add a bookmark for the current offset"""
        if not self.memory_parser:
            return
        
        current_offset = self.hex_view.current_address
        
        # Prompt for bookmark name
        name, ok = QInputDialog.getText(self, "Add Bookmark", 
                                    "Enter a name for this bookmark:")
        
        if ok and name:
            # Create bookmark text (name + offset)
            bookmark_text = f"{name} (0x{current_offset:x})"
            
            # Add to combo box if not already present
            if self.bookmark_combo.findText(bookmark_text) == -1:
                self.bookmark_combo.addItem(bookmark_text, current_offset)
                self.status_label.setText(f"Bookmark added: {bookmark_text}")

    def goto_bookmark(self):
        """Go to the selected bookmark offset"""
        if self.bookmark_combo.currentIndex() == -1:
            return
        
        # Get the stored offset
        offset = self.bookmark_combo.currentData()
        
        # Update the offset field
        self.offset_edit.setText(f"0x{offset:x}")
        
        # Go to the offset
        self.go_to_offset()

    def remove_bookmark(self):
        """Remove the selected bookmark"""
        current_index = self.bookmark_combo.currentIndex()
        if current_index == -1:
            return
        
        self.bookmark_combo.removeItem(current_index)
        self.status_label.setText("Bookmark removed")

    def detect_structure(self, structure_type):
        """Detect a Linux data structure at the current offset"""
        if not self.memory_parser:
            return
        
        current_offset = self.hex_view.current_address
        
        # Check if we have this type of structure pattern defined
        if structure_type in self.memory_parser.patterns:
            pattern = self.memory_parser.patterns[structure_type]
            
            # Read a larger chunk of data to analyze
            data = self.memory_parser.read_data(current_offset, 4096)
            if not data:
                self.structure_view.setText(f"Could not read data at offset 0x{current_offset:x}")
                return
            
            # Look for the pattern
            pattern_pos = data.find(pattern)
            if pattern_pos != -1:
                # Found the pattern
                self.structure_view.setText(f"Found potential {structure_type} at offset 0x{current_offset + pattern_pos:x}\n\n")
                
                # Extract context around the pattern
                context_start = max(0, pattern_pos - 64)
                context_end = min(len(data), pattern_pos + len(pattern) + 256)
                context_data = data[context_start:context_end]
                
                # Display raw data
                self.structure_view.append("Raw data around structure:\n")
                self._display_hex_dump(context_data, current_offset + context_start)
                
                # Try to extract specific fields based on structure type
                if structure_type == 'task_struct':
                    self._analyze_task_struct(data, pattern_pos, current_offset)
                elif structure_type == 'mm_struct':
                    self._analyze_mm_struct(data, pattern_pos, current_offset)
                elif structure_type == 'files_struct':
                    self._analyze_files_struct(data, pattern_pos, current_offset)
                elif structure_type == 'socket':
                    self._analyze_socket_struct(data, pattern_pos, current_offset)
            else:
                self.structure_view.setText(f"No {structure_type} pattern found at offset 0x{current_offset:x}")
        else:
            self.structure_view.setText(f"No pattern defined for {structure_type} structure")

    def _display_hex_dump(self, data, base_offset=0):
        """Display a hex dump of the data in the structure view"""
        for i in range(0, len(data), 16):
            # Get chunk of up to 16 bytes
            chunk = data[i:i+16]
            
            # Format address
            addr = base_offset + i
            line = f"{addr:08x}: "
            
            # Format hex part
            hex_part = ""
            for j in range(min(16, len(chunk))):
                hex_part += f"{chunk[j]:02x} "
                if j == 7:  # Add extra space in the middle
                    hex_part += " "
            
            # Pad hex part if needed
            hex_part = hex_part.ljust(16*3 + 1)
            
            # Format ASCII part
            ascii_part = " |"
            for byte in chunk:
                if 32 <= byte <= 126:  # Printable ASCII
                    ascii_part += chr(byte)
                else:
                    ascii_part += "."
            ascii_part += "|"
            
            self.structure_view.append(line + hex_part + ascii_part)

    def _analyze_task_struct(self, data, pos, base_offset):
        """Try to analyze a task_struct at the given position"""
        # This is a simplified analysis - in a real implementation, you would need
        # proper knowledge of the task_struct layout for the specific kernel version
        self.structure_view.append("\nAttempting to analyze task_struct fields:\n")
        
        # Look for common fields
        # PID field often follows the comm field (process name)
        pid_offset = data.find(b'pid', pos)
        if pid_offset != -1 and pid_offset < pos + 200:
            # Look for a number pattern after pid
            for i in range(pid_offset + 3, min(pid_offset + 20, len(data))):
                if data[i] >= 0x30 and data[i] <= 0x39:  # ASCII digit
                    # Found potential PID value
                    pid_value = 0
                    for j in range(i, min(i + 10, len(data))):
                        if data[j] >= 0x30 and data[j] <= 0x39:
                            pid_value = pid_value * 10 + (data[j] - 0x30)
                        else:
                            break
                    self.structure_view.append(f"  PID: {pid_value} (at offset 0x{base_offset + i:x})")
                    break
        
        # Look for comm field (process name)
        comm_offset = data.find(b'comm', pos)
        if comm_offset != -1 and comm_offset < pos + 200:
            # Process name usually follows comm field
            name_start = comm_offset + 5
            name_end = name_start
            for i in range(name_start, min(name_start + 30, len(data))):
                if data[i] == 0:  # Null terminator
                    name_end = i
                    break
            
            if name_end > name_start:
                process_name = data[name_start:name_end].decode('utf-8', errors='replace')
                self.structure_view.append(f"  Process Name: {process_name} (at offset 0x{base_offset + name_start:x})")
        
        # Parent process reference
        parent_offset = data.find(b'parent', pos)
        if parent_offset != -1 and parent_offset < pos + 200:
            self.structure_view.append(f"  Parent process reference at offset 0x{base_offset + parent_offset:x}")
        
        # State field
        state_offset = data.find(b'state', pos)
        if state_offset != -1 and state_offset < pos + 200:
            # Read a 8-byte value after state
            if state_offset + 8 < len(data):
                state_value = int.from_bytes(data[state_offset+5:state_offset+9], byteorder='little')
                self.structure_view.append(f"  State: {state_value} (at offset 0x{base_offset + state_offset + 5:x})")

    def _analyze_mm_struct(self, data, pos, base_offset):
        """Try to analyze an mm_struct at the given position"""
        self.structure_view.append("\nAttempting to analyze mm_struct fields:\n")
        
        # Look for common memory-related fields
        mmap_offset = data.find(b'mmap', pos)
        if mmap_offset != -1 and mmap_offset < pos + 200:
            self.structure_view.append(f"  mmap reference at offset 0x{base_offset + mmap_offset:x}")
        
        pgd_offset = data.find(b'pgd', pos)
        if pgd_offset != -1 and pgd_offset < pos + 200:
            self.structure_view.append(f"  pgd (Page Global Directory) at offset 0x{base_offset + pgd_offset:x}")
        
        # Virtual memory area bounds
        start_code_offset = data.find(b'start_code', pos)
        if start_code_offset != -1 and start_code_offset < pos + 300:
            self.structure_view.append(f"  start_code at offset 0x{base_offset + start_code_offset:x}")
        
        end_code_offset = data.find(b'end_code', pos)
        if end_code_offset != -1 and end_code_offset < pos + 300:
            self.structure_view.append(f"  end_code at offset 0x{base_offset + end_code_offset:x}")
        
        start_data_offset = data.find(b'start_data', pos)
        if start_data_offset != -1 and start_data_offset < pos + 300:
            self.structure_view.append(f"  start_data at offset 0x{base_offset + start_data_offset:x}")
        
        end_data_offset = data.find(b'end_data', pos)
        if end_data_offset != -1 and end_data_offset < pos + 300:
            self.structure_view.append(f"  end_data at offset 0x{base_offset + end_data_offset:x}")

    def _analyze_files_struct(self, data, pos, base_offset):
        """Try to analyze a files_struct at the given position"""
        self.structure_view.append("\nAttempting to analyze files_struct fields:\n")
        
        # Look for common file-related fields
        fdt_offset = data.find(b'fdt', pos)
        if fdt_offset != -1 and fdt_offset < pos + 200:
            self.structure_view.append(f"  fdt (File Descriptor Table) at offset 0x{base_offset + fdt_offset:x}")
        
        fdtab_offset = data.find(b'fdtab', pos)
        if fdtab_offset != -1 and fdtab_offset < pos + 200:
            self.structure_view.append(f"  fdtab at offset 0x{base_offset + fdtab_offset:x}")
        
        fd_offset = data.find(b'fd', pos)
        if fd_offset != -1 and fd_offset < pos + 100:
            self.structure_view.append(f"  fd array at offset 0x{base_offset + fd_offset:x}")

    def _analyze_socket_struct(self, data, pos, base_offset):
        """Try to analyze a socket struct at the given position"""
        self.structure_view.append("\nAttempting to analyze socket struct fields:\n")
        
        # Look for socket-related fields
        state_offset = data.find(b'state', pos)
        if state_offset != -1 and state_offset < pos + 200:
            if state_offset + 4 < len(data):
                state_value = int.from_bytes(data[state_offset+5:state_offset+9], byteorder='little')
                self.structure_view.append(f"  Socket state: {state_value} (at offset 0x{base_offset + state_offset + 5:x})")
        
        # Look for protocol family, type, etc.
        family_offset = data.find(b'family', pos)
        if family_offset != -1 and family_offset < pos + 200:
            if family_offset + 6 < len(data):
                family = data[family_offset+6]
                family_str = "Unknown"
                if family == 2:
                    family_str = "AF_INET (IPv4)"
                elif family == 10:
                    family_str = "AF_INET6 (IPv6)"
                elif family == 1:
                    family_str = "AF_UNIX"
                self.structure_view.append(f"  Protocol family: {family} ({family_str}) (at offset 0x{base_offset + family_offset + 6:x})")
        
        type_offset = data.find(b'type', pos)
        if type_offset != -1 and type_offset < pos + 200:
            if type_offset + 5 < len(data):
                sock_type = data[type_offset+5]
                type_str = "Unknown"
                if sock_type == 1:
                    type_str = "SOCK_STREAM"
                elif sock_type == 2:
                    type_str = "SOCK_DGRAM"
                elif sock_type == 3:
                    type_str = "SOCK_RAW"
                self.structure_view.append(f"  Socket type: {sock_type} ({type_str}) (at offset 0x{base_offset + type_offset + 5:x})")
        
        # Look for IP addresses in the vicinity
        ip_matches = re.finditer(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', data)
        for ip_match in ip_matches:
            ip_start = ip_match.start()
            # Only consider IPs close to the socket structure
            if pos - 100 <= ip_start <= pos + 300:
                ip_str = ip_match.group(0).decode('ascii')
                self.structure_view.append(f"  Possible IP address: {ip_str} (at offset 0x{base_offset + ip_start:x})")

class HexViewWidget(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        font = QFont("Courier New")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.current_address = 0
        self.highlighted_offsets = []
        
    def set_data(self, data, address=None):
        """Set data to display in hex view, optionally with a specific starting address"""
        self.clear()
        if address is not None:
            self.current_address = address
        else:
            # Keep current_address as is
            pass
            
        line_address = self.current_address
        hex_text = ""
        
        # Calculate number of complete lines and remainder
        num_lines = len(data) // 16
        remainder = len(data) % 16
        
        # Process all complete lines (16 bytes each)
        for i in range(num_lines):
            chunk = data[i*16:(i+1)*16]
            line = self._format_hex_line(chunk, line_address)
            hex_text += line + "\n"
            line_address += 16
            
        # Process remainder if any
        if remainder > 0:
            chunk = data[num_lines*16:]
            line = self._format_hex_line(chunk, line_address)
            hex_text += line
            
        self.setPlainText(hex_text)
        
    def _format_hex_line(self, chunk, address):
        """Format a single line of hex output with address, hex values, and ASCII"""
        # Address part
        line = f"{address:08x}: "
        
        # Hex part (left side)
        hex_part = ""
        for i in range(8):  # First 8 bytes
            if i < len(chunk):
                hex_part += f"{chunk[i]:02x} "
            else:
                hex_part += "   "
        
        hex_part += " "  # Extra space in the middle
        
        # Hex part (right side)
        for i in range(8, 16):  # Last 8 bytes
            if i < len(chunk):
                hex_part += f"{chunk[i]:02x} "
            else:
                hex_part += "   "
        
        # ASCII part
        ascii_part = "|"
        for byte in chunk:
            if 32 <= byte <= 126:  # Printable ASCII
                ascii_part += chr(byte)
            else:
                ascii_part += "."
        
        # Pad ASCII part if needed
        ascii_part += " " * (16 - len(chunk))
        ascii_part += "|"
        
        return line + hex_part + ascii_part
    
    def highlight_offset(self, offset_range, color=QColor(255, 255, 0, 80)):
        """Highlight a range of bytes in the hex display"""
        # This would need to be implemented to visually highlight items of interest
        # This is a stub implementation that would be completed in a real application
        self.highlighted_offsets.append((offset_range, color))
        # Real implementation would need to use QTextCharFormat and setExtraSelections
        # to highlight specific ranges in the text
