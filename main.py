# main.py
import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QIcon
from qt_material import apply_stylesheet
from analyzer.gui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set default font size larger
    default_font = QFont("Segoe UI", 12)
    app.setFont(default_font)
    
    # Enhanced IOTF Red theme configuration with better color harmony
    extra = {
        # Primary colors - IOTF Red with harmonious shades
        'primary': '#FFFFFF',          # Changed to white
        'primary_light': '#FFFFFF',    # Changed to white
        'primary_dark': '#FFFFFF',     # Changed to white
        
        # Secondary colors - Darker grays with slight red tint
        'secondary': '#2A2426',        # Dark gray with red tint
        'secondary_light': '#3A3436',  # Medium gray with red tint
        'secondary_dark': '#1A1416',   # Very dark gray with red tint
        
        # Background colors - Warmer dark tones
        'background': '#1E1B1C',       # Very dark warm gray
        'surface': '#252122',          # Dark warm gray
        'dialog': '#2D2829',           # Medium warm gray
        
        # Accent colors - Complementary palette
        'primary_color': '#FFFFFF',    # Changed to white
        'secondary_color': '#FFFFFF',  # Changed to white
        'success': '#2ECC71',          # Green
        'warning': '#F1C40F',          # Yellow
        'danger': '#E74C3C',           # Red
        
        # Search highlight colors - Warmer tones
        'search_highlight': '#5D4D1E',     # Warm dark yellow
        'search_highlight_text': '#FFE6A0', # Warm light yellow
        
        # Status colors - Harmonious with theme
        'deleted_color': '#6B1D1D',        # Dark warm red
        'deleted_text': '#FFFFFF',         # Changed to white for better visibility
        
        # Text colors
        'text': '#FFFFFF',             # Pure white for primary text
        'text_light': '#E0E0E0',      # Light gray for secondary text
        'text_dark': '#BDBDBD',       # Medium gray for disabled text
        
        # Sample/Placeholder text styling
        'placeholder_text': '#8B8D90',      # Lighter gray for placeholder text
        'sample_data_color': '#A0A4A8',     # Slightly brighter gray for sample data
        'empty_state_color': '#787C80',     # Medium gray for empty states
        
        # Font settings - Improved readability
        'font_family': 'Segoe UI',
        'font_size': '13px',                # Increased base font size
        'font_size_large': '15px',          # Larger headers
        'font_size_small': '12px',          # Increased small text
        'line_height': '2',                 # Increased line height
        
        # Density and spacing - More comfortable
        'density_scale': '0',         # Default density
        'spacing': '12',              # Increased spacing
        
        # Component specific styling
        'button_radius': '6px',       # More rounded buttons
        'tab_height': '40px',         # Taller tabs
        'tab_radius': '6px',          # More rounded tabs
        'tab_indicator_height': '3px', # Thicker indicator
        'button_padding': '12px',     # Horizontal padding
        'button_icon_size': '20px',   # Larger icons
        'border_radius': '6px',       # More rounded corners
        'border_width': '1px',
        
        # Card and panel styling
        'card_radius': '8px',         # More rounded cards
        'card_padding': '20px',       # More padding
        'card_elevation': '3',        # Slightly more elevation
        
        # Table styling
        'table_radius': '6px',
        'table_selected': '#C41016',  # Darker red for selection
        'table_hover': '#E31E2430',   # Semi-transparent red
        
        # Scrollbar styling
        'scrollbar_size': '12px',     # Thicker scrollbars
        'scrollbar_radius': '6px',    # Rounded scrollbars
        
        # Focus and selection
        'focus_color': '#E31E2440',
        'hover_color': '#FFFFFF20',
        'selected_color': '#C41016',
        
        # Disabled state
        'disabled_opacity': '0.38',
        'disabled_color': '#BDBDBD',
        
        # Protocol and frame info text
        'protocol_text': '#FFFFFF',    # White for protocol headers
        'frame_info_text': '#FFFFFF',  # White for frame info
        'detail_text': '#FFFFFF',      # Changed to white
        'status_text': '#FFFFFF',      # White for status messages
        # Font settings - Improved readability
        'protocol_font_size': '15px',       # Increased size for protocol text
        'frame_info_font_size': '15px',     # Increased size for frame info
        
        # Button specific styling
        'button_text': '#FFFFFF',
        'button_radius': '4px',
        'button_padding': '6px',
        'button_height': '28px',
        'button_font_size': '11px',
        'button_font_weight': '500',
        
        # Update the case management buttons styling in the "extra" dictionary
        'case_management_buttons': {
            'min_width': '110px',
            'max_width': '110px',
            'min_height': '28px',
            'max_height': '28px',
            'padding': '0px 5px',
            'margin': '3px',
            'font_size': '12px',
            'font_weight': '600',
            'text_align': 'center',
            'line_height': '1.2',
            'background_color': '#2A2426',
            'border': '1px solid #3A3436',
            'border_radius': '4px',
            'color': '#FFFFFF'  # Added white text color for buttons
        },
        
        # Primary Action Buttons
        'primary_action_buttons': {
            'background_color': '#E31E24',
            'border': 'none'
        },
        
        'primary_action_buttons_hover': {
            'background_color': '#FF4D54'
        },
        
        'primary_action_buttons_pressed': {
            'background_color': '#C41016'
        },
        
        # Secondary Action Buttons
        'secondary_action_buttons': {
            'background_color': '#2A2426',
            'border': '1px solid #3A3436'
        },
        
        'secondary_action_buttons_hover': {
            'background_color': '#3A3436'
        },
        
        # Compact Buttons (for toolbars and tight spaces)
        'compact_buttons': {
            'min_width': '80px',
            'padding': '4px 12px',
            'min_height': '32px'
        },
        
        # Button Groups
        'button_groups': {
            'background': 'transparent',
            'margin': '0px',
            'padding': '0px'
        },
        
        'button_groups_push_button': {
            'margin_right': '-1px',
            'border_radius': '0px'
        },
        
        'button_groups_push_button_first_child': {
            'border_top_left_radius': '6px',
            'border_bottom_left_radius': '6px'
        },
        
        'button_groups_push_button_last_child': {
            'border_top_right_radius': '6px',
            'border_bottom_right_radius': '6px',
            'margin_right': '0px'
        },
        
        # Case Management Section
        'case_management': {
            'background_color': '#252122',
            'border_radius': '8px',
            'padding': '12px',
            'margin': '4px'
        },
        
        'case_management_label': {
            'color': '#E0E0E0',
            'font_size': '13px',
            'margin_bottom': '4px'
        },
        
        'case_management_push_button': {
            'margin_bottom': '8px'
        },
        
        # Case Info Labels
        'case_info_labels': {
            'color': '#FFFFFF',  # Changed to white
            'font_size': '13px',
            'padding': '4px 0px'
        }
    }
    
    # Apply the material theme with IOTF red base
    apply_stylesheet(app, 'dark_red.xml', invert_secondary=True, extra=extra)
    
    # Apply additional global styles with improved typography and spacing
    app.setStyleSheet("""
        QMainWindow, QDialog {
            background: #1E1B1C;
        }
        QWidget {
            font-size: 12px;
        }
        QLabel {
            font-size: 12px;
            color: #FFFFFF;
        }
        QTabWidget::pane {
            background-color: #1A1416;
            border: 1px solid #3A3436;
            border-radius: 6px;
            margin-top: -1px;
        }
        QTabBar::tab {
            background-color: #252122;
            color: #E0E0E0;
            border: 1px solid #3A3436;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 8px 16px;
            min-width: 120px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #C41016;
            color: #FFFFFF;
            font-weight: bold;
        }
        QTabBar::tab:!selected:hover {
            background-color: #2A2426;
        }
        QTreeView, QTableView {
            background: #252122;
            color: #FFFFFF;
            alternate-background-color: #2D2829;
            border: 1px solid #3A3436;
            border-radius: 6px;
            font-size: 12px;
        }
        QTreeView::item, QTableView::item {
            padding: 4px;
            min-height: 24px;
        }
        QTreeView::item:selected, QTableView::item:selected {
            background: #C41016;
        }
        QHeaderView::section {
            background-color: #252122;
            color: #E0E0E0;
            font-weight: bold;
            padding: 8px;
            border: none;
            border-right: 1px solid #3A3436;
            border-bottom: 1px solid #3A3436;
        }
        QPushButton {
            background-color: #252122;
            border: 1px solid #3A3436;
            border-radius: 4px;
            color: #E0E0E0;
            padding: 6px 12px;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #2A2426;
            border-color: #4A4446;
        }
        QPushButton:pressed {
            background-color: #C41016;
            border-color: #E31E24;
        }
        QLineEdit, QTextEdit, QPlainTextEdit {
            font-size: 12px;
            padding: 8px;
            color: #FFFFFF;
            border-radius: 6px;
            background: #252122;
            selection-background-color: #C41016;  
        }
        QScrollBar:vertical {
            background-color: #1A1416;
            width: 12px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background-color: #3A3436;
            border-radius: 6px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #4A4446;
        }
        QScrollBar:horizontal {
            background-color: #1A1416;
            height: 12px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background-color: #3A3436;
            border-radius: 6px;
            min-width: 20px;
        }
        QScrollBar::handle:horizontal:hover {
            background-color: #4A4446;
        }
        QGroupBox {
            background-color: #1E1B1C;
            border: 1px solid #3A3436;
            border-radius: 4px;
            margin-top: 16px;
            padding: 12px;
        }
        QGroupBox::title {
            color: #FFFFFF;  # Changed from #E31E24 to white
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 5px;
        }
        QComboBox {
            background-color: #252122;
            border: 1px solid #3A3436;
            border-radius: 4px;
            padding: 4px 8px;
            min-width: 100px;
            color: #E0E0E0;
        }
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        QComboBox::down-arrow {
            image: url(resources/down-arrow.png);
            width: 12px;
            height: 12px;
        }
        QWidget[class="statistics-section"] {
            background-color: #1E1B1C;
            border: 1px solid #3A3436;
            border-radius: 4px;
            padding: 12px;
            margin: 4px;
        }
        QWidget[class="chart-container"] {
            background-color: #252122;
            border-radius: 4px;
            padding: 12px;
        }
        QStatusBar {
            background-color: #1A1416;
            color: #E0E0E0;
            border-top: 1px solid #3A3436;
            min-height: 30px;
            padding: 0 10px;
        }
        QStatusBar::item {
            border: none;
            padding: 0;
            margin: 0;
        }
        QStatusBar QLabel {
            color: #FFFFFF;  /* Changed from #FF4D54 to white */
            font-weight: 500;
            padding: 5px 10px;
            margin: 0;
            min-height: 30px;
            qproperty-alignment: AlignVCenter;
        }
        QStatusBar QLabel[status="not-capturing"] {
            background-color: #2A1F1F;  /* Slightly reddish dark background */
            border-radius: 4px;
            padding: 5px 15px;
        }
        QLabel[sectionHeader="true"] {
            color: #FFFFFF;  # Changed from #E31E24 to white
            font-size: 13px;
            font-weight: bold;
            padding: 8px 0px;
        }
        QTableWidget, QTreeWidget {
            background-color: #1E1B1C;
            border: 1px solid #3A3436;
            border-radius: 4px;
            gridline-color: #3A3436;
        }
        QTableWidget::item, QTreeWidget::item {
            padding: 6px;
            border-bottom: 1px solid #2A2426;
        }
        QTableWidget::item:selected, QTreeWidget::item:selected {
            background-color: #C41016;
            color: #FFFFFF;
        }
        QLabel[class="empty-state"] {
            color: #787C80;
            font-style: italic;
            padding: 20px;
            qproperty-alignment: AlignCenter;
        }
        QLabel[class="section-title"] {
            color: #FFFFFF;
            font-size: 14px;
            font-weight: bold;
            padding: 8px 0px;
        }
        QLabel[class="data-label"] {
            color: #A0A4A8;
            font-size: 12px;
        }
        QLabel[class="data-value"] {
            color: #E0E0E0;
            font-size: 12px;
            font-weight: bold;
        }
        /* Extracted Files Table Styling */
        QTableWidget#extractedFilesTable {
            background-color: #1A1416;
            border: 1px solid #3A3436;
            border-radius: 4px;
            gridline-color: #2A2426;
            padding: 2px;
        }

        QTableWidget#extractedFilesTable::item {
            padding: 6px;
            border-bottom: 1px solid #2A2426;
            color: #E0E0E0;
        }

        QTableWidget#extractedFilesTable::item:selected {
            background-color: #C41016;
            color: #FFFFFF;
        }

        /* Column-specific styling */
        QTableWidget#extractedFilesTable QTableWidgetItem[column="0"] {  /* ID column */
            color: #787C80;
            font-size: 11px;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="1"] {  /* Filename column */
            color: #FFFFFF;  /* Changed from #E31E24 to white */
            font-family: 'Consolas', monospace;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="2"] {  /* Type column */
            color: #A0A4A8;
            font-size: 11px;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="3"] {  /* Size column */
            color: #E0E0E0;
            font-family: 'Consolas', monospace;
            font-size: 11px;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="4"] {  /* Source column */
            color: #FFFFFF;  /* Changed from #FF4D54 to white */
            font-weight: bold;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="5"] {  /* Hash column */
            color: #787C80;
            font-family: 'Consolas', monospace;
            font-size: 11px;
        }

        /* Header Styling */
        QHeaderView::section {
            background-color: #252122;
            color: #E0E0E0;
            font-weight: bold;
            padding: 8px;
            border: none;
            border-right: 1px solid #3A3436;
            border-bottom: 1px solid #3A3436;
        }

        /* Action Buttons in Table */
        QPushButton[class="table-action"] {
            background-color: #252122;
            border: 1px solid #3A3436;
            border-radius: 3px;
            color: #FFFFFF;
            padding: 4px 8px;
            margin: 2px;
            min-width: 70px;
            max-width: 70px;
            height: 24px;
            font-size: 11px;
            font-weight: 500;
            text-align: center;
        }

        /* Preview Button */
        QPushButton[class="action-preview"] {
            background-color: #1E2A3A;
            border: 1px solid #2E3A4A;
            color: #FFFFFF;
        }

        QPushButton[class="action-preview"]:hover {
            background-color: #2E3A4A;
            border: 1px solid #3E4A5A;
        }

        /* Save Button */
        QPushButton[class="action-save"] {
            background-color: #1E3A23;
            border: 1px solid #2E5A33;
            color: #FFFFFF;
        }

        QPushButton[class="action-save"]:hover {
            background-color: #2E5A33;
            border: 1px solid #3E6A43;
        }

        /* Delete Button */
        QPushButton[class="action-delete"] {
            background-color: #3A1E1E;
            border: 1px solid #4A2E2E;
            color: #FFFFFF;
        }

        QPushButton[class="action-delete"]:hover {
            background-color: #4A2E2E;
            border: 1px solid #5A3E3E;
        }

        /* Table Row Styling */
        QTableWidget#extractedFilesTable {
            background-color: #1A1416;
            border: 1px solid #3A3436;
            border-radius: 4px;
            gridline-color: #2A2426;
        }

        QTableWidget#extractedFilesTable::item {
            padding: 8px;
            border-bottom: 1px solid #2A2426;
        }

        /* Actions Column */
        QTableWidget#extractedFilesTable QWidget[class="action-widget"] {
            background-color: transparent;
            padding: 2px;
        }

        /* Column Headers */
        QHeaderView::section {
            background-color: #252122;
            color: #E0E0E0;
            font-weight: bold;
            padding: 8px;
            border: none;
            border-right: 1px solid #3A3436;
            border-bottom: 1px solid #3A3436;
        }

        /* File Types */
        QTableWidget#extractedFilesTable QTableWidgetItem[column="1"] {  /* Filename */
            color: #FFFFFF;  /* Changed from #E31E24 to white */
            font-family: 'Consolas', monospace;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="2"] {  /* Type */
            color: #A0A4A8;
        }

        QTableWidget#extractedFilesTable QTableWidgetItem[column="4"] {  /* Source */
            color: #FFFFFF;  /* Changed from #FF4D54 to white */
            font-weight: bold;
        }

        /* Progress Bar in Actions */
        QProgressBar {
            border: 1px solid #3A3436;
            border-radius: 2px;
            background-color: #1A1416;
            text-align: center;
            max-height: 12px;
        }

        QProgressBar::chunk {
            background-color: #2E5A33;
        }

        /* Row Selection */
        QTableWidget#extractedFilesTable::item:selected {
            background-color: #C41016;
            color: #FFFFFF;
        }

        QTableWidget#extractedFilesTable::item:hover {
            background-color: #2A2426;
        }

        /* Links and special text */
        QLabel[class="link"], QLabel[class="special-text"] {
            color: #FFFFFF;
        }
        
        /* Evidence items and case notes */
        QTreeWidget::item, QTableWidget::item {
            color: #FFFFFF;
        }
        
        /* Headers and titles */
        QLabel[class="header"], QLabel[class="title"] {
            color: #FFFFFF;
        }
        
        /* Case management text */
        QLabel[class="case-management"], QLabel[class="evidence-items"], QLabel[class="case-notes"] {
            color: #FFFFFF;
        }
        
        /* Report generation text */
        QLabel[class="report-generation"] {
            color: #FFFFFF;
        }
        
        /* All QLabels with red text */
        QLabel {
            color: #FFFFFF;
        }
        
        /* Table headers and content */
        QTableWidget::item, QTreeWidget::item {
            color: #FFFFFF;
        }
        
        QHeaderView::section {
            color: #FFFFFF;
        }
        
        /* Evidence type and description */
        QTableWidget#evidenceTable QTableWidgetItem {
            color: #FFFFFF;
        }
        
        /* Case summary text */
        QLabel[class="case-summary"] {
            color: #FFFFFF;
        }
        
        /* Quick actions text */
        QLabel[class="quick-actions"] {
            color: #FFFFFF;
        }
        
        /* Recent evidence text */
        QLabel[class="recent-evidence"] {
            color: #FFFFFF;
        }
        
        /* Storage text */
        QLabel[class="storage"], QTableWidgetItem[type="storage"] {
            color: #FFFFFF;
        }
        
        /* Network text */
        QLabel[class="network"], QTableWidgetItem[type="network"] {
            color: #FFFFFF;
        }
        
        /* Memory text */
        QLabel[class="memory"], QTableWidgetItem[type="memory"] {
            color: #FFFFFF;
        }
                      
    """)
    
    # Set application icon
    icon_path = os.path.join(os.path.dirname(__file__), 'resources', 'iotf_logo.png')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
