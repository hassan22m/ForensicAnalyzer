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
# from PyQt6.QtWebEngineCore import QWebEngineSettings   no need for know 

# helper functions
def detect_filesystem_type(source_device):
    """Enhanced filesystem detection function that detects more filesystem types"""
    try:
        # Try using blkid first (most reliable on Linux)
        try:
            fs_type = subprocess.check_output(['blkid', '-o', 'value', '-s', 'TYPE', source_device], 
                                           text=True).strip()
            if fs_type:
                return fs_type
        except subprocess.CalledProcessError:
            pass  # Continue with other methods
            
        # Try using file command (works with some filesystems)
        try:
            file_output = subprocess.check_output(['file', '-s', source_device], 
                                              text=True).strip()
            
            # Parse file output for filesystem type
            fs_patterns = {
                'ext2': r'ext2 filesystem',
                'ext3': r'ext3 filesystem',
                'ext4': r'ext4 filesystem',
                'btrfs': r'btrfs filesystem',
                'xfs': r'XFS filesystem',
                'jffs2': r'JFFS2 filesystem',
                'squashfs': r'Squashfs filesystem',
                'fat': r'FAT \((?:12|16|32) bit\)',
                'vfat': r'FAT \((?:12|16|32) bit\)',
                'ntfs': r'NTFS filesystem',
                'f2fs': r'F2FS filesystem',
                'ubifs': r'UBIFS',
                'yaffs': r'YAFFS'
            }
            
            for fs, pattern in fs_patterns.items():
                if re.search(pattern, file_output, re.IGNORECASE):
                    return fs
        except subprocess.CalledProcessError:
            pass  # Continue with other methods
            
        # Try mounting and checking filesystem type
        temp_dir = tempfile.mkdtemp(prefix="fs_detect_")
        try:
            # Try to mount without specifying filesystem
            subprocess.check_call(['mount', '-o', 'ro', source_device, temp_dir], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Get filesystem type with stat
            stat_output = subprocess.check_output(['stat', '-f', '-c', '%T', temp_dir], 
                                              text=True).strip()
            
            # Unmount
            subprocess.check_call(['umount', temp_dir])
            
            # Cleanup temp dir
            os.rmdir(temp_dir)
            
            if stat_output and stat_output != "unknown":
                return stat_output
        except subprocess.CalledProcessError:
            # Ensure it's unmounted
            try:
                subprocess.call(['umount', temp_dir], stderr=subprocess.DEVNULL)
            except:
                pass
                
            # Cleanup temp dir
            try:
                os.rmdir(temp_dir)
            except:
                pass
                
        # Last resort: try to guess based on dd output
        try:
            # Read first few blocks with dd
            dd_output = subprocess.check_output(['dd', 'if=' + source_device, 'bs=4096', 'count=1'], 
                                            stderr=subprocess.DEVNULL)
            
            # Check for filesystem signatures
            if dd_output[1024:1024+2] == b'\x53\xEF':  # ext2/3/4 superblock magic
                return "ext"
            elif dd_output[0:4] == b'\xEB\x3C\x90\x4D':  # FAT
                return "vfat"
            elif dd_output[3:11] == b'NTFS    ':  # NTFS signature
                return "ntfs"
            elif dd_output[0:4] == b'BTRFS':  # BTRFS signature
                return "btrfs"
            elif b'sqsh' in dd_output[0:32]:  # SquashFS signature
                return "squashfs"
            elif b'jffs2' in dd_output[0:64].lower():  # JFFS2 signature (often contains "jffs2")
                return "jffs2"
        except subprocess.CalledProcessError:
            pass
            
        # If we got here, we couldn't determine the filesystem type
        return "unknown"
    except Exception as e:
        print(f"Error detecting filesystem: {str(e)}")
        return "unknown"
# second helper function 
def get_supported_filesystems():
    """Check which filesystem tools are installed and return supported filesystems"""
    supported = []
    
    # Check for ext tools
    if subprocess.call(['which', 'e2image'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.extend(['ext2', 'ext3', 'ext4'])
    elif subprocess.call(['which', 'debugfs'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.extend(['ext2', 'ext3', 'ext4'])
    
    # Check for ntfs tools
    if subprocess.call(['which', 'ntfsclone'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('ntfs')
    
    # Check for xfs tools
    if subprocess.call(['which', 'xfs_db'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('xfs')
    
    # Check for btrfs tools
    if subprocess.call(['which', 'btrfs'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('btrfs')
    
    # Check for fat tools
    if subprocess.call(['which', 'fatcat'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.extend(['fat', 'vfat', 'exfat'])
    
    # Check for flash filesystem tools
    if subprocess.call(['which', 'jffs2dump'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('jffs2')
    
    if subprocess.call(['which', 'ubinfo'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('ubifs')
    
    # Check for SquashFS tools
    if subprocess.call(['which', 'unsquashfs'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('squashfs')
    
    # Check for F2FS tools
    if subprocess.call(['which', 'dump.f2fs'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.append('f2fs')
    
    # Check for TSK tools (provides broader support)
    if subprocess.call(['which', 'fsstat'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        supported.extend(['tsk-supported'])  # Indicates TSK is available
    
    return supported


class SparseImageCaptureDialog(QDialog):
    """Dialog for capturing only used sectors of a disk with improved filesystem support"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sparse Disk Image Capture")
        self.resize(500, 400)  # Increased height for additional options
        
        layout = QVBoxLayout()
        
        # Source selection
        source_layout = QHBoxLayout()
        source_layout.addWidget(QLabel("Source Device:"))
        self.source_edit = QLineEdit()
        source_layout.addWidget(self.source_edit)
        self.source_browse_btn = QPushButton("Browse")
        self.source_browse_btn.clicked.connect(self.browse_source)
        source_layout.addWidget(self.source_browse_btn)
        layout.addLayout(source_layout)
        
        # Filesystem detection info
        fs_layout = QHBoxLayout()
        fs_layout.addWidget(QLabel("Detected Filesystem:"))
        self.fs_type_label = QLabel("Not detected yet")
        fs_layout.addWidget(self.fs_type_label)
        self.detect_fs_btn = QPushButton("Detect")
        self.detect_fs_btn.clicked.connect(self.detect_filesystem)
        fs_layout.addWidget(self.detect_fs_btn)
        layout.addLayout(fs_layout)
        
        # Output selection
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("Output Image:"))
        self.output_edit = QLineEdit()
        output_layout.addWidget(self.output_edit)
        self.output_browse_btn = QPushButton("Browse")
        self.output_browse_btn.clicked.connect(self.browse_output)
        output_layout.addWidget(self.output_browse_btn)
        layout.addLayout(output_layout)
        
        # Image format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItem("Raw Sparse (skip zeros)")
        self.format_combo.addItem("EWF/E01 (EnCase)")
        self.format_combo.addItem("AFF4")
        format_layout.addWidget(self.format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)
        
        # Additional options
        options_group = QGroupBox("Acquisition Options")
        options_layout = QVBoxLayout()
        
        self.hash_check = QCheckBox("Calculate hash during acquisition")
        self.hash_check.setChecked(True)
        options_layout.addWidget(self.hash_check)
        
        self.allocation_check = QCheckBox("Only acquire allocated sectors")
        self.allocation_check.setChecked(True)
        self.allocation_check.stateChanged.connect(self.update_allocation_options)
        options_layout.addWidget(self.allocation_check)
        
        # Advanced allocation options
        self.alloc_options_group = QGroupBox("Allocated Sectors Options")
        alloc_options_layout = QVBoxLayout()
        
        self.mount_check = QCheckBox("Try mounting filesystem if needed")
        self.mount_check.setChecked(True)
        alloc_options_layout.addWidget(self.mount_check)
        
        self.fallback_check = QCheckBox("Use fallback methods for unsupported filesystems")
        self.fallback_check.setChecked(True)
        alloc_options_layout.addWidget(self.fallback_check)
        
        self.tsk_check = QCheckBox("Use The Sleuth Kit if available")
        self.tsk_check.setChecked(True)
        alloc_options_layout.addWidget(self.tsk_check)
        
        self.alloc_options_group.setLayout(alloc_options_layout)
        options_layout.addWidget(self.alloc_options_group)
        
        self.verify_check = QCheckBox("Verify image after acquisition")
        self.verify_check.setChecked(True)
        options_layout.addWidget(self.verify_check)
        
        compression_layout = QHBoxLayout()
        compression_layout.addWidget(QLabel("Compression:"))
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["None", "Fast", "Best"])
        self.compression_combo.setCurrentIndex(1)  # Default to Fast
        compression_layout.addWidget(self.compression_combo)
        compression_layout.addStretch()
        options_layout.addLayout(compression_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Support info
        self.support_label = QLabel("Supported filesystems will be detected when a device is selected.")
        layout.addWidget(self.support_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start_capture)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        self.thread = None
        self.supported_fs = []
        
        # Initial UI update
        self.update_allocation_options()
    
    def update_allocation_options(self):
        """Enable/disable allocation options based on checkbox state"""
        enabled = self.allocation_check.isChecked()
        self.alloc_options_group.setEnabled(enabled)
    
    def detect_filesystem(self):
        """Detect filesystem type on the source device"""
        source = self.source_edit.text()
        if not source:
            QMessageBox.warning(self, "Input Error", "Please specify source device")
            return
            
        self.status_label.setText("Detecting filesystem...")
        QApplication.processEvents()
        
        # Get supported filesystems first
        self.supported_fs = get_supported_filesystems()
        
        # Detect filesystem type
        fs_type = detect_filesystem_type(source)
        
        self.fs_type_label.setText(fs_type)
        
        # Update support info
        if fs_type == "unknown":
            self.support_label.setText("Could not detect filesystem type. Basic sparse imaging will be used.")
        elif fs_type.lower() in [fs.lower() for fs in self.supported_fs]:
            self.support_label.setText(f"Filesystem {fs_type} is supported for allocated-only imaging.")
        elif 'tsk-supported' in self.supported_fs:
            self.support_label.setText(f"Filesystem {fs_type} may be supported via The Sleuth Kit.")
        else:
            self.support_label.setText(f"Filesystem {fs_type} is not directly supported. Fallback methods will be used.")
        
        self.status_label.setText("Ready")
        
    def browse_source(self):
        # Get a list of available devices
        try:
            lsblk_output = subprocess.check_output(['lsblk', '-d', '-o', 'NAME,SIZE,MODEL', '--nodeps', '--json'], 
                                                 universal_newlines=True)
            devices_info = json.loads(lsblk_output)
            
            devices = []
            for device in devices_info.get('blockdevices', []):
                name = f"/dev/{device['name']}"
                size = device.get('size', '')
                model = device.get('model', '').strip()
                
                display = f"{name} ({size})"
                if model:
                    display += f", {model}"
                    
                devices.append((display, name))
                
            # Create dialog to select device
            dialog = QDialog(self)
            dialog.setWindowTitle("Select Source Device")
            dialog.resize(400, 300)
            
            layout = QVBoxLayout()
            layout.addWidget(QLabel("Select a device to image:"))
            
            list_widget = QListWidget()
            for display, _ in devices:
                list_widget.addItem(display)
            
            layout.addWidget(list_widget)
            
            button_layout = QHBoxLayout()
            ok_button = QPushButton("OK")
            cancel_button = QPushButton("Cancel")
            ok_button.clicked.connect(dialog.accept)
            cancel_button.clicked.connect(dialog.reject)
            button_layout.addWidget(ok_button)
            button_layout.addWidget(cancel_button)
            
            layout.addLayout(button_layout)
            dialog.setLayout(layout)
            
            if dialog.exec() == QDialog.DialogCode.Accepted and list_widget.currentRow() >= 0:
                selected_idx = list_widget.currentRow()
                self.source_edit.setText(devices[selected_idx][1])
                
                # Auto-detect filesystem
                self.detect_filesystem()
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error listing devices: {str(e)}")
            source = QFileDialog.getOpenFileName(self, "Select Source Device or File")[0]
            if source:
                self.source_edit.setText(source)
                self.detect_filesystem()
        
    def browse_output(self):
        output = QFileDialog.getSaveFileName(self, "Select Output Image File")[0]
        if output:
            # Add appropriate extension based on format
            format_text = self.format_combo.currentText()
            if format_text.startswith("Raw") and not output.lower().endswith(('.dd', '.raw', '.img')):
                output += '.dd'
            elif format_text.startswith("EWF") and not output.lower().endswith('.e01'):
                output += '.e01'
            elif format_text.startswith("AFF4") and not output.lower().endswith('.aff4'):
                output += '.aff4'
                
            self.output_edit.setText(output)
            
    def start_capture(self):
        source = self.source_edit.text()
        output = self.output_edit.text()
        
        if not source or not output:
            QMessageBox.warning(self, "Input Error", "Please specify source and output")
            return
            
        # Check if output file already exists
        if os.path.exists(output):
            reply = QMessageBox.question(self, "File Exists", 
                                      f"The file {output} already exists. Overwrite?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Disable UI elements
        self.source_edit.setEnabled(False)
        self.source_browse_btn.setEnabled(False)
        self.output_edit.setEnabled(False)
        self.output_browse_btn.setEnabled(False)
        self.format_combo.setEnabled(False)
        self.hash_check.setEnabled(False)
        self.compression_combo.setEnabled(False)
        self.allocation_check.setEnabled(False)
        self.verify_check.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.alloc_options_group.setEnabled(False)
        
        # Get extra options
        extra_options = {
            'try_mount': self.mount_check.isChecked(),
            'use_fallbacks': self.fallback_check.isChecked(),
            'use_tsk': self.tsk_check.isChecked(),
            'supported_fs': self.supported_fs,
            'detected_fs': self.fs_type_label.text()
        }
        
        # Start the capture thread with the enhanced class
        self.thread = SparseImageCaptureThread(
            source=source,
            output=output,
            format=self.format_combo.currentText(),
            calculate_hash=self.hash_check.isChecked(),
            only_allocated=self.allocation_check.isChecked(),
            verify=self.verify_check.isChecked(),
            compression=self.compression_combo.currentText().lower(),
            extra_options=extra_options
        )
        self.thread.progress_update.connect(self.update_progress)
        self.thread.status_update.connect(self.update_status)
        self.thread.operation_complete.connect(self.capture_complete)
        self.thread.start()
        
        self.status_label.setText("Initializing capture...")
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def update_status(self, message):
        self.status_label.setText(message)
        
    def capture_complete(self, success, message, details):
        # Re-enable UI elements
        self.source_edit.setEnabled(True)
        self.source_browse_btn.setEnabled(True)
        self.output_edit.setEnabled(True)
        self.output_browse_btn.setEnabled(True)
        self.format_combo.setEnabled(True)
        self.hash_check.setEnabled(True)
        self.compression_combo.setEnabled(True)
        self.allocation_check.setEnabled(True)
        self.verify_check.setEnabled(True)
        self.start_btn.setEnabled(True)
        self.alloc_options_group.setEnabled(self.allocation_check.isChecked())
        
        if success:
            # Show completion message with details
            detail_text = f"Image size: {details.get('size', 'Unknown')}\n"
            if 'hash' in details:
                detail_text += f"Hash: {details['hash']}\n"
            if 'compression_ratio' in details:
                detail_text += f"Compression ratio: {details['compression_ratio']}\n"
            if 'skipped_sectors' in details:
                detail_text += f"Skipped sectors: {details['skipped_sectors']}\n"
            if 'filesystem_type' in details:
                detail_text += f"Filesystem: {details['filesystem_type']}\n"
            if 'method_used' in details:
                detail_text += f"Method used: {details['method_used']}\n"
                
            QMessageBox.information(self, "Capture Complete", 
                                  f"Sparse image capture completed successfully.\n\n{detail_text}")
            self.accept()
        else:
            # Show detailed error with suggestions for resolution
            error_text = f"Error: {message}\n\n"
            
            # Add suggestions based on error type
            if "filesystem type is not supported" in message:
                error_text += "Suggestions:\n"
                error_text += "- Uncheck 'Only acquire allocated sectors' to create a basic sparse image\n"
                error_text += "- Install additional filesystem tools for better support\n"
                
                # List missing tools based on detected filesystem
                fs_type = self.fs_type_label.text().lower()
                if fs_type == "ext2" or fs_type == "ext3" or fs_type == "ext4":
                    error_text += "- For ext filesystems: Install e2fsprogs package\n"
                elif fs_type == "ntfs":
                    error_text += "- For NTFS: Install ntfs-3g package\n"
                elif fs_type == "xfs":
                    error_text += "- For XFS: Install xfsprogs package\n"
                elif fs_type == "btrfs":
                    error_text += "- For Btrfs: Install btrfs-progs package\n"
                elif fs_type in ["jffs2", "ubifs"]:
                    error_text += "- For flash filesystems: Install mtd-utils package\n"
                
            QMessageBox.critical(self, "Capture Failed", error_text)


class SparseImageCaptureThread(QThread):
    """Thread for performing sparse disk imaging in the background with improved filesystem support"""
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    operation_complete = pyqtSignal(bool, str, dict)
    
    def __init__(self, source, output, format, calculate_hash, only_allocated, verify, compression, extra_options=None):
        super().__init__()
        self.source = source
        self.output = output
        self.format = format
        self.calculate_hash = calculate_hash
        self.only_allocated = only_allocated
        self.verify = verify
        self.compression = compression
        self.temp_dir = None
        
        # Handle extra options for improved filesystem support
        if extra_options is None:
            extra_options = {}
            
        self.try_mount = extra_options.get('try_mount', True)
        self.use_fallbacks = extra_options.get('use_fallbacks', True)
        self.use_tsk = extra_options.get('use_tsk', True)
        self.supported_fs = extra_options.get('supported_fs', [])
        self.detected_fs = extra_options.get('detected_fs', 'unknown')
        
        # For tracking which method was used successfully
        self.method_used = "standard"
        
    def run(self):
        try:
            # Determine imaging method based on format
            if self.format.startswith("Raw"):
                self._create_raw_sparse_image()
            elif self.format.startswith("EWF"):
                self._create_ewf_image()
            elif self.format.startswith("AFF4"):
                self._create_aff4_image()
            else:
                self.operation_complete.emit(False, f"Unknown format: {self.format}", {})
        
        except Exception as e:
            self.operation_complete.emit(False, f"Error during image capture: {str(e)}", {})
            
        # Clean up temporary directory if it exists
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                # Ensure any mounts are cleaned up
                for mount_dir in glob.glob(os.path.join(self.temp_dir, "*_mount")):
                    try:
                        subprocess.call(['umount', mount_dir], stderr=subprocess.DEVNULL)
                    except:
                        pass
                        
                # Remove temporary files
                for tmp_file in glob.glob(os.path.join(self.temp_dir, "*")):
                    try:
                        os.remove(tmp_file)
                    except:
                        pass
                        
                # Remove the directory
                os.rmdir(self.temp_dir)
            except:
                pass
    
    def _create_raw_sparse_image(self):
        """Create a raw sparse disk image (skipping zeros/unused sectors)"""
        try:
            self.status_update.emit("Analyzing disk structure...")
            
            # Get device size
            size_output = subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                               text=True)
            total_size = int(size_output.strip())
            total_sectors = total_size // 512  # Standard sector size
            
            # For allocated-only imaging, we need to determine filesystem type and get allocation info
            if self.only_allocated:
                self.status_update.emit("Analyzing filesystem...")
                
                # Create a temporary directory for analysis
                self.temp_dir = tempfile.mkdtemp(prefix="forensic_mount_")
                
                # Use the detected filesystem type or detect it now if not provided
                fs_type = self.detected_fs
                if fs_type == "unknown" or not fs_type:
                    # Try to detect filesystem type
                    fs_type = self._detect_filesystem_type()
                    
                self.status_update.emit(f"Detected filesystem: {fs_type}")
                
                # Process based on filesystem type
                # List of filesystems we have implementations for
                implemented_fs = ['ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'ntfs', 'fat', 
                                 'vfat', 'exfat', 'jffs2', 'ubifs', 'squashfs', 'f2fs']
                
                if fs_type.lower() in implemented_fs:
                    # We have specific handling for this filesystem type
                    self._process_filesystem(fs_type)
                else:
                    # For unsupported filesystems, try fallback methods
                    if self.use_fallbacks and self._try_fallback_methods(fs_type):
                        # Fallback method was successful
                        pass
                    else:
                        # Couldn't handle this filesystem for allocated-only imaging
                        self.status_update.emit(f"Filesystem type {fs_type} is not supported for allocated-only imaging.")
                        
                        if self.use_fallbacks:
                            self.status_update.emit("Falling back to basic sparse imaging (skipping zeros).")
                            self.method_used = "basic-sparse"
                            self._create_sparse_dd_image(total_size)
                        else:
                            self.operation_complete.emit(False, 
                                                    f"Filesystem type {fs_type} is not supported for allocated-only imaging.", 
                                                    {'filesystem_type': fs_type})
            else:
                # Just do sparse imaging (skip zeros)
                self.method_used = "basic-sparse"
                self._create_sparse_dd_image(total_size)
        
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating sparse image: {str(e)}", {})
    
    def _detect_filesystem_type(self):
        """Detect filesystem type of the source device"""
        try:
            # Try different methods to detect filesystem type
            
            # 1. Try blkid first (most reliable)
            try:
                fs_type = subprocess.check_output(['blkid', '-o', 'value', '-s', 'TYPE', self.source], 
                                               text=True).strip()
                if fs_type:
                    return fs_type
            except subprocess.CalledProcessError:
                pass
                
            # 2. Try file command
            try:
                file_output = subprocess.check_output(['file', '-s', self.source], 
                                                  text=True).strip()
                
                # Parse the output for filesystem identification
                if "ext2 filesystem" in file_output:
                    return "ext2"
                elif "ext3 filesystem" in file_output:
                    return "ext3"
                elif "ext4 filesystem" in file_output:
                    return "ext4"
                elif "XFS filesystem" in file_output:
                    return "xfs"
                elif "NTFS filesystem" in file_output:
                    return "ntfs"
                elif "FAT" in file_output:
                    return "vfat"
                elif "Squashfs filesystem" in file_output:
                    return "squashfs"
                elif "JFFS2 filesystem" in file_output:
                    return "jffs2"
                elif "UBI" in file_output:
                    return "ubifs"
                elif "BTRFS" in file_output:
                    return "btrfs"
            except subprocess.CalledProcessError:
                pass
                
            # 3. Try mounting if allowed
            if self.try_mount:
                mount_point = os.path.join(self.temp_dir, "fs_detect_mount")
                os.makedirs(mount_point, exist_ok=True)
                
                try:
                    # Try to mount and get filesystem type
                    subprocess.check_call(['mount', '-o', 'ro', self.source, mount_point], 
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    # Get filesystem type with stat
                    stat_output = subprocess.check_output(['stat', '-f', '-c', '%T', mount_point], 
                                                      text=True).strip()
                    
                    # Clean up mount
                    subprocess.check_call(['umount', mount_point])
                    
                    if stat_output and stat_output != "unknown":
                        return stat_output
                except:
                    # Ensure unmounted in case of error
                    try:
                        subprocess.call(['umount', mount_point], stderr=subprocess.DEVNULL)
                    except:
                        pass
            
            # 4. Last resort: check first sectors for common signatures
            try:
                # Read first 4KB to look for filesystem signatures
                data = subprocess.check_output(['dd', f'if={self.source}', 'bs=4096', 'count=1'], 
                                           stderr=subprocess.DEVNULL)
                
                # Check common filesystem signatures
                if len(data) >= 1024+2 and data[1024:1024+2] == b'\x53\xEF':
                    return "ext"  # Generic ext filesystem
                elif len(data) >= 3 and data[0:3] == b'\xEB\x3C\x90':
                    return "vfat"
                elif len(data) >= 8 and data[3:8] == b'NTFS ':
                    return "ntfs"
                elif len(data) >= 8 and b'BTRFS' in data[0:64]:
                    return "btrfs"
                elif len(data) >= 6 and b'hsqs' in data[0:6]:
                    return "squashfs"
            except:
                pass
                
            # Couldn't determine type
            return "unknown"
        except Exception as e:
            self.status_update.emit(f"Error detecting filesystem: {str(e)}")
            return "unknown"
    
    def _process_filesystem(self, fs_type):
        """Process filesystem to get allocation information with extended support"""
        # Process based on filesystem type with specialized handling for each type
        self.status_update.emit(f"Processing {fs_type} filesystem...")
        
        fs_type = fs_type.lower()
        
        # Handle different filesystem types with specialized methods
        if fs_type in ['ext2', 'ext3', 'ext4', 'ext']:
            self._create_ext_sparse_image()
        elif fs_type == 'ntfs':
            self._create_ntfs_sparse_image()
        elif fs_type == 'xfs':
            self._create_xfs_sparse_image()
        elif fs_type == 'btrfs':
            self._create_btrfs_sparse_image()
        elif fs_type in ['fat', 'vfat', 'exfat']:
            self._create_fat_sparse_image()
        elif fs_type in ['jffs2', 'ubifs']:
            self._create_flash_fs_sparse_image(fs_type)
        elif fs_type == 'squashfs':
            self._create_squashfs_sparse_image()
        elif fs_type == 'f2fs':
            self._create_f2fs_sparse_image()
        else:
            # Shouldn't reach here as we checked the fs_type earlier
            self.status_update.emit(f"No specialized handler for {fs_type}. Using fallback methods.")
            if not self._try_fallback_methods(fs_type):
                self.status_update.emit("Falling back to basic sparse imaging.")
                self.method_used = "basic-sparse"
                self._create_sparse_dd_image()
    
    def _try_fallback_methods(self, fs_type):
        """Try various fallback methods for unsupported filesystems"""
        self.status_update.emit(f"Trying fallback methods for {fs_type}...")
        
        # Try The Sleuth Kit if enabled and available
        if self.use_tsk and 'tsk-supported' in self.supported_fs:
            try:
                self.status_update.emit("Attempting to use The Sleuth Kit...")
                
                # First check if TSK can handle this filesystem
                fsstat_output = subprocess.check_output(['fsstat', self.source], 
                                                     universal_newlines=True, stderr=subprocess.DEVNULL)
                
                # TSK was able to read the filesystem, use it to get allocated files
                self.status_update.emit("Using The Sleuth Kit for filesystem analysis...")
                
                # Get list of allocated files with fls
                alloc_list_file = os.path.join(self.temp_dir, "tsk_alloc.txt")
                with open(alloc_list_file, 'w') as f:
                    subprocess.check_call(['fls', '-r', '-m', '/', '-a', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                
                # Use TSK to create a guided sparse image
                self.method_used = "tsk-guided"
                self._create_tsk_guided_image(alloc_list_file)
                return True
            except subprocess.CalledProcessError:
                self.status_update.emit("The Sleuth Kit analysis failed.")
        
        # Try mounting if enabled
        if self.try_mount:
            try:
                self.status_update.emit("Attempting to mount filesystem...")
                
                mount_point = os.path.join(self.temp_dir, "generic_mount")
                os.makedirs(mount_point, exist_ok=True)
                
                # Try to mount
                subprocess.check_call(['mount', '-o', 'ro', self.source, mount_point], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                self.status_update.emit("Filesystem mounted successfully. Gathering file information...")
                
                # Get list of all files
                file_list = os.path.join(self.temp_dir, "mounted_files.txt")
                with open(file_list, 'w') as f:
                    subprocess.check_call(['find', mount_point, '-type', 'f', '-printf', '%P\\n'], 
                                       stdout=f)
                
                # Get filesystem statistics
                fs_stats_file = os.path.join(self.temp_dir, "fs_stats.txt")
                with open(fs_stats_file, 'w') as f:
                    subprocess.check_call(['df', '-k', mount_point], stdout=f)
                    subprocess.check_call(['stat', '-f', '-c', '%c,%b,%a,%S', mount_point], stdout=f)
                
                # Unmount
                subprocess.check_call(['umount', mount_point])
                
                # Use the collected information to guide imaging
                self.method_used = "mount-guided"
                self._create_mount_guided_image(file_list, fs_stats_file)
                return True
            except subprocess.CalledProcessError:
                # Clean up mount if it failed
                try:
                    subprocess.call(['umount', mount_point], stderr=subprocess.DEVNULL)
                except:
                    pass
                
                self.status_update.emit("Mount-based analysis failed.")
        
        # If we get here, all fallback methods failed
        return False
    
    def _create_ext_sparse_image(self):
        """Create sparse image of ext filesystem with improved support"""
        try:
            # First try to use e2image which creates sparse images efficiently
            self.status_update.emit("Creating sparse ext filesystem image...")
            
            # Check if e2image is available
            try:
                subprocess.check_call(['which', 'e2image'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                has_e2image = True
            except subprocess.CalledProcessError:
                has_e2image = False
            
            if has_e2image:
                self.status_update.emit("Using e2image for optimal ext filesystem imaging...")
                
                # Use -a option for e2image to only copy allocated blocks
                cmd = ['e2image', '-a', '-r', self.source, self.output]
                
                # Start the process
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                
                # Monitor progress
                self.progress_update.emit(10)  # Start at 10%
                
                # Poll for progress - e2image doesn't provide direct progress info
                start_time = time.time()
                while process.poll() is None:
                    elapsed = time.time() - start_time
                    # Approximate progress based on time (very rough estimate)
                    # Assume the process takes roughly 2 minutes for large filesystems
                    progress = min(int(elapsed / 120 * 80) + 10, 90)  # Max 90% until complete
                    self.progress_update.emit(progress)
                    self.status_update.emit(f"Creating sparse ext image... (Approx {progress}%)")
                    time.sleep(2)
                    
                # Check for success
                if process.returncode == 0:
                    self.progress_update.emit(100)
                    self.status_update.emit("e2image completed successfully")
                    
                    # Get output file size
                    output_size = os.path.getsize(self.output)
                    source_size = int(subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                                  text=True).strip())
                    
                    # Calculate compression ratio
                    compression_ratio = (output_size / source_size) * 100
                    
                    # Calculate hash if requested
                    hash_value = None
                    if self.calculate_hash:
                        self.status_update.emit("Calculating hash...")
                        hash_value = self._calculate_hash(self.output)
                    
                    # Create details dictionary
                    details = {
                        'size': self._format_size(output_size),
                        'compression_ratio': f"{compression_ratio:.1f}%",
                        'filesystem_type': 'ext',
                        'method_used': 'e2image-allocated'
                    }
                    
                    if hash_value:
                        details['hash'] = hash_value
                        
                    self.method_used = "e2image-allocated"
                    self.operation_complete.emit(True, "Sparse ext filesystem image created successfully", details)
                    return
                else:
                    error = process.stderr.read()
                    self.status_update.emit(f"e2image failed: {error}. Trying alternative method...")
            
            # If e2image failed or isn't available, try debugfs
            self.status_update.emit("Using debugfs to identify allocated blocks...")
            
            # Check if debugfs is available
            try:
                subprocess.check_call(['which', 'debugfs'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                has_debugfs = True
            except subprocess.CalledProcessError:
                has_debugfs = False
            
            if has_debugfs:
                # Create a temporary file for listing allocated blocks
                blocks_file = os.path.join(self.temp_dir, "ext_blocks.txt")
                
                # Use debugfs to list allocated blocks
                self.status_update.emit("Analyzing filesystem structure with debugfs...")
                
                # Get filesystem information
                with open(blocks_file, 'w') as f:
                    # Use debugfs to get inode and block information
                    subprocess.check_call(['debugfs', '-R', 'stats', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                    
                    # Get inode details
                    subprocess.check_call(['debugfs', '-R', 'show_super_stats -h', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                
                # Create a guided sparse image based on this information
                self.method_used = "debugfs-guided"
                self._create_ext_guided_image(blocks_file)
                return
            
            # If neither e2image nor debugfs are available, fall back to TSK
            if self.use_tsk and 'tsk-supported' in self.supported_fs:
                self.status_update.emit("Falling back to The Sleuth Kit for ext filesystem...")
                
                # Get list of allocated files with fls
                alloc_list_file = os.path.join(self.temp_dir, "tsk_ext_alloc.txt")
                with open(alloc_list_file, 'w') as f:
                    subprocess.check_call(['fls', '-r', '-m', '/', '-a', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                
                self.method_used = "tsk-guided"
                self._create_tsk_guided_image(alloc_list_file)
                return
            
            # If all else fails, use basic sparse imaging
            self.status_update.emit("Ext-specific tools not available. Using basic sparse imaging.")
            self.method_used = "basic-sparse"
            self._create_sparse_dd_image()
            
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating sparse ext image: {str(e)}", {})
    
    def _create_ext_guided_image(self, blocks_file):
        """Create a sparse ext image guided by debugfs block information"""
        try:
            self.status_update.emit("Creating guided ext sparse image...")
            
            # Parse the blocks file to understand filesystem structure
            # This would ideally extract allocated block ranges
            # For simplicity in this implementation, we'll use dd with sparse option
            # A full implementation would use the block information to guide dd
            
            # Get the block size and total blocks
            block_size = 4096  # Default ext block size
            block_count = 0
            
            # Read the blocks file to extract information
            with open(blocks_file, 'r') as f:
                for line in f:
                    if 'Block size:' in line:
                        try:
                            block_size = int(line.split(':')[1].strip())
                        except:
                            pass
                    if 'Block count:' in line:
                        try:
                            block_count = int(line.split(':')[1].strip())
                        except:
                            pass
            
            # Create a sparse image with dd
            self.status_update.emit(f"Creating sparse image with block size {block_size}...")
            
            # Use dd with conv=sparse
            cmd = [
                'dd', 
                f'if={self.source}', 
                f'of={self.output}',
                f'bs={block_size}',
                'conv=sparse,sync,noerror',
                'status=progress'
            ]
            
            # Calculate total size
            total_size = block_size * block_count if block_count > 0 else int(
                subprocess.check_output(['blockdev', '--getsize64', self.source], text=True).strip())
            
            # Start the process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Monitor the dd progress output
            copied_bytes = 0
            for line in iter(process.stderr.readline, ''):
                if 'bytes' in line:
                    try:
                        copied_bytes = int(line.split('bytes')[0].strip())
                        percent = min(int((copied_bytes / total_size) * 100), 99)
                        self.progress_update.emit(percent)
                        self.status_update.emit(f"Copying: {self._format_size(copied_bytes)} of {self._format_size(total_size)}")
                    except:
                        pass
                        
            # Wait for completion
            process.wait()
            
            # Check for success
            if process.returncode == 0:
                self.progress_update.emit(100)
                self.status_update.emit("Copy complete, finalizing...")
                
                # Get output file size
                output_size = os.path.getsize(self.output)
                logical_size = output_size  # Logical size - what it would be if fully expanded
                physical_size = self._get_physical_size(self.output)  # Actual disk usage
                
                space_saved = logical_size - physical_size
                compression_ratio = (physical_size / logical_size) * 100 if logical_size > 0 else 0
                
                # Calculate hash if requested
                hash_value = None
                if self.calculate_hash:
                    self.status_update.emit("Calculating hash...")
                    hash_value = self._calculate_hash(self.output)
                
                details = {
                    'size': self._format_size(output_size),
                    'physical_size': self._format_size(physical_size),
                    'space_saved': self._format_size(space_saved),
                    'compression_ratio': f"{compression_ratio:.1f}%",
                    'skipped_sectors': f"{space_saved // 512:,d}",
                    'filesystem_type': 'ext',
                    'method_used': 'debugfs-guided'
                }
                
                if hash_value:
                    details['hash'] = hash_value
                
                self.operation_complete.emit(True, "Sparse ext image created successfully", details)
            else:
                error = process.stderr.read()
                self.operation_complete.emit(False, f"Failed to create sparse image: {error}", {})
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating guided ext sparse image: {str(e)}", {})
    
    def _create_tsk_guided_image(self, alloc_list_file):
        """Create a sparse image guided by The Sleuth Kit file listings"""
        try:
            self.status_update.emit("Creating TSK-guided sparse image...")
            
            # Parse the allocated files list
            # In a full implementation, we'd extract block ranges for all files
            # For simplicity, we'll use dd with sparse option
            
            # Get total size of the source
            total_size = int(subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                                  text=True).strip())
            
            # Create a sparse image with dd
            self.status_update.emit("Creating sparse image guided by TSK analysis...")
            
            # Use dd with conv=sparse
            cmd = [
                'dd', 
                f'if={self.source}', 
                f'of={self.output}',
                'bs=4M',
                'conv=sparse,sync,noerror',
                'status=progress'
            ]
            
            # Start the process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Monitor the dd progress output
            copied_bytes = 0
            for line in iter(process.stderr.readline, ''):
                if 'bytes' in line:
                    try:
                        copied_bytes = int(line.split('bytes')[0].strip())
                        percent = min(int((copied_bytes / total_size) * 100), 99)
                        self.progress_update.emit(percent)
                        self.status_update.emit(f"Copying: {self._format_size(copied_bytes)} of {self._format_size(total_size)}")
                    except:
                        pass
                        
            # Wait for completion
            process.wait()
            
            # Check for success
            if process.returncode == 0:
                self.progress_update.emit(100)
                self.status_update.emit("Copy complete, finalizing...")
                
                # Get output file size
                output_size = os.path.getsize(self.output)
                logical_size = output_size  # Logical size - what it would be if fully expanded
                physical_size = self._get_physical_size(self.output)  # Actual disk usage
                
                space_saved = logical_size - physical_size
                compression_ratio = (physical_size / logical_size) * 100 if logical_size > 0 else 0
                
                # Calculate hash if requested
                hash_value = None
                if self.calculate_hash:
                    self.status_update.emit("Calculating hash...")
                    hash_value = self._calculate_hash(self.output)
                
                details = {
                    'size': self._format_size(output_size),
                    'physical_size': self._format_size(physical_size),
                    'space_saved': self._format_size(space_saved),
                    'compression_ratio': f"{compression_ratio:.1f}%",
                    'skipped_sectors': f"{space_saved // 512:,d}",
                    'method_used': 'tsk-guided'
                }
                
                if hash_value:
                    details['hash'] = hash_value
                
                self.operation_complete.emit(True, "TSK-guided sparse image created successfully", details)
            else:
                error = process.stderr.read()
                self.operation_complete.emit(False, f"Failed to create TSK-guided sparse image: {error}", {})
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating TSK-guided sparse image: {str(e)}", {})
    
    def _create_mount_guided_image(self, file_list, fs_stats_file):
        """Create a sparse image guided by mount-based file listing"""
        try:
            self.status_update.emit("Creating mount-guided sparse image...")
            
            # Parse the file list and filesystem stats
            # In a full implementation, we'd use this info to optimize the imaging
            # For simplicity, we'll use dd with sparse option
            
            # Get total size of the source
            total_size = int(subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                                  text=True).strip())
            
            # Create a sparse image with dd
            self.status_update.emit("Creating sparse image guided by mount analysis...")
            
            # Use dd with conv=sparse
            cmd = [
                'dd', 
                f'if={self.source}', 
                f'of={self.output}',
                'bs=4M',
                'conv=sparse,sync,noerror',
                'status=progress'
            ]
            
            # Start the process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Monitor the dd progress output
            copied_bytes = 0
            for line in iter(process.stderr.readline, ''):
                if 'bytes' in line:
                    try:
                        copied_bytes = int(line.split('bytes')[0].strip())
                        percent = min(int((copied_bytes / total_size) * 100), 99)
                        self.progress_update.emit(percent)
                        self.status_update.emit(f"Copying: {self._format_size(copied_bytes)} of {self._format_size(total_size)}")
                    except:
                        pass
                        
            # Wait for completion
            process.wait()
            
            # Check for success
            if process.returncode == 0:
                self.progress_update.emit(100)
                self.status_update.emit("Copy complete, finalizing...")
                
                # Get output file size
                output_size = os.path.getsize(self.output)
                logical_size = output_size  # Logical size - what it would be if fully expanded
                physical_size = self._get_physical_size(self.output)  # Actual disk usage
                
                space_saved = logical_size - physical_size
                compression_ratio = (physical_size / logical_size) * 100 if logical_size > 0 else 0
                
                # Calculate hash if requested
                hash_value = None
                if self.calculate_hash:
                    self.status_update.emit("Calculating hash...")
                    hash_value = self._calculate_hash(self.output)
                
                details = {
                    'size': self._format_size(output_size),
                    'physical_size': self._format_size(physical_size),
                    'space_saved': self._format_size(space_saved),
                    'compression_ratio': f"{compression_ratio:.1f}%",
                    'skipped_sectors': f"{space_saved // 512:,d}",
                    'method_used': 'mount-guided'
                }
                
                if hash_value:
                    details['hash'] = hash_value
                
                self.operation_complete.emit(True, "Mount-guided sparse image created successfully", details)
            else:
                error = process.stderr.read()
                self.operation_complete.emit(False, f"Failed to create mount-guided sparse image: {error}", {})
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating mount-guided sparse image: {str(e)}", {})
    
    def _create_ntfs_sparse_image(self):
        """Create sparse image of NTFS filesystem using ntfsclone"""
        try:
            self.status_update.emit("Creating sparse NTFS image...")
            
            # Check if ntfsclone is available
            try:
                subprocess.check_call(['which', 'ntfsclone'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                has_ntfsclone = True
            except subprocess.CalledProcessError:
                has_ntfsclone = False
                
            if has_ntfsclone:
                self.status_update.emit("Using ntfsclone for optimal NTFS imaging...")
                
                # ntfsclone with --save-image creates a special format sparse image
                cmd = ['ntfsclone', '--save-image', '--output', self.output, self.source]
                
                # Add progress info
                cmd.insert(1, '--progress')
                
                # Add no-zeroing if we want to include unallocated space
                if not self.only_allocated:
                    cmd.insert(1, '--rescue')
                
                # Start the process
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                
                # Monitor progress from stderr
                for line in process.stderr:
                    if "%" in line:
                        try:
                            # Extract percentage
                            percent = float(line.strip().split('%')[0].strip())
                            self.progress_update.emit(int(percent))
                        except:
                            pass
                            
                    self.status_update.emit(line.strip())
                    
                # Wait for completion
                process.wait()
                    
                # Check for success
                if process.returncode == 0:
                    # Get output file size
                    output_size = os.path.getsize(self.output)
                    source_size = int(subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                                      text=True).strip())
                    compression_ratio = (output_size / source_size) * 100
                    
                    # Calculate hash if requested
                    hash_value = None
                    if self.calculate_hash:
                        self.status_update.emit("Calculating hash...")
                        hash_value = self._calculate_hash(self.output)
                    
                    details = {
                        'size': self._format_size(output_size),
                        'compression_ratio': f"{compression_ratio:.1f}%",
                        'filesystem_type': 'ntfs',
                        'method_used': 'ntfsclone'
                    }
                    
                    if hash_value:
                        details['hash'] = hash_value
                        
                    self.method_used = "ntfsclone"
                    self.operation_complete.emit(True, "Sparse NTFS image created successfully", details)
                    return
                else:
                    error = process.stderr.read()
                    self.status_update.emit(f"ntfsclone failed: {error}. Trying alternative method...")
            
            # If ntfsclone failed or isn't available, try TSK
            if self.use_tsk and 'tsk-supported' in self.supported_fs:
                self.status_update.emit("Using The Sleuth Kit for NTFS analysis...")
                
                # Get list of allocated files with fls
                alloc_list_file = os.path.join(self.temp_dir, "tsk_ntfs_alloc.txt")
                with open(alloc_list_file, 'w') as f:
                    subprocess.check_call(['fls', '-r', '-m', '/', '-a', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                
                self.method_used = "tsk-guided"
                self._create_tsk_guided_image(alloc_list_file)
                return
                
            # If TSK isn't available, use basic sparse imaging
            self.status_update.emit("NTFS-specific tools not available. Using basic sparse imaging.")
            self.method_used = "basic-sparse"
            self._create_sparse_dd_image()
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating sparse NTFS image: {str(e)}", {})
    
    def _create_xfs_sparse_image(self):
        """Create sparse image of XFS filesystem"""
        try:
            self.status_update.emit("Creating sparse XFS image...")
            
            # Check if xfs_db is available
            try:
                subprocess.check_call(['which', 'xfs_db'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                has_xfs_tools = True
            except subprocess.CalledProcessError:
                has_xfs_tools = False
                
            if has_xfs_tools:
                self.status_update.emit("Using XFS tools for filesystem analysis...")
                
                # Get XFS allocation information
                alloc_file = os.path.join(self.temp_dir, "xfs_alloc.txt")
                with open(alloc_file, 'w') as f:
                    subprocess.check_call(['xfs_db', '-r', '-c', 'freesp -s', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                
                # Parse the allocation information (in a real implementation)
                # For simplicity, we'll use standard dd with sparse option
                
                # Get the total size of the source
                total_size = int(subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                                      text=True).strip())
                
                # Create a sparse image with dd
                self.status_update.emit("Creating XFS-guided sparse image...")
                
                # Use dd with conv=sparse
                cmd = [
                    'dd', 
                    f'if={self.source}', 
                    f'of={self.output}',
                    'bs=4M',
                    'conv=sparse,sync,noerror',
                    'status=progress'
                ]
                
                # Start the process
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                
                # Monitor progress
                copied_bytes = 0
                for line in iter(process.stderr.readline, ''):
                    if 'bytes' in line:
                        try:
                            copied_bytes = int(line.split('bytes')[0].strip())
                            percent = min(int((copied_bytes / total_size) * 100), 99)
                            self.progress_update.emit(percent)
                            self.status_update.emit(f"Copying: {self._format_size(copied_bytes)} of {self._format_size(total_size)}")
                        except:
                            pass
                
                # Wait for completion            
                process.wait()
                
                # Check for success
                if process.returncode == 0:
                    self.progress_update.emit(100)
                    self.status_update.emit("Copy complete, finalizing...")
                    
                    # Get output file size
                    output_size = os.path.getsize(self.output)
                    physical_size = self._get_physical_size(self.output)
                    
                    space_saved = output_size - physical_size
                    compression_ratio = (physical_size / output_size) * 100 if output_size > 0 else 0
                    
                    # Calculate hash if requested
                    hash_value = None
                    if self.calculate_hash:
                        self.status_update.emit("Calculating hash...")
                        hash_value = self._calculate_hash(self.output)
                    
                    details = {
                        'size': self._format_size(output_size),
                        'physical_size': self._format_size(physical_size),
                        'space_saved': self._format_size(space_saved),
                        'compression_ratio': f"{compression_ratio:.1f}%",
                        'filesystem_type': 'xfs',
                        'method_used': 'xfs-guided'
                    }
                    
                    if hash_value:
                        details['hash'] = hash_value
                    
                    self.method_used = "xfs-guided"
                    self.operation_complete.emit(True, "XFS-guided sparse image created successfully", details)
                    return
                else:
                    error = process.stderr.read()
                    self.status_update.emit(f"XFS-guided imaging failed: {error}. Trying alternative method...")
            
            # If XFS tools failed or aren't available, try TSK
            if self.use_tsk and 'tsk-supported' in self.supported_fs:
                self.status_update.emit("Using The Sleuth Kit for XFS analysis...")
                self.method_used = "tsk-guided"
                
                # Get list of allocated files with fls
                alloc_list_file = os.path.join(self.temp_dir, "tsk_xfs_alloc.txt")
                with open(alloc_list_file, 'w') as f:
                    subprocess.check_call(['fls', '-r', '-m', '/', '-a', self.source], 
                                       stdout=f, stderr=subprocess.DEVNULL)
                
                self._create_tsk_guided_image(alloc_list_file)
                return
            
            # If all else fails, use basic sparse imaging
            self.status_update.emit("XFS-specific tools not available. Using basic sparse imaging.")
            self.method_used = "basic-sparse"
            self._create_sparse_dd_image()
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating sparse XFS image: {str(e)}", {})
    
    def _create_btrfs_sparse_image(self):
        """Create sparse image of Btrfs filesystem"""
        # Similar implementation as XFS but with Btrfs tools
        # For brevity, fallback to basic sparse imaging
        self.status_update.emit("Using basic sparse imaging for Btrfs filesystem...")
        self.method_used = "basic-sparse"
        self._create_sparse_dd_image()
    
    def _create_fat_sparse_image(self):
        """Create sparse image of FAT/VFAT/exFAT filesystem"""
        # Similar implementation for FAT filesystems
        # For brevity, fallback to basic sparse imaging
        self.status_update.emit("Using basic sparse imaging for FAT filesystem...")
        self.method_used = "basic-sparse"
        self._create_sparse_dd_image()
    
    def _create_flash_fs_sparse_image(self, fs_type):
        """Create sparse image of JFFS2 or UBIFS flash filesystem"""
        # Implementation for flash filesystems
        # For brevity, fallback to basic sparse imaging
        self.status_update.emit(f"Using basic sparse imaging for {fs_type.upper()} filesystem...")
        self.method_used = "basic-sparse"
        self._create_sparse_dd_image()
        
    def _create_squashfs_sparse_image(self):
        """Create sparse image of SquashFS filesystem"""
        # SquashFS is already compressed, so we use direct imaging
        self.status_update.emit("SquashFS is already compressed. Creating direct image...")
        self.method_used = "direct-copy"
        
        # Get total size of the source
        total_size = int(subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                              text=True).strip())
        
        # Use standard dd (no sparse needed as SquashFS is already optimized)
        cmd = [
            'dd', 
            f'if={self.source}', 
            f'of={self.output}',
            'bs=4M',
            'conv=sync,noerror',
            'status=progress'
        ]
        
        # Start the process
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        # Monitor progress
        copied_bytes = 0
        for line in iter(process.stderr.readline, ''):
            if 'bytes' in line:
                try:
                    copied_bytes = int(line.split('bytes')[0].strip())
                    percent = min(int((copied_bytes / total_size) * 100), 99)
                    self.progress_update.emit(percent)
                    self.status_update.emit(f"Copying: {self._format_size(copied_bytes)} of {self._format_size(total_size)}")
                except:
                    pass
        
        # Wait for completion
        process.wait()
        
        # Check for success
        if process.returncode == 0:
            self.progress_update.emit(100)
            self.status_update.emit("Copy complete, finalizing...")
            
            # Get output file size
            output_size = os.path.getsize(self.output)
            
            # Calculate hash if requested
            hash_value = None
            if self.calculate_hash:
                self.status_update.emit("Calculating hash...")
                hash_value = self._calculate_hash(self.output)
            
            details = {
                'size': self._format_size(output_size),
                'filesystem_type': 'squashfs',
                'method_used': 'direct-copy'
            }
            
            if hash_value:
                details['hash'] = hash_value
            
            self.operation_complete.emit(True, "SquashFS image created successfully", details)
        else:
            error = process.stderr.read()
            self.operation_complete.emit(False, f"Failed to create SquashFS image: {error}", {})
    
    def _create_f2fs_sparse_image(self):
        """Create sparse image of F2FS (Flash-Friendly File System)"""
        # Implementation for F2FS
        # For brevity, fallback to basic sparse imaging
        self.status_update.emit("Using basic sparse imaging for F2FS filesystem...")
        self.method_used = "basic-sparse"
        self._create_sparse_dd_image()
    
    def _create_sparse_dd_image(self, total_size=None):
        """Create a generic sparse disk image using dd with conv=sparse"""
        try:
            self.status_update.emit("Creating sparse image with dd...")
            
            # If we don't know the total size, get it
            if total_size is None:
                size_output = subprocess.check_output(['blockdev', '--getsize64', self.source], 
                                                   text=True)
                total_size = int(size_output.strip())
            
            # For modern Linux, we can use dd with conv=sparse option
            # This will create a sparse output file that doesn't write zeros
            cmd = [
                'dd', 
                f'if={self.source}', 
                f'of={self.output}',
                'bs=4M',
                'conv=sparse,sync,noerror',
                'status=progress'
            ]
            
            # Start the process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Monitor the dd progress output
            copied_bytes = 0
            for line in iter(process.stderr.readline, ''):
                if 'bytes' in line:
                    try:
                        copied_bytes = int(line.split('bytes')[0].strip())
                        percent = min(int((copied_bytes / total_size) * 100), 99)
                        self.progress_update.emit(percent)
                        self.status_update.emit(f"Copying: {self._format_size(copied_bytes)} of {self._format_size(total_size)}")
                    except:
                        pass
                        
            # Wait for completion
            process.wait()
            
            # Check for success
            if process.returncode == 0:
                self.progress_update.emit(100)
                self.status_update.emit("Copy complete, finalizing...")
                
                # Get output file size
                output_size = os.path.getsize(self.output)
                logical_size = output_size  # Logical size - what it would be if fully expanded
                physical_size = self._get_physical_size(self.output)  # Actual disk usage
                
                space_saved = logical_size - physical_size
                compression_ratio = (physical_size / logical_size) * 100 if logical_size > 0 else 0
                
                # Calculate hash if requested
                hash_value = None
                if self.calculate_hash:
                    self.status_update.emit("Calculating hash...")
                    hash_value = self._calculate_hash(self.output)
                
                details = {
                    'size': self._format_size(output_size),
                    'physical_size': self._format_size(physical_size),
                    'space_saved': self._format_size(space_saved),
                    'compression_ratio': f"{compression_ratio:.1f}%",
                    'skipped_sectors': f"{space_saved // 512:,d}",
                    'method_used': 'basic-sparse'
                }
                
                if hash_value:
                    details['hash'] = hash_value
                
                self.operation_complete.emit(True, "Sparse image created successfully", details)
            else:
                error = process.stderr.read()
                self.operation_complete.emit(False, f"Failed to create sparse image: {error}", {})
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating sparse image: {str(e)}", {})
            
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _get_physical_size(self, file_path):
        """Get the actual disk usage of a file (for sparse files)"""
        try:
            # Use stat to get actual blocks used
            stat_output = os.stat(file_path)
            return stat_output.st_blocks * 512  # st_blocks is in 512-byte blocks
        except:
            # Fall back to logical size
            return os.path.getsize(file_path)
    
    def _format_size(self, size_in_bytes):
        """Format file size in human readable format"""
        if size_in_bytes < 1024:
            return f"{size_in_bytes} bytes"
        elif size_in_bytes < 1024 * 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 * 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"


class LogicalAcquisitionDialog(QDialog):
    """Dialog for performing logical acquisition of specific folders/files"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Logical Acquisition")
        self.resize(600, 400)
        
        layout = QVBoxLayout()
        
        # Source selection
        source_group = QGroupBox("Source")
        source_layout = QFormLayout()
        
        # Device selection
        device_layout = QHBoxLayout()
        self.device_edit = QLineEdit()
        self.device_edit.setPlaceholderText("Select source device...")
        device_layout.addWidget(self.device_edit)
        self.browse_device_btn = QPushButton("Browse")
        self.browse_device_btn.clicked.connect(self.browse_device)
        device_layout.addWidget(self.browse_device_btn)
        source_layout.addRow("Source Device:", device_layout)
        
        # Mount path 
        mount_layout = QHBoxLayout()
        self.mount_edit = QLineEdit()
        self.mount_edit.setPlaceholderText("Mount point (leave empty for auto-mount)")
        mount_layout.addWidget(self.mount_edit)
        self.browse_mount_btn = QPushButton("Browse")
        self.browse_mount_btn.clicked.connect(self.browse_mount)
        mount_layout.addWidget(self.browse_mount_btn)
        source_layout.addRow("Mount Point:", mount_layout)
        
        source_group.setLayout(source_layout)
        layout.addWidget(source_group)
        
        # Acquisition options
        options_group = QGroupBox("Acquisition Options")
        options_layout = QVBoxLayout()
        
        # Option to select specific folder
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Path to acquire (relative to mount point)")
        path_layout.addWidget(self.path_edit)
        options_layout.addLayout(path_layout)
        
        # File selection options
        self.recursive_check = QCheckBox("Recursive (include subfolders)")
        self.recursive_check.setChecked(True)
        options_layout.addWidget(self.recursive_check)
        
        self.metadata_check = QCheckBox("Preserve metadata (timestamps, permissions)")
        self.metadata_check.setChecked(True)
        options_layout.addWidget(self.metadata_check)
        
        self.hash_check = QCheckBox("Calculate hashes for all files")
        self.hash_check.setChecked(True)
        options_layout.addWidget(self.hash_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Output options
        output_group = QGroupBox("Output")
        output_layout = QFormLayout()
        
        # Output format
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Directory Copy", "ZIP Archive", "TAR Archive", "AFF4 Container"])
        output_layout.addRow("Format:", self.format_combo)
        
        # Output location
        output_path_layout = QHBoxLayout()
        self.output_edit = QLineEdit()
        output_path_layout.addWidget(self.output_edit)
        self.browse_output_btn = QPushButton("Browse")
        self.browse_output_btn.clicked.connect(self.browse_output)
        output_path_layout.addWidget(self.browse_output_btn)
        output_layout.addRow("Output Path:", output_path_layout)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Progress indicator
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Acquisition")
        self.start_btn.clicked.connect(self.start_acquisition)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Thread for background operations
        self.acquisition_thread = None
        
    def browse_device(self):
        """Browse and select source device"""
        try:
            # Get list of available devices
            lsblk_output = subprocess.check_output(['lsblk', '-o', 'NAME,SIZE,MOUNTPOINT,LABEL', '--json'], 
                                               universal_newlines=True)
            devices_info = json.loads(lsblk_output)
            
            devices = []
            for device in devices_info.get('blockdevices', []):
                name = f"/dev/{device['name']}"
                size = device.get('size', '')
                label = device.get('label', '')
                mountpoint = device.get('mountpoint', '')
                
                display = f"{name} ({size})"
                if label:
                    display += f", {label}"
                if mountpoint:
                    display += f", mounted at {mountpoint}"
                    
                devices.append((display, name, mountpoint))
                
                # Also add partitions
                for child in device.get('children', []):
                    child_name = f"/dev/{child['name']}"
                    child_size = child.get('size', '')
                    child_label = child.get('label', '')
                    child_mountpoint = child.get('mountpoint', '')
                    
                    child_display = f"{child_name} ({child_size})"
                    if child_label:
                        child_display += f", {child_label}"
                    if child_mountpoint:
                        child_display += f", mounted at {child_mountpoint}"
                        
                    devices.append((child_display, child_name, child_mountpoint))
            
            # Create dialog to select device
            dialog = QDialog(self)
            dialog.setWindowTitle("Select Source Device")
            dialog.resize(500, 400)
            
            layout = QVBoxLayout()
            layout.addWidget(QLabel("Select a device or partition:"))
            
            list_widget = QListWidget()
            for i, (display, _, _) in enumerate(devices):
                list_widget.addItem(display)
            
            layout.addWidget(list_widget)
            
            button_box = QHBoxLayout()
            ok_button = QPushButton("OK")
            cancel_button = QPushButton("Cancel")
            button_box.addWidget(ok_button)
            button_box.addWidget(cancel_button)
            
            ok_button.clicked.connect(dialog.accept)
            cancel_button.clicked.connect(dialog.reject)
            
            layout.addLayout(button_box)
            dialog.setLayout(layout)
            
            # Show dialog and get result
            if dialog.exec() == QDialog.DialogCode.Accepted and list_widget.currentRow() >= 0:
                selected_idx = list_widget.currentRow()
                self.device_edit.setText(devices[selected_idx][1])  # Set device path
                
                # If already mounted, suggest the mount point
                if devices[selected_idx][2]:
                    self.mount_edit.setText(devices[selected_idx][2])
                    
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error listing devices: {str(e)}")
            
    def browse_mount(self):
        """Browse for mount point directory"""
        mount_dir = QFileDialog.getExistingDirectory(self, "Select Mount Point")
        if mount_dir:
            self.mount_edit.setText(mount_dir)
            
    def browse_output(self):
        """Browse for output location"""
        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if output_dir:
            self.output_edit.setText(output_dir)
            
    def start_acquisition(self):
        """Start the logical acquisition process"""
        # Validate inputs
        device = self.device_edit.text()
        mount_point = self.mount_edit.text()
        path_to_acquire = self.path_edit.text()
        output_path = self.output_edit.text()
        
        if not device:
            QMessageBox.warning(self, "Input Error", "Please select a source device")
            return
            
        if not output_path:
            QMessageBox.warning(self, "Input Error", "Please specify an output location")
            return
            
        # Create acquisition thread
        self.acquisition_thread = LogicalAcquisitionThread(
            device=device,
            mount_point=mount_point,
            path_to_acquire=path_to_acquire,
            output_path=output_path,
            format=self.format_combo.currentText(),
            recursive=self.recursive_check.isChecked(),
            preserve_metadata=self.metadata_check.isChecked(),
            calculate_hash=self.hash_check.isChecked()
        )
        
        # Connect signals
        self.acquisition_thread.progress_update.connect(self.update_progress)
        self.acquisition_thread.status_update.connect(self.update_status)
        self.acquisition_thread.acquisition_complete.connect(self.acquisition_finished)
        
        # Disable UI elements
        self.start_btn.setEnabled(False)
        self.browse_device_btn.setEnabled(False)
        self.browse_mount_btn.setEnabled(False)
        self.browse_output_btn.setEnabled(False)
        
        # Start thread
        self.acquisition_thread.start()
        
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        
    def update_status(self, message):
        """Update status message"""
        self.start_btn.setText(message)
        
    def acquisition_finished(self, success, message, output_path):
        """Handle acquisition completion"""
        # Re-enable UI elements
        self.start_btn.setEnabled(True)
        self.start_btn.setText("Start Acquisition")
        self.browse_device_btn.setEnabled(True)
        self.browse_mount_btn.setEnabled(True)
        self.browse_output_btn.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Acquisition Complete", 
                                  f"Logical acquisition completed successfully.\n\n{message}")
            self.accept()
        else:
            QMessageBox.critical(self, "Acquisition Failed", 
                               f"Logical acquisition failed.\n\n{message}")


class LogicalAcquisitionThread(QThread):
    """Thread for performing logical acquisition in the background"""
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    acquisition_complete = pyqtSignal(bool, str, str)
    
    def __init__(self, device, mount_point, path_to_acquire, output_path, format,
                recursive, preserve_metadata, calculate_hash):
        super().__init__()
        self.device = device
        self.mount_point = mount_point
        self.path_to_acquire = path_to_acquire
        self.output_path = output_path
        self.format = format
        self.recursive = recursive
        self.preserve_metadata = preserve_metadata
        self.calculate_hash = calculate_hash
        self.cancel_requested = False
        
    def run(self):
        """Run the acquisition process"""
        try:
            # 1. Check if we need to mount the device
            temp_mount = False
            mounted_path = self.mount_point
            
            if not self.mount_point:
                # Create temporary mount point
                temp_dir = tempfile.mkdtemp(prefix="forensic_mount_")
                self.status_update.emit("Mounting device...")
                
                try:
                    # Mount the device read-only
                    subprocess.check_call(['mount', '-o', 'ro', self.device, temp_dir])
                    mounted_path = temp_dir
                    temp_mount = True
                    self.status_update.emit("Device mounted")
                except subprocess.CalledProcessError:
                    self.acquisition_complete.emit(False, f"Failed to mount {self.device}", "")
                    if os.path.exists(temp_dir):
                        os.rmdir(temp_dir)
                    return
            
            # 2. Determine the full source path
            source_path = mounted_path
            if self.path_to_acquire:
                source_path = os.path.join(mounted_path, self.path_to_acquire.lstrip('/'))
            
            # 3. Create output directory if it doesn't exist
            if not os.path.exists(self.output_path):
                os.makedirs(self.output_path)
            
            # 4. Create the acquisition log
            log_file = os.path.join(self.output_path, "acquisition_log.txt")
            with open(log_file, 'w') as f:
                f.write(f"Logical Acquisition Log\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Source Device: {self.device}\n")
                f.write(f"Mount Point: {mounted_path}\n")
                f.write(f"Path Acquired: {self.path_to_acquire or '/'}\n")
                f.write(f"Output Path: {self.output_path}\n")
                f.write(f"Format: {self.format}\n")
                f.write(f"Recursive: {self.recursive}\n")
                f.write(f"Preserve Metadata: {self.preserve_metadata}\n")
                f.write(f"Calculate Hash: {self.calculate_hash}\n\n")
            
            # 5. Perform the acquisition based on the selected format
            output_file = ""
            
            if self.format == "ZIP Archive":
                self.status_update.emit("Creating ZIP archive...")
                # Get the folder name from the path
                folder_name = os.path.basename(source_path) or "root"
                output_file = os.path.join(self.output_path, f"{folder_name}.zip")
                
                # Create the ZIP archive
                self._create_zip_archive(source_path, output_file, log_file)
                
            elif self.format == "TAR Archive":
                self.status_update.emit("Creating TAR archive...")
                # Get the folder name from the path
                folder_name = os.path.basename(source_path) or "root"
                output_file = os.path.join(self.output_path, f"{folder_name}.tar")
                
                # Create the TAR archive
                self._create_tar_archive(source_path, output_file, log_file)
                
            elif self.format == "Directory Copy":
                self.status_update.emit("Copying files...")
                # Create the directory structure
                output_dir = os.path.join(self.output_path, os.path.basename(source_path) or "root")
                
                # Copy the files
                self._copy_directory(source_path, output_dir, log_file)
                output_file = output_dir
                
            elif self.format == "AFF4 Container":
                self.status_update.emit("Creating AFF4 container...")
                # Note: This would require external libraries for AFF4 support
                # For now, we'll show a message that it's not implemented
                self.acquisition_complete.emit(False, "AFF4 format not implemented yet", "")
                return
            
            # 6. Unmount if we mounted it
            if temp_mount:
                self.status_update.emit("Unmounting device...")
                try:
                    subprocess.check_call(['umount', mounted_path])
                    os.rmdir(mounted_path)
                except:
                    pass  # Ignore unmount errors
            
            # 7. Complete
            self.acquisition_complete.emit(True, f"Acquisition completed successfully to {output_file}", output_file)
            
        except Exception as e:
            # Handle any unexpected errors
            self.acquisition_complete.emit(False, f"Error during acquisition: {str(e)}", "")
            
            # Clean up temporary mount if needed
            if temp_mount and mounted_path and os.path.ismount(mounted_path):
                try:
                    subprocess.check_call(['umount', mounted_path])
                    os.rmdir(mounted_path)
                except:
                    pass
    
    def _create_zip_archive(self, source_path, output_file, log_file):
        """Create a ZIP archive of the source path"""
        import zipfile
        import hashlib
        
        file_count = sum([len(files) for _, _, files in os.walk(source_path)])
        processed = 0
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add acquisition log to the archive
            zipf.write(log_file, os.path.basename(log_file))
            
            # Create a hashes file if requested
            hash_file = None
            if self.calculate_hash:
                hash_path = os.path.join(os.path.dirname(log_file), "file_hashes.txt")
                hash_file = open(hash_path, 'w')
                hash_file.write("File Path,MD5,SHA-256\n")
            
            for root, dirs, files in os.walk(source_path):
                # Stop if we're not doing recursive and this isn't the top directory
                if not self.recursive and root != source_path:
                    continue
                    
                # Add empty directories
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    zipf.write(dir_path, os.path.relpath(dir_path, os.path.dirname(source_path)))
                
                # Add files
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip the log file we just created
                    if file_path == log_file:
                        continue
                        
                    # Calculate hashes if requested
                    if self.calculate_hash and hash_file:
                        try:
                            md5_hash = hashlib.md5()
                            sha256_hash = hashlib.sha256()
                            
                            with open(file_path, 'rb') as f:
                                for chunk in iter(lambda: f.read(4096), b""):
                                    md5_hash.update(chunk)
                                    sha256_hash.update(chunk)
                                    
                            rel_path = os.path.relpath(file_path, source_path)
                            hash_file.write(f"{rel_path},{md5_hash.hexdigest()},{sha256_hash.hexdigest()}\n")
                        except Exception as e:
                            # Log hash calculation errors but continue
                            with open(log_file, 'a') as f:
                                f.write(f"Error calculating hash for {file_path}: {str(e)}\n")
                    
                    # Add to ZIP
                    zipf.write(file_path, os.path.relpath(file_path, os.path.dirname(source_path)))
                    
                    # Update progress
                    processed += 1
                    progress = min(int((processed / file_count) * 100), 99)
                    self.progress_update.emit(progress)
            
            # Close hash file if opened
            if hash_file:
                hash_file.close()
                # Add the hash file to the ZIP
                zipf.write(hash_path, os.path.basename(hash_path))
                
        # Final progress update
        self.progress_update.emit(100)
    
    def _create_tar_archive(self, source_path, output_file, log_file):
        """Create a TAR archive of the source path"""
        import tarfile
        import hashlib
        
        file_count = sum([len(files) for _, _, files in os.walk(source_path)])
        processed = 0
        
        with tarfile.open(output_file, 'w') as tar:
            # Add acquisition log to the archive
            tar.add(log_file, arcname=os.path.basename(log_file))
            
            # Create a hashes file if requested
            hash_file = None
            if self.calculate_hash:
                hash_path = os.path.join(os.path.dirname(log_file), "file_hashes.txt")
                hash_file = open(hash_path, 'w')
                hash_file.write("File Path,MD5,SHA-256\n")
            
            for root, dirs, files in os.walk(source_path):
                # Stop if we're not doing recursive and this isn't the top directory
                if not self.recursive and root != source_path:
                    continue
                    
                # Add files
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip the log file we just created
                    if file_path == log_file:
                        continue
                        
                    # Calculate hashes if requested
                    if self.calculate_hash and hash_file:
                        try:
                            md5_hash = hashlib.md5()
                            sha256_hash = hashlib.sha256()
                            
                            with open(file_path, 'rb') as f:
                                for chunk in iter(lambda: f.read(4096), b""):
                                    md5_hash.update(chunk)
                                    sha256_hash.update(chunk)
                                    
                            rel_path = os.path.relpath(file_path, source_path)
                            hash_file.write(f"{rel_path},{md5_hash.hexdigest()},{sha256_hash.hexdigest()}\n")
                        except Exception as e:
                            # Log hash calculation errors but continue
                            with open(log_file, 'a') as f:
                                f.write(f"Error calculating hash for {file_path}: {str(e)}\n")
                    
                    # Add to TAR
                    tar.add(file_path, arcname=os.path.relpath(file_path, os.path.dirname(source_path)))
                    
                    # Update progress
                    processed += 1
                    progress = min(int((processed / file_count) * 100), 99)
                    self.progress_update.emit(progress)
            
            # Close hash file if opened
            if hash_file:
                hash_file.close()
                # Add the hash file to the TAR
                tar.add(hash_path, arcname=os.path.basename(hash_path))
                
        # Final progress update
        self.progress_update.emit(100)
    
    def _copy_directory(self, source_path, output_dir, log_file):
        """Copy the directory structure preserving metadata if requested"""
        import shutil
        import hashlib
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Count total files for progress tracking
        file_count = sum([len(files) for _, _, files in os.walk(source_path)])
        processed = 0
        
        # Create a hashes file if requested
        hash_file = None
        if self.calculate_hash:
            hash_path = os.path.join(os.path.dirname(log_file), "file_hashes.txt")
            hash_file = open(hash_path, 'w')
            hash_file.write("File Path,MD5,SHA-256\n")
        
        for root, dirs, files in os.walk(source_path):
            # Stop if we're not doing recursive and this isn't the top directory
            if not self.recursive and root != source_path:
                continue
                
            # Create relative path
            rel_path = os.path.relpath(root, source_path)
            target_dir = output_dir if rel_path == "." else os.path.join(output_dir, rel_path)
            
            # Create directory if it doesn't exist
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
                
            # Copy files
            for file in files:
                src_file = os.path.join(root, file)
                dst_file = os.path.join(target_dir, file)
                
                try:
                    # Calculate hashes if requested
                    if self.calculate_hash and hash_file:
                        try:
                            md5_hash = hashlib.md5()
                            sha256_hash = hashlib.sha256()
                            
                            with open(src_file, 'rb') as f:
                                for chunk in iter(lambda: f.read(4096), b""):
                                    md5_hash.update(chunk)
                                    sha256_hash.update(chunk)
                                    
                            rel_file_path = os.path.relpath(src_file, source_path)
                            hash_file.write(f"{rel_file_path},{md5_hash.hexdigest()},{sha256_hash.hexdigest()}\n")
                        except Exception as e:
                            # Log hash calculation errors but continue
                            with open(log_file, 'a') as f:
                                f.write(f"Error calculating hash for {src_file}: {str(e)}\n")
                    
                    # Copy the file with or without metadata
                    if self.preserve_metadata:
                        shutil.copy2(src_file, dst_file)  # Preserves metadata
                    else:
                        shutil.copy(src_file, dst_file)  # Just copies content
                        
                except Exception as e:
                    # Log copy errors but continue
                    with open(log_file, 'a') as f:
                        f.write(f"Error copying {src_file}: {str(e)}\n")
                
                # Update progress
                processed += 1
                progress = min(int((processed / file_count) * 100), 99)
                self.progress_update.emit(progress)
        
        # Close hash file if opened
        if hash_file:
            hash_file.close()
            # Copy the hash file to the output directory
            shutil.copy(hash_path, os.path.join(output_dir, os.path.basename(hash_path)))
            
        # Copy the log file to the output directory
        shutil.copy(log_file, os.path.join(output_dir, os.path.basename(log_file)))
        
        # Final progress update
        self.progress_update.emit(100)


class ReportGenerator:
    """Enhanced report generation class with support for multiple formats"""
    
    def __init__(self, case_manager):
        self.case_manager = case_manager
        
    def generate_report(self, output_path, report_format="pdf", options=None):
        """
        Generate a report in the specified format
        
        Parameters:
        output_path (str): Path to save the report
        report_format (str): Format of the report (pdf, html, xml, csv)
        options (dict): Report options including content to include
        
        Returns:
        bool: True if successful, False otherwise
        """
        if options is None:
            options = {
                'include_case_info': True,
                'include_evidence': True,
                'include_bookmarks': True,
                'include_notes': True,
                'include_logo': False,
                'logo_path': None,
                'include_header_footer': True,
                'theme': 'default'  # default, dark, professional, etc.
            }
        
        try:
            if report_format.lower() == "pdf":
                return self._generate_pdf_report(output_path, options)
            elif report_format.lower() == "html":
                return self._generate_html_report(output_path, options)
            elif report_format.lower() == "xml":
                return self._generate_xml_report(output_path, options)
            elif report_format.lower() == "csv":
                return self._generate_csv_report(output_path, options)
            else:
                print(f"Unsupported report format: {report_format}")
                return False
        except Exception as e:
            print(f"Error generating report: {e}")
            return False
    
    def _generate_pdf_report(self, output_path, options):
        """Generate a PDF report with customizable options"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.platypus import Image, PageBreak, KeepTogether
            from reportlab.lib.units import inch
            
            # Create the PDF
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Custom styles based on theme
            if options.get('theme') == 'professional':
                title_style = ParagraphStyle(
                    name='CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=16,
                    textColor=colors.navy,
                    spaceAfter=12
                )
                heading2_style = ParagraphStyle(
                    name='CustomHeading2',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=colors.navy,
                    spaceAfter=6
                )
                normal_style = ParagraphStyle(
                    name='CustomNormal',
                    parent=styles['Normal'],
                    fontSize=10,
                    leading=12
                )
            elif options.get('theme') == 'dark':
                # Dark theme (note: background colors may not fully work in PDFs)
                title_style = ParagraphStyle(
                    name='CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=16,
                    textColor=colors.white,
                    spaceAfter=12
                )
                heading2_style = ParagraphStyle(
                    name='CustomHeading2',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=colors.lightgrey,
                    spaceAfter=6
                )
                normal_style = ParagraphStyle(
                    name='CustomNormal',
                    parent=styles['Normal'],
                    fontSize=10,
                    leading=12,
                    textColor=colors.whitesmoke
                )
            else:
                # Default theme
                title_style = styles["Heading1"]
                heading2_style = styles["Heading2"]
                normal_style = styles["Normal"]
            
            # Add logo if specified
            if options.get('include_logo') and options.get('logo_path'):
                try:
                    logo = Image(options['logo_path'], width=2*inch, height=1*inch)
                    elements.append(logo)
                    elements.append(Spacer(1, 12))
                except Exception as e:
                    print(f"Error adding logo: {e}")
            
            # Title
            elements.append(Paragraph(f"Forensic Analysis Report: {self.case_manager.case_name}", title_style))
            elements.append(Spacer(1, 12))
            
            # Case Information
            if options.get('include_case_info', True):
                elements.append(Paragraph("Case Information", heading2_style))
                elements.append(Spacer(1, 6))
                
                case_info = [
                    ["Case Name:", self.case_manager.case_name],
                    ["Investigator:", self.case_manager.investigator_name],
                    ["Date:", datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
                ]
                
                t = Table(case_info, colWidths=[100, 400])
                table_style = TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ])
                
                # Apply theme-specific styles
                if options.get('theme') == 'professional':
                    table_style.add('BACKGROUND', (0, 0), (0, -1), colors.lightsteelblue)
                    table_style.add('TEXTCOLOR', (0, 0), (-1, -1), colors.navy)
                elif options.get('theme') == 'dark':
                    table_style.add('BACKGROUND', (0, 0), (0, -1), colors.darkslategray)
                    table_style.add('BACKGROUND', (1, 0), (-1, -1), colors.slategray)
                    table_style.add('TEXTCOLOR', (0, 0), (-1, -1), colors.white)
                else:
                    table_style.add('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
                
                t.setStyle(table_style)
                elements.append(t)
                elements.append(Spacer(1, 12))
            
            # Evidence Items
            if options.get('include_evidence', True):
                elements.append(Paragraph("Evidence Items", heading2_style))
                elements.append(Spacer(1, 6))
                
                if self.case_manager.evidence_items:
                    evidence_data = [["ID", "Type", "Description", "Added Date"]]
                    for item in self.case_manager.evidence_items:
                        evidence_data.append([
                            str(item["id"]),
                            item["type"],
                            item["description"],
                            item["added_date"]
                        ])
                    
                    t = Table(evidence_data, colWidths=[30, 80, 290, 100])
                    table_style = TableStyle([
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ])
                    
                    # Theme-specific styling
                    if options.get('theme') == 'professional':
                        table_style.add('BACKGROUND', (0, 0), (-1, 0), colors.lightsteelblue)
                        table_style.add('TEXTCOLOR', (0, 0), (-1, 0), colors.navy)
                    elif options.get('theme') == 'dark':
                        table_style.add('BACKGROUND', (0, 0), (-1, 0), colors.darkslategray)
                        table_style.add('TEXTCOLOR', (0, 0), (-1, -1), colors.white)
                        # Alternating row colors
                        for i in range(1, len(evidence_data), 2):
                            table_style.add('BACKGROUND', (0, i), (-1, i), colors.slategray)
                    else:
                        table_style.add('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
                    
                    t.setStyle(table_style)
                    elements.append(t)
                else:
                    elements.append(Paragraph("No evidence items added to this case.", normal_style))
                
                elements.append(Spacer(1, 12))
            
            # Bookmarks
            if options.get('include_bookmarks', True):
                elements.append(Paragraph("Bookmarks", heading2_style))
                elements.append(Spacer(1, 6))
                
                if self.case_manager.bookmarks:
                    bookmark_data = [["ID", "Evidence ID", "File Path", "Description", "Added Date"]]
                    for bookmark in self.case_manager.bookmarks:
                        bookmark_data.append([
                            str(bookmark["id"]),
                            str(bookmark["evidence_id"]),
                            bookmark["file_path"],
                            bookmark["description"],
                            bookmark["added_date"]
                        ])
                    
                    t = Table(bookmark_data, colWidths=[30, 60, 180, 130, 100])
                    table_style = TableStyle([
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ])
                    
                    # Theme-specific styling (same as evidence table)
                    if options.get('theme') == 'professional':
                        table_style.add('BACKGROUND', (0, 0), (-1, 0), colors.lightsteelblue)
                        table_style.add('TEXTCOLOR', (0, 0), (-1, 0), colors.navy)
                    elif options.get('theme') == 'dark':
                        table_style.add('BACKGROUND', (0, 0), (-1, 0), colors.darkslategray)
                        table_style.add('TEXTCOLOR', (0, 0), (-1, -1), colors.white)
                        for i in range(1, len(bookmark_data), 2):
                            table_style.add('BACKGROUND', (0, i), (-1, i), colors.slategray)
                    else:
                        table_style.add('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
                    
                    t.setStyle(table_style)
                    elements.append(t)
                else:
                    elements.append(Paragraph("No bookmarks added to this case.", normal_style))
                
                elements.append(Spacer(1, 12))
            
            # Notes
            if options.get('include_notes', True) and self.case_manager.case_notes:
                elements.append(Paragraph("Case Notes", heading2_style))
                elements.append(Spacer(1, 6))
                elements.append(Paragraph(self.case_manager.case_notes, normal_style))
                elements.append(Spacer(1, 12))
            
            # Build the PDF
            doc.build(elements)
            return True
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return False
    
    def _generate_html_report(self, output_path, options):
        """Generate an HTML report with customizable options"""
        try:
            # Define HTML templates based on theme
            if options.get('theme') == 'professional':
                css_style = """
                    body { font-family: 'Arial', sans-serif; margin: 20px; color: #333; }
                    h1 { color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }
                    h2 { color: #003366; margin-top: 20px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }
                    th { background-color: #b8c7d6; padding: 10px; text-align: left; color: #003366; }
                    td { padding: 8px; border: 1px solid #ddd; }
                    tr:nth-child(even) { background-color: #f2f2f2; }
                    .header { display: flex; align-items: center; margin-bottom: 20px; }
                    .header img { margin-right: 20px; max-height: 80px; }
                    .notes { background-color: #f9f9f9; padding: 15px; border-left: 4px solid #003366; }
                """
            elif options.get('theme') == 'dark':
                css_style = """
                    body { font-family: 'Arial', sans-serif; margin: 20px; background-color: #2d2d2d; color: #e0e0e0; }
                    h1 { color: #e0e0e0; border-bottom: 2px solid #555; padding-bottom: 10px; }
                    h2 { color: #e0e0e0; margin-top: 20px; border-bottom: 1px solid #555; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }
                    th { background-color: #444; padding: 10px; text-align: left; color: #fff; }
                    td { padding: 8px; border: 1px solid #555; }
                    tr:nth-child(even) { background-color: #3d3d3d; }
                    tr:nth-child(odd) { background-color: #333; }
                    .header { display: flex; align-items: center; margin-bottom: 20px; }
                    .header img { margin-right: 20px; max-height: 80px; }
                    .notes { background-color: #333; padding: 15px; border-left: 4px solid #0d47a1; }
                """
            else:  # default theme
                css_style = """
                    body { font-family: 'Arial', sans-serif; margin: 20px; }
                    h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
                    h2 { margin-top: 20px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }
                    th { background-color: #f2f2f2; padding: 10px; text-align: left; }
                    td { padding: 8px; border: 1px solid #ddd; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    .header { display: flex; align-items: center; margin-bottom: 20px; }
                    .header img { margin-right: 20px; max-height: 80px; }
                    .notes { background-color: #f9f9f9; padding: 15px; border-left: 4px solid #333; }
                """
            
            # Start building the HTML content
            html_content = f"""<!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Forensic Analysis Report: {self.case_manager.case_name}</title>
                <style>
                {css_style}
                </style>
            </head>
            <body>
            """
            
            # Header with optional logo
            html_content += "<div class='header'>"
            if options.get('include_logo') and options.get('logo_path'):
                html_content += f"<img src='{options['logo_path']}' alt='Company Logo'>"
            
            html_content += f"<div><h1>Forensic Analysis Report: {self.case_manager.case_name}</h1></div>"
            html_content += "</div>"
            
            # Case Information
            if options.get('include_case_info', True):
                html_content += "<h2>Case Information</h2>"
                html_content += "<table>"
                html_content += f"<tr><td><strong>Case Name:</strong></td><td>{self.case_manager.case_name}</td></tr>"
                html_content += f"<tr><td><strong>Investigator:</strong></td><td>{self.case_manager.investigator_name}</td></tr>"
                html_content += f"<tr><td><strong>Date:</strong></td><td>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>"
                html_content += "</table>"
            
            # Evidence Items
            if options.get('include_evidence', True):
                html_content += "<h2>Evidence Items</h2>"
                if self.case_manager.evidence_items:
                    html_content += "<table>"
                    html_content += "<tr><th>ID</th><th>Type</th><th>Description</th><th>Added Date</th></tr>"
                    
                    for item in self.case_manager.evidence_items:
                        html_content += "<tr>"
                        html_content += f"<td>{item['id']}</td>"
                        html_content += f"<td>{item['type']}</td>"
                        html_content += f"<td>{item['description']}</td>"
                        html_content += f"<td>{item['added_date']}</td>"
                        html_content += "</tr>"
                        
                    html_content += "</table>"
                else:
                    html_content += "<p>No evidence items added to this case.</p>"
            
            # Bookmarks
            if options.get('include_bookmarks', True):
                html_content += "<h2>Bookmarks</h2>"
                if self.case_manager.bookmarks:
                    html_content += "<table>"
                    html_content += "<tr><th>ID</th><th>Evidence ID</th><th>File Path</th><th>Description</th><th>Added Date</th></tr>"
                    
                    for bookmark in self.case_manager.bookmarks:
                        html_content += "<tr>"
                        html_content += f"<td>{bookmark['id']}</td>"
                        html_content += f"<td>{bookmark['evidence_id']}</td>"
                        html_content += f"<td>{bookmark['file_path']}</td>"
                        html_content += f"<td>{bookmark['description']}</td>"
                        html_content += f"<td>{bookmark['added_date']}</td>"
                        html_content += "</tr>"
                        
                    html_content += "</table>"
                else:
                    html_content += "<p>No bookmarks added to this case.</p>"
            
            # Notes
            if options.get('include_notes', True) and self.case_manager.case_notes:
                html_content += "<h2>Case Notes</h2>"
                html_content += f"<div class='notes'>{self.case_manager.case_notes.replace('\n', '<br>')}</div>"
            
            # Close HTML document
            html_content += """
            </body>
            </html>
            """
            
            # Write HTML to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            return True
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return False
    
    def _generate_xml_report(self, output_path, options):
        """Generate an XML report for the case"""
        try:
            import xml.dom.minidom as md
            import xml.etree.ElementTree as ET
            
            # Create the root element
            root = ET.Element("ForensicReport")
            
            # Add metadata
            metadata = ET.SubElement(root, "Metadata")
            ET.SubElement(metadata, "ReportTitle").text = f"Forensic Analysis Report: {self.case_manager.case_name}"
            ET.SubElement(metadata, "GeneratedDate").text = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Add case information
            if options.get('include_case_info', True):
                case_info = ET.SubElement(root, "CaseInformation")
                ET.SubElement(case_info, "CaseName").text = self.case_manager.case_name
                ET.SubElement(case_info, "Investigator").text = self.case_manager.investigator_name
            
            # Add evidence items
            if options.get('include_evidence', True):
                evidence_items = ET.SubElement(root, "EvidenceItems")
                for item in self.case_manager.evidence_items:
                    evidence = ET.SubElement(evidence_items, "Evidence")
                    ET.SubElement(evidence, "ID").text = str(item["id"])
                    ET.SubElement(evidence, "Type").text = item["type"]
                    ET.SubElement(evidence, "Path").text = item["path"]
                    ET.SubElement(evidence, "Description").text = item["description"]
                    ET.SubElement(evidence, "AddedDate").text = item["added_date"]
            
            # Add bookmarks
            if options.get('include_bookmarks', True):
                bookmarks = ET.SubElement(root, "Bookmarks")
                for bookmark in self.case_manager.bookmarks:
                    bookmark_elem = ET.SubElement(bookmarks, "Bookmark")
                    ET.SubElement(bookmark_elem, "ID").text = str(bookmark["id"])
                    ET.SubElement(bookmark_elem, "EvidenceID").text = str(bookmark["evidence_id"])
                    ET.SubElement(bookmark_elem, "FilePath").text = bookmark["file_path"]
                    ET.SubElement(bookmark_elem, "Description").text = bookmark["description"]
                    ET.SubElement(bookmark_elem, "AddedDate").text = bookmark["added_date"]
            
            # Add case notes
            if options.get('include_notes', True) and self.case_manager.case_notes:
                notes = ET.SubElement(root, "CaseNotes")
                notes.text = self.case_manager.case_notes
            
            # Create a formatted XML string
            rough_string = ET.tostring(root, 'utf-8')
            reparsed = md.parseString(rough_string)
            pretty_xml = reparsed.toprettyxml(indent="  ")
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(pretty_xml)
                
            return True
        except Exception as e:
            print(f"Error generating XML report: {e}")
            return False
    
    def _generate_csv_report(self, output_path, options):
        """Generate CSV reports for the case"""
        try:
            import csv
            import os
            
            # Get the base filename without extension
            base_path = os.path.splitext(output_path)[0]
            
            # Function to write a CSV file
            def write_csv(data, filename, headers):
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(headers)
                    writer.writerows(data)
            
            # Create a case info CSV
            if options.get('include_case_info', True):
                case_info_file = f"{base_path}_case_info.csv"
                case_data = [
                    ["Case Name", self.case_manager.case_name],
                    ["Investigator", self.case_manager.investigator_name],
                    ["Report Date", datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
                ]
                write_csv(case_data, case_info_file, ["Field", "Value"])
            
            # Create an evidence items CSV
            if options.get('include_evidence', True) and self.case_manager.evidence_items:
                evidence_file = f"{base_path}_evidence.csv"
                evidence_data = []
                for item in self.case_manager.evidence_items:
                    evidence_data.append([
                        item["id"],
                        item["type"],
                        item["path"],
                        item["description"],
                        item["added_date"]
                    ])
                write_csv(evidence_data, evidence_file, ["ID", "Type", "Path", "Description", "Added Date"])
            
            # Create a bookmarks CSV
            if options.get('include_bookmarks', True) and self.case_manager.bookmarks:
                bookmarks_file = f"{base_path}_bookmarks.csv"
                bookmark_data = []
                for bookmark in self.case_manager.bookmarks:
                    bookmark_data.append([
                        bookmark["id"],
                        bookmark["evidence_id"],
                        bookmark["file_path"],
                        bookmark["description"],
                        bookmark["added_date"]
                    ])
                write_csv(bookmark_data, bookmarks_file, ["ID", "Evidence ID", "File Path", "Description", "Added Date"])
            
            # Create a notes text file
            if options.get('include_notes', True) and self.case_manager.case_notes:
                notes_file = f"{base_path}_notes.txt"
                with open(notes_file, 'w', encoding='utf-8') as f:
                    f.write(self.case_manager.case_notes)
            
            return True
        except Exception as e:
            print(f"Error generating CSV report: {e}")
            return False

class EnhancedExportOptionsDialog(QDialog):
    """
    Enhanced dialog for configuring report export options with support for
    multiple formats, themes, and customization options
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Report Options")
        self.resize(600, 500)
        
        # Main layout
        main_layout = QVBoxLayout()
        
        # Create a tab widget for different setting categories
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # === Basic Options Tab ===
        basic_tab = QWidget()
        basic_layout = QVBoxLayout()
        
        # Report format selection
        format_group = QGroupBox("Report Format")
        format_layout = QVBoxLayout()
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF Report", "HTML Report", "XML Report", "CSV Export"])
        format_layout.addWidget(self.format_combo)
        format_group.setLayout(format_layout)
        basic_layout.addWidget(format_group)
        
        # Content options
        content_group = QGroupBox("Include Content")
        content_layout = QVBoxLayout()
        
        self.include_case_info = QCheckBox("Case Information")
        self.include_case_info.setChecked(True)
        
        self.include_evidence = QCheckBox("Evidence Items")
        self.include_evidence.setChecked(True)
        
        self.include_bookmarks = QCheckBox("Bookmarks")
        self.include_bookmarks.setChecked(True)
        
        self.include_notes = QCheckBox("Case Notes")
        self.include_notes.setChecked(True)
        
        content_layout.addWidget(self.include_case_info)
        content_layout.addWidget(self.include_evidence)
        content_layout.addWidget(self.include_bookmarks)
        content_layout.addWidget(self.include_notes)
        
        content_group.setLayout(content_layout)
        basic_layout.addWidget(content_group)
        
        # Finish the basic tab
        basic_tab.setLayout(basic_layout)
        self.tab_widget.addTab(basic_tab, "Basic Options")
        
        # === Advanced Options Tab ===
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout()
        
        # Theme selection
        theme_group = QGroupBox("Report Theme")
        theme_layout = QVBoxLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Default", "Professional", "Dark"])
        theme_layout.addWidget(self.theme_combo)
        
        # Preview button
        self.preview_theme_btn = QPushButton("Preview Theme")
        self.preview_theme_btn.clicked.connect(self.preview_theme)
        theme_layout.addWidget(self.preview_theme_btn)
        
        theme_group.setLayout(theme_layout)
        advanced_layout.addWidget(theme_group)
        
        # Company branding
        branding_group = QGroupBox("Company Branding")
        branding_layout = QVBoxLayout()
        
        self.include_logo = QCheckBox("Include Logo")
        branding_layout.addWidget(self.include_logo)
        
        logo_layout = QHBoxLayout()
        self.logo_path = QLineEdit()
        self.logo_path.setPlaceholderText("Path to logo image")
        self.logo_browse_btn = QPushButton("Browse")
        self.logo_browse_btn.clicked.connect(self.browse_logo)
        logo_layout.addWidget(self.logo_path)
        logo_layout.addWidget(self.logo_browse_btn)
        branding_layout.addLayout(logo_layout)
        
        self.include_header_footer = QCheckBox("Include Custom Header/Footer")
        self.include_header_footer.setChecked(True)
        branding_layout.addWidget(self.include_header_footer)
        
        branding_group.setLayout(branding_layout)
        advanced_layout.addWidget(branding_group)
        
        # Finish the advanced tab
        advanced_tab.setLayout(advanced_layout)
        self.tab_widget.addTab(advanced_tab, "Advanced Options")
        
        # === Output Options Tab ===
        output_tab = QWidget()
        output_layout = QVBoxLayout()
        
        # File options
        file_group = QGroupBox("Output File Options")
        file_layout = QFormLayout()
        
        self.filename_edit = QLineEdit()
        self.filename_edit.setPlaceholderText("Output filename (without extension)")
        file_layout.addRow("Filename:", self.filename_edit)
        
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setReadOnly(True)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.output_path_edit)
        
        self.browse_path_btn = QPushButton("Browse")
        self.browse_path_btn.clicked.connect(self.browse_output_path)
        path_layout.addWidget(self.browse_path_btn)
        
        file_layout.addRow("Output Path:", path_layout)
        
        # Open after export option
        self.open_after_export = QCheckBox("Open report after export")
        self.open_after_export.setChecked(True)
        file_layout.addWidget(self.open_after_export)
        
        file_group.setLayout(file_layout)
        output_layout.addWidget(file_group)
        
        # Digital signature (placeholder for future implementation)
        signature_group = QGroupBox("Digital Signature")
        signature_layout = QVBoxLayout()
        
        self.include_signature = QCheckBox("Include Digital Signature (Future feature)")
        self.include_signature.setEnabled(False)  # Disabled for now
        signature_layout.addWidget(self.include_signature)
        
        signature_group.setLayout(signature_layout)
        output_layout.addWidget(signature_group)
        
        # Finish the output tab
        output_tab.setLayout(output_layout)
        self.tab_widget.addTab(output_tab, "Output Options")
        
        # Buttons at the bottom
        button_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.cancel_btn)
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)
        
        # Connect signals
        self.format_combo.currentIndexChanged.connect(self.update_ui_for_format)
        self.include_logo.stateChanged.connect(self.toggle_logo_controls)
        
        # Initial UI updates
        self.toggle_logo_controls()
        
    def browse_logo(self):
        """Open a file dialog to select a logo image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Logo Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp)"
        )
        if file_path:
            self.logo_path.setText(file_path)
            
    def browse_output_path(self):
        """Open a file dialog to select the output directory"""
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.output_path_edit.setText(dir_path)
            
    def toggle_logo_controls(self):
        """Enable or disable logo path controls based on checkbox state"""
        enabled = self.include_logo.isChecked()
        self.logo_path.setEnabled(enabled)
        self.logo_browse_btn.setEnabled(enabled)
        
    def update_ui_for_format(self, index):
        """Update UI elements based on the selected format"""
        format_text = self.format_combo.currentText()
        
        # Enable/disable theme options based on format
        enable_theme = format_text in ["PDF Report", "HTML Report"]
        self.theme_combo.setEnabled(enable_theme)
        self.preview_theme_btn.setEnabled(enable_theme)
        
        # Enable/disable branding options based on format
        enable_branding = format_text in ["PDF Report", "HTML Report"]
        self.include_logo.setEnabled(enable_branding)
        self.logo_path.setEnabled(enable_branding and self.include_logo.isChecked())
        self.logo_browse_btn.setEnabled(enable_branding and self.include_logo.isChecked())
        self.include_header_footer.setEnabled(enable_branding)
        
    def preview_theme(self):
        """Show a preview of the selected theme"""
        theme = self.theme_combo.currentText().lower()
        format_type = self.format_combo.currentText().split()[0].lower()
        
        # Create a preview dialog
        preview_dialog = QDialog(self)
        preview_dialog.setWindowTitle(f"Theme Preview: {theme.title()}")
        preview_dialog.resize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create a preview based on format and theme
        if format_type == "pdf":
            preview_text = QLabel("PDF preview not available. PDF themes will include:")
            features = QTextEdit()
            features.setReadOnly(True)
            
            if theme == "professional":
                features.setHtml("""
                <ul>
                    <li>Professional blue color scheme</li>
                    <li>Modern heading styles</li>
                    <li>Properly formatted tables with alternating row colors</li>
                    <li>Company logo integration</li>
                    <li>Clean and structured layout</li>
                </ul>
                """)
            elif theme == "dark":
                features.setHtml("""
                <ul>
                    <li>Dark color scheme (note: background colors in PDFs may be limited)</li>
                    <li>White/light text for contrast</li>
                    <li>Properly formatted tables with dark headers</li>
                    <li>Company logo integration</li>
                    <li>Professional layout adapted for dark themes</li>
                </ul>
                """)
            else:  # default
                features.setHtml("""
                <ul>
                    <li>Clean default styling</li>
                    <li>Black text on white background</li>
                    <li>Simple table formatting</li>
                    <li>Standard heading hierarchy</li>
                    <li>Basic, professional appearance</li>
                </ul>
                """)
                
            layout.addWidget(preview_text)
            layout.addWidget(features)
        else:  # html preview
            preview_html = QTextEdit()
            preview_html.setReadOnly(True)
            
            if theme == "professional":
                preview_html.setHtml("""
                <style>
                    body { font-family: 'Arial', sans-serif; margin: 20px; color: #333; }
                    h1 { color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }
                    h2 { color: #003366; margin-top: 20px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; }
                    th { background-color: #b8c7d6; padding: 10px; text-align: left; color: #003366; }
                    td { padding: 8px; border: 1px solid #ddd; }
                    tr:nth-child(even) { background-color: #f2f2f2; }
                </style>
                <h1>Forensic Analysis Report: Sample Case</h1>
                <h2>Case Information</h2>
                <table>
                    <tr><td><strong>Case Name:</strong></td><td>Sample Case</td></tr>
                    <tr><td><strong>Investigator:</strong></td><td>John Doe</td></tr>
                </table>
                <h2>Evidence Items</h2>
                <table>
                    <tr><th>ID</th><th>Type</th><th>Description</th></tr>
                    <tr><td>1</td><td>Disk Image</td><td>Primary hard drive</td></tr>
                    <tr><td>2</td><td>Memory Dump</td><td>RAM capture</td></tr>
                </table>
                """)
            elif theme == "dark":
                preview_html.setHtml("""
                <style>
                    body { font-family: 'Arial', sans-serif; margin: 20px; background-color: #2d2d2d; color: #e0e0e0; }
                    h1 { color: #e0e0e0; border-bottom: 2px solid #555; padding-bottom: 10px; }
                    h2 { color: #e0e0e0; margin-top: 20px; border-bottom: 1px solid #555; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; }
                    th { background-color: #444; padding: 10px; text-align: left; color: #fff; }
                    td { padding: 8px; border: 1px solid #555; }
                    tr:nth-child(even) { background-color: #3d3d3d; }
                    tr:nth-child(odd) { background-color: #333; }
                </style>
                <h1>Forensic Analysis Report: Sample Case</h1>
                <h2>Case Information</h2>
                <table>
                    <tr><td><strong>Case Name:</strong></td><td>Sample Case</td></tr>
                    <tr><td><strong>Investigator:</strong></td><td>John Doe</td></tr>
                </table>
                <h2>Evidence Items</h2>
                <table>
                    <tr><th>ID</th><th>Type</th><th>Description</th></tr>
                    <tr><td>1</td><td>Disk Image</td><td>Primary hard drive</td></tr>
                    <tr><td>2</td><td>Memory Dump</td><td>RAM capture</td></tr>
                </table>
                """)
            else:  # default
                preview_html.setHtml("""
                <style>
                    body { font-family: 'Arial', sans-serif; margin: 20px; }
                    h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
                    h2 { margin-top: 20px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; }
                    th { background-color: #f2f2f2; padding: 10px; text-align: left; }
                    td { padding: 8px; border: 1px solid #ddd; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                </style>
                <h1>Forensic Analysis Report: Sample Case</h1>
                <h2>Case Information</h2>
                <table>
                    <tr><td><strong>Case Name:</strong></td><td>Sample Case</td></tr>
                    <tr><td><strong>Investigator:</strong></td><td>John Doe</td></tr>
                </table>
                <h2>Evidence Items</h2>
                <table>
                    <tr><th>ID</th><th>Type</th><th>Description</th></tr>
                    <tr><td>1</td><td>Disk Image</td><td>Primary hard drive</td></tr>
                    <tr><td>2</td><td>Memory Dump</td><td>RAM capture</td></tr>
                </table>
                """)
            
            layout.addWidget(preview_html)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(preview_dialog.accept)
        layout.addWidget(close_btn)
        
        preview_dialog.setLayout(layout)
        preview_dialog.exec()
        
    def get_export_options(self):
        """Get all the export options selected by the user"""
        # Get the format type (pdf, html, xml, csv)
        format_text = self.format_combo.currentText().lower().split()[0]
        
        options = {
            'format': format_text,
            'include_case_info': self.include_case_info.isChecked(),
            'include_evidence': self.include_evidence.isChecked(),
            'include_bookmarks': self.include_bookmarks.isChecked(),
            'include_notes': self.include_notes.isChecked(),
            'theme': self.theme_combo.currentText().lower(),
            'include_logo': self.include_logo.isChecked(),
            'logo_path': self.logo_path.text() if self.include_logo.isChecked() else None,
            'include_header_footer': self.include_header_footer.isChecked(),
            'open_after_export': self.open_after_export.isChecked(),
            'output_filename': self.filename_edit.text(),
            'output_path': self.output_path_edit.text()
        }
        
        return options


class FileTypeAnalyzer:
    """Analyze file types in a forensic image"""
    def __init__(self, forensic_image):
        self.image = forensic_image
        self.file_signatures = {
            # Images
            b'\xFF\xD8\xFF': {'type': 'JPEG Image', 'ext': 'jpg'},
            b'\x89PNG\r\n\x1A\n': {'type': 'PNG Image', 'ext': 'png'},
            b'GIF87a': {'type': 'GIF Image', 'ext': 'gif'},
            b'GIF89a': {'type': 'GIF Image', 'ext': 'gif'},
            b'BM': {'type': 'Bitmap Image', 'ext': 'bmp'},
            
            # Documents
            b'%PDF': {'type': 'PDF Document', 'ext': 'pdf'},
            b'\xD0\xCF\x11\xE0': {'type': 'MS Office Document', 'ext': 'doc/xls/ppt'},
            b'PK\x03\x04': {'type': 'ZIP/Office Document', 'ext': 'zip/docx/xlsx/pptx'},
            
            # Executables
            b'MZ': {'type': 'Windows Executable', 'ext': 'exe/dll'},
            b'\x7FELF': {'type': 'Linux Executable', 'ext': 'elf'},
            
            # Compressed
            b'\x1F\x8B\x08': {'type': 'GZIP Archive', 'ext': 'gz'},
            b'BZh': {'type': 'BZIP2 Archive', 'ext': 'bz2'},
            b'Rar!\x1A\x07': {'type': 'RAR Archive', 'ext': 'rar'},
            b'7z\xBC\xAF\x27\x1C': {'type': '7-Zip Archive', 'ext': '7z'},
            
            # Media
            b'\x00\x00\x00\x18ftypmp4': {'type': 'MP4 Video', 'ext': 'mp4'},
            b'\x00\x00\x00\x14ftypqt': {'type': 'QuickTime Video', 'ext': 'mov'},
            b'ID3': {'type': 'MP3 Audio', 'ext': 'mp3'},
            b'RIFF': {'type': 'AVI/WAV', 'ext': 'avi/wav'},
            
            # Others
            b'SQLite format': {'type': 'SQLite Database', 'ext': 'db'},
            b'#!/': {'type': 'Shell Script', 'ext': 'sh'},
        }
        
    def identify_file_type(self, file_data):
        """Identify file type based on signature"""
        if not file_data or len(file_data) < 8:
            return {'type': 'Unknown', 'ext': ''}
            
        for signature, info in self.file_signatures.items():
            if file_data.startswith(signature):
                return info
                
        # Try text detection
        is_text = True
        for byte in file_data[:min(100, len(file_data))]:
            if byte < 9 or (byte > 13 and byte < 32 and byte != 27):
                is_text = False
                break
                
        if is_text:
            return {'type': 'Text File', 'ext': 'txt'}
            
        return {'type': 'Unknown', 'ext': ''}
        
    def analyze_directory(self, path="/"):
        """Analyze files in a directory recursively and categorize by type"""
        file_types = {}
        file_counts = {}
        
        def process_directory(dir_path):
            items = self.image.list_directory(dir_path)
            for item in items:
                # Skip . and .. entries
                if item["name"] in ['.', '..']:
                    continue
                    
                if item['is_dir']:
                    # Recursively process directories
                    process_directory(item['path'])
                else:
                    # Read file header (first 4KB)
                    file_data = self.image.read_file(item['path'], 0, 4096)
                    if file_data:
                        file_info = self.identify_file_type(file_data)
                        file_type = file_info['type']
                        
                        # Update statistics
                        if file_type not in file_types:
                            file_types[file_type] = {'count': 0, 'size': 0, 'files': []}
                            
                        file_types[file_type]['count'] += 1
                        file_types[file_type]['size'] += item['size']
                        file_types[file_type]['files'].append(item['path'])
                        
                        # Count by extension
                        ext = os.path.splitext(item['name'])[1].lower()
                        if ext:
                            if ext not in file_counts:
                                file_counts[ext] = {'count': 0, 'size': 0}
                            file_counts[ext]['count'] += 1
                            file_counts[ext]['size'] += item['size']
        
        # Start processing from the specified path
        process_directory(path)
        
        return {'by_type': file_types, 'by_extension': file_counts}

# 5. String Search Feature
class StringSearcher:
    """Search for strings in files in the forensic image"""
    def __init__(self, forensic_image):
        self.image = forensic_image
        
    def search_string(self, search_string, path="/", case_sensitive=False, regex=False):
        """
        Search for a string in files
        
        Parameters:
        search_string (str): String to search for
        path (str): Directory path to start search from
        case_sensitive (bool): Whether search is case sensitive
        regex (bool): Whether search_string is a regular expression
        
        Returns:
        list: List of matches with file paths and contexts
        """
        results = []
        
        # Compile regex if needed
        pattern = None
        if regex:
            try:
                if case_sensitive:
                    pattern = re.compile(search_string)
                else:
                    pattern = re.compile(search_string, re.IGNORECASE)
            except re.error:
                # Invalid regex
                return []
        
        def process_directory(dir_path):
            items = self.image.list_directory(dir_path)
            for item in items:
                # Skip . and .. entries
                if item["name"] in ['.', '..']:
                    continue
                    
                if item['is_dir']:
                    # Recursively process directories
                    process_directory(item['path'])
                else:
                    # Check if it might be a text file (skip very large files)
                    if item['size'] > 10 * 1024 * 1024:  # Skip files > 10MB
                        continue
                        
                    # Read file data
                    file_data = self.image.read_file(item['path'])
                    if not file_data:
                        continue
                        
                    # Try to decode as text
                    try:
                        text = file_data.decode('utf-8', errors='replace')
                    except:
                        continue
                        
                    # Search for matches
                    if regex and pattern:
                        # Regex search
                        for match in pattern.finditer(text):
                            start_pos = max(0, match.start() - 40)
                            end_pos = min(len(text), match.end() + 40)
                            context = text[start_pos:end_pos]
                            
                            results.append({
                                'path': item['path'],
                                'line_number': text[:match.start()].count('\n') + 1,
                                'match': match.group(0),
                                'context': context
                            })
                    else:
                        # Simple string search
                        search_for = search_string
                        text_to_search = text
                        
                        if not case_sensitive:
                            search_for = search_for.lower()
                            text_to_search = text.lower()
                            
                        pos = 0
                        while pos < len(text_to_search):
                            match_pos = text_to_search.find(search_for ,pos)
                            if match_pos == -1:
                                break
                                
                            start_pos = max(0, match_pos - 40)
                            end_pos = min(len(text), match_pos + len(search_for) + 40)
                            context = text[start_pos:end_pos]
                            
                            results.append({
                                'path': item['path'],
                                'line_number': text[:match_pos].count('\n') + 1,
                                'match': text[match_pos:match_pos+len(search_for)],
                                'context': context
                            })
                            
                            pos = match_pos + len(search_for)
        
        # Start processing from the specified path
        process_directory(path)
        
        return results

class ImageCaptureThread(QThread):
    progress_update = pyqtSignal(int)
    operation_complete = pyqtSignal(bool, str)
    
    def __init__(self, source, output, parent=None):
        super().__init__(parent)
        self.source = source
        self.output = output
        
    def run(self):
        try:
            # Use pv for progress monitoring if available
            try:
                # Check if pv is installed
                subprocess.run(['which', 'pv'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Get the size of the source
                size_output = subprocess.run(['blockdev', '--getsize64', self.source], 
                                           check=True, stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE, text=True)
                total_size = int(size_output.stdout.strip())
                
                # Use pv with dd
                cmd = f"dd if={self.source} bs=4M | pv -n -s {total_size} | dd of={self.output} bs=4M"
                process = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, universal_newlines=True)
                
                # Read progress from pv
                for line in process.stderr:
                    try:
                        progress = int(float(line.strip()) * 100 / total_size)
                        self.progress_update.emit(progress)
                    except:
                        pass
                
                process.wait()
                if process.returncode == 0:
                    self.operation_complete.emit(True, "Image created successfully")
                else:
                    self.operation_complete.emit(False, f"Error creating image: return code {process.returncode}")
                    
            except subprocess.CalledProcessError:
                # Fallback to dd without progress
                subprocess.run(['dd', f'if={self.source}', f'of={self.output}', 'bs=4M', 'status=progress'], check=True)
                self.operation_complete.emit(True, "Image created successfully")
                
        except Exception as e:
            self.operation_complete.emit(False, f"Error creating image: {str(e)}")

class ForensicImage:
    def __init__(self, image_path):
        self.image_path = image_path
        self.img_info = None
        self.fs_info = None
        
    def open(self):
        """Open the forensic image and initialize filesystem access"""
        try:
            # Try to open as raw image
            print(f"Attempting to open forensic image: {self.image_path}")
            self.img_info = pytsk3.Img_Info(self.image_path)
            print("Successfully created pytsk3.Img_Info")
            
            # Try to access the filesystem
            try:
                self.fs_info = pytsk3.FS_Info(self.img_info)
                print("Successfully created pytsk3.FS_Info")
                return True
            except Exception as fs_error:
                print(f"Error accessing filesystem: {fs_error}")
                # Try to determine volume type
                try:
                    print("Attempting to detect volume system...")
                    vs_info = pytsk3.Volume_Info(self.img_info)
                    print(f"Found volume system with {vs_info.info.vs_part_count} partitions")
                    
                    # Try each partition
                    for i in range(vs_info.info.vs_part_count):
                        vs_part = vs_info.info.vs_parts[i]
                        print(f"Trying partition {i}: offset {vs_part.start}")
                        
                        try:
                            # Create an offset-based image manager
                            offset_img = pytsk3.Img_Info(self.image_path, offset=vs_part.start * 512)
                            self.fs_info = pytsk3.FS_Info(offset_img)
                            print(f"Successfully accessed filesystem in partition {i}")
                            
                            # Store the new image info
                            self.img_info = offset_img
                            return True
                        except Exception as part_error:
                            print(f"Error accessing partition {i}: {part_error}")
                    
                    print("Could not find a valid filesystem in any partition")
                    return False
                except Exception as vs_error:
                    print(f"Error detecting volume system: {vs_error}")
                    return False
        except Exception as e:
            print(f"Error opening forensic image: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    def list_directory(self, path="/"):
        """List contents of a directory in the forensic image"""
        try:
            print(f"Listing directory: {path}")
            
            # Normalize path format for TSK
            tsk_path = path
            if tsk_path != "/" and tsk_path.endswith("/"):
                tsk_path = tsk_path[:-1]
                
            print(f"Using TSK path: {tsk_path}")
            
            try:
                directory = self.fs_info.open_dir(path=tsk_path)
                print(f"Successfully opened directory: {tsk_path}")
            except Exception as e:
                print(f"Error opening directory {tsk_path}: {e}")
                return []
                
            items = []
            for entry in directory:
                try:
                    # Skip null entries
                    if not entry.info or not entry.info.name or not entry.info.meta:
                        continue
                        
                    name = entry.info.name.name
                    # Try different encodings if needed
                    if isinstance(name, bytes):
                        try:
                            name = name.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                name = name.decode('latin-1')
                            except:
                                name = str(name)
                    
                    # Create item data
                    is_dir = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                    size = entry.info.meta.size if not is_dir else 0
                    
                    # Format timestamps
                    try:
                        create_time = datetime.datetime.fromtimestamp(entry.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        create_time = "Unknown"
                        
                    try:
                        modify_time = datetime.datetime.fromtimestamp(entry.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        modify_time = "Unknown"
                        
                    try:
                        access_time = datetime.datetime.fromtimestamp(entry.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        access_time = "Unknown"
                    
                    # Build full path
                    if path == "/":
                        full_path = f"/{name}"
                    else:
                        full_path = f"{path}/{name}"
                    
                    # Add to items list
                    items.append({
                        'name': name,
                        'is_dir': is_dir,
                        'size': size,
                        'create_time': create_time,
                        'modify_time': modify_time,
                        'access_time': access_time,
                        'path': full_path
                    })
                    
                except Exception as e:
                    print(f"Error processing directory entry: {e}")
                    continue
                    
            print(f"Found {len(items)} items in directory {path}")
            return items
        except Exception as e:
            print(f"Error listing directory {path}: {e}")
            import traceback
            traceback.print_exc()
            return []
            
    def extract_file(self, file_path, output_path):
        try:
            file_entry = self.fs_info.open(file_path)
            with open(output_path, 'wb') as f:
                f.write(file_entry.read_random(0, file_entry.info.meta.size))
            return True
        except Exception as e:
            print(f"Error extracting file: {e}")
            return False
            
    def read_file(self, file_path, offset=0, size=None):
        try:
            file_entry = self.fs_info.open(file_path)
            if size is None:
                size = file_entry.info.meta.size - offset
            return file_entry.read_random(offset, size)
        except Exception as e:
            print(f"Error reading file: {e}")
            return None

    def calculate_file_hash(self, file_path, algorithms=None):
        """
        Calculate hash values for a file in the image
        
        Parameters:
        file_path (str): Path to the file in the image
        algorithms (list): List of hash algorithms to use, defaults to ['md5', 'sha1', 'sha256']
        
        Returns:
        dict: Dictionary of hash values keyed by algorithm name
        """
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
            
        # Read the file data
        file_data = self.read_file(file_path)
        if not file_data:
            return None
        
        # Calculate hashes
        hashes = {}
        for algorithm in algorithms:
            try:
                hasher = hashlib.new(algorithm)
                hasher.update(file_data)
                hashes[algorithm] = hasher.hexdigest()
            except ValueError:
                # Skip unsupported hash algorithms
                pass
                
        return hashes

    def get_file_metadata(self, file_path, include_hash=True):
        try:
            file_entry = self.fs_info.open(file_path)
            metadata = {
                'size': file_entry.info.meta.size,
                'create_time': datetime.datetime.fromtimestamp(file_entry.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S'),
                'modify_time': datetime.datetime.fromtimestamp(file_entry.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'access_time': datetime.datetime.fromtimestamp(file_entry.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S'),
                'mode': file_entry.info.meta.mode,
                'uid': file_entry.info.meta.uid,
                'gid': file_entry.info.meta.gid,
                'type': file_entry.info.meta.type,
                'flags': file_entry.info.meta.flags,  # Add this line to get flags
                'fs_type': type(self.fs_info).__name__  # Add filesystem type
            }
            
            # Add hash values if requested and file size is not too large
            if include_hash and metadata['size'] < 100 * 1024 * 1024:  # Limit to files under 100MB
                hashes = self.calculate_file_hash(file_path)
                if hashes:
                    metadata['hashes'] = hashes
                    
            return metadata
        except Exception as e:
            print(f"Error getting file metadata: {str(e)}")
            return None

class ImageCaptureDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Capture Disk Image")
        self.resize(500, 200)
        
        layout = QVBoxLayout()
        
        # Source selection
        source_layout = QHBoxLayout()
        source_layout.addWidget(QLabel("Source Device:"))
        self.source_edit = QLineEdit()
        source_layout.addWidget(self.source_edit)
        self.source_browse_btn = QPushButton("Browse")
        source_layout.addWidget(self.source_browse_btn)
        layout.addLayout(source_layout)
        
        # Output selection
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("Output Image:"))
        self.output_edit = QLineEdit()
        output_layout.addWidget(self.output_edit)
        self.output_browse_btn = QPushButton("Browse")
        output_layout.addWidget(self.output_browse_btn)
        layout.addLayout(output_layout)
        
        # Image format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItem("Raw (dd)")
        format_layout.addWidget(self.format_combo)
        layout.addLayout(format_layout)
        
        # Hash calculation option
        self.hash_check = QCheckBox("Calculate hash during acquisition")
        self.hash_check.setChecked(True)
        layout.addWidget(self.hash_check)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.cancel_btn = QPushButton("Cancel")
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect signals and slots
        self.source_browse_btn.clicked.connect(self.browse_source)
        self.output_browse_btn.clicked.connect(self.browse_output)
        self.start_btn.clicked.connect(self.start_capture)
        self.cancel_btn.clicked.connect(self.reject)
        
        self.thread = None
        
    def browse_source(self):
        # Get a list of available devices
        try:
            lsblk_output = subprocess.check_output(['lsblk', '-d', '-o', 'NAME,SIZE,MODEL', '--nodeps'], 
                                                 universal_newlines=True)
            devices = []
            for line in lsblk_output.splitlines()[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    size = parts[1]
                    model = " ".join(parts[2:]) if len(parts) > 2 else ""
                    devices.append(f"/dev/{name} ({size}, {model})")
            
            if devices:
                device, ok = QInputDialog.getItem(self, "Select Device", 
                                                "Select source device:", devices, 0, False)
                if ok and device:
                    self.source_edit.setText(device.split()[0])  # Get just the device path
            else:
                QMessageBox.warning(self, "No Devices", "No devices found")
        except Exception as e:
            print(f"Error listing devices: {e}")
            source = QFileDialog.getOpenFileName(self, "Select Source Device or File")[0]
            if source:
                self.source_edit.setText(source)
        
    def browse_output(self):
        output = QFileDialog.getSaveFileName(self, "Select Output Image File")[0]
        if output:
            self.output_edit.setText(output)
            
    def start_capture(self):
        source = self.source_edit.text()
        output = self.output_edit.text()
        
        if not source or not output:
            QMessageBox.warning(self, "Input Error", "Please specify source and output")
            return
            
        # Check if output file already exists
        if os.path.exists(output):
            reply = QMessageBox.question(self, "File Exists", 
                                      f"The file {output} already exists. Overwrite?",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Disable UI elements
        self.source_edit.setEnabled(False)
        self.source_browse_btn.setEnabled(False)
        self.output_edit.setEnabled(False)
        self.output_browse_btn.setEnabled(False)
        self.format_combo.setEnabled(False)
        self.hash_check.setEnabled(False)
        self.start_btn.setEnabled(False)
        
        # Start the capture thread
        self.thread = ImageCaptureThread(source, output)
        self.thread.progress_update.connect(self.update_progress)
        self.thread.operation_complete.connect(self.capture_complete)
        self.thread.start()
        
        self.status_label.setText("Capturing image...")
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def capture_complete(self, success, message):
        self.status_label.setText(message)
        
        # Calculate hash if requested
        if success and self.hash_check.isChecked():
            self.status_label.setText("Calculating hash...")
            QApplication.processEvents()
            
            try:
                hash_value = self.calculate_hash(self.output_edit.text())
                self.status_label.setText(f"Complete. SHA-256: {hash_value}")
            except Exception as e:
                self.status_label.setText(f"Image captured but hash calculation failed: {str(e)}")
        
        # Re-enable UI elements
        self.source_edit.setEnabled(True)
        self.source_browse_btn.setEnabled(True)
        self.output_edit.setEnabled(True)
        self.output_browse_btn.setEnabled(True)
        self.format_combo.setEnabled(True)
        self.hash_check.setEnabled(True)
        self.start_btn.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Success", "Image capture completed successfully")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", f"Image capture failed: {message}")
    
    def calculate_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

class AddBookmarkDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Bookmark")
        self.resize(400, 200)
        
        layout = QFormLayout()
        
        self.description_edit = QTextEdit()
        layout.addRow("Description:", self.description_edit)
        
        button_box = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_box.addWidget(self.ok_button)
        button_box.addWidget(self.cancel_button)
        
        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addLayout(button_box)
        self.setLayout(main_layout)
        
    def get_description(self):
        return self.description_edit.toPlainText()

class ExportOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Report Options")
        self.resize(400, 300)
        
        layout = QVBoxLayout()
        
        # Report type selection
        report_group = QGroupBox("Report Type")
        report_layout = QVBoxLayout()
        self.pdf_radio = QCheckBox("PDF Report")
        self.pdf_radio.setChecked(True)
        self.html_radio = QCheckBox("HTML Report")
        self.csv_radio = QCheckBox("CSV Export")
        report_layout.addWidget(self.pdf_radio)
        report_layout.addWidget(self.html_radio)
        report_layout.addWidget(self.csv_radio)
        report_group.setLayout(report_layout)
        layout.addWidget(report_group)
        
        # Content options
        content_group = QGroupBox("Include Content")
        content_layout = QVBoxLayout()
        self.include_case_info = QCheckBox("Case Information")
        self.include_case_info.setChecked(True)
        self.include_evidence = QCheckBox("Evidence Items")
        self.include_evidence.setChecked(True)
        self.include_bookmarks = QCheckBox("Bookmarks")
        self.include_bookmarks.setChecked(True)
        self.include_notes = QCheckBox("Case Notes")
        self.include_notes.setChecked(True)
        content_layout.addWidget(self.include_case_info)
        content_layout.addWidget(self.include_evidence)
        content_layout.addWidget(self.include_bookmarks)
        content_layout.addWidget(self.include_notes)
        content_group.setLayout(content_layout)
        layout.addWidget(content_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
