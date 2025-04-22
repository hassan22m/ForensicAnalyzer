from concurrent.futures import ThreadPoolExecutor
import queue,logging,subprocess,os,threading
import csv,time,json,tempfile,re,shutil,datetime,hashlib
from PyQt6.QtCore import QThread, pyqtSignal
#setup logger 
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('linux_memory_forensics')


class LinuxMemoryParser:
    """
    Enhanced memory parser for Linux memory dumps
    Focuses on extracting detailed process, kernel, and network information
    """
    
    def __init__(self, memory_file):
        self.memory_file = memory_file
        self.file_handle = None
        self.size = 0
        self.format = 'raw'  # Default format
        
        # Linux-specific constants and structures
        self.TASK_STRUCT_SIZE = 4096  # Approximation, varies by kernel
        self.PAGE_SIZE = 4096
        
        # Patterns for various kernel structures
        self.patterns = {
            'task_struct': rb'(task_struct|task).*\x00\x00',
            'mm_struct': rb'mm_struct.*\x00\x00',
            'files_struct': rb'files_struct.*\x00\x00',
            'socket': rb'socket.*\x00\x00',
            'tcp_sock': rb'tcp_sock.*\x00\x00',
        }
        
        # Regular expressions for finding information
        self.regex = {
            'kernel_version': re.compile(rb'Linux version ([0-9.]+).*\x00'),
            'ip_address': re.compile(rb'(?:\d{1,3}\.){3}\d{1,3}'),
            'process_name': re.compile(rb'([a-zA-Z0-9_\-\./]+)\x00'),
            'username': re.compile(rb'([a-zA-Z0-9_\-\.]+):[x*]:([0-9]+):'),
            'filesystem': re.compile(rb'(ext[234]|xfs|btrfs|ntfs|fat|vfat)\x00'),
            'docker_run': re.compile(rb'docker\s+run\s+(\-[a-zA-Z0-9]+\s+)?([0-9]+:[0-9]+)?\s*([a-zA-Z0-9_\-\.\/]+)'),
            'pid_pattern': re.compile(rb'pid[=\s:]+(\d+)'),
            'ppid_pattern': re.compile(rb'(?:parent|ppid)[=\s:]+(\d+)')
        }
        
    def open(self):
        """Open the memory dump file with improved error handling"""
        try:
            self.file_handle = open(self.memory_file, 'rb')
            self.size = os.path.getsize(self.memory_file)
            
            # Try to detect format based on header or file extension
            self._detect_format()
            
            # Try to identify Linux kernel version
            self.kernel_version = self._find_kernel_version()
            
            return True
        except FileNotFoundError:
            logger.error(f"Memory file not found: {self.memory_file}")
            return False
        except PermissionError:
            logger.error(f"Permission denied when opening memory file: {self.memory_file}")
            return False
        except Exception as e:
            logger.error(f"Error opening memory file: {str(e)}")
            return False
    
    def close(self):
        """Close the memory dump file"""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def _detect_format(self):
        """Detect memory dump format"""
        # Check file extension
        if self.memory_file.lower().endswith('.lime'):
            self.format = 'lime'
        else:
            self.format = 'raw'  # Default to raw format
    
    def _find_kernel_version(self):
        """Attempt to identify the Linux kernel version"""
        if not self.file_handle:
            return None
            
        # Save current position
        current_pos = self.file_handle.tell()
        
        try:
            # Reset to beginning
            self.file_handle.seek(0)
            
            # Read chunks of data
            chunk_size = 1024 * 1024  # 1MB chunks
            for chunk_start in range(0, min(500 * 1024 * 1024, self.size), chunk_size):
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(chunk_size)
                
                # Search for kernel version pattern
                match = self.regex['kernel_version'].search(data)
                if match:
                    return match.group(1).decode('utf-8', errors='replace')
            
            return "Unknown"
        finally:
            # Restore position
            self.file_handle.seek(current_pos)
    


    def extract_kernel_info(self):
        """Extract comprehensive kernel information from the memory dump"""
        if not self.file_handle:
            return {}
            
        kernel_info = {
            'version': self.kernel_version or "Unknown",
            'version_detailed': None,
            'build_info': None,
            'gcc_version': None,
            'boot_time': None,
            'uptime': None,
            'modules': [],
            'command_line': None,
            'hostname': None,
            'distribution': None,
            'architecture': None
        }
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        # Shared queue for results
        info_queue = queue.Queue()
        
        # Full version pattern (captures detailed version info like in the strings output)
        full_version_pattern = re.compile(
            rb'Linux version (\d+\.\d+\.\d+[\-\.\w]+)[\s\(]+([^\)]+)\)[\s\(]+(gcc version [^\)]+)'
        )
        
        # Specific patterns for other kernel information
        patterns = {
            'hostname': [
                re.compile(rb'hostname=([a-zA-Z0-9_\-\.]+)'),
                re.compile(rb'nodename=([a-zA-Z0-9_\-\.]+)')
            ],
            'command_line': [
                re.compile(rb'BOOT_IMAGE=([^\x00\n]+)'),
                re.compile(rb'Command line[:\s]+([^\x00\n]{10,})')
            ],
            'distribution': [
                re.compile(rb'(Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|SUSE|Arch|Gentoo)[^\n]{1,30}[\d\.]+')
            ],
            'boot_time': [
                re.compile(rb'started at[\s:]+([^\n]+\d{4})'),
                re.compile(rb'Linux started[\s:]+([^\n]+)')
            ],
            'architecture': [
                re.compile(rb'(x86_64|i386|amd64|arm64|aarch64)[- ]gcc'),
                re.compile(rb'CPU architecture: ([a-zA-Z0-9_]+)')
            ],
            'modules': [
                re.compile(rb'Loading module ([a-zA-Z0-9_\-\.]+)'),
                re.compile(rb'Loaded module ([a-zA-Z0-9_\-\.]+)')
            ]
        }
        
        def process_chunk(chunk_data, chunk_offset):
            """Process a chunk of data looking for kernel information"""
            results = {}
            
            # Look for full version info
            for match in full_version_pattern.finditer(chunk_data):
                try:
                    version = match.group(1).decode('utf-8', errors='replace')
                    build_info = match.group(2).decode('utf-8', errors='replace')
                    gcc_version = match.group(3).decode('utf-8', errors='replace')
                    
                    results['version_detailed'] = version
                    results['build_info'] = build_info
                    results['gcc_version'] = gcc_version
                except:
                    pass
            
            # Check each pattern type
            for info_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if info_type == 'modules':
                        # For modules, collect all matches
                        module_list = []
                        for m in pattern.finditer(chunk_data):
                            try:
                                module = m.group(1).decode('utf-8', errors='replace')
                                module_list.append(module)
                            except:
                                pass
                        if module_list:
                            results[info_type] = module_list
                    else:
                        # For other types, just get the first match
                        match = pattern.search(chunk_data)
                        if match:
                            try:
                                if info_type == 'boot_time':
                                    # Try to parse as timestamp or formatted date
                                    value = match.group(1).decode('utf-8', errors='replace')
                                    # Check if it's a unix timestamp
                                    if value.isdigit() and len(value) == 10:
                                        results[info_type] = datetime.datetime.fromtimestamp(
                                            int(value)).strftime('%Y-%m-%d %H:%M:%S')
                                    else:
                                        results[info_type] = value
                                else:
                                    results[info_type] = match.group(1).decode('utf-8', errors='replace')
                            except:
                                pass
            
            # If we found any results, add them to the queue
            if results:
                info_queue.put(results)
        
        try:
            # Reset to beginning, but only read the first 500MB at most
            # Most kernel info should be near the beginning
            search_size = min(500 * 1024 * 1024, self.size)
            chunk_size = 4 * 1024 * 1024  # 4MB chunks
            
            # Calculate number of chunks
            num_chunks = (search_size // chunk_size) + 1
            max_workers = min(8, num_chunks)
            
            # Use threads to search in parallel
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                
                for chunk_start in range(0, search_size, chunk_size):
                    self.file_handle.seek(chunk_start)
                    read_size = min(chunk_size, search_size - chunk_start)
                    data = self.file_handle.read(read_size)
                    
                    # Submit the chunk for processing
                    futures.append(executor.submit(process_chunk, data, chunk_start))
                
                # Wait for all futures to complete
                for future in futures:
                    future.result()
            
            # Process all results from the queue
            while not info_queue.empty():
                chunk_results = info_queue.get()
                
                # Update kernel_info with new findings
                for key, value in chunk_results.items():
                    if key == 'modules':
                        # Merge module lists without duplicates
                        kernel_info['modules'] = list(set(kernel_info['modules'] + value))
                    elif not kernel_info[key]:
                        kernel_info[key] = value
            
            # Format the full version string if we have detailed info
            if kernel_info['version_detailed'] and kernel_info['build_info']:
                kernel_info['version_full'] = f"{kernel_info['version_detailed']} ({kernel_info['build_info']})"
                
                # If the original version was just a number, update it
                if kernel_info['version'] and len(kernel_info['version'].split('.')) <= 3 and '-' not in kernel_info['version']:
                    kernel_info['version'] = kernel_info['version_detailed']
            
            # If we found command line but no hostname, try to extract it
            if kernel_info['command_line'] and not kernel_info['hostname']:
                hostname_match = re.search(r'hostname=([a-zA-Z0-9_\-\.]+)', kernel_info['command_line'])
                if hostname_match:
                    kernel_info['hostname'] = hostname_match.group(1)
            
            return kernel_info
        
        finally:
            # Restore position
            self.file_handle.seek(current_pos)


    def extract_detailed_processes(self, max_processes=100, progress_callback=None):
        """
        Extract detailed process information using heuristics with improved performance
        """
        if not self.file_handle:
            return []
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        # Precompile regex patterns
        pid_patterns = [
            re.compile(rb'pid=(\d+)'),
            re.compile(rb'PID=(\d+)'),
            re.compile(rb'pid\x00+(\d+)'),
            # Add more patterns that might indicate a PID
            re.compile(rb'\x00pid\x00+(\d+)'),
            re.compile(rb'process.+?id.+?(\d+)', re.IGNORECASE)
        ]
        
        # Enhanced name pattern - more flexible to catch various formats
        name_pattern = re.compile(rb'([a-zA-Z0-9_\-\.\/]{2,19})\x00{1,8}')
        alt_name_pattern = re.compile(rb'comm[\x00\s]+([a-zA-Z0-9_\-\.\/]{2,19})')
        
        # These are potential markers for process structures - expanded list
        markers = [
            rb'task_struct',
            rb'comm\x00',  # process name field
            rb'TASK_RUNNING',
            rb'TASK_INTERRUPTIBLE',
            rb'pid=\d+',
            rb'process_\w+',
            rb'exec_domain',
            rb'thread_info',
            rb'sched_entity',
            rb'thread_struct'
        ]
        
        # Create a thread-safe queue for results
        result_queue = queue.Queue()
        # Create a set for tracking unique PIDs
        seen_pids = set()
        
        # Define chunk processor function
        def process_chunk(chunk_data, chunk_offset):
            chunk_processes = []
            
            # Use a sliding window approach for better coverage
            for marker in markers:
                offset = 0
                while offset < len(chunk_data):
                    match_pos = chunk_data.find(marker, offset)
                    if match_pos == -1:
                        break
                    
                    # Look for process info around this marker with a larger context window
                    context_start = max(0, match_pos - 150)
                    context_end = min(len(chunk_data), match_pos + 350)
                    context = chunk_data[context_start:context_end]
                    
                    # Extract potential PID using multiple patterns
                    pid = None
                    for pid_pattern in pid_patterns:
                        pid_match = pid_pattern.search(context)
                        if pid_match:
                            try:
                                pid = int(pid_match.group(1))
                                if 1 <= pid <= 200000:  # Reasonable PID range
                                    break
                            except:
                                continue
                    
                    # Extract potential process name with multiple patterns
                    name = None
                    name_match = name_pattern.search(context)
                    if not name_match:
                        name_match = alt_name_pattern.search(context)
                    
                    if name_match:
                        try:
                            name = name_match.group(1).decode('utf-8', errors='replace')
                            # Filter out clearly invalid process names
                            if not (len(name) > 2 and len(name) < 20 and not name.startswith("\\")):
                                name = None
                        except:
                            name = None
                    
                    # Only add if we found both pid and name
                    if pid and name:
                        # Create a unique key to avoid duplicates across threads
                        process_key = (pid, name)
                        
                        if process_key not in seen_pids:
                            seen_pids.add(process_key)
                            
                            # Extract additional details
                            state = self._extract_process_state(context)
                            uid = self._extract_uid(context)
                            parent_pid = self._extract_parent_pid(context)
                            
                            chunk_processes.append({
                                'pid': pid,
                                'name': name,
                                'offset': chunk_offset + match_pos,
                                'state': state,
                                'uid': uid,
                                'parent_pid': parent_pid
                            })
                    
                    # Move to the next position
                    offset = match_pos + 1
            
            # Add results to the queue
            if chunk_processes:
                result_queue.put(chunk_processes)
        
        try:
            processes = []
            chunk_size = 8 * 1024 * 1024  # 8MB chunks for better throughput
            overlap = 500  # Larger overlap to avoid missing processes at boundaries
            
            # Calculate number of chunks
            num_chunks = (self.size // (chunk_size - overlap)) + 1
            
            # Create a thread pool with a reasonable number of workers
            max_workers = min(8, num_chunks)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                
                # Submit chunks for processing
                for chunk_start in range(0, self.size, chunk_size - overlap):
                    self.file_handle.seek(chunk_start)
                    read_size = min(chunk_size, self.size - chunk_start)
                    data = self.file_handle.read(read_size)
                    
                    # Submit the chunk for processing
                    futures.append(
                        executor.submit(process_chunk, data, chunk_start)
                    )
                    
                    # Update progress
                    if progress_callback:
                        progress_callback(min(100, int((chunk_start / self.size) * 100)))
                
                # Process completed chunks
                total_chunks = len(futures)
                for i, future in enumerate(futures):
                    # Wait for each future to complete
                    future.result()
                    
                    # Update progress based on completed futures
                    if progress_callback:
                        progress_callback(min(100, int(((i + 1) / total_chunks) * 95)))  # Save 5% for post-processing
            
            # Collect all results from the queue
            while not result_queue.empty():
                processes.extend(result_queue.get())
            
            # Sort by PID
            processes.sort(key=lambda p: p['pid'])
            
            # Limit to max_processes
            processes = processes[:max_processes]
            
            # Final progress update
            if progress_callback:
                progress_callback(100)
            
            return processes
            
        finally:
            # Restore position
            self.file_handle.seek(current_pos)
    
    def _extract_process_state(self, context):
        """
        Extract process state from context with improved performance
        """
        # Pre-compiled patterns (these could be class variables to avoid recompilation)
        state_patterns = [
            (re.compile(rb'state=([A-Z_]+)'), lambda m: m.group(1).decode('utf-8', errors='replace')),
            (re.compile(rb'state:\s*([A-Z_]+)'), lambda m: m.group(1).decode('utf-8', errors='replace')),
            (re.compile(rb'__state\s*=\s*([A-Z_]+)'), lambda m: m.group(1).decode('utf-8', errors='replace'))
        ]
        
        # Common state mappings for quick lookup
        state_mappings = {
            b'TASK_RUNNING': 'RUNNING',
            b'TASK_INTERRUPTIBLE': 'SLEEPING',
            b'TASK_UNINTERRUPTIBLE': 'WAITING',
            b'TASK_STOPPED': 'STOPPED',
            b'TASK_TRACED': 'TRACED',
            b'TASK_ZOMBIE': 'ZOMBIE',
            b'EXIT_DEAD': 'DEAD',
            b'EXIT_ZOMBIE': 'ZOMBIE',
            b'TASK_DEAD': 'DEAD',
            b'TASK_WAKEKILL': 'WAKING',
            b'TASK_WAKING': 'WAKING',
            b'R': 'RUNNING',
            b'S': 'SLEEPING',
            b'D': 'WAITING',
            b'Z': 'ZOMBIE',
            b'T': 'STOPPED',
            b'X': 'DEAD'
        }
        
        # First try direct regex matches
        for pattern, extractor in state_patterns:
            match = pattern.search(context)
            if match:
                try:
                    return extractor(match)
                except:
                    pass
        
        # Next, try keyword search for state values
        for state_key, state_value in state_mappings.items():
            # Use an efficient 'in' search rather than regex when possible
            if state_key in context:
                return state_value
        
        # Try looking for numeric state values using regex
        numeric_state_match = re.search(rb'state[:=]\s*(\d+)', context)
        if numeric_state_match:
            try:
                state_num = int(numeric_state_match.group(1))
                # Map state numbers to names (common Linux task state numeric values)
                if state_num == 0:
                    return 'RUNNING'
                elif state_num == 1:
                    return 'SLEEPING'
                elif state_num == 2:
                    return 'WAITING'
                elif state_num == 4:
                    return 'STOPPED'
                elif state_num == 8:
                    return 'TRACED'
                elif state_num == 16:
                    return 'ZOMBIE'
                elif state_num == 32:
                    return 'DEAD'
                else:
                    return f'STATE_{state_num}'
            except:
                pass
        
        # If no state found, try to determine from other context clues
        if b'running' in context.lower():
            return 'RUNNING'
        elif b'sleep' in context.lower():
            return 'SLEEPING'
        elif b'wait' in context.lower():
            return 'WAITING'
        elif b'zombie' in context.lower():
            return 'ZOMBIE'
        elif b'stop' in context.lower():
            return 'STOPPED'
        
        return 'UNKNOWN'
    
    def _extract_uid(self, context):
        """Extract user ID from context"""
        uid_match = re.search(rb'uid=(\d+)', context)
        if uid_match:
            return int(uid_match.group(1))
        return None
    
    def _extract_parent_pid(self, context):
        """
        Extract parent process ID from context with improved pattern matching
        """
        # Define multiple patterns to increase detection chances
        ppid_patterns = [
            re.compile(rb'parent.+?pid=(\d+)'),  # Original pattern
            re.compile(rb'ppid=(\d+)'),          # Original alternative
            re.compile(rb'parent_pid\s*[:=]\s*(\d+)'),
            re.compile(rb'PPID\s*[:=]\s*(\d+)'),
            re.compile(rb'parent\s*[:=]\s*(\d+)'),
            re.compile(rb'p_ppid\s*[:=]\s*(\d+)'),
            re.compile(rb'parent_id\s*[:=]\s*(\d+)'),
            re.compile(rb'proc_parent.*?(\d+)'),
            re.compile(rb'task_parent.*?id.*?(\d+)')
        ]
        
        # Try each pattern in sequence
        for pattern in ppid_patterns:
            match = pattern.search(context)
            if match:
                try:
                    ppid = int(match.group(1))
                    # Validate the PPID is in a reasonable range
                    if 0 <= ppid < 100000:  # Most systems won't have PIDs over 100,000
                        return ppid
                except (ValueError, IndexError, TypeError):
                    # Continue to next pattern if we can't extract a valid integer
                    continue
        
        # Look for PID in a more structured format (hex values or other formats)
        structured_match = re.search(rb'parent.*?pid.*?0x([0-9a-fA-F]+)', context)
        if structured_match:
            try:
                # Convert from hex to decimal
                return int(structured_match.group(1), 16)
            except (ValueError, IndexError, TypeError):
                pass
        
        # As a last resort, look for any digit sequence after parent-related keywords
        last_resort = re.search(rb'(?:parent|father|progenitor).*?(\d{1,6})', context)
        if last_resort:
            try:
                ppid = int(last_resort.group(1))
                if 0 <= ppid < 100000:
                    return ppid
            except (ValueError, IndexError, TypeError):
                pass
        
        return None  # Return None if no valid parent PID found
    
    def extract_commands(self, max_results=50):
        """Extract command lines that were executed with optimized performance"""
        if not self.file_handle:
            return []
        
        commands = []
        command_count = 0
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        try:
            chunk_size = 4 * 1024 * 1024  # 4MB chunks
            
            # Define high-value command patterns to prioritize their extraction
            high_value_patterns = [
                # Docker commands (very specific to ensure we catch the docker run example)
                (rb'docker\s+run\s+(\-[a-zA-Z0-9]+\s+)?([0-9]+:[0-9]+)?\s*([a-zA-Z0-9_\-\.\/]+)', 'docker_run'),
                (rb'docker\s+exec\s+(\-[a-zA-Z0-9]+\s+)?([a-zA-Z0-9_\-\.\/]+)', 'docker_exec'),
                (rb'docker\s+pull\s+([a-zA-Z0-9_\-\.\/\:]+)', 'docker_pull'),
                (rb'docker\s+build\s+(\-[a-zA-Z0-9]+\s+)?([a-zA-Z0-9_\-\.\/]+)', 'docker_build'),
                
                # Administration commands
                (rb'sudo\s+([a-zA-Z0-9_\-\.\/\s\-\+\=]+)', 'sudo'),
                (rb'apt-get\s+(install|remove|update|upgrade)\s+([a-zA-Z0-9_\-\.\/\s\-\+\=]+)', 'apt'),
                (rb'systemctl\s+(start|stop|enable|disable|restart|status)\s+([a-zA-Z0-9_\-\.\/\s\-\+\=]+)', 'systemctl'),
                
                # Network commands
                (rb'ssh\s+(\-[a-zA-Z0-9]+\s+)?([a-zA-Z0-9_\-\.\/\@\:]+)', 'ssh'),
                (rb'curl\s+(\-[a-zA-Z0-9]+\s+)?(https?://[a-zA-Z0-9_\-\.\/\?\&\=\+\%]+)', 'curl'),
                (rb'wget\s+(\-[a-zA-Z0-9]+\s+)?(https?://[a-zA-Z0-9_\-\.\/\?\&\=\+\%]+)', 'wget')
            ]
            
            # Process smaller chunks for high-value patterns - we'll scan faster but more targeted
            small_chunk_size = 512 * 1024  # 512KB is more manageable and causes less hangtime
            
            # First, scan for high-value commands with smaller chunks
            for chunk_start in range(0, min(200 * 1024 * 1024, self.size), small_chunk_size):  # Limit to first 200MB for speed
                if command_count >= max_results:
                    break
                    
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(small_chunk_size, self.size - chunk_start))
                
                # Process high-value patterns
                for pattern, cmd_type in high_value_patterns:
                    for match in re.finditer(pattern, data):
                        try:
                            # Get full match
                            full_match = match.group(0).decode('ascii', errors='strict')
                            
                            # Basic validation
                            if len(full_match) >= 5 and len(full_match) <= 200 and not any(ord(c) < 32 or ord(c) > 126 for c in full_match):
                                # Special handling for Docker run command to ensure we get all options
                                if cmd_type == 'docker_run':
                                    # For docker run, try to get more context (e.g., port mapping, image name)
                                    start_pos = max(0, match.start() - 10)  # Look a bit before the match
                                    end_pos = min(len(data), match.end() + 50)  # Look ahead for more args
                                    
                                    # Extract extended context
                                    extended_data = data[start_pos:end_pos]
                                    # Find the end of the command
                                    cmd_end = min(extended_data.find(b'\x00'), extended_data.find(b'\n'))
                                    if cmd_end == -1:  # If no terminator found
                                        cmd_end = len(extended_data)
                                        
                                    # Extract the extended command
                                    extended_cmd = extended_data[:cmd_end].decode('ascii', errors='replace')
                                    # Clean up the command: remove any non-printable chars
                                    extended_cmd = ''.join(c for c in extended_cmd if 32 <= ord(c) <= 126)
                                    # Further cleanup: remove anything before "docker run"
                                    docker_pos = extended_cmd.find("docker run")
                                    if docker_pos != -1:
                                        extended_cmd = extended_cmd[docker_pos:]
                                        
                                    commands.append({
                                        'command': extended_cmd.strip(),
                                        'offset': chunk_start + match.start()
                                    })
                                else:
                                    # For other commands, just use the match
                                    commands.append({
                                        'command': full_match.strip(),
                                        'offset': chunk_start + match.start()
                                    })
                                    
                                command_count += 1
                                if command_count >= max_results:
                                    break
                        except UnicodeDecodeError:
                            continue
            
            # Now look for standard commands with full paths (reliable and less noise)
            bin_paths = [rb'/bin/', rb'/usr/bin/', rb'/sbin/', rb'/usr/sbin/', rb'/usr/local/bin/']
            
            for chunk_start in range(0, min(100 * 1024 * 1024, self.size), chunk_size):  # Limit to first 100MB
                if command_count >= max_results:
                    break
                    
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(chunk_size, self.size - chunk_start))
                
                for bin_path in bin_paths:
                    path_pos = 0
                    while True:
                        path_pos = data.find(bin_path, path_pos)
                        if path_pos == -1:
                            break
                        
                        # Find the end of the command (null byte or newline)
                        cmd_end = data.find(b'\x00', path_pos)
                        if cmd_end == -1:
                            cmd_end = data.find(b'\n', path_pos)
                        if cmd_end == -1 or cmd_end - path_pos > 200:
                            cmd_end = path_pos + 200  # Limit if no terminator found
                        
                        # Extract the command
                        cmd_bytes = data[path_pos:cmd_end]
                        
                        try:
                            cmd = cmd_bytes.decode('ascii', errors='strict')
                            # Filter based on length and content
                            if len(cmd) > 5 and ' ' in cmd:
                                # Strict ASCII-only filtering
                                if not any(ord(c) < 32 or ord(c) > 126 for c in cmd):
                                    commands.append({
                                        'command': cmd,
                                        'offset': chunk_start + path_pos
                                    })
                                    command_count += 1
                                    
                                    if command_count >= max_results:
                                        break
                        except UnicodeDecodeError:
                            pass
                        
                        path_pos += len(bin_path)
            
            # We want to ensure we capture shell history commands
            # This is valuable forensic evidence and worth dedicated scan
            history_markers = [b'.bash_history', b'HISTFILE=']
            
            # Use small chunks for history marker scan too
            for chunk_start in range(0, min(50 * 1024 * 1024, self.size), small_chunk_size):  # First 50MB
                if command_count >= max_results:
                    break
                    
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(small_chunk_size, self.size - chunk_start))
                
                for marker in history_markers:
                    marker_pos = data.find(marker)
                    if marker_pos != -1:
                        # Found a history file marker! Look for commands nearby
                        vicinity_start = max(0, marker_pos - 500)  # Look back 500 bytes
                        vicinity_end = min(len(data), marker_pos + 1000)  # Look ahead 1000 bytes
                        vicinity = data[vicinity_start:vicinity_end]
                        
                        # Look for command lines
                        # In bash history, commands typically appear one per line
                        lines = re.split(rb'[\x00\n]', vicinity)
                        for line in lines:
                            if 5 <= len(line) <= 200:  # Reasonable command length
                                try:
                                    cmd_str = line.decode('ascii', errors='strict')
                                    
                                    # Basic validation for command-like format
                                    if (re.match(r'^[a-zA-Z0-9_/\.\-]', cmd_str) and  # Starts with letter, number, or common path chars
                                        ' ' in cmd_str and  # Has a space (like a command with args)
                                        not any(ord(c) < 32 or ord(c) > 126 for c in cmd_str)):  # No control chars
                                        
                                        # Additional filter: common command beginnings
                                        if (any(cmd_str.startswith(p) for p in ['/', './', 'sudo ', 'apt', 'docker', 'git', 'cd ', 'ls ']) or
                                            any(p in cmd_str for p in ['-h', '--help', '-v', '-p', '-l', '-a'])):  # Common options
                                            
                                            commands.append({
                                                'command': cmd_str,
                                                'offset': chunk_start + vicinity_start + vicinity.find(line)
                                            })
                                            command_count += 1
                                            
                                            if command_count >= max_results:
                                                break
                                except UnicodeDecodeError:
                                    continue
            
            # Sort and deduplicate commands
            unique_commands = []
            seen = set()
            
            # First pass: Organize by offset to maintain logical sequence
            for cmd in sorted(commands, key=lambda x: x['offset']):
                cmd_text = cmd['command'].strip()
                if cmd_text and cmd_text not in seen:
                    seen.add(cmd_text)
                    unique_commands.append({
                        'command': cmd_text,
                        'offset': cmd['offset']
                    })
            
            return unique_commands
            
        finally:
            # Restore position
            self.file_handle.seek(current_pos)
    
    def extract_users(self):
        """Extract user information"""
        if not self.file_handle:
            return []
            
        users = []
        seen_uids = set()
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        try:
            chunk_size = 4 * 1024 * 1024  # 4MB chunks
            
            for chunk_start in range(0, self.size, chunk_size):
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(chunk_size, self.size - chunk_start))
                
                # Look for /etc/passwd format entries
                for match in re.finditer(rb'([a-zA-Z0-9_\-\.]+):[x*]:(\d+):(\d+):([^:]*):([^:]*):([^\x00\n]*)', data):
                    try:
                        username = match.group(1).decode('utf-8', errors='replace')
                        uid = int(match.group(2))
                        gid = int(match.group(3))
                        
                        if uid not in seen_uids and username != 'nobody' and len(username) > 1:
                            users.append({
                                'username': username,
                                'uid': uid,
                                'gid': gid,
                                'home': match.group(5).decode('utf-8', errors='replace'),
                                'shell': match.group(6).decode('utf-8', errors='replace')
                            })
                            seen_uids.add(uid)
                    except:
                        pass
            
            # Sort by UID
            users.sort(key=lambda u: u['uid'])
            
            return users
            
        finally:
            # Restore position
            self.file_handle.seek(current_pos)

   

    def extract_network_connections(self, progress_callback=None):
        """Extract IPv4 network connection patterns from memory dump with improved performance"""
        if not self.file_handle:
            return []
        
        # Pre-compile patterns
        ip_port_pattern = re.compile(
            rb'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}).{1,20}?(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})'
        )
        udp_pattern = re.compile(rb'udp', re.IGNORECASE)
        tcp_pattern = re.compile(rb'tcp', re.IGNORECASE)
        
        # Store the current position to restore it later
        current_pos = self.file_handle.tell()
        
        # Create a thread-safe queue for results
        result_queue = queue.Queue()
        # Create a set for tracking unique connections
        seen_connections = set()
        
        # Define a chunk processor function
        def process_chunk(chunk_data, chunk_offset):
            chunk_connections = []
            
            # Use a sliding window approach for network connections
            for match in ip_port_pattern.finditer(chunk_data):
                try:
                    local_ip = match.group(1).decode()
                    local_port = int(match.group(2))
                    remote_ip = match.group(3).decode()
                    remote_port = int(match.group(4))
                    
                    # Additional validation for IP and port
                    if (self._is_valid_ipv4(local_ip) and 
                        self._is_valid_ipv4(remote_ip) and
                        0 < local_port < 65536 and
                        0 < remote_port < 65536):
                        
                        # Check for protocol context nearby
                        context_start = max(0, match.start() - 30)
                        context_end = min(len(chunk_data), match.end() + 30)
                        context_range = chunk_data[context_start:context_end]
                        
                        # Determine protocol more accurately
                        if udp_pattern.search(context_range):
                            proto = 'UDP'
                        elif tcp_pattern.search(context_range):
                            proto = 'TCP'
                        else:
                            # Look for other protocol indicators
                            if b'SOCK_DGRAM' in context_range:
                                proto = 'UDP'
                            elif b'SOCK_STREAM' in context_range:
                                proto = 'TCP'
                            else:
                                # Default to TCP as more common
                                proto = 'TCP'
                        
                        # Create a unique key to avoid duplicates
                        conn_key = (local_ip, local_port, remote_ip, remote_port, proto)
                        
                        if conn_key not in seen_connections:
                            seen_connections.add(conn_key)
                            
                            chunk_connections.append({
                                'local_ip': local_ip,
                                'local_port': local_port,
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'protocol': proto,
                                'offset': chunk_offset + match.start()
                            })
                except Exception:
                    continue
            
            # Add results to the queue
            if chunk_connections:
                result_queue.put(chunk_connections)
        
        try:
            connections = []
            chunk_size = 8 * 1024 * 1024  # 8MB chunks
            overlap = 150  # Increased overlap to catch more boundary matches
            
            # Calculate number of chunks
            num_chunks = (self.size // (chunk_size - overlap)) + 1
            
            # Create a thread pool with a reasonable number of workers
            max_workers = min(8, num_chunks)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                
                # Submit chunks for processing
                for chunk_start in range(0, self.size, chunk_size - overlap):
                    self.file_handle.seek(chunk_start)
                    read_size = min(chunk_size, self.size - chunk_start)
                    data = self.file_handle.read(read_size)
                    
                    # Submit the chunk for processing
                    futures.append(
                        executor.submit(process_chunk, data, chunk_start)
                    )
                    
                    # Update progress 
                    if progress_callback:
                        progress_callback(min(95, int((chunk_start / self.size) * 95)))  # Save 5% for post-processing
                
                # Process completed chunks
                total_chunks = len(futures)
                for i, future in enumerate(futures):
                    # Wait for each future to complete
                    future.result()
                    
                    # Update progress based on completed futures
                    if progress_callback:
                        progress_callback(min(95, int(((i + 1) / total_chunks) * 95)))
            
            # Collect all results from the queue
            while not result_queue.empty():
                connections.extend(result_queue.get())
            
            # Final progress update
            if progress_callback:
                progress_callback(100)
            
            return connections
            
        finally:
            self.file_handle.seek(current_pos)
    
    def _is_valid_ipv4(self, ip):
        """Check if string is a valid IPv4 address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
            
        for part in parts:
            try:
                n = int(part)
                if n < 0 or n > 255:
                    return False
            except:
                return False
                
        return True
    
    def find_php_in_uploads(self, max_results=20):
        """
        Simplified search for PHP files in upload directories
        """
        if not self.file_handle:
            return []
            
        results = []
        seen_paths = set()
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        try:
            # Use very small chunks to avoid memory issues
            chunk_size = 256 * 1024  # 256KB chunks
            
            # Simpler patterns focusing just on shell.php
            simple_patterns = [
                rb'uploads/shell\.php',
                rb'shell\.php',
                rb'upload/.*\.php'
            ]
            
            # Only scan the first part of the file for better performance
            max_scan_size = min(100 * 1024 * 1024, self.size)  # Only scan first 100MB max
            
            for chunk_start in range(0, max_scan_size, chunk_size):
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(chunk_size, max_scan_size - chunk_start))
                
                # Look for each pattern
                for pattern in simple_patterns:
                    for match in re.finditer(pattern, data):
                        path = match.group(0).decode('utf-8', errors='replace')
                        
                        # Only add if not already seen
                        if path not in seen_paths:
                            results.append({
                                'path': path,
                                'offset': chunk_start + match.start()
                            })
                            seen_paths.add(path)
                
                # Limit results
                if len(results) >= max_results:
                    break
            
            return results
            
        finally:
            # Restore position
            self.file_handle.seek(current_pos)

    def extract_file_listing(self, max_files=500):
        """Extract file paths with improved detection for PHP files"""
        if not self.file_handle:
            return []
            
        files = []
        
        # First, try to find PHP files in uploads directories
        php_uploads = self.find_php_in_uploads(max_results=50)
        for php_file in php_uploads:
            files.append(php_file)
        
        # Then run the regular file listing extraction
        seen_paths = set([f['path'] for f in files])  # Track already found paths
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        try:
            chunk_size = 1 * 1024 * 1024  # 1MB chunks
            
            # Regular file patterns
            patterns = [
                rb'/([a-zA-Z0-9_\-\.]+/)+[a-zA-Z0-9_\-\.]+',
                rb'[A-Za-z]:\\[^\\/:*?"<>|\r\n]*\\[^\\/:*?"<>|\r\n]*'
            ]
            
            for chunk_start in range(0, self.size, chunk_size):
                if len(files) >= max_files:
                    break
                    
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(chunk_size, self.size - chunk_start))
                
                # Look for absolute paths
                for pattern in patterns:
                    for match in re.finditer(pattern, data):
                        path = match.group(0).decode('utf-8', errors='replace')
                        
                        # Filter out common false positives
                        if len(path) > 7 and not path.endswith('//') and not '//' in path:
                            # Don't add if already in the results
                            if path not in seen_paths:
                                files.append({
                                    'path': path,
                                    'offset': chunk_start + match.start()
                                })
                                seen_paths.add(path)
                                
                                if len(files) >= max_files:
                                    break
            
            return files
            
        finally:
            # Restore position
            self.file_handle.seek(current_pos)
    
    

    def extract_environment_variables(self):
        """Extract environment variables"""
        if not self.file_handle:
            return {}
            
        env_vars = {}
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        try:
            chunk_size = 4 * 1024 * 1024  # 4MB chunks
            
            # Common environment variables to look for
            common_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'TERM', 'PWD', 
                          'LANG', 'HOSTNAME', 'LOGNAME', 'SUDO_USER']
            
            for chunk_start in range(0, min(200 * 1024 * 1024, self.size), chunk_size):
                self.file_handle.seek(chunk_start)
                data = self.file_handle.read(min(chunk_size, self.size - chunk_start))
                
                # Search for each environment variable
                for var in common_vars:
                    if var in env_vars:
                        continue  # Already found
                        
                    var_bytes = var.encode('ascii')
                    pattern = var_bytes + b'=([^\x00\n]+)'
                    
                    match = re.search(pattern, data)
                    if match:
                        value = match.group(1).decode('utf-8', errors='replace')
                        env_vars[var] = value
            
            return env_vars
            
        finally:
            # Restore position
            self.file_handle.seek(current_pos)
    
    def search_string(self, search_string, start_offset=0, max_results=100):
        """Search for a string in the memory dump"""
        if not self.file_handle:
            return []
            
        results = []
        search_bytes = search_string.encode('utf-8')
        
        # Save current position
        current_pos = self.file_handle.tell()
        
        # Start at the specified offset
        self.file_handle.seek(start_offset)
        
        # Read the file in chunks to handle large memory dumps
        chunk_size = 10 * 1024 * 1024  # 10MB chunks
        overlap = len(search_bytes) - 1  # Overlap between chunks
        
        offset = start_offset
        found_count = 0
        
        while offset < self.size and found_count < max_results:
            # Determine chunk size, handling end of file
            actual_chunk_size = min(chunk_size, self.size - offset)
            
            # Read chunk
            chunk = self.file_handle.read(actual_chunk_size)
            
            # Search for string in chunk
            pos = 0
            while True:
                pos = chunk.find(search_bytes, pos)
                if pos == -1:
                    break
                    
                # Calculate absolute position in file
                abs_pos = offset + pos
                
                # Get some context around the match
                context_start = max(0, pos - 20)
                context_end = min(len(chunk), pos + len(search_bytes) + 20)
                context = chunk[context_start:context_end]
                
                try:
                    # Try to decode as UTF-8, fall back to showing bytes
                    context_text = context.decode('utf-8', errors='replace')
                    # Remove non-printable characters
                    context_text = ''.join(c for c in context_text if c.isprintable() or c.isspace())
                except:
                    context_text = str(context)
                
                results.append({
                    'offset': abs_pos,
                    'match': search_string,
                    'context': context_text
                })
                
                found_count += 1
                if found_count >= max_results:
                    break
                    
                pos += 1  # Move past the current match
            
            # Handle overlap between chunks
            if actual_chunk_size < chunk_size:
                # Reached end of file
                break
                
            # Move to next chunk, accounting for overlap
            offset += chunk_size - overlap
            self.file_handle.seek(offset)
        
        # Restore original position
        self.file_handle.seek(current_pos)
        
        return results
    
    def read_data(self, offset, size):
        """Read a chunk of data from the memory dump"""
        if not self.file_handle:
            return None
            
        # Save current position
        current_pos = self.file_handle.tell()
        
        # Seek to requested offset
        self.file_handle.seek(offset)
        
        # Read requested size
        data = self.file_handle.read(size)
        
        # Restore position
        self.file_handle.seek(current_pos)
        
        return data

class VolatilityRunnerThread(QThread):
    """Thread for running Volatility commands without blocking the UI"""
    progress_update = pyqtSignal(int, str)
    operation_complete = pyqtSignal(bool, str, object)
    
    def __init__(self, memory_file, plugin_name, args=None, vol_path=None):
        super().__init__()
        self.memory_file = memory_file
        self.plugin_name = plugin_name
        self.args = args if args else {}
        self.vol_path = vol_path or 'vol'  # Default to 'vol' if not provided
        self.process = None
        self.terminated = False
        
    def run(self):
        try:
            # Verify the memory file exists and is readable
            if not os.path.exists(self.memory_file):
                self.operation_complete.emit(False, f"Memory file not found: {self.memory_file}", None)
                return
                
            if not os.access(self.memory_file, os.R_OK):
                self.operation_complete.emit(False, f"Cannot read memory file (permission denied): {self.memory_file}", None)
                return
            
            # Create temporary directory for output
            output_dir = tempfile.mkdtemp()
            logger.info(f"Created temp directory for output: {output_dir}")
            
            # Build the vol command with correct arguments for Volatility 3
            vol_command = [
                self.vol_path,
                '-f', self.memory_file,
                '-r', 'json',
                '-o', output_dir,
                self.plugin_name
            ]
            
            # Add any plugin-specific arguments
            for arg_name, arg_value in self.args.items():
                if arg_value is not None:  # Only add if it has a value (including False)
                    if isinstance(arg_value, bool) and arg_value:
                        # For boolean flags that are True, just add the flag
                        vol_command.extend([f'--{arg_name}'])
                    elif not (isinstance(arg_value, bool) and not arg_value):
                        # Don't add False boolean flags, but add everything else
                        vol_command.extend([f'--{arg_name}', str(arg_value)])
            
            cmd_str = ' '.join(vol_command)
            self.progress_update.emit(10, f"Running command: {cmd_str}")
            logger.info(f"Running Volatility command: {cmd_str}")
            
            # Run the vol command
            try:
                self.progress_update.emit(20, "Starting Volatility process...")
                
                # Windows-compatible approach with timeout
                # Create the process
                self.process = subprocess.Popen(
                    vol_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,  # Universal newlines mode
                    bufsize=1   # Line buffered
                )
                
                stdout_data = []
                stderr_data = []
                
                # Set up reader threads for stdout and stderr
                # Use nonlocal last_progress to track the current progress correctly
                last_progress = 20  # Start at the same value as initial progress
                
                def read_stdout():
                    nonlocal last_progress
                    for line in iter(self.process.stdout.readline, ''):
                        if self.terminated:
                            break
                        if line:
                            stdout_data.append(line)
                            # Don't update progress here, just log the line
                            self.progress_update.emit(last_progress, f"Processing: {line.strip()}")
                
                def read_stderr():
                    nonlocal last_progress
                    for line in iter(self.process.stderr.readline, ''):
                        if self.terminated:
                            break
                        if line:
                            stderr_data.append(line)
                            # Look for progress indicators in stderr
                            if 'progress' in line.lower():
                                # Try to extract percentage
                                if 'Progress: ' in line:
                                    try:
                                        pct = float(line.split('Progress: ')[1].split()[0])
                                        # Map from Volatility's 0-100 to our 20-80 range
                                        progress = min(80, 20 + int(60 * pct / 100))
                                        # Only update if the new progress is greater than current
                                        if progress > last_progress:
                                            last_progress = progress
                                            self.progress_update.emit(progress, f"Volatility progress: {pct}%")
                                    except (ValueError, IndexError):
                                        pass
                            # Log stderr output but maintain progress
                            self.progress_update.emit(last_progress, f"Processing: {line.strip()}")
                
                # Start reader threads
                stdout_thread = threading.Thread(target=read_stdout)
                stderr_thread = threading.Thread(target=read_stderr)
                stdout_thread.daemon = True
                stderr_thread.daemon = True
                stdout_thread.start()
                stderr_thread.start()
                
                start_time = time.time()
                timeout = 300  # 5 minutes max
                
                # Monitor the process with a timeout
                while self.process.poll() is None:
                    if self.terminated:
                        logger.warning("Volatility process terminated by user")
                        self.process.terminate()
                        self.operation_complete.emit(False, "Operation cancelled by user", None)
                        shutil.rmtree(output_dir, ignore_errors=True)
                        return
                    
                    # Check for timeout
                    elapsed_time = time.time() - start_time
                    if elapsed_time > timeout:
                        self.process.terminate()
                        logger.error(f"Volatility process timed out after {timeout} seconds")
                        self.operation_complete.emit(False, f"Operation timed out after {timeout} seconds", None)
                        shutil.rmtree(output_dir, ignore_errors=True)
                        return
                    
                    # Update progress based on elapsed time percentage of timeout
                    progress = min(80, 20 + int(60 * elapsed_time / timeout))
                    if progress > last_progress:
                        self.progress_update.emit(progress, f"Processing... ({int(elapsed_time)}s elapsed)")
                        last_progress = progress
                    
                    # Sleep briefly to avoid high CPU usage
                    QThread.msleep(100)
                
                # Process has completed, wait for reader threads to finish
                self.progress_update.emit(85, "Collecting results...")
                
                # Give threads a moment to finish
                stdout_thread.join(2)
                stderr_thread.join(2)
                
                # Get any remaining output
                try:
                    remaining_stdout, remaining_stderr = self.process.communicate(timeout=5)
                    if remaining_stdout:
                        stdout_data.append(remaining_stdout)
                    if remaining_stderr:
                        stderr_data.append(remaining_stderr)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    remaining_stdout, remaining_stderr = self.process.communicate()
                    if remaining_stdout:
                        stdout_data.append(remaining_stdout)
                    if remaining_stderr:
                        stderr_data.append(remaining_stderr)
                
                # Combine all data
                stdout = ''.join(stdout_data)
                stderr = ''.join(stderr_data)
                
            except Exception as e:
                self.operation_complete.emit(False, f"Error executing Volatility: {str(e)}", None)
                shutil.rmtree(output_dir, ignore_errors=True)
                return
            
            self.progress_update.emit(90, "Processing results...")
            
            # Improved JSON results handling
            if self.process.returncode == 0:
                # Process completed successfully
                # Look for JSON files in the output directory
                try:
                    json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
                    
                    if json_files:
                        # Read the first JSON file
                        try:
                            file_path = os.path.join(output_dir, json_files[0])
                            logger.info(f"Reading JSON from: {file_path}")
                            
                            with open(file_path, 'r') as f:
                                file_content = f.read()
                            
                            # If file is empty, handle that case
                            if not file_content.strip():
                                logger.warning(f"Empty JSON file: {file_path}")
                                self.operation_complete.emit(True, 
                                                    "Analysis completed but output file is empty", 
                                                    {"data": {"output": "No output was generated by the plugin"}})
                                shutil.rmtree(output_dir, ignore_errors=True)
                                return
                            
                            # Try to parse as JSON
                            try:
                                results = json.loads(file_content)
                                
                                # Special handling for linux.psscan.PsScan
                                if "linux.psscan" in self.plugin_name:
                                    # Extract process list and format it for table display
                                    if isinstance(results, dict):
                                        # Look for plugin data in different formats
                                        plugin_data = None
                                        
                                        # Look for the plugin result key (starts with volatility3)
                                        for key in results.keys():
                                            if key.startswith('volatility3'):
                                                plugin_data = results[key]
                                                break
                                        
                                        if plugin_data and isinstance(plugin_data, list):
                                            # Format: We have a list of process dictionaries
                                            formatted_results = {
                                                "data": {
                                                    "columns": list(plugin_data[0].keys()) if plugin_data else [],
                                                    "rows": [[str(proc.get(col, "")) for col in list(plugin_data[0].keys())] 
                                                             for proc in plugin_data] if plugin_data else []
                                                }
                                            }
                                            self.operation_complete.emit(True, "Analysis completed successfully", formatted_results)
                                            shutil.rmtree(output_dir, ignore_errors=True)
                                            return
                                
                                # For other plugins, return as is
                                self.operation_complete.emit(True, "Analysis completed successfully", results)
                            except json.JSONDecodeError as json_err:
                                logger.warning(f"Invalid JSON in {file_path}: {str(json_err)}")
                                # Return as raw text
                                results = {"data": {"output": file_content}}
                                self.operation_complete.emit(True, 
                                                    "Analysis completed but results file is not valid JSON", 
                                                    results)
                        except Exception as e:
                            logger.error(f"Error processing results file: {str(e)}")
                            # If any error occurs reading the file, use stdout
                            self.operation_complete.emit(True, 
                                                "Analysis completed but error processing results file", 
                                                {"data": {"output": stdout or stderr or "No readable output"}})
                    else:
                        # No JSON files found but process still completed - check if we got output on stdout or stderr
                        if stdout:
                            try:
                                json_data = json.loads(stdout)
                                
                                # Special handling for linux.psscan.PsScan
                                if "linux.psscan" in self.plugin_name:
                                    # Extract process list and format it for table display
                                    if isinstance(json_data, dict):
                                        # Look for plugin data in different formats
                                        plugin_data = None
                                        
                                        # Look for the plugin result key (starts with volatility3)
                                        for key in json_data.keys():
                                            if key.startswith('volatility3'):
                                                plugin_data = json_data[key]
                                                break
                                        
                                        if plugin_data and isinstance(plugin_data, list):
                                            # Format: We have a list of process dictionaries
                                            formatted_results = {
                                                "data": {
                                                    "columns": list(plugin_data[0].keys()) if plugin_data else [],
                                                    "rows": [[str(proc.get(col, "")) for col in list(plugin_data[0].keys())] 
                                                             for proc in plugin_data] if plugin_data else []
                                                }
                                            }
                                            self.operation_complete.emit(True, "Analysis completed successfully", formatted_results)
                                            shutil.rmtree(output_dir, ignore_errors=True)
                                            return
                                
                                self.operation_complete.emit(True, 
                                                    "Analysis completed (JSON from stdout)", 
                                                    json_data)
                            except json.JSONDecodeError:
                                # Just return the stdout as raw text
                                self.operation_complete.emit(True, 
                                                    "Analysis completed (output from stdout)", 
                                                    {"data": {"output": stdout}})
                        elif stderr:
                            # Sometimes Volatility outputs to stderr instead
                            if "Error" not in stderr and "Exception" not in stderr:
                                self.operation_complete.emit(True, 
                                                    "Analysis completed (output from stderr)", 
                                                    {"data": {"output": stderr}})
                            else:
                                self.operation_complete.emit(False, 
                                                    f"Plugin error: {stderr}", 
                                                    None)
                        else:
                            # No output files and no stdout/stderr, but process completed successfully
                            self.operation_complete.emit(True, 
                                                "Analysis completed but no output generated", 
                                                {"data": {"output": "No results were returned by the plugin. This could mean no matching data was found."}})
                except Exception as e:
                    logger.error(f"Error processing output: {str(e)}")
                    self.operation_complete.emit(False, f"Error processing output: {str(e)}", None)
            else:
                # Process failed
                error_msg = stderr.strip() if stderr.strip() else stdout.strip()
                
                # Try to provide more helpful error messages
                if "Not a supported file format" in error_msg:
                    error_msg = "The memory dump format is not supported. Please verify this is a valid memory dump file."
                elif "No such file or directory" in error_msg:
                    error_msg = f"File not found: {error_msg}"
                elif "Symbol table not found" in error_msg:
                    error_msg = "Symbol table not found. This OS/kernel version may not be supported by Volatility."
                elif ".vmss" in error_msg or ".vmem" in error_msg:
                    error_msg = "VMware metadata file is needed. Put the .vmss file in the same directory as your .vmem file."
                elif not error_msg:
                    error_msg = f"Volatility command failed with return code {self.process.returncode}"
                
                logger.error(f"Volatility execution error: {error_msg}")
                self.operation_complete.emit(False, f"Volatility execution error: {error_msg}", None)
            
            # Clean up temp directory
            shutil.rmtree(output_dir, ignore_errors=True)
                
        except Exception as e:
            logger.exception(f"Error running Volatility: {str(e)}")
            self.operation_complete.emit(False, f"Error running Volatility: {str(e)}", None)
    
    def terminate(self):
        """Safely terminate the process"""
        self.terminated = True
        if self.process:
            try:
                self.process.terminate()
            except:
                pass
        super().terminate()

class MemoryCaptureThread(QThread):
    """Thread for capturing memory dumps without freezing the UI"""
    progress_update = pyqtSignal(int, str)
    operation_complete = pyqtSignal(bool, str, str)
    
    def __init__(self, source_system, output_path, capture_method='dd'):
        super().__init__()
        self.source_system = source_system
        self.output_path = output_path
        self.capture_method = capture_method
        self.terminated = False
        
    def run(self):
        try:
            # Choose the capture method based on settings
            if self.capture_method == 'dd':
                success, message = self._capture_with_dd()
            elif self.capture_method == 'lime':
                success, message = self._capture_with_lime()
            elif self.capture_method == 'ssh':
                success, message = self._capture_with_ssh()
            else:
                success = False
                message = f"Unsupported capture method: {self.capture_method}"
                
            self.operation_complete.emit(success, message, self.output_path)
            
        except Exception as e:
            self.operation_complete.emit(False, f"Error: {str(e)}", "")
    
    def _capture_with_dd(self):
        """Capture memory using dd on local system"""
        try:
            # For local Linux systems, use /proc/kcore or /dev/mem
            # Note: This requires root privileges
            source = "/proc/kcore"
            if not os.path.exists(source):
                source = "/dev/mem"
                if not os.path.exists(source):
                    return False, "Neither /proc/kcore nor /dev/mem available. Try running with sudo."
            
            # Set up the dd command
            command = ['dd', f'if={source}', f'of={self.output_path}', 'bs=4M', 'status=progress']
            
            # Execute with progress monitoring
            process = subprocess.Popen(command, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Poll output for progress information
            for line in process.stderr:
                if self.terminated:
                    process.terminate()
                    return False, "Capture terminated by user"
                    
                try:
                    if 'bytes' in line:
                        # Extract bytes copied from dd output
                        match = re.search(r'(\d+)\s+bytes', line)
                        if match:
                            bytes_copied = int(match.group(1))
                            # We don't know total size in advance, so use a placeholder
                            # and report in MB instead
                            mb_copied = bytes_copied / (1024 * 1024)
                            self.progress_update.emit(0, f"{mb_copied:.2f} MB captured")
                except Exception as e:
                    # Continue even if progress parsing fails
                    pass
            
            process.wait()
            
            if process.returncode == 0:
                return True, "Memory capture completed successfully"
            else:
                return False, f"Memory capture failed with return code {process.returncode}"
        
        except Exception as e:
            return False, f"Error during memory capture: {str(e)}"
    
    def _capture_with_lime(self):
        """Capture memory using LiME (Linux Memory Extractor)"""
        try:
            # Check if LiME module is available
            lime_check = subprocess.run(['modinfo', 'lime'], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE)
            
            if lime_check.returncode != 0:
                return False, "LiME kernel module not found. Please install LiME first."
            
            # Insert LiME module with parameters
            command = ['sudo', 'insmod', '/lib/modules/lime.ko', 
                      f'path={self.output_path}', 'format=raw']
            
            # Execute LiME
            self.progress_update.emit(10, "Starting LiME memory acquisition...")
            process = subprocess.run(command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   universal_newlines=True)
            
            # Check for errors
            if process.returncode != 0:
                return False, f"LiME failed: {process.stderr}"
            
            # Remove module after capture
            subprocess.run(['sudo', 'rmmod', 'lime'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE,
                         check=False)
            
            self.progress_update.emit(100, "Memory acquisition complete")
            return True, "Memory capture completed successfully with LiME"
            
        except Exception as e:
            return False, f"Error during LiME memory capture: {str(e)}"
    
    def _capture_with_ssh(self):
        """Capture memory from a remote system using SSH"""
        try:
            # This implementation focuses on Linux-specific remote acquisition
            self.progress_update.emit(10, "Connecting to remote Linux system...")
            
            # Define commands based on whether we're using LiME or DD
            if self.capture_method == "lime":
                # First check if LiME is available on remote system
                check_lime_cmd = f"ssh {self.source_system} 'modinfo lime'"
                check_process = subprocess.run(check_lime_cmd, shell=True, 
                                            stdout=subprocess.PIPE, 
                                            stderr=subprocess.PIPE)
                
                if check_process.returncode != 0:
                    return False, "LiME module not found on remote system. Please install LiME first."
                
                # Create a named pipe and capture through SSH
                self.progress_update.emit(20, "Setting up memory acquisition with LiME...")
                
                # Create a pipeline: run LiME on remote, stream through SSH, save locally
                ssh_cmd = (f"ssh {self.source_system} 'sudo insmod /lib/modules/lime.ko format=raw path=- | gzip -c' " +
                          f"| gunzip -c > {self.output_path}")
                
            else:  # Default to DD
                # Check for /proc/kcore or /dev/mem on remote system
                check_cmd = f"ssh {self.source_system} '[ -r /proc/kcore ] || [ -r /dev/mem ]'"
                check_process = subprocess.run(check_cmd, shell=True, 
                                             stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE)
                
                if check_process.returncode != 0:
                    return False, "Neither /proc/kcore nor /dev/mem is accessible on remote system. Try running with sudo."
                
                # Determine which source to use
                source_cmd = f"ssh {self.source_system} '[ -r /proc/kcore ] && echo /proc/kcore || echo /dev/mem'"
                source_process = subprocess.run(source_cmd, shell=True, 
                                              stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE)
                
                mem_source = source_process.stdout.decode('utf-8').strip()
                self.progress_update.emit(20, f"Using {mem_source} for memory acquisition...")
                
                # Create the SSH command to stream memory
                ssh_cmd = (f"ssh {self.source_system} 'sudo dd if={mem_source} bs=4M status=progress | gzip -c' " +
                          f"| gunzip -c > {self.output_path}")
            
            # Execute the command and monitor progress
            self.progress_update.emit(25, "Starting memory capture...")
            process = subprocess.Popen(ssh_cmd, shell=True, 
                                     stderr=subprocess.PIPE, 
                                     universal_newlines=True)
            
            # Monitor stderr for progress information
            for line in process.stderr:
                if self.terminated:
                    process.terminate()
                    return False, "Capture terminated by user"
                    
                try:
                    if 'bytes' in line:
                        # Extract bytes copied from dd output
                        match = re.search(r'(\d+)\s+bytes', line)
                        if match:
                            bytes_copied = int(match.group(1))
                            mb_copied = bytes_copied / (1024 * 1024)
                            progress_percent = min(90, 25 + int(mb_copied / 10))  # Cap at 90%
                            self.progress_update.emit(progress_percent, f"{mb_copied:.2f} MB captured")
                except Exception as e:
                    # Continue even if progress parsing fails
                    pass
            
            process.wait()
            
            if process.returncode == 0:
                self.progress_update.emit(100, "Memory capture complete!")
                return True, "Memory capture from remote system completed successfully"
            else:
                return False, f"Memory capture failed with return code {process.returncode}"
                
        except Exception as e:
            return False, f"Error during SSH memory capture: {str(e)}"
    
    def terminate(self):
        """Safely terminate the process"""
        self.terminated = True
        super().terminate()

# to be delted later 
class CaseManager:
    def __init__(self):
        self.case_directory = None
        self.case_name = None
        self.case_info = {}
        self.evidence_list = []
    
    def create_case(self, case_name, case_directory):
        """Create a new case with the specified name and directory"""
        if not os.path.exists(case_directory):
            try:
                os.makedirs(case_directory)
            except Exception as e:
                return False, f"Error creating case directory: {str(e)}"
        
        # Create subdirectories for the case
        evidence_dir = os.path.join(case_directory, "evidence")
        reports_dir = os.path.join(case_directory, "reports")
        
        try:
            if not os.path.exists(evidence_dir):
                os.makedirs(evidence_dir)
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
        except Exception as e:
            return False, f"Error creating case subdirectories: {str(e)}"
        
        # Set case information
        self.case_directory = case_directory
        self.case_name = case_name
        self.case_info = {
            'name': case_name,
            'created': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'directory': case_directory
        }
        
        # Create case metadata file
        self._save_case_info()
        
        return True, "Case created successfully"
    
    def open_case(self, case_directory):
        """Open an existing case from the specified directory"""
        if not os.path.exists(case_directory):
            return False, "Case directory does not exist"
        
        # Check for case metadata file
        metadata_file = os.path.join(case_directory, "case_info.txt")
        if not os.path.exists(metadata_file):
            return False, "Invalid case directory (missing metadata)"
        
        # Load case information
        try:
            with open(metadata_file, 'r') as f:
                lines = f.readlines()
                self.case_info = {}
                for line in lines:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        self.case_info[key] = value.strip()
        except Exception as e:
            return False, f"Error reading case metadata: {str(e)}"
        
        # Set case variables
        self.case_directory = case_directory
        self.case_name = self.case_info.get('name', os.path.basename(case_directory))
        
        # Load evidence list
        self._load_evidence_list()
        
        return True, "Case opened successfully"
    
    def _save_case_info(self):
        """Save case information to metadata file"""
        if not self.case_directory:
            return False
        
        metadata_file = os.path.join(self.case_directory, "case_info.txt")
        try:
            with open(metadata_file, 'w') as f:
                for key, value in self.case_info.items():
                    f.write(f"{key}: {value}\n")
            return True
        except Exception as e:
            print(f"Error saving case info: {e}")
            return False
    
    def _load_evidence_list(self):
        """Load the list of evidence from the evidence log file"""
        evidence_log = os.path.join(self.case_directory, "evidence_log.csv")
        self.evidence_list = []
        
        if os.path.exists(evidence_log):
            try:
                with open(evidence_log, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.evidence_list.append(row)
            except Exception as e:
                print(f"Error loading evidence list: {e}")
    
    def add_evidence(self, file_path, evidence_type, description=""):
        """Add evidence to the case"""
        if not self.case_directory:
            return False, "No case is currently open"
        
        # Generate a unique evidence ID
        evidence_id = f"EV{len(self.evidence_list) + 1:03d}"
        
        # Get file information
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # Calculate file hash
        try:
            md5_hash = self._calculate_file_hash(file_path)
        except:
            md5_hash = "Unknown"
        
        # Create evidence entry
        evidence_entry = {
            'id': evidence_id,
            'type': evidence_type,
            'name': file_name,
            'path': file_path,
            'size': file_size,
            'md5': md5_hash,
            'description': description,
            'added': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Add to evidence list
        self.evidence_list.append(evidence_entry)
        
        # Update evidence log file
        self._update_evidence_log()
        
        return True, f"Evidence added with ID: {evidence_id}"
    
    def _calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def _update_evidence_log(self):
        """Update the evidence log CSV file"""
        if not self.case_directory or not self.evidence_list:
            return
            
        evidence_log = os.path.join(self.case_directory, "evidence_log.csv")
        
        try:
            with open(evidence_log, 'w', newline='') as f:
                fieldnames = ['id', 'type', 'name', 'path', 'size', 'md5', 'description', 'added']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for evidence in self.evidence_list:
                    writer.writerow(evidence)
        except Exception as e:
            print(f"Error updating evidence log: {e}")
        return True         
