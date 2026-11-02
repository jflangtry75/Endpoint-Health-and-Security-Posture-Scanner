"""
System Diagnostic Scanner
Scans the local device for potential issues and collects system information.
"""

import psutil
import platform
import os
from datetime import datetime
from typing import Dict, List, Any
import subprocess
import sys
import json


class SystemScanner:
    """Scans the system for various metrics and potential issues."""
    
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.info = []
        self.system_info = {}
        
    def scan_all(self) -> Dict[str, Any]:
        """Run all diagnostic scans."""
        print("🔍 Starting system scan...")
        
        self.scan_system_info()
        self.scan_disk_space()
        self.scan_memory()
        self.scan_cpu()
        self.scan_temperature()
        self.scan_battery()
        self.scan_processes()
        self.scan_network()
        self.scan_windows_updates()
        self.scan_disk_health()
        self.scan_filesystem_structure()
        
        return {
            'system_info': self.system_info,
            'issues': self.issues,
            'warnings': self.warnings,
            'info': self.info,
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def scan_system_info(self):
        """Collect basic system information."""
        print("  📋 Collecting system information...")
        self.system_info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'platform_release': platform.release(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'python_version': platform.python_version()
        }
        
        # Get Windows-specific info if available
        if platform.system() == 'Windows':
            try:
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | ConvertTo-Json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    os_info = json.loads(result.stdout)
                    if os_info.get('Caption'):
                        self.system_info['os_name'] = os_info['Caption'].strip()
                    if os_info.get('Version'):
                        self.system_info['os_version'] = os_info['Version'].strip()
            except Exception:
                pass
    
    def scan_disk_space(self):
        """Check disk space usage."""
        print("  💾 Checking disk space...")
        try:
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    total_gb = usage.total / (1024**3)
                    used_gb = usage.used / (1024**3)
                    free_gb = usage.free / (1024**3)
                    percent_used = (usage.used / usage.total) * 100
                    
                    disk_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_gb': round(total_gb, 2),
                        'used_gb': round(used_gb, 2),
                        'free_gb': round(free_gb, 2),
                        'percent_used': round(percent_used, 2)
                    }
                    
                    if percent_used > 90:
                        self.issues.append({
                            'type': 'critical',
                            'category': 'disk_space',
                            'message': f"Disk {partition.device} is {percent_used:.1f}% full ({free_gb:.1f} GB free)",
                            'details': disk_info
                        })
                    elif percent_used > 80:
                        self.warnings.append({
                            'type': 'warning',
                            'category': 'disk_space',
                            'message': f"Disk {partition.device} is {percent_used:.1f}% full ({free_gb:.1f} GB free)",
                            'details': disk_info
                        })
                    else:
                        self.info.append({
                            'type': 'info',
                            'category': 'disk_space',
                            'message': f"Disk {partition.device}: {percent_used:.1f}% used ({free_gb:.1f} GB free)",
                            'details': disk_info
                        })
                except PermissionError:
                    continue
        except Exception as e:
            self.warnings.append({
                'type': 'warning',
                'category': 'disk_space',
                'message': f"Could not scan disk space: {str(e)}"
            })
    
    def scan_memory(self):
        """Check memory usage."""
        print("  🧠 Checking memory usage...")
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            memory_gb = memory.total / (1024**3)
            memory_used_gb = memory.used / (1024**3)
            memory_available_gb = memory.available / (1024**3)
            memory_percent = memory.percent
            
            memory_info = {
                'total_gb': round(memory_gb, 2),
                'used_gb': round(memory_used_gb, 2),
                'available_gb': round(memory_available_gb, 2),
                'percent_used': round(memory_percent, 2),
                'swap_total_gb': round(swap.total / (1024**3), 2),
                'swap_used_gb': round(swap.used / (1024**3), 2)
            }
            
            if memory_percent > 90:
                self.issues.append({
                    'type': 'critical',
                    'category': 'memory',
                    'message': f"Memory usage is {memory_percent:.1f}% ({memory_available_gb:.1f} GB available)",
                    'details': memory_info
                })
            elif memory_percent > 80:
                self.warnings.append({
                    'type': 'warning',
                    'category': 'memory',
                    'message': f"Memory usage is {memory_percent:.1f}% ({memory_available_gb:.1f} GB available)",
                    'details': memory_info
                })
            else:
                self.info.append({
                    'type': 'info',
                    'category': 'memory',
                    'message': f"Memory usage: {memory_percent:.1f}% ({memory_available_gb:.1f} GB available)",
                    'details': memory_info
                })
            
            # Check if system has low memory
            if memory_gb < 4:
                self.warnings.append({
                    'type': 'warning',
                    'category': 'memory',
                    'message': f"System has only {memory_gb:.1f} GB of RAM, which may impact performance",
                    'details': memory_info
                })
                
        except Exception as e:
            self.warnings.append({
                'type': 'warning',
                'category': 'memory',
                'message': f"Could not scan memory: {str(e)}"
            })
    
    def scan_cpu(self):
        """Check CPU usage and information."""
        print("  ⚙️  Checking CPU...")
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count(logical=True)
            cpu_count_physical = psutil.cpu_count(logical=False)
            cpu_freq = psutil.cpu_freq()
            
            cpu_info = {
                'usage_percent': round(cpu_percent, 2),
                'cores_logical': cpu_count,
                'cores_physical': cpu_count_physical,
                'frequency_mhz': round(cpu_freq.current, 2) if cpu_freq else None
            }
            
            if cpu_percent > 90:
                self.issues.append({
                    'type': 'critical',
                    'category': 'cpu',
                    'message': f"CPU usage is {cpu_percent:.1f}% - system may be overloaded",
                    'details': cpu_info
                })
            elif cpu_percent > 80:
                self.warnings.append({
                    'type': 'warning',
                    'category': 'cpu',
                    'message': f"CPU usage is {cpu_percent:.1f}% - high load detected",
                    'details': cpu_info
                })
            else:
                self.info.append({
                    'type': 'info',
                    'category': 'cpu',
                    'message': f"CPU usage: {cpu_percent:.1f}%",
                    'details': cpu_info
                })
                
        except Exception as e:
            self.warnings.append({
                'type': 'warning',
                'category': 'cpu',
                'message': f"Could not scan CPU: {str(e)}"
            })
    
    def scan_temperature(self):
        """Check system temperatures if available."""
        print("  🌡️  Checking temperatures...")
        try:
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        for entry in entries:
                            temp = entry.current
                            if temp and temp > 80:
                                self.issues.append({
                                    'type': 'critical',
                                    'category': 'temperature',
                                    'message': f"High temperature detected: {name} at {temp}°C",
                                    'details': {'sensor': name, 'temperature': temp}
                                })
                            elif temp and temp > 70:
                                self.warnings.append({
                                    'type': 'warning',
                                    'category': 'temperature',
                                    'message': f"Elevated temperature: {name} at {temp}°C",
                                    'details': {'sensor': name, 'temperature': temp}
                                })
        except Exception:
            # Temperature sensors may not be available on all systems
            pass
    
    def scan_battery(self):
        """Check battery status if available."""
        print("  🔋 Checking battery...")
        try:
            battery = psutil.sensors_battery()
            if battery:
                percent = battery.percent
                plugged = battery.power_plugged
                
                if not plugged and percent < 20:
                    self.issues.append({
                        'type': 'critical',
                        'category': 'battery',
                        'message': f"Battery is critically low: {percent:.1f}%",
                        'details': {'percent': percent, 'plugged': plugged}
                    })
                elif not plugged and percent < 30:
                    self.warnings.append({
                        'type': 'warning',
                        'category': 'battery',
                        'message': f"Battery is low: {percent:.1f}%",
                        'details': {'percent': percent, 'plugged': plugged}
                    })
        except Exception:
            # Battery may not be available on desktop systems
            pass
    
    def scan_processes(self):
        """Check for problematic processes."""
        print("  🔄 Checking processes...")
        try:
            processes = []
            high_cpu_processes = []
            high_memory_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    if pinfo['cpu_percent'] and pinfo['cpu_percent'] > 50:
                        high_cpu_processes.append(pinfo)
                    if pinfo['memory_percent'] and pinfo['memory_percent'] > 10:
                        high_memory_processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if high_cpu_processes:
                top_cpu = sorted(high_cpu_processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:3]
                self.warnings.append({
                    'type': 'warning',
                    'category': 'processes',
                    'message': f"High CPU usage detected in: {', '.join([p['name'] for p in top_cpu])}",
                    'details': {'high_cpu_processes': top_cpu}
                })
            
            if high_memory_processes:
                top_memory = sorted(high_memory_processes, key=lambda x: x['memory_percent'] or 0, reverse=True)[:3]
                self.warnings.append({
                    'type': 'warning',
                    'category': 'processes',
                    'message': f"High memory usage detected in: {', '.join([p['name'] for p in top_memory])}",
                    'details': {'high_memory_processes': top_memory}
                })
                
        except Exception as e:
            self.warnings.append({
                'type': 'warning',
                'category': 'processes',
                'message': f"Could not scan processes: {str(e)}"
            })
    
    def scan_network(self):
        """Check network connectivity and statistics."""
        print("  🌐 Checking network...")
        try:
            net_io = psutil.net_io_counters()
            connections = psutil.net_connections(kind='inet')
            
            network_info = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'active_connections': len(connections)
            }
            
            self.info.append({
                'type': 'info',
                'category': 'network',
                'message': f"Network: {len(connections)} active connections",
                'details': network_info
            })
        except Exception as e:
            self.warnings.append({
                'type': 'warning',
                'category': 'network',
                'message': f"Could not scan network: {str(e)}"
            })
    
    def scan_windows_updates(self):
        """Check Windows Update status (Windows only)."""
        if platform.system() != 'Windows':
            return
            
        print("  🔄 Checking Windows Update status...")
        try:
            # Try to check Windows Update status using PowerShell
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-WindowsUpdate -MicrosoftUpdate | Select-Object -First 1 | ConvertTo-Json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            # Note: This may require admin privileges and Windows Update module
        except Exception:
            # Windows Update check may not be available
            pass
    
    def scan_disk_health(self):
        """Check disk health indicators (Windows only)."""
        if platform.system() != 'Windows':
            return
            
        print("  💿 Checking disk health...")
        try:
            # Use CIM to check disk health on Windows
            # -InputObject @(...) keeps the JSON an array even with a single disk
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'ConvertTo-Json -InputObject @(Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Model, Status)'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                for disk in json.loads(result.stdout):
                    status = (disk.get('Status') or '').strip()
                    if status and 'OK' not in status.upper():
                        self.warnings.append({
                            'type': 'warning',
                            'category': 'disk_health',
                            'message': f"Disk status: {status}",
                            'details': {'status': status, 'model': disk.get('Model')}
                        })
        except Exception:
            pass
    
    def scan_filesystem_structure(self):
        """Check file system structure and important directories."""
        print("  📁 Checking file system structure...")
        
        missing_dirs = []
        missing_files = []
        permission_issues = []
        suspicious_paths = []
        
        system_platform = platform.system()
        
        if system_platform == 'Windows':
            # Windows critical directories
            critical_dirs = [
                ('C:\\Windows', 'Windows system directory'),
                ('C:\\Windows\\System32', 'System32 directory'),
                ('C:\\Windows\\SysWOW64', 'SysWOW64 directory (if 64-bit)'),
                ('C:\\Program Files', 'Program Files directory'),
                ('C:\\Program Files (x86)', 'Program Files x86 directory (if exists)'),
                ('C:\\Users', 'Users directory'),
                ('C:\\ProgramData', 'ProgramData directory'),
            ]
            
            # Windows critical files
            critical_files = [
                ('C:\\Windows\\System32\\kernel32.dll', 'Kernel32 DLL'),
                ('C:\\Windows\\System32\\ntdll.dll', 'NTDLL DLL'),
                ('C:\\Windows\\System32\\winlogon.exe', 'Winlogon executable'),
                ('C:\\Windows\\explorer.exe', 'Windows Explorer'),
            ]
            
            # Check for suspicious locations
            suspicious_locations = [
                ('C:\\Windows\\Temp', 'Windows Temp directory'),
                ('C:\\Temp', 'Root Temp directory'),
            ]
            
        elif system_platform == 'Linux':
            # Linux critical directories
            critical_dirs = [
                ('/bin', 'Binary directory'),
                ('/usr/bin', 'User binary directory'),
                ('/etc', 'Configuration directory'),
                ('/home', 'Home directory'),
                ('/var', 'Variable data directory'),
                ('/usr/lib', 'Library directory'),
                ('/boot', 'Boot directory'),
            ]
            
            # Linux critical files
            critical_files = [
                ('/bin/sh', 'Shell executable'),
                ('/bin/ls', 'List command'),
                ('/etc/passwd', 'Password file'),
                ('/etc/group', 'Group file'),
            ]
            
            suspicious_locations = [
                ('/tmp', 'Temporary directory'),
                ('/var/tmp', 'Variable temp directory'),
            ]
            
        elif system_platform == 'Darwin':  # macOS
            # macOS critical directories
            critical_dirs = [
                ('/Applications', 'Applications directory'),
                ('/System', 'System directory'),
                ('/Library', 'Library directory'),
                ('/Users', 'Users directory'),
                ('/usr/bin', 'User binary directory'),
            ]
            
            critical_files = [
                ('/System/Library/CoreServices/SystemVersion.plist', 'System version file'),
            ]
            
            suspicious_locations = [
                ('/tmp', 'Temporary directory'),
                ('/var/tmp', 'Variable temp directory'),
            ]
        else:
            # Unknown platform, skip
            return
        
        # Check critical directories
        for dir_path, description in critical_dirs:
            try:
                if not os.path.exists(dir_path):
                    missing_dirs.append({'path': dir_path, 'description': description})
                elif not os.path.isdir(dir_path):
                    self.warnings.append({
                        'type': 'warning',
                        'category': 'filesystem_structure',
                        'message': f"Expected directory is a file: {dir_path}",
                        'details': {'path': dir_path, 'description': description}
                    })
                else:
                    # Check if directory is readable
                    try:
                        os.listdir(dir_path)
                        self.info.append({
                            'type': 'info',
                            'category': 'filesystem_structure',
                            'message': f"Directory exists and accessible: {dir_path}",
                            'details': {'path': dir_path, 'description': description}
                        })
                    except PermissionError:
                        permission_issues.append({'path': dir_path, 'description': description})
            except Exception as e:
                self.warnings.append({
                    'type': 'warning',
                    'category': 'filesystem_structure',
                    'message': f"Could not check directory {dir_path}: {str(e)}",
                    'details': {'path': dir_path, 'description': description}
                })
        
        # Check critical files
        for file_path, description in critical_files:
            try:
                if not os.path.exists(file_path):
                    missing_files.append({'path': file_path, 'description': description})
                elif not os.path.isfile(file_path):
                    self.warnings.append({
                        'type': 'warning',
                        'category': 'filesystem_structure',
                        'message': f"Expected file is a directory: {file_path}",
                        'details': {'path': file_path, 'description': description}
                    })
            except Exception:
                pass
        
        # Check suspicious locations for unusual content
        for sus_path, description in suspicious_locations:
            try:
                if os.path.exists(sus_path) and os.path.isdir(sus_path):
                    try:
                        files = os.listdir(sus_path)
                        if len(files) > 1000:  # Large number of files might indicate issues
                            self.warnings.append({
                                'type': 'warning',
                                'category': 'filesystem_structure',
                                'message': f"Large number of files in {sus_path} ({len(files)} files)",
                                'details': {'path': sus_path, 'file_count': len(files)}
                            })
                    except PermissionError:
                        pass
            except Exception:
                pass
        
        # Report missing critical directories
        if missing_dirs:
            for missing in missing_dirs:
                self.issues.append({
                    'type': 'critical',
                    'category': 'filesystem_structure',
                    'message': f"Missing critical directory: {missing['path']} ({missing['description']})",
                    'details': missing
                })
        
        # Report missing critical files
        if missing_files:
            for missing in missing_files:
                self.issues.append({
                    'type': 'critical',
                    'category': 'filesystem_structure',
                    'message': f"Missing critical file: {missing['path']} ({missing['description']})",
                    'details': missing
                })
        
        # Report permission issues
        if permission_issues:
            for perm_issue in permission_issues:
                self.warnings.append({
                    'type': 'warning',
                    'category': 'filesystem_structure',
                    'message': f"Cannot access directory (permission denied): {perm_issue['path']}",
                    'details': perm_issue
                })
        
        # Check for unusual file system structure issues
        if system_platform == 'Windows':
            # Check for Windows-specific issues
            try:
                # Check that core Windows executables are where Windows installs them
                system32_path = 'C:\\Windows\\System32'
                if os.path.exists(system32_path):
                    try:
                        expected_files = [
                            ('cmd.exe', os.path.join(system32_path, 'cmd.exe')),
                            ('powershell.exe', os.path.join(system32_path, 'WindowsPowerShell', 'v1.0', 'powershell.exe')),
                            ('regedit.exe', 'C:\\Windows\\regedit.exe'),
                        ]
                        for name, full_path in expected_files:
                            if not os.path.exists(full_path):
                                self.warnings.append({
                                    'type': 'warning',
                                    'category': 'filesystem_structure',
                                    'message': f"Expected system file missing: {name}",
                                    'details': {'path': full_path}
                                })
                    except PermissionError:
                        pass
            except Exception:
                pass
        
        # Summary info
        if not missing_dirs and not missing_files and not permission_issues:
            self.info.append({
                'type': 'info',
                'category': 'filesystem_structure',
                'message': "File system structure appears intact - critical directories and files are present",
                'details': {'platform': system_platform}
            })

