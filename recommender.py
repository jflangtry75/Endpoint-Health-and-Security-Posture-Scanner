"""
Recommendation Engine
Generates actionable recommendations based on scan results.
"""

from typing import Dict, List, Any


class RecommendationEngine:
    """Generates recommendations based on diagnostic scan results."""
    
    def __init__(self):
        self.recommendations = []
    
    def generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations based on scan results."""
        self.recommendations = []
        
        issues = scan_results.get('issues', [])
        warnings = scan_results.get('warnings', [])
        
        # Process issues and warnings by category
        self._process_disk_space(issues, warnings)
        self._process_memory(issues, warnings)
        self._process_cpu(issues, warnings)
        self._process_temperature(issues, warnings)
        self._process_battery(issues, warnings)
        self._process_processes(issues, warnings)
        self._process_filesystem_structure(issues, warnings)
        self._process_security(scan_results)
        self._process_general(scan_results)
        
        return self.recommendations
    
    def _process_security(self, scan_results: Dict[str, Any]):
        """Generate recommendations for security issues."""
        # This will be called if security results are included in scan_results
        # For now, security scanning is separate, but we can integrate it here if needed
        pass
    
    def _process_disk_space(self, issues: List, warnings: List):
        """Generate recommendations for disk space issues."""
        disk_issues = [i for i in issues if i.get('category') == 'disk_space']
        disk_warnings = [w for w in warnings if w.get('category') == 'disk_space']
        
        for item in disk_issues + disk_warnings:
            details = item.get('details', {})
            percent_used = details.get('percent_used', 0)
            free_gb = details.get('free_gb', 0)
            mountpoint = details.get('mountpoint', '')
            
            priority = 'high' if item in disk_issues else 'medium'
            
            recs = []
            
            if percent_used > 90:
                recs.append({
                    'action': 'Free up disk space immediately',
                    'description': f'Disk {mountpoint} is critically full. Free up at least {free_gb * 0.2:.1f} GB.',
                    'steps': [
                        'Run Disk Cleanup (cleanmgr.exe)',
                        'Uninstall unused programs',
                        'Delete temporary files',
                        'Empty Recycle Bin',
                        'Clear browser cache',
                        'Move large files to external storage'
                    ]
                })
            elif percent_used > 80:
                recs.append({
                    'action': 'Free up disk space soon',
                    'description': f'Disk {mountpoint} is getting full. Consider freeing up space.',
                    'steps': [
                        'Run Disk Cleanup utility',
                        'Review and delete unused files',
                        'Uninstall programs you no longer use',
                        'Move media files to external storage'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': priority,
                    'category': 'disk_space',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_memory(self, issues: List, warnings: List):
        """Generate recommendations for memory issues."""
        memory_issues = [i for i in issues if i.get('category') == 'memory']
        memory_warnings = [w for w in warnings if w.get('category') == 'memory']
        
        for item in memory_issues + memory_warnings:
            details = item.get('details', {})
            percent_used = details.get('percent_used', 0)
            total_gb = details.get('total_gb')  # None when the memory scan failed
            
            priority = 'high' if item in memory_issues else 'medium'
            
            recs = []
            
            if percent_used > 90:
                recs.append({
                    'action': 'Reduce memory usage immediately',
                    'description': 'System memory is critically low. Close unnecessary applications.',
                    'steps': [
                        'Close unused browser tabs and applications',
                        'End unnecessary background processes',
                        'Restart your computer to free up memory',
                        'Check for memory leaks in running applications',
                        'Consider upgrading RAM if this is a recurring issue'
                    ]
                })
            elif percent_used > 80:
                recs.append({
                    'action': 'Monitor and reduce memory usage',
                    'description': 'Memory usage is high. Consider closing some applications.',
                    'steps': [
                        'Close unused applications',
                        'Disable unnecessary startup programs',
                        'Check Task Manager for memory-intensive processes',
                        'Consider adding more RAM if frequently hitting high usage'
                    ]
                })
            
            if total_gb is not None and total_gb < 4:
                recs.append({
                    'action': 'Consider upgrading RAM',
                    'description': f'System has only {total_gb:.1f} GB of RAM, which may limit performance.',
                    'steps': [
                        'Check your motherboard specifications for maximum RAM support',
                        'Consider upgrading to at least 8 GB for better performance',
                        '16 GB is recommended for modern applications and multitasking'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': priority,
                    'category': 'memory',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_cpu(self, issues: List, warnings: List):
        """Generate recommendations for CPU issues."""
        cpu_issues = [i for i in issues if i.get('category') == 'cpu']
        cpu_warnings = [w for w in warnings if w.get('category') == 'cpu']
        
        for item in cpu_issues + cpu_warnings:
            details = item.get('details', {})
            usage_percent = details.get('usage_percent', 0)
            
            priority = 'high' if item in cpu_issues else 'medium'
            
            recs = []
            
            if usage_percent > 90:
                recs.append({
                    'action': 'Reduce CPU load immediately',
                    'description': 'CPU is overloaded. Close resource-intensive applications.',
                    'steps': [
                        'Open Task Manager and identify high CPU processes',
                        'End unnecessary processes',
                        'Close resource-intensive applications',
                        'Check for malware or unwanted software',
                        'Restart your computer if the issue persists'
                    ]
                })
            elif usage_percent > 80:
                recs.append({
                    'action': 'Monitor CPU usage',
                    'description': 'CPU usage is high. Check for resource-intensive applications.',
                    'steps': [
                        'Use Task Manager to identify CPU-intensive processes',
                        'Close unnecessary applications',
                        'Check for background updates or scans',
                        'Consider scheduling heavy tasks for off-peak hours'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': priority,
                    'category': 'cpu',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_temperature(self, issues: List, warnings: List):
        """Generate recommendations for temperature issues."""
        temp_issues = [i for i in issues if i.get('category') == 'temperature']
        temp_warnings = [w for w in warnings if w.get('category') == 'temperature']
        
        for item in temp_issues + temp_warnings:
            details = item.get('details', {})
            temp = details.get('temperature', 0)
            
            priority = 'high' if item in temp_issues else 'medium'
            
            recs = []
            
            if temp > 80:
                recs.append({
                    'action': 'Address overheating immediately',
                    'description': f'System temperature is critically high ({temp}°C).',
                    'steps': [
                        'Shut down the system and let it cool',
                        'Check that all fans are working',
                        'Clean dust from fans and heat sinks',
                        'Ensure proper ventilation around the computer',
                        'Check thermal paste on CPU if temperatures remain high',
                        'Consider professional cleaning if needed'
                    ]
                })
            elif temp > 70:
                recs.append({
                    'action': 'Monitor system temperature',
                    'description': f'Temperature is elevated ({temp}°C).',
                    'steps': [
                        'Ensure proper ventilation',
                        'Clean dust from air vents',
                        'Check that fans are spinning properly',
                        'Avoid blocking air vents',
                        'Consider using a cooling pad for laptops'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': priority,
                    'category': 'temperature',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_battery(self, issues: List, warnings: List):
        """Generate recommendations for battery issues."""
        battery_issues = [i for i in issues if i.get('category') == 'battery']
        battery_warnings = [w for w in warnings if w.get('category') == 'battery']
        
        for item in battery_issues + battery_warnings:
            details = item.get('details', {})
            percent = details.get('percent')
            if percent is None:
                # No reading (e.g. a scan error), so there is nothing to advise on
                continue

            priority = 'high' if item in battery_issues else 'medium'

            recs = []

            if percent < 20:
                recs.append({
                    'action': 'Plug in charger immediately',
                    'description': f'Battery is critically low ({percent:.1f}%).',
                    'steps': [
                        'Connect to power source immediately',
                        'Save all work',
                        'Consider replacing battery if capacity has degraded significantly',
                        'Check battery health in system settings'
                    ]
                })
            elif percent < 30:
                recs.append({
                    'action': 'Connect to power soon',
                    'description': f'Battery is low ({percent:.1f}%).',
                    'steps': [
                        'Connect to power source when possible',
                        'Reduce screen brightness',
                        'Close unnecessary applications to conserve power',
                        'Enable power saving mode'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': priority,
                    'category': 'battery',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_processes(self, issues: List, warnings: List):
        """Generate recommendations for process issues."""
        process_warnings = [w for w in warnings if w.get('category') == 'processes']
        
        for item in process_warnings:
            details = item.get('details', {})
            
            recs = []
            
            if 'high_cpu_processes' in details:
                processes = details['high_cpu_processes']
                process_names = [p.get('name', 'Unknown') for p in processes]
                recs.append({
                    'action': 'Review high CPU processes',
                    'description': f'These processes are using significant CPU: {", ".join(process_names)}',
                    'steps': [
                        'Open Task Manager to view process details',
                        'Determine if these processes are necessary',
                        'End processes that are not needed',
                        'Check for malware if unknown processes are consuming resources',
                        'Update or reinstall applications if they are misbehaving'
                    ]
                })
            
            if 'high_memory_processes' in details:
                processes = details['high_memory_processes']
                process_names = [p.get('name', 'Unknown') for p in processes]
                recs.append({
                    'action': 'Review high memory processes',
                    'description': f'These processes are using significant memory: {", ".join(process_names)}',
                    'steps': [
                        'Check if these processes are necessary',
                        'Close applications that are using excessive memory',
                        'Restart applications that may have memory leaks',
                        'Update applications to latest versions'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': 'medium',
                    'category': 'processes',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_filesystem_structure(self, issues: List, warnings: List):
        """Generate recommendations for file system structure issues."""
        fs_issues = [i for i in issues if i.get('category') == 'filesystem_structure']
        fs_warnings = [w for w in warnings if w.get('category') == 'filesystem_structure']
        
        for item in fs_issues + fs_warnings:
            details = item.get('details', {})
            path = details.get('path', 'Unknown path')
            description = details.get('description', '')
            
            priority = 'high' if item in fs_issues else 'medium'
            
            recs = []
            
            # Missing critical directories or files
            if 'Missing critical' in item.get('message', ''):
                recs.append({
                    'action': 'Address missing system files/directories',
                    'description': f'Critical system component missing: {path}. This may indicate system corruption.',
                    'steps': [
                        'Run System File Checker: Open Command Prompt as Administrator and run "sfc /scannow"',
                        'Run DISM tool: In Admin Command Prompt, run "DISM /Online /Cleanup-Image /RestoreHealth"',
                        'Check Windows Event Viewer for system errors',
                        'Consider running Windows Startup Repair',
                        'If issues persist, may need to repair or reinstall Windows',
                        'Back up important data before attempting repairs'
                    ]
                })
            
            # Permission issues
            elif 'permission denied' in item.get('message', '').lower() or 'Cannot access' in item.get('message', ''):
                recs.append({
                    'action': 'Resolve file system permission issues',
                    'description': f'Cannot access directory: {path}. This may require administrator privileges.',
                    'steps': [
                        'Run the diagnostic tool as Administrator',
                        'Check folder permissions: Right-click folder → Properties → Security',
                        'Verify your user account has appropriate permissions',
                        'Run "icacls" command to check and repair permissions (Windows)',
                        'Check if antivirus is blocking access',
                        'Review Windows Event Viewer for permission-related errors'
                    ]
                })
            
            # Unusual file structure
            elif 'Expected' in item.get('message', '') and ('file is a directory' in item.get('message', '') or 'directory is a file' in item.get('message', '')):
                recs.append({
                    'action': 'Fix file system structure anomaly',
                    'description': f'File system structure issue detected at {path}.',
                    'steps': [
                        'This may indicate file system corruption',
                        'Run chkdsk: Open Command Prompt as Admin, run "chkdsk C: /f /r"',
                        'Back up important data immediately',
                        'Run System File Checker: "sfc /scannow"',
                        'Check disk health using Windows built-in tools',
                        'Consider professional data recovery if critical data is at risk'
                    ]
                })
            
            # Large number of files in temp directories
            elif 'Large number of files' in item.get('message', ''):
                recs.append({
                    'action': 'Clean up temporary files',
                    'description': f'Large number of files detected in {path}. This may slow down the system.',
                    'steps': [
                        'Run Disk Cleanup utility (cleanmgr.exe)',
                        'Manually review and delete old temporary files',
                        'Use Windows Storage Sense to automatically clean temp files',
                        'Check for stuck processes that may be creating temp files',
                        'Consider scheduling regular temp file cleanup'
                    ]
                })
            
            # Missing expected system files
            elif 'Expected system file missing' in item.get('message', ''):
                recs.append({
                    'action': 'Restore missing system files',
                    'description': f'System file missing: {path}. This may affect system functionality.',
                    'steps': [
                        'Run System File Checker: "sfc /scannow" in Admin Command Prompt',
                        'Run DISM: "DISM /Online /Cleanup-Image /RestoreHealth"',
                        'Check if file was quarantined by antivirus',
                        'Restore from Windows backup if available',
                        'Consider Windows repair installation if critical files are missing'
                    ]
                })
            
            if recs:
                self.recommendations.append({
                    'priority': priority,
                    'category': 'filesystem_structure',
                    'issue': item.get('message'),
                    'recommendations': recs
                })
    
    def _process_general(self, scan_results: Dict[str, Any]):
        """Generate general maintenance recommendations."""
        issues_count = len(scan_results.get('issues', []))
        warnings_count = len(scan_results.get('warnings', []))
        
        general_recs = []
        
        if issues_count == 0 and warnings_count == 0:
            general_recs.append({
                'action': 'System is healthy',
                'description': 'No critical issues detected. Continue regular maintenance.',
                'steps': [
                    'Keep Windows and software updated',
                    'Run regular antivirus scans',
                    'Perform regular disk cleanup',
                    'Back up important data regularly',
                    'Monitor system performance periodically'
                ]
            })
        else:
            general_recs.append({
                'action': 'Regular maintenance',
                'description': 'Perform regular system maintenance to prevent issues.',
                'steps': [
                    'Keep Windows and all software updated',
                    'Run Windows Defender or your antivirus regularly',
                    'Perform disk cleanup weekly',
                    'Defragment hard drives (if using HDD)',
                    'Back up important data regularly',
                    'Review and uninstall unused programs',
                    'Clear browser cache and temporary files regularly'
                ]
            })
        
        self.recommendations.append({
            'priority': 'low',
            'category': 'general',
            'issue': 'General system maintenance',
            'recommendations': general_recs
        })

