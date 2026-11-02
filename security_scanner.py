"""
Security Scanner Module
Scans the system for security-related issues and vulnerabilities.
"""

import os
import platform
import subprocess
import json
from typing import Dict, List, Any
import psutil
from cis_mapping import annotate_findings


class SecurityScanner:
    """Scans the system for security issues."""
    
    def __init__(self):
        self.security_issues = []
        self.security_warnings = []
        self.security_info = []
    
    def scan_all(self) -> Dict[str, Any]:
        """Run all security scans."""
        print("🔒 Starting security scan...")
        
        self.scan_firewall()
        self.scan_antivirus()
        self.scan_user_accounts()
        self.scan_network_security()
        self.scan_startup_programs()
        self.scan_suspicious_processes()
        self.scan_file_permissions()
        self.scan_windows_defender()
        self.scan_remote_access()
        self.scan_encryption()

        # Attach CIS Controls / Benchmark references to every finding
        for findings in (self.security_issues, self.security_warnings, self.security_info):
            annotate_findings(findings, platform.system())

        return {
            'security_issues': self.security_issues,
            'security_warnings': self.security_warnings,
            'security_info': self.security_info
        }
    
    def scan_firewall(self):
        """Check firewall status."""
        print("  🛡️  Checking firewall status...")
        system_platform = platform.system()
        
        if system_platform == 'Windows':
            try:
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    output = result.stdout.lower()
                    if 'off' in output or 'disabled' in output:
                        self.security_issues.append({
                            'type': 'critical',
                            'category': 'firewall',
                            'message': 'Windows Firewall is disabled',
                            'details': {'status': 'disabled'}
                        })
                    else:
                        self.security_info.append({
                            'type': 'info',
                            'category': 'firewall',
                            'message': 'Windows Firewall appears to be enabled',
                            'details': {'status': 'enabled'}
                        })
            except Exception as e:
                self.security_warnings.append({
                    'type': 'warning',
                    'category': 'firewall',
                    'message': f'Could not check firewall status: {str(e)}',
                    'details': {'error': str(e)}
                })
        else:
            # Linux/macOS firewall check
            try:
                # Check for UFW (Ubuntu/Debian)
                result = subprocess.run(
                    ['ufw', 'status'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    if 'inactive' in result.stdout.lower():
                        self.security_warnings.append({
                            'type': 'warning',
                            'category': 'firewall',
                            'message': 'UFW firewall is inactive',
                            'details': {'status': 'inactive'}
                        })
            except Exception:
                pass
    
    def scan_antivirus(self):
        """Check antivirus status."""
        print("  🦠 Checking antivirus status...")
        if platform.system() == 'Windows':
            try:
                # Check Windows Security Center
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        status = json.loads(result.stdout)
                        if not status.get('AntivirusEnabled', False):
                            self.security_issues.append({
                                'type': 'critical',
                                'category': 'antivirus',
                                'message': 'Windows Defender antivirus is disabled',
                                'details': status
                            })
                        elif not status.get('RealTimeProtectionEnabled', False):
                            self.security_warnings.append({
                                'type': 'warning',
                                'category': 'antivirus',
                                'message': 'Windows Defender real-time protection is disabled',
                                'details': status
                            })
                        else:
                            self.security_info.append({
                                'type': 'info',
                                'category': 'antivirus',
                                'message': 'Windows Defender is enabled and active',
                                'details': status
                            })
                    except json.JSONDecodeError:
                        pass
            except Exception:
                # Try alternative method
                try:
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-Command',
                         'ConvertTo-Json -InputObject @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState)'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    products = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
                    if products:
                        self.security_info.append({
                            'type': 'info',
                            'category': 'antivirus',
                            'message': 'Antivirus software detected',
                            'details': {'products': products}
                        })
                except Exception:
                    self.security_warnings.append({
                        'type': 'warning',
                        'category': 'antivirus',
                        'message': 'Could not verify antivirus status. Ensure antivirus is installed and active.',
                        'details': {}
                    })
    
    def scan_user_accounts(self):
        """Check whether the built-in Guest and Administrator accounts are enabled."""
        print("  👤 Checking user accounts...")
        if platform.system() == 'Windows':
            try:
                # Both accounts exist on every Windows install, so only an enabled one is a finding.
                # They are matched by their well-known RIDs (500, 501) because they are often
                # renamed and other local accounts are left out of the report.
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     "ConvertTo-Json -InputObject @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' "
                     "| Where-Object { $_.SID -match '-50[01]$' } | Select-Object Name, SID, Disabled)"],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    builtin_roles = {'500': 'Administrator', '501': 'Guest'}
                    accounts = []
                    for account in json.loads(result.stdout):
                        role = builtin_roles[account['SID'].rsplit('-', 1)[1]]
                        name = account['Name'] if account['Name'] == role else f"{role} (renamed to {account['Name']})"
                        accounts.append({'account': name, 'enabled': not account['Disabled']})

                    enabled = [a['account'] for a in accounts if a['enabled']]
                    if enabled:
                        self.security_warnings.append({
                            'type': 'warning',
                            'category': 'user_accounts',
                            'message': f'Built-in accounts enabled: {", ".join(enabled)}',
                            'details': {'accounts': accounts}
                        })
                    elif accounts:
                        self.security_info.append({
                            'type': 'info',
                            'category': 'user_accounts',
                            'message': 'Built-in Guest and Administrator accounts are disabled',
                            'details': {'accounts': accounts}
                        })
            except Exception:
                pass
    
    def scan_network_security(self):
        """Check network security settings."""
        print("  🌐 Checking network security...")
        try:
            # Check for open network shares
            if platform.system() == 'Windows':
                try:
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-Command',
                         'ConvertTo-Json -InputObject @(Get-CimInstance -ClassName Win32_Share | Select-Object Name, Path, Type)'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        # Windows creates administrative shares (C$, ADMIN$, IPC$) on every machine
                        # and flags them in the high bit of Type, so only the rest were shared by someone
                        admin_share_flag = 0x80000000
                        shares = [{'name': s['Name'], 'path': s.get('Path') or ''}
                                  for s in json.loads(result.stdout) if not s['Type'] & admin_share_flag]
                        if shares:
                            self.security_warnings.append({
                                'type': 'warning',
                                'category': 'network_security',
                                'message': f'Network shares detected: {len(shares)} share(s) found '
                                           f'({", ".join(s["name"] for s in shares)})',
                                'details': {'share_count': len(shares), 'shares': shares}
                            })
                        else:
                            self.security_info.append({
                                'type': 'info',
                                'category': 'network_security',
                                'message': 'No user-created network shares (only built-in administrative shares)',
                                'details': {'share_count': 0}
                            })
                except Exception:
                    pass
        except Exception:
            pass
    
    def scan_startup_programs(self):
        """Check startup programs for suspicious entries."""
        print("  🚀 Checking startup programs...")
        try:
            if platform.system() == 'Windows':
                # Check registry startup locations
                startup_locations = [
                    (r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', 'Current User'),
                    (r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run', 'Local Machine')
                ]
                
                suspicious_count = 0
                for location, desc in startup_locations:
                    try:
                        result = subprocess.run(
                            ['reg', 'query', location],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            entries = [line for line in result.stdout.split('\n') if line.strip() and 'REG_' in line]
                            suspicious_count += len(entries)
                    except Exception:
                        pass
                
                if suspicious_count > 10:
                    self.security_warnings.append({
                        'type': 'warning',
                        'category': 'startup_programs',
                        'message': f'Large number of startup programs detected: {suspicious_count}',
                        'details': {'startup_count': suspicious_count}
                    })
        except Exception:
            pass
    
    def scan_suspicious_processes(self):
        """Check for suspicious or known malicious processes."""
        print("  🔍 Checking for suspicious processes...")
        try:
            suspicious_names = [
                'bitcoin', 'miner', 'crypto', 'torrent', 'keylogger',
                'trojan', 'virus', 'malware', 'spyware'
            ]
            
            found_suspicious = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(sus in proc_name for sus in suspicious_names):
                        found_suspicious.append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if found_suspicious:
                self.security_warnings.append({
                    'type': 'warning',
                    'category': 'suspicious_processes',
                    'message': f'Processes with suspicious names detected: {", ".join(found_suspicious[:5])}',
                    'details': {'processes': found_suspicious[:10]}
                })
        except Exception as e:
            self.security_warnings.append({
                'type': 'warning',
                'category': 'suspicious_processes',
                'message': f'Could not scan processes: {str(e)}',
                'details': {}
            })
    
    def scan_file_permissions(self):
        """Check sensitive directories for write access granted to broad groups.

        Reads each directory's access control list with PowerShell Get-Acl, so the
        check is read-only and gives the same answer whether or not the tool runs
        elevated. Administrators are expected to have write access and are not flagged.
        """
        print("  📝 Checking file permissions...")
        if platform.system() != 'Windows':
            return

        sensitive_dirs = [
            'C:\\Windows\\System32',
            'C:\\Program Files',
        ]
        # Well-known SIDs, so the check works on any Windows display language
        broad_sids = {
            'S-1-1-0': 'Everyone',
            'S-1-5-32-545': 'Users',
            'S-1-5-11': 'Authenticated Users',
        }
        write_rights = {'FullControl', 'Modify', 'Write', 'WriteData', 'CreateFiles'}
        generic_write_bits = 0x10000000 | 0x40000000  # GENERIC_ALL | GENERIC_WRITE

        for dir_path in sensitive_dirs:
            if not os.path.exists(dir_path):
                continue
            ps_command = (
                f"(Get-Acl -LiteralPath '{dir_path}').Access | "
                "Where-Object { $_.AccessControlType -eq 'Allow' } | "
                "ForEach-Object { "
                "$sid = try { $_.IdentityReference.Translate("
                "[System.Security.Principal.SecurityIdentifier]).Value } catch { '' }; "
                "[PSCustomObject]@{ Sid = $sid; "
                "Identity = $_.IdentityReference.Value; "
                "Rights = $_.FileSystemRights.ToString() } } | ConvertTo-Json"
            )
            try:
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command', ps_command],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode != 0 or not result.stdout.strip():
                    continue
                entries = json.loads(result.stdout)
                if isinstance(entries, dict):
                    entries = [entries]

                exposed = []
                for entry in entries:
                    sid = entry.get('Sid') or ''
                    if sid not in broad_sids:
                        continue
                    rights = str(entry.get('Rights') or '')
                    if rights.lstrip('-').isdigit():
                        # Generic rights on inherit-only entries come back as a number
                        has_write = bool(int(rights) & generic_write_bits)
                    else:
                        has_write = bool(write_rights & {r.strip() for r in rights.split(',')})
                    if has_write:
                        exposed.append(f"{broad_sids[sid]}: {rights}")

                if exposed:
                    self.security_warnings.append({
                        'type': 'warning',
                        'category': 'file_permissions',
                        'message': f'Directory appears to have overly permissive access: {dir_path}',
                        'details': {'path': dir_path, 'write_access': exposed}
                    })
            except Exception:
                pass

    def scan_windows_defender(self):
        """Check Windows Defender status and definitions."""
        print("  🛡️  Checking Windows Defender...")
        if platform.system() == 'Windows':
            try:
                result = subprocess.run(
                    ['powershell', '-Command',
                     'Get-MpComputerStatus | Select-Object AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, LastQuickScan, LastFullScan | ConvertTo-Json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        status = json.loads(result.stdout)
                        issues = []
                        if not status.get('AntivirusEnabled', False):
                            issues.append('Antivirus disabled')
                        if not status.get('AntispywareEnabled', False):
                            issues.append('Antispyware disabled')
                        if not status.get('RealTimeProtectionEnabled', False):
                            issues.append('Real-time protection disabled')
                        
                        if issues:
                            self.security_issues.append({
                                'type': 'critical',
                                'category': 'windows_defender',
                                'message': f'Windows Defender issues: {", ".join(issues)}',
                                'details': status
                            })
                        else:
                            self.security_info.append({
                                'type': 'info',
                                'category': 'windows_defender',
                                'message': 'Windows Defender is properly configured',
                                'details': status
                            })
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass
    
    def scan_remote_access(self):
        """Check for remote access services."""
        print("  🔌 Checking remote access...")
        if platform.system() == 'Windows':
            try:
                # Check Remote Desktop
                result = subprocess.run(
                    ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server', '/v', 'fDenyTSConnections'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    if '0x0' in result.stdout or 'REG_DWORD' in result.stdout:
                        # Check if it's actually enabled
                        if '0x1' not in result.stdout:
                            self.security_warnings.append({
                                'type': 'warning',
                                'category': 'remote_access',
                                'message': 'Remote Desktop may be enabled',
                                'details': {'service': 'Remote Desktop'}
                            })
            except Exception:
                pass
    
    def scan_encryption(self):
        """Check encryption status."""
        print("  🔐 Checking encryption...")
        if platform.system() == 'Windows':
            try:
                # Check BitLocker status
                result = subprocess.run(
                    ['manage-bde', '-status'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    if 'Protection Off' in result.stdout or 'Protection Status: Off' in result.stdout:
                        self.security_warnings.append({
                            'type': 'warning',
                            'category': 'encryption',
                            'message': 'BitLocker encryption is not enabled',
                            'details': {'encryption': 'disabled'}
                        })
                    elif 'Protection On' in result.stdout:
                        self.security_info.append({
                            'type': 'info',
                            'category': 'encryption',
                            'message': 'BitLocker encryption is enabled',
                            'details': {'encryption': 'enabled'}
                        })
            except Exception:
                # BitLocker may not be available
                self.security_info.append({
                    'type': 'info',
                    'category': 'encryption',
                    'message': 'Could not check encryption status (BitLocker may not be available)',
                    'details': {}
                })


