"""
CIS Mapping Module
Maps security finding categories to CIS Controls v8 safeguards and, on Windows,
to the matching CIS Microsoft Windows Benchmark recommendation titles.

Benchmark recommendation numbers change between benchmark releases, so only the
recommendation titles are listed. Look them up in the benchmark version you use.
"""

from typing import Dict, List, Any

CIS_CONTROLS_VERSION = 'CIS Controls v8'

# Finding category -> CIS Controls v8 safeguards
CIS_CONTROLS = {
    'firewall': [
        {'id': '4.5', 'title': 'Implement and Manage a Firewall on End-User Devices'},
    ],
    'antivirus': [
        {'id': '10.1', 'title': 'Deploy and Maintain Anti-Malware Software'},
    ],
    'windows_defender': [
        {'id': '10.1', 'title': 'Deploy and Maintain Anti-Malware Software'},
    ],
    'user_accounts': [
        {'id': '4.7', 'title': 'Manage Default Accounts on Enterprise Assets and Software'},
    ],
    'network_security': [
        {'id': '3.3', 'title': 'Configure Data Access Control Lists'},
    ],
    'startup_programs': [
        {'id': '2.3', 'title': 'Address Unauthorized Software'},
    ],
    'suspicious_processes': [
        {'id': '2.3', 'title': 'Address Unauthorized Software'},
        {'id': '10.1', 'title': 'Deploy and Maintain Anti-Malware Software'},
    ],
    'file_permissions': [
        {'id': '3.3', 'title': 'Configure Data Access Control Lists'},
    ],
    'remote_access': [
        {'id': '4.8', 'title': 'Uninstall or Disable Unnecessary Services on Enterprise Assets and Software'},
    ],
    'encryption': [
        {'id': '3.6', 'title': 'Encrypt Data on End-User Devices'},
    ],
}

# Finding category -> CIS Microsoft Windows Benchmark recommendation titles
WINDOWS_BENCHMARK = {
    'firewall': [
        "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'",
        "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'",
        "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'",
    ],
    'antivirus': [
        "Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'",
    ],
    'windows_defender': [
        "Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'",
        "Ensure 'Turn off real-time protection' is set to 'Disabled'",
    ],
    'user_accounts': [
        "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
        "Ensure 'Accounts: Administrator account status' is set to 'Disabled'",
    ],
    'remote_access': [
        "Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'",
    ],
}


def get_cis_mapping(category: str, platform_name: str) -> Dict[str, Any]:
    """Return the CIS references for a finding category."""
    mapping = {
        'controls_version': CIS_CONTROLS_VERSION,
        'controls': CIS_CONTROLS.get(category, []),
    }
    if platform_name == 'Windows':
        mapping['windows_benchmark'] = WINDOWS_BENCHMARK.get(category, [])
    return mapping


def annotate_findings(findings: List[Dict[str, Any]], platform_name: str):
    """Add a 'cis' entry to each finding that has a mapped category."""
    for finding in findings:
        category = finding.get('category')
        if category in CIS_CONTROLS:
            finding['cis'] = get_cis_mapping(category, platform_name)
