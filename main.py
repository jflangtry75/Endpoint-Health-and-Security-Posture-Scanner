"""
Endpoint Health & Security Posture Scanner
Main application entry point.
"""

import sys
import json
from datetime import datetime
from scanner import SystemScanner
from recommender import RecommendationEngine
from html_report import save_html_report


def print_header():
    """Print application header."""
    print("=" * 70)
    print(" " * 14 + "ENDPOINT HEALTH & SECURITY POSTURE SCANNER")
    print("=" * 70)
    print()


def print_section(title: str):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_system_info(system_info: dict):
    """Print system information."""
    print_section("SYSTEM INFORMATION")
    print(f"  Platform:        {system_info.get('platform', 'Unknown')}")
    print(f"  OS Version:      {system_info.get('platform_version', 'Unknown')}")
    print(f"  Architecture:    {system_info.get('architecture', 'Unknown')}")
    print(f"  Processor:       {system_info.get('processor', 'Unknown')}")
    print(f"  Hostname:        {system_info.get('hostname', 'Unknown')}")
    if 'os_name' in system_info:
        print(f"  OS Name:         {system_info.get('os_name', 'Unknown')}")


def print_issues(issues: list, warnings: list, info: list):
    """Print detected issues, warnings, and info."""
    print_section("SCAN RESULTS")
    
    if issues:
        print("\n  🔴 CRITICAL ISSUES:")
        for i, issue in enumerate(issues, 1):
            print(f"    {i}. {issue.get('message', 'Unknown issue')}")
    
    if warnings:
        print("\n  ⚠️  WARNINGS:")
        for i, warning in enumerate(warnings, 1):
            print(f"    {i}. {warning.get('message', 'Unknown warning')}")
    
    if info:
        print("\n  ℹ️  INFORMATION:")
        for i, info_item in enumerate(info[:10], 1):  # Limit to first 10 info items
            print(f"    {i}. {info_item.get('message', 'Unknown info')}")
        if len(info) > 10:
            print(f"    ... and {len(info) - 10} more information items")
    
    if not issues and not warnings:
        print("\n  ✅ No critical issues or warnings detected!")


def print_recommendations(recommendations: list):
    """Print recommendations."""
    print_section("RECOMMENDATIONS")
    
    # Sort by priority
    priority_order = {'high': 0, 'medium': 1, 'low': 2}
    sorted_recs = sorted(recommendations, key=lambda x: priority_order.get(x.get('priority', 'low'), 2))
    
    for rec in sorted_recs:
        priority = rec.get('priority', 'low').upper()
        category = rec.get('category', 'unknown').upper()
        issue = rec.get('issue', 'Unknown issue')
        
        print(f"\n  [{priority}] {category}: {issue}")
        print("  " + "-" * 66)
        
        for rec_item in rec.get('recommendations', []):
            action = rec_item.get('action', 'Unknown action')
            description = rec_item.get('description', '')
            steps = rec_item.get('steps', [])
            
            print(f"\n  📌 {action}")
            if description:
                print(f"     {description}")
            if steps:
                print("     Steps:")
                for step in steps:
                    print(f"       • {step}")


def print_summary(scan_results: dict, recommendations: list):
    """Print summary statistics."""
    print_section("SUMMARY")
    
    issues_count = len(scan_results.get('issues', []))
    warnings_count = len(scan_results.get('warnings', []))
    recommendations_count = len(recommendations)
    
    print(f"  Critical Issues:     {issues_count}")
    print(f"  Warnings:            {warnings_count}")
    print(f"  Recommendations:     {recommendations_count}")
    print(f"  Scan Time:           {scan_results.get('scan_timestamp', 'Unknown')}")
    
    if issues_count == 0 and warnings_count == 0:
        print("\n  ✅ Your system appears to be in good health!")
    elif issues_count == 0:
        print("\n  ⚠️  Some warnings detected, but no critical issues.")
    else:
        print("\n  🔴 Critical issues detected. Please review recommendations above.")


def save_report(scan_results: dict, recommendations: list, filename: str = None, report_format: str = 'json'):
    """Save scan results and recommendations to a JSON or HTML file."""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"diagnostic_report_{timestamp}.{report_format}"

    report = {
        'scan_results': scan_results,
        'recommendations': recommendations,
        'generated_at': datetime.now().isoformat()
    }

    try:
        if report_format == 'html':
            save_html_report(report, filename)
        else:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
        print(f"\n  💾 Report saved to: {filename}")
        return filename
    except Exception as e:
        print(f"\n  ⚠️  Could not save report: {str(e)}")
        return None


def main():
    """Main application function."""
    print_header()
    
    # Initialize components
    scanner = SystemScanner()
    recommender = RecommendationEngine()
    
    # Run scan
    print("Starting comprehensive system scan...\n")
    scan_results = scanner.scan_all()
    
    # Generate recommendations
    print("\n🔍 Analyzing results and generating recommendations...")
    recommendations = recommender.generate_recommendations(scan_results)
    
    # Display results
    print("\n" + "=" * 70)
    print_system_info(scan_results.get('system_info', {}))
    print_issues(
        scan_results.get('issues', []),
        scan_results.get('warnings', []),
        scan_results.get('info', [])
    )
    print_recommendations(recommendations)
    print_summary(scan_results, recommendations)
    
    # Ask to save report
    print("\n" + "=" * 70)
    save_choice = input("\n  Save detailed report to file? (y = JSON, h = HTML, n = no): ").strip().lower()
    if save_choice in ('y', 'h'):
        report_format = 'html' if save_choice == 'h' else 'json'
        filename = save_report(scan_results, recommendations, report_format=report_format)
        if filename:
            print(f"\n  ✅ Report saved successfully!")
    
    print("\n" + "=" * 70)
    print("  Scan complete. Thank you for using the Endpoint Health & Security Posture Scanner!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  ⚠️  Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n  ❌ An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


