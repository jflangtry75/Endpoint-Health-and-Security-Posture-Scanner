"""
Graphical User Interface for the Endpoint Health & Security Posture Scanner
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import threading
from scanner import SystemScanner
from recommender import RecommendationEngine
from security_scanner import SecurityScanner
from html_report import save_html_report
from scan_compare import compare_reports, format_comparison, load_report
import json


class DiagnosticGUI:
    """Main GUI application for the diagnostic tool."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Endpoint Health & Security Posture Scanner")
        self.root.geometry("1000x700")
        self.root.minsize(960, 600)
        
        # Variables
        self.scan_results = None
        self.recommendations = None
        self.security_results = None
        self.is_scanning = False
        self.is_security_scanning = False
        
        # Create UI
        self.create_widgets()
        
        # Center window
        self.center_window()
    
    def center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create and layout all UI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        title_label = ttk.Label(
            header_frame,
            text="🔧 Endpoint Health & Security Posture Scanner",
            font=("Arial", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Control buttons
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT)
        
        self.scan_button = ttk.Button(
            button_frame,
            text="🔍 Start Scan",
            command=self.start_scan,
            width=15
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.security_scan_button = ttk.Button(
            button_frame,
            text="🔒 Security Scan",
            command=self.start_security_scan,
            width=15
        )
        self.security_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(
            button_frame,
            text="💾 Save Report",
            command=self.save_report,
            width=15,
            state=tk.DISABLED
        )
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.compare_button = ttk.Button(
            button_frame,
            text="📊 Compare Reports",
            command=self.compare_reports,
            width=18
        )
        self.compare_button.pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(
            main_frame,
            mode='indeterminate',
            length=300
        )
        self.progress.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(
            main_frame,
            text="Ready to scan. Click 'Start Scan' to begin.",
            font=("Arial", 10)
        )
        self.status_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # System Info Tab
        self.system_info_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 9)
        )
        self.notebook.add(self.system_info_text, text="System Information")
        
        # Issues Tab
        self.issues_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 9)
        )
        self.notebook.add(self.issues_text, text="Issues & Warnings")
        
        # Recommendations Tab
        self.recommendations_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 9)
        )
        self.notebook.add(self.recommendations_text, text="Recommendations")
        
        # Summary Tab
        self.summary_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 9)
        )
        self.notebook.add(self.summary_text, text="Summary")
        
        # Security Tab
        self.security_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 9)
        )
        self.notebook.add(self.security_text, text="Security")

        # Changes Tab (report comparison)
        self.changes_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 9)
        )
        self.notebook.add(self.changes_text, text="Changes")

        # Configure text tags for formatting
        self.configure_text_tags()
    
    def configure_text_tags(self):
        """Configure text formatting tags."""
        for text_widget in [self.issues_text, self.recommendations_text, self.summary_text, self.security_text,
                            self.changes_text]:
            text_widget.tag_configure("header", font=("Arial", 12, "bold"), foreground="navy")
            text_widget.tag_configure("critical", foreground="red", font=("Arial", 10, "bold"))
            text_widget.tag_configure("warning", foreground="orange", font=("Arial", 10, "bold"))
            text_widget.tag_configure("info", foreground="blue")
            text_widget.tag_configure("success", foreground="green", font=("Arial", 10, "bold"))
            text_widget.tag_configure("normal", font=("Arial", 9))
            text_widget.tag_configure("step", foreground="darkgreen")
    
    def start_scan(self):
        """Start the diagnostic scan in a separate thread."""
        if self.is_scanning:
            return
        
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.security_scan_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.progress.start()
        self.status_label.config(text="Scanning system... Please wait.")
        
        # Clear previous results
        self.system_info_text.delete(1.0, tk.END)
        self.issues_text.delete(1.0, tk.END)
        self.recommendations_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        
        # Run scan in separate thread to prevent UI freezing
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()
    
    def run_scan(self):
        """Run the actual scan (called from thread)."""
        try:
            scanner = SystemScanner()
            recommender = RecommendationEngine()
            
            # Run scan
            self.scan_results = scanner.scan_all()
            
            # Generate recommendations
            self.recommendations = recommender.generate_recommendations(self.scan_results)
            
            # Update UI in main thread
            self.root.after(0, self.display_results)
            
        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))
    
    def scan_error(self, error_msg):
        """Handle scan errors."""
        self.is_scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.security_scan_button.config(state=tk.NORMAL)
        self.status_label.config(text=f"Error: {error_msg}")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
    
    def start_security_scan(self):
        """Start the security scan in a separate thread."""
        if self.is_security_scanning:
            return
        
        self.is_security_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.security_scan_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.progress.start()
        self.status_label.config(text="Running security scan... Please wait.")
        
        # Clear previous security results
        self.security_text.delete(1.0, tk.END)
        
        # Run scan in separate thread
        thread = threading.Thread(target=self.run_security_scan, daemon=True)
        thread.start()
    
    def run_security_scan(self):
        """Run the security scan (called from thread)."""
        try:
            security_scanner = SecurityScanner()
            self.security_results = security_scanner.scan_all()
            
            # Update UI in main thread
            self.root.after(0, self.display_security_results)
            
        except Exception as e:
            self.root.after(0, lambda: self.security_scan_error(str(e)))
    
    def security_scan_error(self, error_msg):
        """Handle security scan errors."""
        self.is_security_scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.security_scan_button.config(state=tk.NORMAL)
        self.status_label.config(text=f"Security scan error: {error_msg}")
        messagebox.showerror("Security Scan Error", f"An error occurred during security scanning:\n{error_msg}")
    
    def insert_cis_references(self, text, finding, tag):
        """Insert a finding's CIS Controls and Benchmark references, then a blank line."""
        cis = finding.get('cis', {})
        for control in cis.get('controls', []):
            text.insert(tk.END, f"   CIS Control {control['id']}: {control['title']}\n", tag)
        for recommendation in cis.get('windows_benchmark', []):
            text.insert(tk.END, f"   CIS Benchmark: {recommendation}\n", tag)
        text.insert(tk.END, "\n", tag)

    def display_security_results(self):
        """Display security scan results in the UI."""
        self.is_security_scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.security_scan_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.status_label.config(text="Security scan complete! Review the results in the Security tab.")
        
        # Display security results
        text = self.security_text
        text.delete(1.0, tk.END)
        
        issues = self.security_results.get('security_issues', [])
        warnings = self.security_results.get('security_warnings', [])
        info = self.security_results.get('security_info', [])
        
        text.insert(tk.END, "SECURITY SCAN RESULTS\n", "header")
        text.insert(tk.END, "=" * 70 + "\n\n", "normal")
        
        if issues:
            text.insert(tk.END, "🔴 CRITICAL SECURITY ISSUES\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            for i, issue in enumerate(issues, 1):
                text.insert(tk.END, f"{i}. ", "normal")
                text.insert(tk.END, f"{issue.get('message', 'Unknown issue')}\n", "critical")
                category = issue.get('category', 'unknown')
                text.insert(tk.END, f"   Category: {category}\n", "info")
                self.insert_cis_references(text, issue, "info")
        
        if warnings:
            text.insert(tk.END, "\n⚠️  SECURITY WARNINGS\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            for i, warning in enumerate(warnings, 1):
                text.insert(tk.END, f"{i}. ", "normal")
                text.insert(tk.END, f"{warning.get('message', 'Unknown warning')}\n", "warning")
                category = warning.get('category', 'unknown')
                text.insert(tk.END, f"   Category: {category}\n", "info")
                self.insert_cis_references(text, warning, "info")
        
        if info:
            text.insert(tk.END, "\nℹ️  SECURITY INFORMATION\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            for i, info_item in enumerate(info, 1):
                text.insert(tk.END, f"{i}. ", "normal")
                text.insert(tk.END, f"{info_item.get('message', 'Unknown info')}\n", "info")
                category = info_item.get('category', 'unknown')
                text.insert(tk.END, f"   Category: {category}\n", "normal")
                self.insert_cis_references(text, info_item, "normal")
        
        if not issues and not warnings:
            text.insert(tk.END, "\n✅ NO SECURITY ISSUES DETECTED\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            text.insert(tk.END, "Your system appears to have good security configuration!\n", "success")
        
        # Summary
        text.insert(tk.END, "\n" + "=" * 70 + "\n", "normal")
        text.insert(tk.END, "SUMMARY\n", "header")
        text.insert(tk.END, "=" * 70 + "\n\n", "normal")
        text.insert(tk.END, f"Critical Issues: {len(issues)}\n", "normal")
        text.insert(tk.END, f"Warnings: {len(warnings)}\n", "normal")
        text.insert(tk.END, f"Information Items: {len(info)}\n", "normal")
        
        # Switch to security tab
        self.notebook.select(4)  # Security tab (5th tab, 0-indexed)
    
    def display_results(self):
        """Display scan results in the UI."""
        self.is_scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.security_scan_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.status_label.config(text="Scan complete! Review the results in the tabs below.")
        
        # Display system information
        self.display_system_info()
        
        # Display issues and warnings
        self.display_issues()
        
        # Display recommendations
        self.display_recommendations()
        
        # Display summary
        self.display_summary()
        
        # Switch to issues tab if there are critical issues
        if self.scan_results.get('issues'):
            self.notebook.select(1)  # Issues tab
    
    def display_system_info(self):
        """Display system information."""
        text = self.system_info_text
        text.delete(1.0, tk.END)
        
        system_info = self.scan_results.get('system_info', {})
        
        text.insert(tk.END, "SYSTEM INFORMATION\n", "header")
        text.insert(tk.END, "=" * 70 + "\n\n")
        
        info_items = [
            ("Platform", system_info.get('platform', 'Unknown')),
            ("OS Version", system_info.get('platform_version', 'Unknown')),
            ("OS Release", system_info.get('platform_release', 'Unknown')),
            ("Architecture", system_info.get('architecture', 'Unknown')),
            ("Processor", system_info.get('processor', 'Unknown')),
            ("Hostname", system_info.get('hostname', 'Unknown')),
        ]
        
        if 'os_name' in system_info:
            info_items.append(("OS Name", system_info.get('os_name')))
        
        for label, value in info_items:
            text.insert(tk.END, f"{label:.<30} {value}\n")
        
        text.insert(tk.END, f"\nScan Time: {self.scan_results.get('scan_timestamp', 'Unknown')}\n")
    
    def display_issues(self):
        """Display issues and warnings."""
        text = self.issues_text
        text.delete(1.0, tk.END)
        
        issues = self.scan_results.get('issues', [])
        warnings = self.scan_results.get('warnings', [])
        info = self.scan_results.get('info', [])
        
        if issues:
            text.insert(tk.END, "🔴 CRITICAL ISSUES\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            for i, issue in enumerate(issues, 1):
                text.insert(tk.END, f"{i}. ", "normal")
                text.insert(tk.END, f"{issue.get('message', 'Unknown issue')}\n", "critical")
            text.insert(tk.END, "\n")
        
        if warnings:
            text.insert(tk.END, "⚠️  WARNINGS\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            for i, warning in enumerate(warnings, 1):
                text.insert(tk.END, f"{i}. ", "normal")
                text.insert(tk.END, f"{warning.get('message', 'Unknown warning')}\n", "warning")
            text.insert(tk.END, "\n")
        
        if info:
            text.insert(tk.END, "ℹ️  INFORMATION\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            for i, info_item in enumerate(info[:20], 1):  # Limit to 20 items
                text.insert(tk.END, f"{i}. ", "normal")
                text.insert(tk.END, f"{info_item.get('message', 'Unknown info')}\n", "info")
            if len(info) > 20:
                text.insert(tk.END, f"\n... and {len(info) - 20} more information items\n", "info")
        
        if not issues and not warnings:
            text.insert(tk.END, "✅ NO ISSUES DETECTED\n", "header")
            text.insert(tk.END, "=" * 70 + "\n\n", "normal")
            text.insert(tk.END, "Your system appears to be in good health!\n", "success")
    
    def display_recommendations(self):
        """Display recommendations."""
        text = self.recommendations_text
        text.delete(1.0, tk.END)
        
        if not self.recommendations:
            text.insert(tk.END, "No recommendations available.\n")
            return
        
        # Sort by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_recs = sorted(
            self.recommendations,
            key=lambda x: priority_order.get(x.get('priority', 'low'), 2)
        )
        
        for rec in sorted_recs:
            priority = rec.get('priority', 'low').upper()
            category = rec.get('category', 'unknown').upper()
            issue = rec.get('issue', 'Unknown issue')
            
            text.insert(tk.END, f"[{priority}] {category}\n", "header")
            text.insert(tk.END, f"Issue: {issue}\n", "normal")
            text.insert(tk.END, "-" * 70 + "\n\n", "normal")
            
            for rec_item in rec.get('recommendations', []):
                action = rec_item.get('action', 'Unknown action')
                description = rec_item.get('description', '')
                steps = rec_item.get('steps', [])
                
                text.insert(tk.END, f"📌 {action}\n", "warning")
                if description:
                    text.insert(tk.END, f"   {description}\n\n", "normal")
                if steps:
                    text.insert(tk.END, "   Steps:\n", "normal")
                    for step in steps:
                        text.insert(tk.END, f"   • {step}\n", "step")
                text.insert(tk.END, "\n")
            
            text.insert(tk.END, "\n")
    
    def display_summary(self):
        """Display summary statistics."""
        text = self.summary_text
        text.delete(1.0, tk.END)
        
        text.insert(tk.END, "SCAN SUMMARY\n", "header")
        text.insert(tk.END, "=" * 70 + "\n\n", "normal")
        
        issues_count = len(self.scan_results.get('issues', []))
        warnings_count = len(self.scan_results.get('warnings', []))
        recommendations_count = len(self.recommendations)
        
        text.insert(tk.END, f"Critical Issues:     {issues_count}\n", "normal")
        text.insert(tk.END, f"Warnings:            {warnings_count}\n", "normal")
        text.insert(tk.END, f"Recommendations:     {recommendations_count}\n", "normal")
        text.insert(tk.END, f"Scan Time:           {self.scan_results.get('scan_timestamp', 'Unknown')}\n", "normal")
        
        text.insert(tk.END, "\n" + "=" * 70 + "\n\n", "normal")
        
        if issues_count == 0 and warnings_count == 0:
            text.insert(tk.END, "✅ Your system appears to be in good health!\n", "success")
        elif issues_count == 0:
            text.insert(tk.END, "⚠️  Some warnings detected, but no critical issues.\n", "warning")
        else:
            text.insert(tk.END, "🔴 Critical issues detected. Please review recommendations.\n", "critical")
    
    def save_report(self):
        """Save scan results to a JSON or HTML file (chosen by file extension)."""
        if not self.scan_results and not self.security_results:
            messagebox.showwarning("No Data", "Please run a scan first before saving a report.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"diagnostic_report_{timestamp}"

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("HTML report", "*.html"), ("All files", "*.*")],
            initialfile=default_filename
        )

        if filename:
            try:
                report = {
                    'scan_results': self.scan_results or {},
                    'recommendations': self.recommendations or [],
                    'generated_at': datetime.now().isoformat()
                }

                # Include security results if available
                if self.security_results:
                    report['security_results'] = self.security_results

                if filename.lower().endswith(('.html', '.htm')):
                    save_html_report(report, filename)
                else:
                    with open(filename, 'w') as f:
                        json.dump(report, f, indent=2)
                
                messagebox.showinfo("Success", f"Report saved successfully to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save report:\n{str(e)}")


    def compare_reports(self):
        """Compare two saved JSON reports and show what changed."""
        filenames = filedialog.askopenfilenames(
            title="Select two JSON reports to compare",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not filenames:
            return
        if len(filenames) != 2:
            messagebox.showwarning("Select Two Reports", "Please select exactly two JSON reports to compare.")
            return

        try:
            result = compare_reports(load_report(filenames[0]), load_report(filenames[1]))
        except Exception as e:
            messagebox.showerror("Error", f"Could not compare reports:\n{str(e)}")
            return

        text = self.changes_text
        text.delete(1.0, tk.END)
        for line, style in format_comparison(result):
            text.insert(tk.END, line + "\n", style)

        self.notebook.select(self.changes_text)
        self.status_label.config(text="Comparison complete. Review the results in the Changes tab.")


def main():
    """Launch the GUI application."""
    root = tk.Tk()
    app = DiagnosticGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

