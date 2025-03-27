#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import argparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from typing import Dict, List, Optional

class NSensoScanner:
    def __init__(self):
        self.console = Console()
        self.findings = {
            "critical": [],
            "warning": [],
            "info": []
        }
        
    def run_command(self, command: str) -> str:
        """Execute a shell command and return its output."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )
            return result.stdout
        except Exception as e:
            self.console.print(f"[red]Error executing command '{command}': {str(e)}[/red]")
            return ""

    def check_sudo_misconfigurations(self) -> None:
        """Check for sudo misconfigurations and SUID binaries."""
        self.console.print("\n[bold blue]Checking sudo configurations and SUID binaries...[/bold blue]")
        
        # Check sudo -l output
        sudo_l_output = self.run_command("sudo -l 2>/dev/null")
        if "NOPASSWD" in sudo_l_output:
            self.findings["critical"].append({
                "type": "sudo_misconfig",
                "description": "NOPASSWD sudo access detected",
                "command": "sudo -l",
                "remediation": "Review and restrict sudo access in /etc/sudoers"
            })

        # Check SUID binaries
        suid_binaries = self.run_command("find / -perm -4000 -type f 2>/dev/null")
        if suid_binaries:
            self.findings["warning"].append({
                "type": "suid_binaries",
                "description": f"Found SUID binaries:\n{suid_binaries}",
                "command": "find / -perm -4000 -type f",
                "remediation": "Review and remove unnecessary SUID permissions"
            })

    def check_file_permissions(self) -> None:
        """Check for world-writable files and directories."""
        self.console.print("\n[bold blue]Checking file permissions...[/bold blue]")
        
        # Check world-writable files
        world_writable = self.run_command("find / -type f -perm -o+w -exec ls -lh {} + 2>/dev/null")
        if world_writable:
            self.findings["critical"].append({
                "type": "world_writable_files",
                "description": "Found world-writable files",
                "command": "find / -type f -perm -o+w",
                "remediation": "Review and restrict file permissions"
            })

    def check_user_security(self) -> None:
        """Check for weak user credentials and security issues."""
        self.console.print("\n[bold blue]Checking user security...[/bold blue]")
        
        # Check for empty passwords
        empty_passwords = self.run_command("cat /etc/shadow | awk -F: '($2==\"\"){print $1}'")
        if empty_passwords:
            self.findings["critical"].append({
                "type": "empty_passwords",
                "description": f"Users with empty passwords:\n{empty_passwords}",
                "command": "cat /etc/shadow",
                "remediation": "Set strong passwords for all users"
            })

    def check_process_security(self) -> None:
        """Check for processes running as root."""
        self.console.print("\n[bold blue]Checking process security...[/bold blue]")
        
        # Check for root processes
        root_processes = self.run_command("ps aux | grep root | grep -v grep")
        if root_processes:
            self.findings["warning"].append({
                "type": "root_processes",
                "description": "Processes running as root",
                "command": "ps aux | grep root",
                "remediation": "Review and restrict root process execution"
            })

    def check_kernel_hardening(self) -> None:
        """Check kernel security settings."""
        self.console.print("\n[bold blue]Checking kernel hardening...[/bold blue]")
        
        # Check kernel parameters
        kernel_params = self.run_command("sysctl -a | grep kernel")
        if kernel_params:
            self.findings["info"].append({
                "type": "kernel_parameters",
                "description": "Current kernel parameters",
                "command": "sysctl -a | grep kernel",
                "remediation": "Review and adjust kernel parameters for security"
            })

    def generate_report(self, output_format: str = "text") -> None:
        """Generate a security report in the specified format."""
        if output_format == "json":
            self._generate_json_report()
        else:
            self._generate_text_report()

    def _generate_json_report(self) -> None:
        """Generate a JSON report of findings."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings
        }
        print(json.dumps(report, indent=2))

    def _generate_text_report(self) -> None:
        """Generate a text report with rich formatting."""
        self.console.print("\n[bold green]=== nSenso Security Scan Report ===[/bold green]")
        self.console.print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Define severity colors
        severity_colors = {
            "critical": "red",
            "warning": "yellow",
            "info": "blue"
        }

        for severity, findings in self.findings.items():
            if findings:
                self.console.print(f"\n[bold {severity_colors[severity]}]{severity.upper()} FINDINGS:[/bold {severity_colors[severity]}]")
                for finding in findings:
                    self.console.print(Panel(
                        f"[bold]Type:[/bold] {finding['type']}\n"
                        f"[bold]Description:[/bold] {finding['description']}\n"
                        f"[bold]Command:[/bold] {finding['command']}\n"
                        f"[bold]Remediation:[/bold] {finding['remediation']}",
                        title=f"{severity.upper()} Issue",
                        border_style=severity_colors[severity]
                    ))

def main():
    parser = argparse.ArgumentParser(description="nSenso Linux Security Scanner")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                      help="Output format (text or json)")
    args = parser.parse_args()

    scanner = NSensoScanner()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Running security checks...", total=5)
        
        scanner.check_sudo_misconfigurations()
        progress.update(task, advance=1)
        
        scanner.check_file_permissions()
        progress.update(task, advance=1)
        
        scanner.check_user_security()
        progress.update(task, advance=1)
        
        scanner.check_process_security()
        progress.update(task, advance=1)
        
        scanner.check_kernel_hardening()
        progress.update(task, advance=1)

    scanner.generate_report(args.format)

if __name__ == "__main__":
    main() 