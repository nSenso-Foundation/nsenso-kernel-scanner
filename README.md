# nSenso Linux Security Scanner

A comprehensive Linux security auditing tool that identifies misconfigurations and potential privilege escalation vectors.

## Features

- Sudo & SUID misconfiguration detection
- World-writable file and directory scanning
- User security and credential auditing
- Process and service security analysis
- Kernel hardening checks

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nsenso-kernel-scanner.git
cd nsenso-kernel-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable:
```bash
chmod +x nsenso_scan.py
```

## Usage

Run the scanner with default settings (text output):
```bash
./nsenso_scan.py
```

Generate JSON output:
```bash
./nsenso_scan.py --format json
```

## Output Format

The tool provides two output formats:

1. **Text Output (Default)**
   - Color-coded findings by severity (Critical, Warning, Info)
   - Detailed descriptions and remediation steps
   - Progress bar during scanning

2. **JSON Output**
   - Structured data for programmatic analysis
   - Timestamp and categorized findings
   - Command outputs and remediation suggestions

## Security Considerations

- The tool requires root privileges to perform certain checks
- Some checks may trigger security alerts in IDS/IPS systems
- Use responsibly and only on systems you own or have permission to audit

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 