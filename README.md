# VAPT Scanner - Automated Vulnerability Assessment & Penetration Testing Tool

An automated security scanner that detects vulnerabilities in web applications including SQL Injection, XSS, CSRF, insecure dependencies, and more.

## Features

✅ **SQL Injection Detection** - Identifies SQL injection vulnerabilities  
✅ **XSS (Cross-Site Scripting) Detection** - Finds XSS vulnerabilities  
✅ **CSRF Protection Checker** - Validates CSRF token implementation  
✅ **Dependency Scanning** - Checks for vulnerable packages  
✅ **Static Code Analysis** - Scans source code for security issues  
✅ **HTML/JSON Reports** - Generates detailed vulnerability reports  
✅ **CI/CD Integration** - GitHub Actions ready  

## Installation

```bash
git clone https://github.com/harshkumar2725/vapt-.git
cd vapt-
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python vapt_scanner.py --url https://example.com
```

### Scan with Detailed Report
```bash
python vapt_scanner.py --url https://example.com --output report.html
```

### Scan Local Code
```bash
python vapt_scanner.py --path ./src --type code
```

## Vulnerability Types Detected

| Type | Detection Method | Severity |
|------|-----------------|----------|
| SQL Injection | Pattern matching & payload injection | Critical |
| XSS | DOM analysis & payload testing | High |
| CSRF | Token validation | High |
| Insecure Headers | Response header analysis | Medium |
| Weak Credentials | Brute force attempts | High |
| Path Traversal | Directory traversal testing | Critical |
| Command Injection | Shell command injection detection | Critical |

## Reports

Reports are generated in HTML and JSON formats with:
- Vulnerability summary
- Detailed findings
- Severity classification
- Remediation recommendations
- Evidence/proof of concept

## Configuration

Edit `config.json` to customize:
- Scan timeout
- Payload lists
- Target URLs
- Report format

## GitHub Actions Integration

Automatically run VAPT scans on:
- Pull requests
- Scheduled daily/weekly
- Manual workflow dispatch

See `.github/workflows/vapt-scan.yml`

## License

MIT License

## Author

harshkumar2725
