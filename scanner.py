import argparse
import socket
import requests
from concurrent.futures import ThreadPoolExecutor

# A list of common ports to scan
COMMON_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 8080]

def check_port(host, port):
    """
    Checks if a single port is open on the target host.
    """
    try:
        # Create a new socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a tomeout for the connection attempt
        s.settimeout(1)
        # Attempt to connect to the host and port
        result = s.connect_ex((host, port))
        if result == 0:
            return True, port
        else:
            return False, port
    except Exception as e:
        print(f"Error checking port {port}: {e}")
        return False, port
    finally:
        s.close()

def port_scanner(host):
    """
    Scans a list of common ports on the target host and returns a list of open ports.
    """
    print("\nStarting Port Scan...")
    open_ports = []

    # We use ThreadPoolExecutor to speed up the scanning process
    with ThreadPoolExecutor(max_workers =20) as executor:
        futures = {executor.submit(check_port, host, port) for port in COMMON_PORTS}
        for future in futures:
            is_open, port = future.result()
            if is_open:
                print(f" [+] Port {port} is OPEN")
                open_ports.append(port)
            else:
                print(f" [-] Port {port} is CLOSED")
    print("\nPort Scan Complete")
    return open_ports

def check_security_headers(url):
    """
    Checks for the presence of common security headers on the target URL.
    """
    print("\nStarting Security Header Scan...")
    
    # We will use a dictionary to store the results
    # Added X-XSS-Protection as requested
    headers_to_check = {
        'Strict-Transport-Security': False,
        'X-Frame-Options': False,
        'X-Content-Type-Options': False,
        'Content-Security-Policy': False,
        'X-XSS-Protection': False, 
    }

    try:
        # Add 'https://' to the URL if it's not present
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        response = requests.get(url, timeout=5)
        
        # Access the headers from the response
        headers = response.headers

        # Check for each security header
        print("  [+] Checking for security headers:")
        for header in headers_to_check.keys():
            if header in headers:
                headers_to_check[header] = True
                print(f"    [+] Found '{header}' header.")
            else:
                print(f"    [-] Missing '{header}' header.")

    except requests.exceptions.RequestException as e:
        print(f"  [-] Failed to retrieve headers for {url}: {e}")

    print("Security Header Scan Complete.")
    return headers_to_check

def generate_report(target, open_ports, headers_found):
    """
    Generates a consolidated report as a string.
    """
    report_content = f"--- Final Consolidated Report ---\n"
    report_content += f"Target: {target}\n"

    # Port Scan Results
    report_content += "\nPort Scan Results:\n"
    if open_ports:
        for port in open_ports:
            report_content += f"  [+] Port {port} is OPEN\n"
    else:
        report_content += "  [-] No open ports found.\n"

    # Security Header Results
    report_content += "\nSecurity Header Results:\n"
    for header, found in headers_found.items():
        if found:
            report_content += f"  [+] '{header}' header is PRESENT.\n"
        else:
            report_content += f"  [-] '{header}' header is MISSING.\n"
    
    # Scan Summary
    report_content += "\nScan Summary:\n"
    report_content += f"Total Open Ports: {len(open_ports)}\n"
    report_content += f"Security Headers Found: {sum(headers_found.values())} out of {len(headers_found)}\n"
    
    report_content += "\nScan Complete.\n"
    report_content += "Thank you for using the scanner tool!"
    
    return report_content

def main():
    # Create the parser
    parser = argparse.ArgumentParser(description="A tool to scan websites for open ports and security headers.")

    # Add an argument for the target URL/domain
    parser.add_argument("target", help="The target URL or domain to scan (e.g., example.com).")

    # Parse the arguments from the command line
    args = parser.parse_args()

    # Access the target argument
    target = args.target
    print(f"Scanning target: {target}")

    # Call the port_scanner function
    open_ports = port_scanner(target)

    # Call the security header checker
    headers_found = check_security_headers(target)

    # Generate the final report as a string
    final_report = generate_report(target, open_ports, headers_found)

    # Print the report to the console for a quick view
    print(final_report)

    # Save the report to a file
    report_filename = f"report_{target}.txt"
    with open(report_filename, "w") as f:
        f.write(final_report)
    
    print(f"\nReport saved to {report_filename}")

if __name__ == "__main__":
    main()