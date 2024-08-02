import subprocess
import nmap
import re
from tabulate import tabulate

def get_active_interface():
    """
    Finds the active network interface on the machine (e.g., en0 on macOS).
    """
    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
    interface = None
    for line in result.stdout.split('\n'):
        if 'en0' in line:  # Adjust if necessary for different interfaces
            interface = line.split(':')[0]
            break
    return interface

def get_local_ip(interface):
    """
    Retrieves the local IP address of the specified network interface.
    """
    result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
    if match:
        return match.group(1)
    return None

def get_network_range(ip):
    """
    Computes the network range from the given IP address (assumes /24 subnet).
    """
    parts = ip.split('.')
    parts[-1] = '0/24'
    return '.'.join(parts)

def scan_network(network_range):
    """
    Scans the specified network range to find active hosts.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')  # Ping scan to find live hosts
    active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
    return active_hosts

def scan_vulnerabilities(host):
    """
    Scans the specified host for vulnerabilities using Nmap's vulners script.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-sV --script vulners')  # Service version detection and vulnerability scan
    return nm[host]

def get_host_details(host):
    """
    Retrieves detailed information about the specified host.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-O -sV')  # OS detection and service version detection
    host_info = nm[host]
    details = {
        'IP': host,
        'Hostname': host_info.get('hostnames', ['N/A'])[0],
        'MAC Address': host_info.get('addresses', {}).get('mac', 'N/A'),
        'Operating System': host_info.get('osclass', [{}])[0].get('osfamily', 'N/A'),
        'Open Ports': ', '.join([f"{port}/{proto}" for proto in host_info.all_protocols() for port in host_info[proto].keys()])
    }
    return details

def list_hosts(active_hosts):
    """
    Displays a list of active hosts in a table format.
    """
    table = [[idx + 1, host] for idx, host in enumerate(active_hosts)]
    print(tabulate(table, headers=["#", "Host"], tablefmt="pretty"))

def main():
    """
    Main function to drive the scanning process and user interactions.
    """
    interface = get_active_interface()
    if not interface:
        print("No active interface found.")
        return

    ip = get_local_ip(interface)
    if not ip:
        print("No IP address found for interface.")
        return

    while True:
        network_range = get_network_range(ip)
        print(f"Scanning network: {network_range}")

        active_hosts = scan_network(network_range)
        if not active_hosts:
            print("No active hosts found.")
            print("00: Rescan Network")
            print("0: Exit")
            choice = input("Enter your choice: ")
            if choice == "0":
                break
            elif choice == "00":
                continue
            else:
                print("Invalid choice. Please enter a valid number.")
            continue

        print("Active hosts:")
        list_hosts(active_hosts)

        print("00: Rescan Network")
        print("0: Exit")

        try:
            choice = int(input("Enter the number of the host to scan (0 to exit): "))
            if choice == 0:
                break
            elif choice == 00:
                continue
            elif 1 <= choice <= len(active_hosts):
                host_to_scan = active_hosts[choice - 1]
                print(f"Scanning host: {host_to_scan}")

                # Get detailed information about the host
                details = get_host_details(host_to_scan)
                print("Host Details:")
                print(tabulate(details.items(), headers=["Attribute", "Value"], tablefmt="pretty"))

                # Scan for vulnerabilities
                vulnerabilities = scan_vulnerabilities(host_to_scan)
                if 'hostnames' in vulnerabilities:
                    print(f"\nVulnerabilities for host {host_to_scan}:")
                    table = []
                    for proto in vulnerabilities.all_protocols():
                        lport = vulnerabilities[proto].keys()
                        for port in lport:
                            service_info = vulnerabilities[proto][port]
                            table.append([port, service_info['name'], service_info.get('script', 'None')])
                    print(tabulate(table, headers=["Port", "Service", "Vulnerabilities"], tablefmt="pretty"))
                else:
                    print(f"No vulnerabilities found for host {host_to_scan}.")
            else:
                print("Invalid choice. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    main()
