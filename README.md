# Nmap Vulnerability Scanner

## Overview

The Nmap Vulnerability Scanner is a Python application that scans a network to identify active hosts and checks them for vulnerabilities using Nmap. It provides detailed information about each host, including IP address, hostname, MAC address, operating system, and open ports. It also scans for vulnerabilities using Nmap's `vulners` script and displays the results.

## Features

- Scans the local network to find active hosts.
- Provides detailed information about each host.
- Scans each host for vulnerabilities using Nmap.
- Displays vulnerabilities in a tabulated format.

## Prerequisites

- Python 3.x
- Nmap (installed and accessible via command line)
- Required Python libraries: `nmap`, `tabulate`

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/nmap-vulnerability-scanner.git
    ```

2. Navigate to the project directory:

    ```bash
    cd nmap-vulnerability-scanner
    ```

3. Install the required Python libraries:

    ```bash
    pip install python-nmap tabulate
    ```

## Usage

1. Run the script:

    ```bash
   sudo python nmap_scan.py
    ```

2. Follow the on-screen instructions to scan the network and select a host for detailed scanning.

## How It Works

1. **Network Scanning**: Uses Nmap to perform a network scan (`-sn` argument) to identify active hosts.
2. **Host Details**: Retrieves detailed information about a selected host, including OS and open ports, using Nmap (`-O -sV` arguments).
3. **Vulnerability Scanning**: Scans the selected host for vulnerabilities using Nmap's `vulners` script (`-sV --script vulners` arguments).
4. **Output**: Displays the results in a tabulated format using the `tabulate` library.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to open issues or submit pull requests. Contributions are welcome!

## Contact

If you have any questions or suggestions, please contact [your-email@example.com](mailto:your-email@example.com).

