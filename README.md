# Port-scanner
The Port Scanner Tool is a professional and detailed port scanning utility that provides functionality similar to Nmap. It allows users to scan specific ports on a target IP address, detect open ports, probe for service/version information, and perform OS detection using TCP/IP fingerprinting.
## Features
- **Simplicity and Ease of Use**: The Port Scanner Tool is designed to be user-friendly, with a straightforward command-line interface that allows users to quickly perform scans without a steep learning curve.

- **Customizable Services File**: Unlike many tools that have a predefined list of services, this tool allows you to load a custom services file, giving you flexibility in identifying services based on your specific needs.

- **Integrated Features**: Combine multiple functionalities like service/version probing and OS detection in one tool, reducing the need for multiple separate tools.

- **Efficient Performance**: The tool is optimized for speed and resource efficiency, allowing for quick scans without overwhelming system resources.

- **Verbose and Silent Modes**: Choose between detailed output for in-depth analysis or silent mode for minimal console output, making it suitable for both casual and professional use.
## Why Use This Tool Over Others?

- **Lightweight**: Unlike heavier tools like Nmap, this tool is lightweight and easy to set up, making it ideal for quick scans and lightweight environments.

- **Tailored to Your Needs**: You can customize the ports and services you want to scan based on your environment, making it more adaptable than fixed configurations found in other tools.

- **Real-time OS Detection**: Perform OS detection on the fly using TCP/IP fingerprinting, which is often a manual process in other tools.
## How to Download and Use
### 1. Download the Tool from GitHub
To download the tool, clone the repository from GitHub using the following command:
```bash
git clone https://github.com/Adamzayene/Port-scanner.git
```
### 2.Then navigate to the tool's directory:
```bash
cd Port-scanner
```
## How to Use
```bash
python port_scanner.py -t <TARGET_IP> [OPTIONS]
```
### Options
-t, --target: Specify the target IP address to scan. (Required)

-s, --silent: Enable silent mode. Only errors will be displayed.

-v, --verbose: Enable verbose mode. Provides detailed scan progress.

-sV, --service-version: Probe open ports for service/version information.

-O, --os-detection: Enable OS detection using TCP/IP fingerprinting.

--services-file: Specify a custom file path for services. Default is services.txt.

--log: Specify a filename to save the results. If not provided, results won't be saved.
## Contributing
If you want to contribute to the development of the tool, you can fork the repository, make the necessary changes, and then submit a pull request to have your changes merged.
