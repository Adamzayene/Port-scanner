import argparse
from socket import socket, AF_INET, SOCK_STREAM
import time
import os
from scapy.all import sr1, IP, TCP
from colorama import Fore, Style, init
import sys

init(autoreset=True)

def check_root_privileges():
    """Check if the script is run as root."""
    if os.geteuid() != 0:
        print("[ERROR] OS detection requires root privileges. Please run as root.")
        sys.exit(1)

def load_services(file_path):
    """Function to load services from a file into a dictionary."""
    services = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip(): 
                    port, service = line.strip().split(maxsplit=1)
                    services[int(port)] = service
        print(f"{Fore.GREEN}[INFO] Loaded services from {file_path}")
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] The services file '{file_path}' was not found.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] An error occurred while loading the services file: {e}")
    return services

def scan_port(ip, port):
    """Function to scan a specific port on a given IP address."""
    with socket(AF_INET, SOCK_STREAM) as so:
        so.settimeout(0.5)
        try:
            con = so.connect((ip, port))
            if con is None:
                return True
        except:
            return False

def probe_service_version(ip, port):
    """Function to probe the service and version on a specific open port."""
    try:
        with socket(AF_INET, SOCK_STREAM) as so:
            so.settimeout(2)
            so.connect((ip, port))
            so.send(b'\n')
            banner = so.recv(1024).decode().strip()
            return banner if banner else 'Unknown'
    except:
        return 'Unknown'

def os_detection(ip):
    """Function to perform OS detection using TCP/IP fingerprinting."""
    check_root_privileges()
    try:
        pkt = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=1, verbose=0)
        if pkt:
            ttl = pkt.ttl
            window_size = pkt[TCP].window
            if ttl == 64:
                os_name = "Linux"
            elif ttl == 128:
                os_name = "Windows"
            elif ttl == 255:
                os_name = "Cisco/Router"
            else:
                os_name = "Unknown"
            return f"{os_name} (TTL: {ttl}, Window Size: {window_size})"
        else:
            return "Unknown"
    except Exception as e:
        return f"Error during OS detection: {str(e)}"

def get_service_name(port, services):
    """Function to get the common service name for a given port."""
    return services.get(port, 'Unknown')

def save_open_port(ip, port, service, filename):
    """Function to save the open port information to a file."""
    with open(filename, "a") as f:
        f.write(f"{ip}\n{port} - {service}\n")

def print_banner():
    """Function to print the program banner."""
    banner = f'''
{Fore.YELLOW}.
{Fore.YELLOW}______     ______   .______      .___________             _______.  ______      ___      .__   __. .__   __.  _______ .______      
{Fore.YELLOW}|   _  \   /  __  \  |   _  \     |           |            /       | /      |    /   \     |  \ |  | |  \ |  | |   ____||   _  \     
{Fore.YELLOW}|  |_)  | |  |  |  | |  |_)  |    `---|  |----` ______    |   (----`|  ,----'   /  ^  \    |   \|  | |   \|  | |  |__   |  |_)  |    
{Fore.YELLOW}|   ___/  |  |  |  | |      /         |  |     |______|    \   \    |  |       /  /_\  \   |  . `  | |  . `  | |   __|  |      /     
{Fore.YELLOW}|  |      |  `--'  | |  |\  \----.    |  |             .----)   |   |  `----. /  _____  \  |  |\   | |  |\   | |  |____ |  |\  \----.
{Fore.YELLOW}| _|       \______/  | _| `._____|    |__|             |_______/     \______|/__/     \__\ |__| \__| |__| \__| |_______|| _| `._____|
                                                                        
{Fore.CYAN}Port Scanner  by {Fore.RED}Adam Zayene(Black_Shadow)
    '''
    print(banner)

def print_results_header():
    """Function to print the results header."""
    header = f'''
    {Fore.CYAN}==============================================
    |  {"PORT".center(6)}  |  {"STATE".center(8)}  |  {"SERVICE".center(14)}  |  {"VERSION".center(20)}  |
    ==============================================
    '''
    print(header)

def display_progress(elapsed_time, completed_ports, total_ports, open_ports_count):
    """Function to display the progress of the scan."""
    if completed_ports > 0:
        avg_time_per_port = elapsed_time / completed_ports
        remaining_ports = total_ports - completed_ports
        estimated_time_remaining = avg_time_per_port * remaining_ports
        open_port_probability = (open_ports_count / completed_ports) * 100

        print(f"{Fore.YELLOW}[PROGRESS] Estimated time remaining: {estimated_time_remaining:.2f} seconds")
        print(f"{Fore.YELLOW}[PROGRESS] Probability of finding an open port: {open_port_probability:.2f}%")

def parse_ports(port_ranges):
    """Function to parse port ranges and return a list of individual ports."""
    ports = set()
    for part in port_ranges.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:  
            ports.add(int(part))
    return sorted(ports)

def main():
    """Main function to handle the port scanning process."""
    parser = argparse.ArgumentParser(description="A professional and detailed port scanner tool similar to Nmap.")
    
    parser.add_argument(
        "-t", "--target", 
        dest="ip", 
        required=True, 
        help="Specify the target IP address to scan."
    )
    
    parser.add_argument(
        "-p", "--ports", 
        dest="ports", 
        default=None, 
        help="Specify the port ranges to scan (e.g., 80, 443, or 20-80)."
    )
    
    parser.add_argument(
        "-s", "--silent", 
        action="store_true", 
        help="Enable silent mode. No output will be shown except errors."
    )
    
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Enable verbose mode. Shows detailed progress of the scan including estimated time remaining and open port probability."
    )
    
    parser.add_argument(
        "-sV", "--service-version", 
        action="store_true", 
        help="Probe open ports to determine service/version info."
    )
    
    parser.add_argument(
        "-O", "--os-detection", 
        action="store_true", 
        help="Enable OS detection using TCP/IP fingerprinting."
    )
    
    parser.add_argument(
        "--services-file", 
        dest="services_file", 
        default="services.txt", 
        help="Specify the file path that contains ports and their associated services. Default is 'services.txt'."
    )
    
    parser.add_argument(
        "--log", 
        dest="log_file", 
        help="Specify the file name where the open port results will be saved. If not provided, results won't be saved."
    )

    args = parser.parse_args()

    print_banner()
    print_results_header()

    services = load_services(args.services_file)

    if not services:
        print(f"{Fore.RED}[ERROR] No services loaded. Exiting.")
        return

    open_ports = []
    start_time = time.time()
    
    if args.ports:
        ports_to_scan = parse_ports(args.ports)
    else:
        ports_to_scan = services.keys()

    total_ports = len(ports_to_scan)
    open_ports_count = 0

    for i, port in enumerate(ports_to_scan):
        if scan_port(args.ip, port):
            service = get_service_name(port, services)
            version_info = ''
            if args.service_version:
                version_info = probe_service_version(args.ip, port)
            if not args.silent:
                print(f"{Fore.GREEN}|  {str(port).ljust(6)}  |  OPEN    |  {service.ljust(14)}  |  {version_info.ljust(20)}  |")
            if args.log_file: 
                save_open_port(args.ip, port, service, args.log_file)
            open_ports.append(port)
            open_ports_count += 1

        if args.verbose and (i + 1) % 10 == 0:  
            elapsed_time = time.time() - start_time
            display_progress(elapsed_time, i + 1, total_ports, open_ports_count)

    if args.os_detection:
        os_info = os_detection(args.ip)
        if not args.silent:
            print(f"\n{Fore.YELLOW}[OS DETECTION] Detected OS: {os_info}")
        if args.log_file:
            with open(args.log_file, "a") as log_file:
                log_file.write(f"\nDetected OS: {os_info}\n")

    end_time = time.time()
    elapsed_time = end_time - start_time

    if not args.silent:
        print(f"{Fore.YELLOW}\n[INFO] Scan completed in {elapsed_time:.2f} seconds.")
        if open_ports:
            print(f"{Fore.GREEN}[INFO] Open Ports: {', '.join(map(str, open_ports))}")
        else:
            print(f"{Fore.RED}[INFO] No open ports found.")

if __name__ == "__main__":
    main()
