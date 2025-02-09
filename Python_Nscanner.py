from scapy.all import ARP, Ether, srp
import nmap
import argparse
import csv
from threading import Thread
from queue import Queue

# Function to scan the network for active devices
def network_scanner(ip_range):
    print(f"Scanning network {ip_range} for active devices...")
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [received.psrc for sent, received in result]
    return devices

# Function to perform Nmap scan on a target
def nmap_scan(target, options, result_queue):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments=options)
    result_queue.put((target, scanner[target]))

# Main function
def main(ip_range, nmap_options, output_file=None):
    # Step 1: Discover active devices
    active_devices = network_scanner(ip_range)
    print("\nActive devices found:")
    for device in active_devices:
        print(device)

    # Step 2: Perform Nmap scan on each device
    print(f"\nPerforming Nmap scan with options: {nmap_options}")
    result_queue = Queue()
    threads = []

    for target in active_devices:
        thread = Thread(target=nmap_scan, args=(target, nmap_options, result_queue))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    # Collect and display results
    results = []
    while not result_queue.empty():
        target, scan_result = result_queue.get()
        results.append((target, scan_result))
        print(f"\nScan results for {target}:")
        for proto in scan_result.all_protocols():
            print(f"Protocol: {proto}")
            ports = scan_result[proto].keys()
            for port in ports:
                print(f"Port: {port}\tState: {scan_result[proto][port]['state']}")

    # Export results to a file if specified
    if output_file:
        with open(output_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "Port", "State", "Service"])
            for target, scan_result in results:
                for proto in scan_result.all_protocols():
                    ports = scan_result[proto].keys()
                    for port in ports:
                        writer.writerow([target, port, scan_result[proto][port]['state'], scan_result[proto][port]['name']])
        print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Scanner with Nmap Integration")
    parser.add_argument("--ip", required=True, help="IP range to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("--nmap", default="-sV -O", help="Nmap options (e.g., -sV -O)")
    parser.add_argument("--output", help="Output file to save results (e.g., results.csv)")
    args = parser.parse_args()

    # Run the scanner
    main(args.ip, args.nmap, args.output)
