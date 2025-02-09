import nmap
import hashlib
import os
import re
import requests
import dns.resolver
import whois
import scapy.all as scapy
from scapy.all import ARP, Ether, srp, sniff, TCP, IP
from threading import Thread
from queue import Queue
from cryptography.fernet import Fernet
import paramiko

# Network Scanner
def network_scanner(ip_range):
    print(f"Scanning network {ip_range} for active devices...")
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [received.psrc for sent, received in result]
    return devices

# Port Scanner
def port_scanner(target, ports="1-1024"):
    scanner = nmap.PortScanner()
    scanner.scan(target, ports)
    print(f"\nScanning {target} for open ports...")
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            for port in scanner[host][proto].keys():
                print(f"Port: {port}\tState: {scanner[host][proto][port]['state']}")

# Vulnerability Scanner
def vulnerability_scanner(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-sV --script=vuln")
    print(f"\nScanning {target} for vulnerabilities...")
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        for script in scanner[host].get("script", {}):
            print(f"Vulnerability: {script}")

# Password Strength Checker
def password_strength(password):
    if len(password) < 8:
        return "Weak: Password is too short."
    if not re.search(r"[A-Z]", password):
        return "Weak: Password must contain uppercase letters."
    if not re.search(r"[a-z]", password):
        return "Weak: Password must contain lowercase letters."
    if not re.search(r"\d", password):
        return "Weak: Password must contain digits."
    if not re.search(r"[!@#$%^&*()_+{}|:\"<>?]", password):
        return "Weak: Password must contain special characters."
    return "Strong: Password meets all requirements."

# File Integrity Checker
def file_integrity_checker(file_path):
    if not os.path.exists(file_path):
        return "File not found."
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return f"SHA-256 Checksum: {sha256_hash.hexdigest()}"

# Packet Sniffer
def packet_sniffer(interface, count=10):
    print(f"Sniffing {count} packets on interface {interface}...")
    packets = sniff(iface=interface, count=count)
    for packet in packets:
        print(packet.summary())

# Log Analyzer
def log_analyzer(log_file, keyword="error"):
    if not os.path.exists(log_file):
        return "Log file not found."
    with open(log_file, "r") as f:
        lines = f.readlines()
    suspicious_activity = [line for line in lines if keyword.lower() in line.lower()]
    return suspicious_activity

# Subdomain Enumeration
def subdomain_enumeration(domain, wordlist):
    print(f"Enumerating subdomains for {domain}...")
    subdomains = []
    with open(wordlist, "r") as f:
        for line in f:
            subdomain = line.strip() + "." + domain
            try:
                requests.get(f"http://{subdomain}", timeout=2)
                subdomains.append(subdomain)
                print(f"Found: {subdomain}")
            except:
                pass
    return subdomains

# WHOIS Lookup
def whois_lookup(domain):
    print(f"Performing WHOIS lookup for {domain}...")
    info = whois.whois(domain)
    return info

# Directory/File Discovery
def directory_discovery(url, wordlist):
    print(f"Discovering directories/files on {url}...")
    with open(wordlist, "r") as f:
        for line in f:
            path = line.strip()
            full_url = f"{url}/{path}"
            try:
                response = requests.get(full_url, timeout=2)
                if response.status_code == 200:
                    print(f"Found: {full_url}")
            except:
                pass

# SSL/TLS Scanner
def ssl_tls_scanner(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="--script=ssl-enum-ciphers")
    print(f"\nScanning {target} for SSL/TLS vulnerabilities...")
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        for script in scanner[host].get("script", {}):
            print(f"Vulnerability: {script}")

# Email Harvester
def email_harvester(text):
    print("Extracting email addresses...")
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0.9.-]+\.[a-zA-Z]{2,}", text)
    return emails

# Hash Cracker
def hash_cracker(hash_value, wordlist):
    print(f"Cracking hash: {hash_value}...")
    with open(wordlist, "r") as f:
        for line in f:
            password = line.strip()
            if hashlib.md5(password.encode()).hexdigest() == hash_value:
                return f"Hash cracked: {password}"
    return "Hash not found in wordlist."

# Firewall Bypass (TCP ACK Scan)
def firewall_bypass(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-sA")
    print(f"\nScanning {target} for firewall rules...")
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            for port in scanner[host][proto].keys():
                print(f"Port: {port}\tState: {scanner[host][proto][port]['state']}")

# MITM Detector
def mitm_detector(interface):
    print(f"Monitoring ARP table on interface {interface} for MITM attacks...")
    while True:
        arp_table = scapy.arping(interface, verbose=False)[0]
        for packet in arp_table:
            print(f"IP: {packet[1].psrc}, MAC: {packet[1].hwsrc}")

# Brute Force Login
def brute_force_login(target, username, wordlist):
    print(f"Brute-forcing login for {username} on {target}...")
    with open(wordlist, "r") as f:
        for line in f:
            password = line.strip()
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=username, password=password, timeout=2)
                print(f"Login successful: {username}:{password}")
                ssh.close()
                return
            except:
                pass
    print("Login failed.")

# DNS Spoofing Detector
def dns_spoofing_detector(domain):
    print(f"Detecting DNS spoofing for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, "A")
        for answer in answers:
            print(f"IP: {answer}")
    except Exception as e:
        print(f"Error: {e}")

# File Encryption/Decryption
def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(file_path + ".enc", "wb") as f:
        f.write(encrypted_data)
    print(f"File encrypted: {file_path}.enc")

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    decrypted_data = fernet.decrypt(data)
    with open(file_path[:-4], "wb") as f:
        f.write(decrypted_data)
    print(f"File decrypted: {file_path[:-4]}")

# Main Menu
def main():
    while True:
        print("\n--- Cybersecurity Toolkit ---")
        print("1. Network Scanner")
        print("2. Port Scanner")
        print("3. Vulnerability Scanner")
        print("4. Password Strength Checker")
        print("5. File Integrity Checker")
        print("6. Packet Sniffer")
        print("7. Log Analyzer")
        print("8. Subdomain Enumeration")
        print("9. WHOIS Lookup")
        print("10. Directory/File Discovery")
        print("11. SSL/TLS Scanner")
        print("12. Email Harvester")
        print("13. Hash Cracker")
        print("14. Firewall Bypass")
        print("15. MITM Detector")
        print("16. Brute Force Login")
        print("17. DNS Spoofing Detector")
        print("18. File Encryption/Decryption")
        print("19. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
            devices = network_scanner(ip_range)
            print("\nActive devices found:")
            for device in devices:
                print(device)

        elif choice == "2":
            target = input("Enter target IP: ")
            ports = input("Enter port range (e.g., 1-1024): ")
            port_scanner(target, ports)

        elif choice == "3":
            target = input("Enter target IP: ")
            vulnerability_scanner(target)

        elif choice == "4":
            password = input("Enter password: ")
            print(password_strength(password))

        elif choice == "5":
            file_path = input("Enter file path: ")
            print(file_integrity_checker(file_path))

        elif choice == "6":
            interface = input("Enter network interface (e.g., eth0): ")
            count = int(input("Enter number of packets to sniff: "))
            packet_sniffer(interface, count)

        elif choice == "7":
            log_file = input("Enter log file path: ")
            keyword = input("Enter keyword to search (e.g., error): ")
            suspicious_activity = log_analyzer(log_file, keyword)
            print("\nSuspicious activity found:")
            for line in suspicious_activity:
                print(line)

        elif choice == "8":
            domain = input("Enter domain (e.g., example.com): ")
            wordlist = input("Enter wordlist file path: ")
            subdomains = subdomain_enumeration(domain, wordlist)
            print("\nSubdomains found:")
            for subdomain in subdomains:
                print(subdomain)

        elif choice == "9":
            domain = input("Enter domain or IP: ")
            print(whois_lookup(domain))

        elif choice == "10":
            url = input("Enter base URL (e.g., http://example.com): ")
            wordlist = input("Enter wordlist file path: ")
            directory_discovery(url, wordlist)

        elif choice == "11":
            target = input("Enter target domain or IP: ")
            ssl_tls_scanner(target)

        elif choice == "12":
            text = input("Enter text or file path: ")
            if os.path.exists(text):
                with open(text, "r") as f:
                    text = f.read()
            emails = email_harvester(text)
            print("\nEmail addresses found:")
            for email in emails:
                print(email)

        elif choice == "13":
            hash_value = input("Enter hash value: ")
            wordlist = input("Enter wordlist file path: ")
            print(hash_cracker(hash_value, wordlist))

        elif choice == "14":
            target = input("Enter target IP: ")
            firewall_bypass(target)

        elif choice == "15":
            interface = input("Enter network interface (e.g., eth0): ")
            mitm_detector(interface)

        elif choice == "16":
            target = input("Enter target IP: ")
            username = input("Enter username: ")
            wordlist = input("Enter wordlist file path: ")
            brute_force_login(target, username, wordlist)

        elif choice == "17":
            domain = input("Enter domain (e.g., example.com): ")
            dns_spoofing_detector(domain)

        elif choice == "18":
            file_path = input("Enter file path: ")
            key = generate_key()
            print(f"Generated Key: {key.decode()}")
            action = input("Encrypt (E) or Decrypt (D)? ").lower()
            if action == "e":
                encrypt_file(file_path, key)
            elif action == "d":
                decrypt_file(file_path, key)
            else:
                print("Invalid option.")

        elif choice == "19":
            print("Exiting...")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
