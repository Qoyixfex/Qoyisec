#!/usr/bin/env python3
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
import requests
import argparse
import hashlib
import zipfile
import threading
import queue

# Colors for terminal output
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Banner
def banner():
    print(colors.HEADER + """
 ██████╗  ██████╗ ██╗   ██╗██╗███████╗███████╗ ██████╗
██╔═══██╗██╔═══██╗╚██╗ ██╔╝██║██╔════╝██╔════╝██╔════╝
██║   ██║██║   ██║ ╚████╔╝ ██║███████╗█████╗  ██║     
██║▄▄ ██║██║   ██║  ╚██╔╝  ██║╚════██║██╔══╝  ██║     
╚██████╔╝╚██████╔╝   ██║   ██║███████║███████╗╚██████╗
                                                            
    """ + colors.ENDC)
    print(colors.WARNING + "ETHICAL HACKING MULTI-TOOL" + colors.ENDC)
    print(colors.WARNING + "For authorized penetration testing only!" + colors.ENDC)
    print(colors.WARNING + "="*50 + colors.ENDC + "\n")

# Port Scanner
def port_scan(target, ports):
    try:
        target_ip = socket.gethostbyname(target)
        print(colors.OKBLUE + f"\nStarting scan on {target_ip}" + colors.ENDC)
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(colors.OKGREEN + f"Port {port}: Open" + colors.ENDC)
            else:
                print(colors.FAIL + f"Port {port}: Closed" + colors.ENDC)
            sock.close()
            
    except socket.gaierror:
        print(colors.FAIL + "Hostname could not be resolved" + colors.ENDC)
    except socket.error:
        print(colors.FAIL + "Could not connect to server" + colors.ENDC)

# Directory Brute Forcer
def dir_brute(target, wordlist):
    try:
        if not os.path.exists(wordlist):
            print(colors.FAIL + "Wordlist file not found!" + colors.ENDC)
            return
            
        with open(wordlist, 'r') as file:
            directories = file.read().splitlines()
            
        print(colors.OKBLUE + f"\nStarting directory brute force on {target}" + colors.ENDC)
        
        for dir in directories:
            url = f"{target}/{dir}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    print(colors.OKGREEN + f"[+] Found: {url}" + colors.ENDC)
            except requests.exceptions.RequestException:
                pass
                
    except KeyboardInterrupt:
        print(colors.WARNING + "\nScan interrupted by user" + colors.ENDC)

# Password Cracker (Dictionary Attack)
def password_cracker(hash_file, wordlist):
    try:
        if not os.path.exists(hash_file) or not os.path.exists(wordlist):
            print(colors.FAIL + "Hash file or wordlist not found!" + colors.ENDC)
            return
            
        with open(hash_file, 'r') as h_file:
            target_hash = h_file.read().strip()
            
        with open(wordlist, 'r', errors='ignore') as w_file:
            print(colors.OKBLUE + "\nStarting password cracking..." + colors.ENDC)
            
            for password in w_file:
                password = password.strip()
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                if hashed_password == target_hash:
                    print(colors.OKGREEN + f"\n[+] Password found: {password}" + colors.ENDC)
                    return
                    
        print(colors.FAIL + "\nPassword not found in wordlist" + colors.ENDC)
        
    except KeyboardInterrupt:
        print(colors.WARNING + "\nCracking interrupted by user" + colors.ENDC)

# Network Sniffer (basic)
def network_sniffer(interface, count=10):
    try:
        print(colors.OKBLUE + f"\nStarting network sniffer on {interface}" + colors.ENDC)
        print(colors.WARNING + "Press Ctrl+C to stop..." + colors.ENDC)
        
        # This is a placeholder - actual packet sniffing requires root privileges
        # and libraries like scapy would be better for this
        for i in range(count):
            # Simulate packet capture
            print(f"Packet {i+1} captured")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(colors.WARNING + "\nSniffing stopped" + colors.ENDC)

# Vulnerability Scanner (basic)
def vuln_scanner(target):
    try:
        print(colors.OKBLUE + f"\nStarting basic vulnerability scan on {target}" + colors.ENDC)
        
        # Check for common vulnerabilities
        # This is a very basic example - real scanners are much more comprehensive
        vulns = {
            'SQL Injection': False,
            'XSS': False,
            'Command Injection': False
        }
        
        # Simulate finding vulnerabilities
        if "vulnerable" in target.lower():
            vulns['SQL Injection'] = True
            vulns['XSS'] = True
            
        for vuln, found in vulns.items():
            if found:
                print(colors.FAIL + f"[!] {vuln} vulnerability found!" + colors.ENDC)
            else:
                print(colors.OKGREEN + f"[+] No {vuln} found" + colors.ENDC)
                
    except Exception as e:
        print(colors.FAIL + f"Error during scan: {e}" + colors.ENDC)

# Main menu
def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Ethical Hacking Multi-Tool')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Port scan command
    scan_parser = subparsers.add_parser('scan', help='Port scanning')
    scan_parser.add_argument('target', help='Target IP or hostname')
    scan_parser.add_argument('-p', '--ports', nargs='+', type=int, default=[21, 22, 80, 443, 8080], 
                           help='Ports to scan (default: 21,22,80,443,8080)')
    
    # Directory brute force command
    dir_parser = subparsers.add_parser('dir', help='Directory brute forcing')
    dir_parser.add_argument('target', help='Target URL (e.g., http://example.com)')
    dir_parser.add_argument('-w', '--wordlist', default='wordlist.txt', 
                          help='Wordlist file (default: wordlist.txt)')
    
    # Password cracker command
    crack_parser = subparsers.add_parser('crack', help='Password cracking')
    crack_parser.add_argument('hash_file', help='File containing the hash to crack')
    crack_parser.add_argument('-w', '--wordlist', default='wordlist.txt', 
                            help='Wordlist file (default: wordlist.txt)')
    
    # Network sniffer command
    sniff_parser = subparsers.add_parser('sniff', help='Network sniffing')
    sniff_parser.add_argument('interface', help='Network interface to sniff')
    sniff_parser.add_argument('-c', '--count', type=int, default=10, 
                            help='Number of packets to capture (default: 10)')
    
    # Vulnerability scanner command
    vuln_parser = subparsers.add_parser('vuln', help='Vulnerability scanning')
    vuln_parser.add_argument('target', help='Target URL or IP to scan')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'scan':
        port_scan(args.target, args.ports)
    elif args.command == 'dir':
        dir_brute(args.target, args.wordlist)
    elif args.command == 'crack':
        password_cracker(args.hash_file, args.wordlist)
    elif args.command == 'sniff':
        network_sniffer(args.interface, args.count)
    elif args.command == 'vuln':
        vuln_scanner(args.target)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
