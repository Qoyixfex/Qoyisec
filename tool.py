# warning this code is still on developement by qoyi, may not working.

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
from shodan import Shodan
import whois
import socketio
import aiortc
import asyncio
from colorama import init, Fore, Back, Style
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import socialscan
import pyhibp
from pyhibp import pwnedpasswords as pw
from pyhibp import set_user_agent
import instaloader
import tweepy
import google
from googlesearch import search
import socket
import re
import urllib.parse
import configparser

# Initialize colorama
init(autoreset=True)

# ================ CONFIGURATION ================
# api keys for tools
SHODAN_API_KEY = Z8agNMRJRapg3exo0nZOrb4cI7xbb0Yb"
VIRUSTOTAL_API_KEY = "053c6ce23645f7b09fd0b790f1114f347a2a10353960d8ca295be65e5985f33d"

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
    print(Fore.CYAN + "Hackin tool by QoyiSec")
    print(Fore.RED + "2025 copyright law")
    print(Fore.YELLOW + "="*80 + Style.RESET_ALL + "\n")
    print(Fore.GREEN + f"Runtime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.GREEN + f"Python: {sys.version.split()[0]}")
    print(Fore.GREEN + f"Platform: {sys.platform}")
    print(Style.RESET_ALL)

# ================ OSINT MODULES ================
class PhoneAnalyzer:
    def analyze(self, phone_number):
        try:
            print(Fore.BLUE + f"\nAnalyzing phone number: {phone_number}" + Style.RESET_ALL)
            parsed_number = phonenumbers.parse(phone_number)
            
            print(Fore.YELLOW + "\n[+] Carrier Information:" + Style.RESET_ALL)
            print(f"Carrier: {carrier.name_for_number(parsed_number, 'en')}")
            
            print(Fore.YELLOW + "\n[+] Geographic Information:" + Style.RESET_ALL)
            print(f"Region: {geocoder.description_for_number(parsed_number, 'en')}")
            print(f"Timezone: {timezone.time_zones_for_number(parsed_number)}")
            
            print(Fore.YELLOW + "\n[+] Number Validation:" + Style.RESET_ALL)
            print(f"Valid: {phonenumbers.is_valid_number(parsed_number)}")
            print(f"Possible: {phonenumbers.is_possible_number(parsed_number)}")
            
        except Exception as e:
            print(Fore.RED + f"Error analyzing phone number: {e}" + Style.RESET_ALL)

class EmailAnalyzer:
    def __init__(self):
        set_user_agent(ua="hackingtool/1.0")
        pyhibp.set_api_key("YOUR_HIBP_API_KEY")  # do not edit this until u have the apikey
        
    def analyze(self, email):
        try:
            print(Fore.BLUE + f"\nAnalyzing email: {email}" + Style.RESET_ALL)
            
            # Check if email has been breached
            breaches = pyhibp.get_account_breaches(account=email, truncate_response=True)
            if breaches:
                print(Fore.RED + "\n[!] Email found in breaches:" + Style.RESET_ALL)
                for breach in breaches:
                    print(f"- {breach['Name']} ({breach['BreachDate']})")
                    print(f"  Data leaked: {', '.join(breach['DataClasses'])}")
            else:
                print(Fore.GREEN + "\n[+] No breaches found for this email" + Style.RESET_ALL)
                
            # Check if email is associated with pastes
            pastes = pyhibp.get_account_pastes(account=email)
            if pastes:
                print(Fore.RED + "\n[!] Email found in pastes:" + Style.RESET_ALL)
                for paste in pastes:
                    print(f"- {paste['Source']} ({paste['Date']})")
            else:
                print(Fore.GREEN + "\n[+] No pastes found for this email" + Style.RESET_ALL)
                
        except Exception as e:
            print(Fore.RED + f"Error analyzing email: {e}" + Style.RESET_ALL)

class UsernameAnalyzer:
    def search(self, username):
        try:
            print(Fore.BLUE + f"\nSearching for username: {username}" + Style.RESET_ALL)
            
            sites = [
                f"https://github.com/{username}",
                f"https://twitter.com/{username}",
                f"https://instagram.com/{username}",
                f"https://reddit.com/user/{username}",
                f"https://pinterest.com/{username}",
                f"https://vk.com/{username}",
                f"https://t.me/{username}"
            ]
            
            print(Fore.YELLOW + "\nChecking social media platforms:" + Style.RESET_ALL)
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.check_profile, site): site for site in sites}
                for future in asyncio.as_completed(futures):
                    site = futures[future]
                    try:
                        exists = future.result()
                        if exists:
                            print(Fore.GREEN + f"[+] Found: {site}" + Style.RESET_ALL)
                    except Exception as e:
                        print(Fore.RED + f"Error checking {site}: {e}" + Style.RESET_ALL)
                        
        except Exception as e:
            print(Fore.RED + f"Error searching username: {e}" + Style.RESET_ALL)
    
    def check_profile(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return True
            return False
        except:
            return False

class InstagramOSINT:
    def __init__(self):
        self.loader = instaloader.Instaloader()
        
    def profile_info(self, username):
        try:
            print(Fore.BLUE + f"\nGathering Instagram info for: {username}" + Style.RESET_ALL)
            profile = instaloader.Profile.from_username(self.loader.context, username)
            
            print(Fore.YELLOW + "\n[+] Profile Information:" + Style.RESET_ALL)
            print(f"Full Name: {profile.full_name}")
            print(f"Bio: {profile.biography}")
            print(f"Followers: {profile.followers}")
            print(f"Following: {profile.followees}")
            print(f"Posts: {profile.mediacount}")
            print(f"Private: {profile.is_private}")
            print(f"Verified: {profile.is_verified}")
            
            print(Fore.YELLOW + "\n[+] Recent Posts:" + Style.RESET_ALL)
            for post in profile.get_posts():
                print(f"- {post.date_local}: {post.caption[:50]}... (Likes: {post.likes})")
                if post.is_video:
                    print("  (Video)")
                if len(post.caption_hashtags) > 0:
                    print(f"  Hashtags: {', '.join(post.caption_hashtags)}")
                break  # Just show first post for demo
            
        except Exception as e:
            print(Fore.RED + f"Error gathering Instagram info: {e}" + Style.RESET_ALL)

class TwitterOSINT:
    def __init__(self):
        self.auth = tweepy.OAuthHandler(TWITTER_API_KEY, TWITTER_API_SECRET)
        self.auth.set_access_token(TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET)
        self.api = tweepy.API(self.auth)
        
    def user_info(self, username):
        try:
            print(Fore.BLUE + f"\nGathering Twitter info for: @{username}" + Style.RESET_ALL)
            user = self.api.get_user(screen_name=username)
            
            print(Fore.YELLOW + "\n[+] Profile Information:" + Style.RESET_ALL)
            print(f"Name: {user.name}")
            print(f"Bio: {user.description}")
            print(f"Location: {user.location}")
            print(f"Followers: {user.followers_count}")
            print(f"Following: {user.friends_count}")
            print(f"Tweets: {user.statuses_count}")
            print(f"Verified: {user.verified}")
            print(f"Created: {user.created_at}")
            
            print(Fore.YELLOW + "\n[+] Recent Tweets:" + Style.RESET_ALL)
            for tweet in self.api.user_timeline(screen_name=username, count=3):
                print(f"- {tweet.created_at}: {tweet.text[:100]}...")
                
        except Exception as e:
            print(Fore.RED + f"Error gathering Twitter info: {e}" + Style.RESET_ALL)

class DomainAnalyzer:
    def analyze(self, domain):
        try:
            print(Fore.BLUE + f"\nAnalyzing domain: {domain}" + Style.RESET_ALL)
            
            # WHOIS lookup
            print(Fore.YELLOW + "\n[+] WHOIS Information:" + Style.RESET_ALL)
            domain_info = whois.whois(domain)
            print(f"Registrar: {domain_info.registrar}")
            print(f"Creation Date: {domain_info.creation_date}")
            print(f"Expiration Date: {domain_info.expiration_date}")
            print(f"Name Servers: {', '.join(domain_info.name_servers[:3])}")
            
            # DNS records
            print(Fore.YELLOW + "\n[+] DNS Records:" + Style.RESET_ALL)
            record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME']
            for record in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record)
                    print(f"{record}:")
                    for rdata in answers:
                        print(f"  {rdata.to_text()}")
                except:
                    pass
                    
            # Subdomain enumeration
            print(Fore.YELLOW + "\n[+] Common Subdomains:" + Style.RESET_ALL)
            subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test']
            for sub in subdomains:
                full_domain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(full_domain)
                    print(Fore.GREEN + f"[+] Found: {full_domain}" + Style.RESET_ALL)
                except:
                    pass
                    
        except Exception as e:
            print(Fore.RED + f"Error analyzing domain: {e}" + Style.RESET_ALL)

class GoogleDorker:
    def search(self, query, num_results=10):
        try:
            print(Fore.BLUE + f"\nGoogle Dorking for: {query}" + Style.RESET_ALL)
            print(Fore.YELLOW + "Results:" + Style.RESET_ALL)
            
            for result in search(query, num_results=num_results, stop=num_results, pause=2):
                print(f"- {result}")
                
        except Exception as e:
            print(Fore.RED + f"Error performing Google dork: {e}" + Style.RESET_ALL)

# ================ MAIN MENU ================
def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Ultimate Ethical Hacking & OSINT Tool (2025)')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Existing hacking tool commands...
    
    # OSINT commands
    phone_parser = subparsers.add_parser('phone', help='Phone number analysis')
    phone_parser.add_argument('number', help='Phone number to analyze')
    
    email_parser = subparsers.add_parser('email', help='Email analysis')
    email_parser.add_argument('address', help='Email address to analyze')
    
    username_parser = subparsers.add_parser('username', help='Username search')
    username_parser.add_argument('username', help='Username to search')
    
    ig_parser = subparsers.add_parser('instagram', help='Instagram OSINT')
    ig_parser.add_argument('username', help='Instagram username')
    
    twitter_parser = subparsers.add_parser('twitter', help='Twitter OSINT')
    twitter_parser.add_argument('username', help='Twitter username')
    
    domain_parser = subparsers.add_parser('domain', help='Domain analysis')
    domain_parser.add_argument('domain', help='Domain to analyze')
    
    dork_parser = subparsers.add_parser('dork', help='Google dorking')
    dork_parser.add_argument('query', help='Search query')
    dork_parser.add_argument('-n', '--num', type=int, default=10, help='Number of results')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Existing command handling...
    
    # OSINT command handling
    elif args.command == 'phone':
        analyzer = PhoneAnalyzer()
        analyzer.analyze(args.number)
    elif args.command == 'email':
        analyzer = EmailAnalyzer()
        analyzer.analyze(args.address)
    elif args.command == 'username':
        analyzer = UsernameAnalyzer()
        analyzer.search(args.username)
    elif args.command == 'instagram':
        osint = InstagramOSINT()
        osint.profile_info(args.username)
    elif args.command == 'twitter':
        osint = TwitterOSINT()
        osint.user_info(args.username)
    elif args.command == 'domain':
        analyzer = DomainAnalyzer()
        analyzer.analyze(args.domain)
    elif args.command == 'dork':
        dorker = GoogleDorker()
        dorker.search(args.query, args.num)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
