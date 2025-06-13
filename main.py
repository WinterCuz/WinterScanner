import os
import sys
import time
import socket
import random
import threading
import ipaddress
import platform
import subprocess
import concurrent.futures
import re
import json
import ssl
import urllib.parse
import urllib3
import base64
import hashlib
import tempfile
import webbrowser
import logging
import datetime
import csv
import xml.etree.ElementTree as ET
import uuid
import signal
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Union, Any, Set, Callable
from pathlib import Path
from collections import defaultdict

os.system("title WinterScanner v1.0")


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("winter_scanner.log"),
    
    ]
)
logger = logging.getLogger("WinterScanner")


try:
    import pystyle
    from pystyle import Colors, Colorate, Center, Box, Write
    import requests
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import scapy.all as scapy
    from colorama import Fore, Back, Style, init
    from bs4 import BeautifulSoup
    import whois
    import dns.resolver
    import tldextract
    import cryptography
    from cryptography.hazmat.primitives import hashes
    from fake_useragent import UserAgent
    import matplotlib.pyplot as plt
    import networkx as nx
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors as pdf_colors
    import shodan
    import censys.search
    import pdfkit
    import jinja2
    import schedule
    import stem
    import stem.control
    from stem.control import Controller
    from PIL import Image, ImageDraw, ImageFont
    import nmap
    init(autoreset=True)
except ImportError as e:
    print(f"Installing required packages... ({str(e)})")
    os.system('pip install pystyle requests scapy colorama bs4 python-whois dnspython tldextract cryptography fake_useragent urllib3 matplotlib networkx reportlab shodan censys pdfkit jinja2 schedule stem pillow python-nmap')
    import pystyle
    from pystyle import Colors, Colorate, Center, Box, Write
    import requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import scapy.all as scapy
    from colorama import Fore, Back, Style, init
    from bs4 import BeautifulSoup
    import whois
    import dns.resolver
    import tldextract
    import cryptography
    from cryptography.hazmat.primitives import hashes
    from fake_useragent import UserAgent
    import matplotlib.pyplot as plt
    import networkx as nx
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors as pdf_colors
    import shodan
    import censys.search
    import pdfkit
    import jinja2
    import schedule
    import stem
    import stem.control
    from stem.control import Controller
    from PIL import Image, ImageDraw, ImageFont
    import nmap
    init(autoreset=True)


VERSION = "1.0"
AUTHOR = "Winter"
MAX_THREADS = 100
SCAN_TIMEOUT = 2.0
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
}


USE_PROXIES = False
PROXY_LIST = []
CURRENT_PROXY_INDEX = 0
USE_GRADIENTS = True
DARK_MODE = True
SCAN_HISTORY_FILE = os.path.join("data", "scan_history.json")
SCHEDULED_SCANS_FILE = os.path.join("data", "scheduled_scans.json")
API_KEYS = {
    "shodan": "",
    "censys_id": "",
    "censys_secret": "",
    "virustotal": ""
}
WORDLISTS_DIR = os.path.join("assets", "wordlists")
REPORTS_DIR = os.path.join("reports")
PLUGINS_DIR = os.path.join("plugins")
TOR_ENABLED = False
TOR_PORT = 9050
RANDOMIZE_SCAN_DELAY = True
MIN_SCAN_DELAY = 0.5
MAX_SCAN_DELAY = 3.0


ua = UserAgent()


os.makedirs(os.path.dirname(SCAN_HISTORY_FILE), exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(WORDLISTS_DIR, exist_ok=True)
os.makedirs(PLUGINS_DIR, exist_ok=True)


def get_banner() -> str:
    
    banner = f"""
██╗    ██╗██╗███╗   ██╗████████╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║    ██║██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝██║██║ ╚████║   ██║   ███████╗██║  ██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                        v{VERSION}
by {AUTHOR}
    """
    return banner

def clear_screen() -> None:
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def print_gradient_text(text: str, gradient_type: str = "winter") -> None:
    global USE_GRADIENTS
    
   
    if platform.system() == 'Windows':
        os.system('')
    
    if not USE_GRADIENTS:
        if gradient_type == "winter":
            print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")
        elif gradient_type == "error":
            print(f"{Fore.RED}{text}{Style.RESET_ALL}")
        elif gradient_type == "success":
            print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}{text}{Style.RESET_ALL}")
        return
    
  
    if gradient_type == "winter":
        colors = Colors.cyan_to_blue
    elif gradient_type == "error":
        colors = Colors.red_to_purple
    elif gradient_type == "success":
        colors = Colors.green_to_cyan
    else:
        colors = Colors.blue_to_purple
    
    try:
        
        clean_text = text.replace('\t', '    ')
        
       
        gradient_text = Colorate.Horizontal(colors, clean_text, 1)
        print(gradient_text)
    except Exception as e:
       
        if gradient_type == "winter":
            print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")
        elif gradient_type == "error":
            print(f"{Fore.RED}{text}{Style.RESET_ALL}")
        elif gradient_type == "success":
            print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}{text}{Style.RESET_ALL}")

def print_banner() -> None:
 
    clear_screen()
    print_gradient_text(get_banner())
    print_gradient_text("=" * 100)
    print()

def center_text(text: str) -> str:
    
    try:
        return Center.XCenter(text)
    except:
    
        terminal_width = os.get_terminal_size().columns
        lines = text.split('\n')
        centered_lines = []
        for line in lines:
            padding = (terminal_width - len(line)) // 2
            if padding > 0:
                centered_lines.append(' ' * padding + line)
            else:
                centered_lines.append(line)
        return '\n'.join(centered_lines)

def box_text(text: str) -> str:
 
    try:
        return Box.DoubleCube(text)
    except:
     
        lines = text.strip().split('\n')
        width = max(len(line) for line in lines) + 4
        
        box_top = "╔" + "═" * (width - 2) + "╗"
        box_bottom = "╚" + "═" * (width - 2) + "╝"
        
        result = [box_top, "║" + " " * (width - 2) + "║"]
        
        for line in lines:
            padded_line = line + " " * (width - 2 - len(line))
            result.append("║ " + padded_line + " ║")
        
        result.extend(["║" + " " * (width - 2) + "║", box_bottom])
        return '\n'.join(result)

def print_menu() -> None:
 
    menu = """
    [1] Port Scanner          - Scan for open ports on a target
    [2] Network Scanner       - Discover devices on your network
    [3] Service Detector      - Identify services running on open ports
    [4] Vulnerability Scanner - Advanced vulnerability checks
    [5] Traceroute            - Trace the route to a target
    [6] DNS Lookup            - Perform DNS lookups
    [7] Ping Sweep            - Check if hosts are online
    [8] Website Scanner       - Analyze and scan websites securely
    [9] Advanced Tools        - Additional specialized scanning tools
    [10] Reports              - View and manage scan reports
    [11] Scheduled Scans      - Set up and manage scheduled scans
    [12] Settings             - Configure scanner settings
    [0] Exit                  - Exit the program
    """
    
    try:
       
        boxed_menu = Center.XCenter(Box.DoubleCube(menu))
        print_gradient_text(boxed_menu)
    except:
        
        boxed_menu = center_text(box_text(menu))
        print_gradient_text(boxed_menu)

def print_advanced_menu() -> None:
  
    menu = """
    [1] Subdomain Enumeration - Discover subdomains of a target domain
    [2] Directory Bruteforce  - Find hidden directories and files
    [3] WAF Detection         - Identify web application firewalls
    [4] CMS Detection         - Detect content management systems
    [5] API Endpoint Discovery - Find API endpoints
    [6] OSINT Gathering       - Collect open-source intelligence
    [7] SSL/TLS Analyzer      - Check SSL/TLS configuration
    [8] Network Topology Map  - Create visual network maps
    [9] Fuzzing Tools         - Test applications with malformed input
    [10] IoT Scanner          - Specialized IoT device scanning
    [0] Back to Main Menu
    """
    
    try:
      
        boxed_menu = Center.XCenter(Box.DoubleCube(menu))
        print_gradient_text(boxed_menu)
    except:
        
        boxed_menu = center_text(box_text(menu))
        print_gradient_text(boxed_menu)

def print_loading(message: str = "Loading", duration: int = 3) -> None:
  
    for i in range(duration):
        for char in ['|', '/', '-', '\\']:
            clear_screen()
            print_gradient_text(f"\n\n{message} {char}\n\n")
            time.sleep(0.1)

def get_input(prompt: str) -> str:
   
   
    try:
        username = os.getlogin()
    except:
        username = "user"
    

    styled_prompt = f"{username}@WinterScanner ~ > "
    
 
    if prompt:
        print(f"[?] {prompt}")
    
 
    return input(styled_prompt)


def check_for_updates() -> bool:
    try:
        version_url = "https://raw.githubusercontent.com/WinterCuz/WinterScanner/refs/heads/main/version.txt"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(version_url, headers=headers, timeout=5)
        
       
        if response.status_code != 200:
            print_error(f"Failed to check for updates (Status code: {response.status_code})")
            return False
            
        latest_version = response.text.strip()
        
    
        if not latest_version or len(latest_version) > 10:
            print_error("Invalid version format received")
            return False
        
        if latest_version > VERSION:
            print_gradient_text(f"New version {latest_version} available!")
            update = get_input("Would you like to update? (y/n)").lower()
            
            if update == 'y':
                return perform_update(latest_version)
        else:
            print_info("You are running the latest version!")
            
        return False
    except Exception as e:
        print_error(f"Error checking for updates: {str(e)}")
        return False

def perform_update(new_version: str) -> bool:

    try:
        print_loading("Downloading update", 2)
        
        update_url = "https://raw.githubusercontent.com/WinterCuz/WinterScanner/refs/heads/main/main.py"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(update_url, headers=headers)
        
        if response.status_code != 200:
            print_error(f"Failed to download update (Status code: {response.status_code})")
            return False
        
    
        if not response.text.startswith("import") and "def" not in response.text:
            print_error("Invalid update file received")
            return False
        
     
        backup_path = f"winterscanner_backup_v{VERSION}.py"
        with open(backup_path, 'w', encoding='utf-8') as f:
            with open(sys.argv[0], 'r', encoding='utf-8') as current:
                f.write(current.read())
        
       
        with open(sys.argv[0], 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print_success(f"Update successful! Backup saved to {backup_path}")
        print_info("Restarting application...")
        
      
        os.execv(sys.executable, [sys.executable] + sys.argv)
        return True
    except Exception as e:
        print_error(f"Error during update: {str(e)}")
        return False




def print_info(message: str) -> None:
  
    print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
    logger.info(message)

def print_success(message: str) -> None:
 
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
    logger.info(message)

def print_error(message: str) -> None:
   
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
    logger.error(message)

def print_warning(message: str) -> None:
 
    print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    logger.warning(message)

def print_result_table(headers: List[str], rows: List[List[str]]) -> None:
 
  
    col_widths = [max(len(str(row[i])) for row in [headers] + rows) + 2 for i in range(len(headers))]
    

    header_line = "│"
    for i, header in enumerate(headers):
        header_line += f" {header.center(col_widths[i])} │"
    
    separator = "┌"
    for width in col_widths:
        separator += "─" * (width + 2) + "┬"
    separator = separator[:-1] + "┐"
    
    bottom_separator = "└"
    for width in col_widths:
        bottom_separator += "─" * (width + 2) + "┴"
    bottom_separator = bottom_separator[:-1] + "┘"
    
    mid_separator = "├"
    for width in col_widths:
        mid_separator += "─" * (width + 2) + "┼"
    mid_separator = mid_separator[:-1] + "┤"
    
    print_gradient_text(separator)
    print_gradient_text(header_line)
    print_gradient_text(mid_separator)
    

    for row in rows:
        row_line = "│"
        for i, cell in enumerate(row):
            row_line += f" {str(cell).center(col_widths[i])} │"
        print_gradient_text(row_line)
    
    print_gradient_text(bottom_separator)


def load_proxies(file_path: str = "proxies.txt") -> List[str]:

    proxies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                proxy = line.strip()
                if proxy:
                    proxies.append(proxy)
        return proxies
    except:
        return []

def get_next_proxy() -> Dict[str, str]:

    global CURRENT_PROXY_INDEX, PROXY_LIST
    
    if not PROXY_LIST or not USE_PROXIES:
        return {}
    
    proxy = PROXY_LIST[CURRENT_PROXY_INDEX]
    CURRENT_PROXY_INDEX = (CURRENT_PROXY_INDEX + 1) % len(PROXY_LIST)
    
    return {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}"
    }

def get_random_user_agent() -> str:
    return ua.random

def setup_tor_connection() -> bool:
    global TOR_ENABLED, TOR_PORT
    
    if not TOR_ENABLED:
        return False
    
    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', TOR_PORT))
        sock.close()
        
        if result != 0:
            print_error(f"Tor is not running on port {TOR_PORT}")
            return False
        
  
        proxies = {
            'http': f'socks5h://127.0.0.1:{TOR_PORT}',
            'https': f'socks5h://127.0.0.1:{TOR_PORT}'
        }
        

        response = requests.get('https://check.torproject.org/', proxies=proxies, timeout=10)
        if 'Congratulations' in response.text:
            print_success("Successfully connected through Tor network")
            return True
        else:
            print_error("Connected to Tor, but traffic is not routing properly")
            return False
    
    except Exception as e:
        print_error(f"Error setting up Tor connection: {str(e)}")
        return False

def secure_request(url: str, method: str = "GET", headers: Dict = None, data: Dict = None, 
                  verify: bool = True, allow_redirects: bool = True, timeout: int = 10) -> requests.Response:
    if headers is None:
        headers = {}
    
   
    if 'User-Agent' not in headers:
        headers['User-Agent'] = get_random_user_agent()
    
   
    headers.update({
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'DNT': '1', 
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0'
    })
    
 
    proxies = {}
    if TOR_ENABLED:
        proxies = {
            'http': f'socks5h://127.0.0.1:{TOR_PORT}',
            'https': f'socks5h://127.0.0.1:{TOR_PORT}'
        }
    elif USE_PROXIES:
        proxies = get_next_proxy()
    

    if RANDOMIZE_SCAN_DELAY:
        time.sleep(random.uniform(MIN_SCAN_DELAY, MAX_SCAN_DELAY))
    
    try:
        if method.upper() == "GET":
            response = requests.get(
                url, 
                headers=headers, 
                proxies=proxies,
                verify=verify,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
        elif method.upper() == "POST":
            response = requests.post(
                url, 
                headers=headers, 
                data=data,
                proxies=proxies,
                verify=verify,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
        elif method.upper() == "HEAD":
            response = requests.head(
                url, 
                headers=headers, 
                proxies=proxies,
                verify=verify,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
        elif method.upper() == "PUT":
            response = requests.put(
                url, 
                headers=headers, 
                data=data,
                proxies=proxies,
                verify=verify,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
        elif method.upper() == "DELETE":
            response = requests.delete(
                url, 
                headers=headers, 
                proxies=proxies,
                verify=verify,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
        elif method.upper() == "OPTIONS":
            response = requests.options(
                url, 
                headers=headers, 
                proxies=proxies,
                verify=verify,
                allow_redirects=allow_redirects,
                timeout=timeout
            )
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        return response
    except requests.exceptions.RequestException as e:

        if USE_PROXIES or TOR_ENABLED:
            try:
                if method.upper() == "GET":
                    return requests.get(url, headers=headers, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
                elif method.upper() == "POST":
                    return requests.post(url, headers=headers, data=data, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
                elif method.upper() == "HEAD":
                    return requests.head(url, headers=headers, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
                elif method.upper() == "PUT":
                    return requests.put(url, headers=headers, data=data, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
                elif method.upper() == "DELETE":
                    return requests.delete(url, headers=headers, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
                elif method.upper() == "OPTIONS":
                    return requests.options(url, headers=headers, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
            except:
                pass
        raise e

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_hostname(hostname: str) -> bool:
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def is_valid_url(url: str) -> bool:
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_ip_from_hostname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def scan_port(ip: str, port: int, timeout: float = SCAN_TIMEOUT) -> Tuple[int, bool, Optional[str]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = identify_service(ip, port)
            return port, True, service
        return port, False, None
    except:
        return port, False, None
    finally:
        sock.close()

def identify_service(ip: str, port: int) -> str:
    service = COMMON_SERVICES.get(port, "Unknown")
    
   
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        
        
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if banner:
            return f"{service} ({banner.split('\n')[0]})"
        return service
    except:
        return service
    finally:
        try:
            sock.close()
        except:
            pass

def scan_network(network: str) -> List[Dict[str, str]]:
    try:
      
        arp_request = scapy.ARP(pdst=network)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        devices = []
        for sent, received in answered_list:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        return devices
    except Exception as e:
        print_error(f"Error scanning network: {str(e)}")
        return []

def get_mac_vendor(mac: str) -> str:
    try:
        mac_prefix = mac.replace(':', '').replace('-', '').replace('.', '').upper()[:6]
        response = secure_request(f"https://api.macvendors.com/{mac_prefix}", timeout=2)
        
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except:
        return "Unknown"

def perform_traceroute(target: str, max_hops: int = 30) -> List[Dict[str, Union[int, str, float]]]:
    results = []
    
    if platform.system().lower() == "windows":
       
        output = subprocess.check_output(f"tracert -d -h {max_hops} {target}", shell=True).decode('utf-8', errors='ignore')
        lines = output.split('\n')
        
        for line in lines:
            if line.strip() and line[0].isdigit():
                parts = line.strip().split()
                if len(parts) >= 8:
                    hop = int(parts[0])
                    try:
                        ip = parts[7]
                        if ip == '*':
                            ip = "Request timed out"
                        time_ms = float(parts[6].replace('ms', ''))
                    except:
                        ip = "Request timed out"
                        time_ms = 0
                    
                    results.append({
                        'hop': hop,
                        'ip': ip,
                        'time_ms': time_ms
                    })
    else:
        output = subprocess.check_output(f"traceroute -n -m {max_hops} {target}", shell=True).decode('utf-8', errors='ignore')
        lines = output.split('\n')
        
        for line in lines:
            if line.strip() and line[0].isdigit():
                parts = line.strip().split()
                if len(parts) >= 4:
                    hop = int(parts[0])
                    ip = parts[1]
                    if ip == '*':
                        ip = "Request timed out"
                    
                    try:
                        time_ms = float(parts[2].replace('ms', ''))
                    except:
                        time_ms = 0
                    
                    results.append({
                        'hop': hop,
                        'ip': ip,
                        'time_ms': time_ms
                    })
    
    return results

def perform_dns_lookup(domain: str) -> Dict[str, List[str]]:
    results = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'NS': [],
        'TXT': [],
        'CNAME': [],
        'SOA': [],
        'PTR': []
    }
    
    try:
      
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            results['A'].append(str(rdata))
    except:
        pass
    
    try:
      
        answers = dns.resolver.resolve(domain, 'AAAA')
        for rdata in answers:
            results['AAAA'].append(str(rdata))
    except:
        pass
    
    try:
       
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            results['MX'].append(f"{rdata.preference} {rdata.exchange}")
    except:
        pass
    
    try:
        
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            results['NS'].append(str(rdata))
    except:
        pass
    
    try:
       
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            results['TXT'].append(str(rdata))
    except:
        pass
    
    try:
      
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            results['CNAME'].append(str(rdata))
    except:
        pass
    
    try:
        
        answers = dns.resolver.resolve(domain, 'SOA')
        for rdata in answers:
            results['SOA'].append(str(rdata))
    except:
        pass
    
    try:
        
        if is_valid_ip(domain):
            arpa = '.'.join(reversed(domain.split('.'))) + '.in-addr.arpa'
            answers = dns.resolver.resolve(arpa, 'PTR')
            for rdata in answers:
                results['PTR'].append(str(rdata))
    except:
        pass
    
    return results

def ping_host(ip: str) -> Tuple[str, bool, float]:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    
    start_time = time.time()
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        end_time = time.time()
        return ip, True, (end_time - start_time) * 1000  
    except subprocess.CalledProcessError:
        return ip, False, 0

def check_common_vulnerabilities(ip: str, open_ports: List[int]) -> List[Dict[str, str]]:
    vulnerabilities = []
    
   
    for port in open_ports:
        if port == 21:
       
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(ip, 21, timeout=5)
                try:
                    ftp.login('anonymous', 'anonymous@example.com')
                    vulnerabilities.append({
                        'port': port,
                        'service': 'FTP',
                        'vulnerability': 'Anonymous FTP login allowed',
                        'severity': 'Medium',
                        'description': 'The FTP server allows anonymous logins, which could allow unauthorized access to files.',
                        'recommendation': 'Disable anonymous FTP access if not required.'
                    })
                except:
                    pass
                ftp.quit()
            except:
                pass
        
        elif port == 22:
          
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
              
                common_credentials = [
                    ('root', 'root'),
                    ('admin', 'admin'),
                    ('user', 'user'),
                    ('ubuntu', 'ubuntu'),
                    ('pi', 'raspberry')
                ]
                
                for username, password in common_credentials:
                    try:
                        ssh.connect(ip, port=22, username=username, password=password, timeout=3)
                        vulnerabilities.append({
                            'port': port,
                            'service': 'SSH',
                            'vulnerability': f'Weak credentials: {username}/{password}',
                            'severity': 'High',
                            'description': f'SSH server accepts login with weak credentials: {username}/{password}',
                            'recommendation': 'Change default passwords and implement strong password policies.'
                        })
                        ssh.close()
                        break
                    except:
                        pass
            except:
                pass
        
        elif port == 23:
            vulnerabilities.append({
                'port': port,
                'service': 'Telnet',
                'vulnerability': 'Telnet service running (cleartext protocol)',
                'severity': 'High',
                'description': 'Telnet transmits data in cleartext, including passwords.',
                'recommendation': 'Replace Telnet with SSH for secure remote access.'
            })
        
        elif port == 25 or port == 587:
         
            try:
                import smtplib
                server = smtplib.SMTP(ip, port, timeout=5)
                server.ehlo()
                
                try:
                   
                    server.sendmail('test@example.com', 'test@example.net', 'Subject: Test\n\nTest message')
                    vulnerabilities.append({
                        'port': port,
                        'service': 'SMTP',
                        'vulnerability': 'Open relay detected',
                        'severity': 'Critical',
                        'description': 'The SMTP server is configured as an open relay, which can be abused for spam.',
                        'recommendation': 'Configure the SMTP server to prevent unauthorized relaying.'
                    })
                except:
                    pass
                
                server.quit()
            except:
                pass
        
        elif port == 80 or port == 8080 or port == 443:
           
            try:
                protocol = 'https' if port == 443 else 'http'
                response = secure_request(f"{protocol}://{ip}:{port}/", timeout=5)
                server = response.headers.get('Server', '')
                
                if server:
                    vulnerabilities.append({
                        'port': port,
                        'service': 'HTTP/HTTPS',
                        'vulnerability': f'Server information disclosure: {server}',
                        'severity': 'Low',
                        'description': 'The server reveals version information which can help attackers identify vulnerabilities.',
                        'recommendation': 'Configure the server to hide version information.'
                    })
                
              
                try:
                    response = secure_request(f"{protocol}://{ip}:{port}/images/", timeout=5)
                    if 'Index of' in response.text or 'Directory Listing' in response.text:
                        vulnerabilities.append({
                            'port': port,
                            'service': 'HTTP/HTTPS',
                            'vulnerability': 'Directory listing enabled',
                            'severity': 'Medium',
                            'description': 'Directory listing is enabled, which may expose sensitive files.',
                            'recommendation': 'Disable directory listing in the web server configuration.'
                        })
                except:
                    pass
                
            
                sensitive_files = ['/robots.txt', '/sitemap.xml', '/.git/HEAD', '/.env', '/wp-config.php', '/config.php']
                for file in sensitive_files:
                    try:
                        response = secure_request(f"{protocol}://{ip}:{port}{file}", timeout=2)
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'port': port,
                                'service': 'HTTP/HTTPS',
                                'vulnerability': f'Sensitive file exposed: {file}',
                                'severity': 'Medium',
                                'description': f'The file {file} is accessible and may contain sensitive information.',
                                'recommendation': f'Restrict access to {file} or remove it if not needed.'
                            })
                    except:
                        pass
            except:
                pass
        
        elif port == 445:
         
            vulnerabilities.append({
                'port': port,
                'service': 'SMB',
                'vulnerability': 'SMB service might be vulnerable to various exploits (EternalBlue, etc.)',
                'severity': 'Info',
                'description': 'SMB services have historically been vulnerable to critical exploits.',
                'recommendation': 'Ensure SMB is patched to the latest version and disable SMBv1.'
            })
            
           
            try:
                cmd = ['smbclient', '-L', ip, '-N']
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                if result.returncode == 0 and b'Sharename' in result.stdout:
                    vulnerabilities.append({
                        'port': port,
                        'service': 'SMB',
                        'vulnerability': 'SMB null session allowed',
                        'severity': 'High',
                        'description': 'The SMB server allows null sessions, which can be used to enumerate users and shares.',
                        'recommendation': 'Disable null sessions in the SMB configuration.'
                    })
            except:
                pass
        
        elif port == 3306:
         
            try:
                import mysql.connector
                common_credentials = [
                    ('root', ''),
                    ('root', 'root'),
                    ('root', 'password'),
                    ('admin', 'admin')
                ]
                
                for username, password in common_credentials:
                    try:
                        conn = mysql.connector.connect(
                            host=ip,
                            user=username,
                            password=password,
                            database='mysql',
                            connection_timeout=3
                        )
                        vulnerabilities.append({
                            'port': port,
                            'service': 'MySQL',
                            'vulnerability': f'Weak credentials: {username}/{password}',
                            'severity': 'High',
                            'description': f'MySQL server accepts login with weak credentials: {username}/{password}',
                            'recommendation': 'Change default passwords and implement strong password policies.'
                        })
                        conn.close()
                        break
                    except:
                        pass
            except:
                pass
        
        elif port == 3389:
           
            vulnerabilities.append({
                'port': port,
                'service': 'RDP',
                'vulnerability': 'Remote Desktop Protocol exposed',
                'severity': 'Medium',
                'description': 'RDP is exposed and could be subject to brute force attacks or exploits.',
                'recommendation': 'Use a VPN or firewall to restrict RDP access to trusted IPs.'
            })
    
    return vulnerabilities


def subdomain_enumeration(domain: str, techniques: List[str] = None, wordlist_path: str = None) -> List[str]:
    """
    Discover subdomains using multiple techniques.
    
    Args:
        domain: Target domain
        techniques: List of techniques to use (dns_brute, cert_transparency, search_engines)
        wordlist_path: Path to subdomain wordlist for brute forcing
    
    Returns:
        List of discovered subdomains
    """
    if techniques is None:
        techniques = ["dns_brute", "cert_transparency", "search_engines"]
    
    discovered_subdomains = set()
    
    print_info(f"Starting subdomain enumeration for {domain}")
    

    if wordlist_path is None:
        wordlist_path = os.path.join(WORDLISTS_DIR, "subdomains-top1000.txt")
        if not os.path.exists(wordlist_path):
            
            os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
            with open(wordlist_path, 'w') as f:
                f.write("www\nmail\nblog\nshop\nadmin\napi\ndev\nstage\ntest\ndocs\n")
    
   
    if "dns_brute" in techniques:
        print_info("Performing DNS brute force enumeration...")
        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            def check_subdomain(subdomain):
                try:
                    target = f"{subdomain}.{domain}"
                    dns.resolver.resolve(target, 'A')
                    return target
                except:
                    return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                results = executor.map(check_subdomain, subdomains)
                
                for result in results:
                    if result:
                        discovered_subdomains.add(result)
                        print_success(f"Found subdomain: {result}")
        
        except Exception as e:
            print_error(f"Error during DNS brute force: {str(e)}")
    
  
    if "cert_transparency" in techniques:
        print_info("Querying certificate transparency logs...")
        try:
            ct_apis = [
                f"https://crt.sh/?q=%.{domain}&output=json",
                f"https://certspotter.com/api/v0/certs?domain={domain}"
            ]
            
            for api_url in ct_apis:
                response = secure_request(api_url, timeout=10)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "crt.sh" in api_url:
                            for entry in data:
                                name_value = entry.get('name_value', '')
                                if name_value:
                                   
                                    for subdomain in name_value.split('\n'):
                                        if subdomain.endswith(f".{domain}"):
                                            discovered_subdomains.add(subdomain)
                                            print_success(f"Found subdomain: {subdomain}")
                        elif "certspotter" in api_url:
                            for entry in data:
                                for dns_name in entry.get('dns_names', []):
                                    if dns_name.endswith(f".{domain}"):
                                        discovered_subdomains.add(dns_name)
                                        print_success(f"Found subdomain: {dns_name}")
                    except:
                        pass
        except Exception as e:
            print_error(f"Error querying certificate transparency logs: {str(e)}")
    
    
    if "search_engines" in techniques:
        print_info("Searching for subdomains in search engine results...")
        try:
            search_url = f"https://www.google.com/search?q=site%3A{domain}"
            headers = {
                'User-Agent': get_random_user_agent()
            }
            response = secure_request(search_url, headers=headers, timeout=10)
            if response.status_code == 200:
                
                pattern = re.compile(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+' + re.escape(domain))
                for match in pattern.finditer(response.text):
                    subdomain = match.group(0)
                    discovered_subdomains.add(subdomain)
                    print_success(f"Found subdomain: {subdomain}")
        except Exception as e:
            print_error(f"Error searching for subdomains: {str(e)}")
    
    return list(discovered_subdomains)

def directory_bruteforce(url: str, wordlist_path: str = None, extensions: List[str] = None, 
                         recursion_level: int = 1) -> List[Dict[str, Any]]:
    """
    Scan websites for hidden directories and files.
    
    Args:
        url: Target URL
        wordlist_path: Path to directory/file wordlist
        extensions: List of file extensions to check
        recursion_level: How deep to recurse into discovered directories
    
    Returns:
        List of discovered directories and files
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    if not url.endswith('/'):
        url += '/'
    
    if extensions is None:
        extensions = ['', '.php', '.html', '.js', '.txt', '.xml', '.json']
    
    if wordlist_path is None:
        wordlist_path = os.path.join(WORDLISTS_DIR, "directories-top1000.txt")
        if not os.path.exists(wordlist_path):
           
            os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
            with open(wordlist_path, 'w') as f:
                f.write("admin\nwp-admin\nlogin\nbackup\nwp-content\nimages\njs\ncss\napi\nstatic\nassets\n")
    
    print_info(f"Starting directory bruteforce on {url}")
    print_info(f"Using wordlist: {wordlist_path}")
    print_info(f"Extensions: {', '.join(extensions)}")
    
    discovered = []
    visited = set()
    
    try:
        with open(wordlist_path, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        
       
        paths_to_check = []
        for word in wordlist:
            for ext in extensions:
                paths_to_check.append(word + ext)
        
        print_info(f"Testing {len(paths_to_check)} paths...")
        
        def check_path(path):
            target_url = url + path
            if target_url in visited:
                return None
            
            visited.add(target_url)
            
            try:
                response = secure_request(target_url, method="HEAD", timeout=5, allow_redirects=False)
                status_code = response.status_code
                
                if status_code < 400: 
                   
                    if 300 <= status_code < 400:
                        content_length = 0
                        redirect_url = response.headers.get('Location', '')
                    else:
                        get_response = secure_request(target_url, method="GET", timeout=5)
                        content_length = len(get_response.content)
                        redirect_url = ""
                    
                    result = {
                        'url': target_url,
                        'status_code': status_code,
                        'content_length': content_length,
                        'redirect_url': redirect_url,
                        'is_directory': path.endswith('/')
                    }
                    
                    return result
            except:
                pass
            
            return None
        
      
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            results = list(executor.map(check_path, paths_to_check))
            
            for result in results:
                if result:
                    discovered.append(result)
                    status_desc = {
                        200: "OK",
                        201: "Created",
                        204: "No Content",
                        301: "Moved Permanently",
                        302: "Found",
                        307: "Temporary Redirect",
                        308: "Permanent Redirect",
                        403: "Forbidden",
                    }.get(result['status_code'], "")
                    
                    print_success(f"Found: {result['url']} [{result['status_code']} {status_desc}] - Size: {result['content_length']} bytes")
        
      
        if recursion_level > 0:
            directories = [d['url'] for d in discovered if d['is_directory']]
            for directory in directories:
                print_info(f"Recursively scanning directory: {directory}")
                sub_results = directory_bruteforce(directory, wordlist_path, extensions, recursion_level - 1)
                discovered.extend(sub_results)
        
    except Exception as e:
        print_error(f"Error during directory bruteforce: {str(e)}")
    
    return discovered

def detect_waf(url: str) -> Dict[str, Any]:
    """
    Detect if a website is protected by a WAF and identify which one.
    
    Args:
        url: Target URL
    
    Returns:
        Dictionary with WAF detection results
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print_info(f"Detecting WAF on {url}")
    
 
    waf_signatures = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'cookies': ['__cfduid', '__cf_bm'],
            'patterns': ['cloudflare', 'cloudflare-nginx']
        },
        'Akamai': {
            'headers': ['x-akamai-transformed', 'akamai-origin-hop'],
            'cookies': ['ak_bmsc', 'bm_sz', 'akm_push'],
            'patterns': []
        },
        'Imperva/Incapsula': {
            'headers': ['x-iinfo', 'x-cdn'],
            'cookies': ['incap_ses', 'visid_incap'],
            'patterns': ['incapsula', 'imperva']
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'cookies': [],
            'patterns': ['sucuri']
        },
        'F5 BIG-IP ASM': {
            'headers': ['x-wa-info'],
            'cookies': ['TS', 'BIGipServer'],
            'patterns': []
        },
        'AWS WAF': {
            'headers': ['x-amzn-waf-action'],
            'cookies': [],
            'patterns': []
        },
        'ModSecurity': {
            'headers': [],
            'cookies': [],
            'patterns': ['mod_security', 'modsecurity']
        }
    }
    
   
    test_payloads = [
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "/?param=../../etc/passwd",
        "/?param=<script>alert(1)</script>",
        "/?param=' OR 1=1 --"
    ]
    
    results = {
        'protected': False,
        'waf_detected': None,
        'confidence': 0,
        'evidence': []
    }
    
    try:
    
        normal_response = secure_request(url, timeout=10)
        
      
        for waf_name, signatures in waf_signatures.items():
         
            for header in signatures['headers']:
                if header.lower() in [h.lower() for h in normal_response.headers]:
                    results['evidence'].append(f"Found {waf_name} header: {header}")
                    results['protected'] = True
                    results['waf_detected'] = waf_name
                    results['confidence'] += 30
            
            
            for cookie in signatures['cookies']:
                if cookie in [c.name for c in normal_response.cookies]:
                    results['evidence'].append(f"Found {waf_name} cookie: {cookie}")
                    results['protected'] = True
                    results['waf_detected'] = waf_name
                    results['confidence'] += 30
            
           
            for pattern in signatures['patterns']:
                if pattern.lower() in normal_response.text.lower():
                    results['evidence'].append(f"Found {waf_name} pattern in response: {pattern}")
                    results['protected'] = True
                    results['waf_detected'] = waf_name
                    results['confidence'] += 20
        
       
        for payload in test_payloads:
            try:
             
                test_url = f"{url}{payload}"
                payload_response = secure_request(test_url, timeout=5)
                
             
                if payload_response.status_code in [403, 406, 429, 503]:
                    results['evidence'].append(f"Payload '{payload}' triggered status code {payload_response.status_code}")
                    results['protected'] = True
                    results['confidence'] += 10
                
           
                block_indicators = ['blocked', 'security', 'firewall', 'waf', 'attack', 'violation', 'suspicious']
                for indicator in block_indicators:
                    if indicator in payload_response.text.lower():
                        results['evidence'].append(f"Payload '{payload}' triggered block message containing '{indicator}'")
                        results['protected'] = True
                        results['confidence'] += 15
            
            except requests.exceptions.RequestException:
             
                results['evidence'].append(f"Payload '{payload}' caused connection error (possible WAF block)")
                results['protected'] = True
                results['confidence'] += 5
        
   
        results['confidence'] = min(results['confidence'], 100)
        
    
        if results['protected'] and not results['waf_detected']:
            results['waf_detected'] = "Generic WAF/Security Solution"
        
       
        if results['protected']:
            print_success(f"WAF detected: {results['waf_detected']} (Confidence: {results['confidence']}%)")
            for evidence in results['evidence']:
                print_info(f"Evidence: {evidence}")
        else:
            print_warning("No WAF detected")
        
    except Exception as e:
        print_error(f"Error during WAF detection: {str(e)}")
    
    return results

def detect_cms(url: str) -> Dict[str, Any]:
    """
    Identify content management systems and scan for known vulnerabilities.
    
    Args:
        url: Target URL
    
    Returns:
        Dictionary with CMS detection results and vulnerabilities
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print_info(f"Detecting CMS on {url}")
    
    cms_signatures = {
        'WordPress': {
            'paths': ['/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/'],
            'headers': [],
            'meta': ['name="generator" content="WordPress'],
            'patterns': ['wp-content', 'wp-includes']
        },
        'Joomla': {
            'paths': ['/administrator/', '/components/', '/modules/', '/templates/'],
            'headers': [],
            'meta': ['name="generator" content="Joomla'],
            'patterns': ['joomla']
        },
        'Drupal': {
            'paths': ['/user/login', '/admin/', '/sites/default/', '/sites/all/'],
            'headers': ['X-Drupal-Cache', 'X-Generator'],
            'meta': ['name="generator" content="Drupal'],
            'patterns': ['drupal']
        },
        'Magento': {
            'paths': ['/admin/', '/app/etc/', '/skin/', '/js/mage/'],
            'headers': [],
            'meta': ['name="generator" content="Magento'],
            'patterns': ['Mage.', 'magento']
        },
        'Shopify': {
            'paths': [],
            'headers': [],
            'meta': ['content="Shopify'],
            'patterns': ['shopify', 'Shopify.theme']
        },
        'PrestaShop': {
            'paths': ['/admin/', '/modules/', '/themes/'],
            'headers': [],
            'meta': ['name="generator" content="PrestaShop'],
            'patterns': ['prestashop']
        },
        'TYPO3': {
            'paths': ['/typo3/', '/fileadmin/'],
            'headers': [],
            'meta': ['name="generator" content="TYPO3'],
            'patterns': ['typo3']
        },
        'Ghost': {
            'paths': ['/ghost/'],
            'headers': [],
            'meta': ['content="Ghost'],
            'patterns': ['ghost-blog', 'ghost-frontend']
        }
    }
    
    results = {
        'cms_detected': None,
        'version': None,
        'confidence': 0,
        'evidence': [],
        'vulnerabilities': []
    }
    
    try:
      
        response = secure_request(url, timeout=10)
        
    
        for cms_name, signatures in cms_signatures.items():
         
            for pattern in signatures['patterns']:
                if pattern.lower() in response.text.lower():
                    results['evidence'].append(f"Found {cms_name} pattern: {pattern}")
                    results['cms_detected'] = cms_name
                    results['confidence'] += 10
            
            
            for meta in signatures['meta']:
                if meta.lower() in response.text.lower():
                    results['evidence'].append(f"Found {cms_name} meta tag: {meta}")
                    results['cms_detected'] = cms_name
                    results['confidence'] += 30
                    
          
                    version_match = re.search(r'content="[^"]+ ([0-9.]+)"', response.text)
                    if version_match:
                        results['version'] = version_match.group(1)
                        results['evidence'].append(f"Found version: {results['version']}")
            
           
            for header in signatures['headers']:
                if header.lower() in [h.lower() for h in response.headers]:
                    results['evidence'].append(f"Found {cms_name} header: {header}")
                    results['cms_detected'] = cms_name
                    results['confidence'] += 20
        
      
        if not results['cms_detected'] or results['confidence'] < 50:
            for cms_name, signatures in cms_signatures.items():
                for path in signatures['paths']:
                    try:
                        path_url = url.rstrip('/') + path
                        path_response = secure_request(path_url, method="HEAD", timeout=5)
                        
                        if path_response.status_code < 400:
                            results['evidence'].append(f"Found {cms_name} path: {path}")
                            results['cms_detected'] = cms_name
                            results['confidence'] += 15
                    except:
                        pass
        
        
        results['confidence'] = min(results['confidence'], 100)
        
       
        if results['cms_detected']:
            print_success(f"CMS detected: {results['cms_detected']} (Confidence: {results['confidence']}%)")
            
            if results['version']:
                print_info(f"Version: {results['version']}")
            
           
            if results['cms_detected'] == 'WordPress':
                
                wp_plugins = []
                plugin_pattern = re.compile(r'wp-content/plugins/([^/]+)/')
                for match in plugin_pattern.finditer(response.text):
                    plugin = match.group(1)
                    if plugin not in wp_plugins:
                        wp_plugins.append(plugin)
                
                if wp_plugins:
                    print_info(f"WordPress plugins detected: {', '.join(wp_plugins)}")
                    results['evidence'].append(f"WordPress plugins: {', '.join(wp_plugins)}")
                    
                
                    vulnerable_plugins = {
                        'contact-form-7': 'SQL Injection vulnerability in versions < 5.3.2',
                        'wp-file-manager': 'Remote code execution in versions < 6.9',
                        'elementor': 'XSS vulnerability in versions < 3.1.1',
                        'woocommerce': 'SQL Injection in versions < 5.5.1',
                        'yoast-seo': 'XSS vulnerability in versions < 16.2',
                        'wordfence': 'Authentication bypass in versions < 7.4.6'
                    }
                    
                    for plugin in wp_plugins:
                        if plugin in vulnerable_plugins:
                            vuln = {
                                'component': plugin,
                                'description': vulnerable_plugins[plugin],
                                'severity': 'High'
                            }
                            results['vulnerabilities'].append(vuln)
                            print_warning(f"Potential vulnerability in {plugin}: {vulnerable_plugins[plugin]}")
            
            elif results['cms_detected'] == 'Joomla':
            
                if results['version']:
                    version = results['version']
                    if version.startswith('3.') and float(version[2:]) < 9.24:
                        vuln = {
                            'component': 'Joomla Core',
                            'description': f'Multiple vulnerabilities in Joomla {version}',
                            'severity': 'High'
                        }
                        results['vulnerabilities'].append(vuln)
                        print_warning(f"Potential vulnerability in Joomla {version}")
            
            elif results['cms_detected'] == 'Drupal':
         
                if results['version']:
                    version = results['version']
                    if version.startswith('7.') and float(version[2:]) < 78:
                        vuln = {
                            'component': 'Drupal Core',
                            'description': f'Multiple vulnerabilities in Drupal {version}',
                            'severity': 'High'
                        }
                        results['vulnerabilities'].append(vuln)
                        print_warning(f"Potential vulnerability in Drupal {version}")
        else:
            print_warning("No CMS detected")
        
       
        if results['vulnerabilities']:
            print_warning(f"Found {len(results['vulnerabilities'])} potential vulnerabilities")
            for vuln in results['vulnerabilities']:
                print_warning(f"{vuln['component']}: {vuln['description']} (Severity: {vuln['severity']})")
        
    except Exception as e:
        print_error(f"Error during CMS detection: {str(e)}")
    
    return results

def discover_api_endpoints(url: str) -> List[Dict[str, Any]]:
    """
    Discover and test API endpoints on web applications.
    
    Args:
        url: Target URL
    
    Returns:
        List of discovered API endpoints
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print_info(f"Discovering API endpoints on {url}")
    
   
    api_paths = [
        '/api/',
        '/api/v1/',
        '/api/v2/',
        '/api/v3/',
        '/rest/',
        '/rest/v1/',
        '/rest/v2/',
        '/graphql',
        '/graphql/console',
        '/v1/',
        '/v2/',
        '/swagger/',
        '/swagger-ui/',
        '/swagger-ui.html',
        '/api-docs/',
        '/api/docs/',
        '/docs/',
        '/openapi.json',
        '/swagger.json',
        '/api/swagger.json',
        '/api-docs.json',
        '/openapi.yaml',
        '/swagger.yaml'
    ]
    
  
    common_endpoints = [
        'users',
        'user',
        'accounts',
        'account',
        'products',
        'product',
        'items',
        'item',
        'orders',
        'order',
        'customers',
        'customer',
        'auth',
        'login',
        'register',
        'signup',
        'data',
        'info',
        'status',
        'health',
        'config',
        'settings',
        'admin'
    ]
    
    discovered_endpoints = []
    
    try:
       
        response = secure_request(url, timeout=10)
        
   
        js_files = []
        js_pattern = re.compile(r'<script[^>]+src="([^"]+\.js)"')
        for match in js_pattern.finditer(response.text):
            js_url = match.group(1)
            if js_url.startswith('/'):
                js_url = url.rstrip('/') + js_url
            elif not js_url.startswith(('http://', 'https://')):
                js_url = url.rstrip('/') + '/' + js_url
            js_files.append(js_url)
        
        
        api_patterns = [
            r'url:\s*[\'"]([^\'"\s]+api[^\'"\s]+)[\'"]',
            r'endpoint:\s*[\'"]([^\'"\s]+)[\'"]',
            r'\.get\([\'"]([^\'"\s]+)[\'"]\)',
            r'\.post\([\'"]([^\'"\s]+)[\'"]\)',
            r'\.ajax\([\'"]([^\'"\s]+)[\'"]\)',
            r'fetch\([\'"]([^\'"\s]+)[\'"]\)'
        ]
        
        for js_url in js_files:
            try:
                js_response = secure_request(js_url, timeout=5)
                if js_response.status_code == 200:
                    for pattern in api_patterns:
                        for match in re.finditer(pattern, js_response.text):
                            endpoint = match.group(1)
                            if endpoint not in [e['endpoint'] for e in discovered_endpoints]:
                                discovered_endpoints.append({
                                    'endpoint': endpoint,
                                    'source': 'JavaScript',
                                    'js_file': js_url,
                                    'methods': [],
                                    'parameters': [],
                                    'status_code': None
                                })
                                print_success(f"Found API endpoint in JS: {endpoint}")
            except:
                pass
        
       
        for path in api_paths:
            try:
                api_url = url.rstrip('/') + path
                response = secure_request(api_url, method="HEAD", timeout=5)
                
                if response.status_code < 400:
                    discovered_endpoints.append({
                        'endpoint': api_url,
                        'source': 'Common API path',
                        'methods': [],
                        'parameters': [],
                        'status_code': response.status_code
                    })
                    print_success(f"Found API path: {api_url} [{response.status_code}]")
                    
                 
                    for endpoint in common_endpoints:
                        endpoint_url = api_url.rstrip('/') + '/' + endpoint
                        try:
                            endpoint_response = secure_request(endpoint_url, method="HEAD", timeout=5)
                            if endpoint_response.status_code < 400:
                                discovered_endpoints.append({
                                    'endpoint': endpoint_url,
                                    'source': 'Common endpoint',
                                    'methods': [],
                                    'parameters': [],
                                    'status_code': endpoint_response.status_code
                                })
                                print_success(f"Found API endpoint: {endpoint_url} [{endpoint_response.status_code}]")
                        except:
                            pass
            except:
                pass
        
     
        swagger_paths = [
            '/swagger.json',
            '/api-docs.json',
            '/openapi.json',
            '/api/swagger.json',
            '/api/docs',
            '/swagger-ui.html'
        ]
        
        for path in swagger_paths:
            try:
                swagger_url = url.rstrip('/') + path
                response = secure_request(swagger_url, timeout=5)
                
                if response.status_code == 200:
                    print_success(f"Found API documentation: {swagger_url}")
                    
                
                    try:
                        swagger_data = response.json()
                        
                       
                        if 'paths' in swagger_data:
                            for path, methods in swagger_data['paths'].items():
                                for method, details in methods.items():
                                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                                        endpoint_url = url.rstrip('/') + path
                                        
                                  
                                        parameters = []
                                        if 'parameters' in details:
                                            for param in details['parameters']:
                                                parameters.append({
                                                    'name': param.get('name', ''),
                                                    'in': param.get('in', ''),
                                                    'required': param.get('required', False),
                                                    'type': param.get('type', '')
                                                })
                                        
                                        discovered_endpoints.append({
                                            'endpoint': endpoint_url,
                                            'source': 'Swagger/OpenAPI',
                                            'methods': [method.upper()],
                                            'parameters': parameters,
                                            'description': details.get('summary', ''),
                                            'status_code': None
                                        })
                                        
                                        print_success(f"Found API endpoint in docs: {method.upper()} {endpoint_url}")
                    except:
                        pass
            except:
                pass
        
    
        for i, endpoint in enumerate(discovered_endpoints):
            if 'status_code' not in endpoint or endpoint['status_code'] is None:
                try:
                    response = secure_request(endpoint['endpoint'], method="HEAD", timeout=5)
                    discovered_endpoints[i]['status_code'] = response.status_code
                except:
                    pass
            
         
            if not endpoint.get('methods'):
                methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
                supported_methods = []
                
                for method in methods_to_test:
                    try:
                        if method == 'OPTIONS':
                            response = secure_request(endpoint['endpoint'], method=method, timeout=5)
                            if response.status_code < 400:
                                supported_methods.append(method)
                            
                                allow_header = response.headers.get('Allow', '')
                                if allow_header:
                                    for allowed_method in allow_header.split(','):
                                        allowed_method = allowed_method.strip()
                                        if allowed_method and allowed_method not in supported_methods:
                                            supported_methods.append(allowed_method)
                        else:
                            response = secure_request(endpoint['endpoint'], method=method, timeout=5)
                            if response.status_code < 400 or response.status_code == 405:  
                                supported_methods.append(method)
                    except:
                        pass
                
                if supported_methods:
                    discovered_endpoints[i]['methods'] = supported_methods
                    print_info(f"Endpoint {endpoint['endpoint']} supports methods: {', '.join(supported_methods)}")
    
    except Exception as e:
        print_error(f"Error discovering API endpoints: {str(e)}")
    
    return discovered_endpoints

def analyze_ssl_tls(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Analyze SSL/TLS configuration of a server.
    
    Args:
        hostname: Target hostname
        port: Target port (default: 443)
    
    Returns:
        Dictionary with SSL/TLS analysis results
    """
    print_info(f"Analyzing SSL/TLS configuration for {hostname}:{port}")
    
    results = {
        'certificate': {},
        'protocols': {},
        'cipher_suites': [],
        'vulnerabilities': [],
        'grade': 'Unknown'
    }
    
    try:
        
        protocols_to_check = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        supported_protocols = []
        
        for protocol in protocols_to_check:
            try:
                context = ssl.SSLContext()
                if protocol == 'SSLv2':
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
                elif protocol == 'SSLv3':
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                elif protocol == 'TLSv1':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                elif protocol == 'TLSv1.1':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                elif protocol == 'TLSv1.2':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                elif protocol == 'TLSv1.3':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                
                with socket.create_connection((hostname, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported_protocols.append(protocol)
                        cipher = ssock.cipher()
                        results['cipher_suites'].append({
                            'protocol': protocol,
                            'cipher': cipher[0],
                            'bits': cipher[1]
                        })
                        print_success(f"Supported: {protocol} with cipher {cipher[0]} ({cipher[1]} bits)")
            except:
                print_info(f"Not supported: {protocol}")
        
        results['protocols'] = {protocol: (protocol in supported_protocols) for protocol in protocols_to_check}
        
     
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                
                results['certificate'] = {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'valid_from': cert['notBefore'],
                    'valid_until': cert['notAfter'],
                    'serial_number': cert['serialNumber'],
                    'signature_algorithm': ssock.context.get_ca_certs()[0]['signature_algorithm'] if ssock.context.get_ca_certs() else 'Unknown'
                }
                
                
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                
                if now < not_before:
                    results['vulnerabilities'].append({
                        'name': 'Certificate not yet valid',
                        'description': f"Certificate will be valid from {not_before}",
                        'severity': 'High'
                    })
                
                if now > not_after:
                    results['vulnerabilities'].append({
                        'name': 'Expired certificate',
                        'description': f"Certificate expired on {not_after}",
                        'severity': 'Critical'
                    })
                
             
                days_to_expiry = (not_after - now).days
                if 0 < days_to_expiry <= 30:
                    results['vulnerabilities'].append({
                        'name': 'Certificate expiring soon',
                        'description': f"Certificate will expire in {days_to_expiry} days",
                        'severity': 'Medium'
                    })
                
                print_info(f"Certificate: {results['certificate']['subject'].get('commonName', 'Unknown')}")
                print_info(f"Issuer: {results['certificate']['issuer'].get('commonName', 'Unknown')}")
                print_info(f"Valid from: {results['certificate']['valid_from']}")
                print_info(f"Valid until: {results['certificate']['valid_until']}")
        
        
        if results['protocols'].get('SSLv2', False):
            results['vulnerabilities'].append({
                'name': 'SSLv2 Supported',
                'description': 'SSLv2 is insecure and deprecated',
                'severity': 'Critical'
            })
        
        if results['protocols'].get('SSLv3', False):
            results['vulnerabilities'].append({
                'name': 'SSLv3 Supported',
                'description': 'SSLv3 is vulnerable to POODLE attack',
                'severity': 'Critical'
            })
        
        if results['protocols'].get('TLSv1', False):
            results['vulnerabilities'].append({
                'name': 'TLSv1.0 Supported',
                'description': 'TLSv1.0 is considered insecure',
                'severity': 'High'
            })
        
        if results['protocols'].get('TLSv1.1', False):
            results['vulnerabilities'].append({
                'name': 'TLSv1.1 Supported',
                'description': 'TLSv1.1 is considered outdated',
                'severity': 'Medium'
            })
        
    
        weak_ciphers = ['NULL', 'EXPORT', 'DES', 'RC4', 'MD5']
        for cipher_suite in results['cipher_suites']:
            for weak_cipher in weak_ciphers:
                if weak_cipher in cipher_suite['cipher']:
                    results['vulnerabilities'].append({
                        'name': f'Weak cipher supported: {cipher_suite["cipher"]}',
                        'description': f'The cipher {cipher_suite["cipher"]} is considered weak',
                        'severity': 'High'
                    })
        
    
        if any(v['severity'] == 'Critical' for v in results['vulnerabilities']):
            results['grade'] = 'F'
        elif any(v['severity'] == 'High' for v in results['vulnerabilities']):
            results['grade'] = 'D'
        elif any(v['severity'] == 'Medium' for v in results['vulnerabilities']):
            results['grade'] = 'C'
        elif results['protocols'].get('TLSv1.2', False) and results['protocols'].get('TLSv1.3', False):
            results['grade'] = 'A'
        elif results['protocols'].get('TLSv1.2', False):
            results['grade'] = 'B'
        else:
            results['grade'] = 'C'
        
        print_info(f"SSL/TLS Grade: {results['grade']}")
        
       
        if results['vulnerabilities']:
            print_warning(f"Found {len(results['vulnerabilities'])} SSL/TLS vulnerabilities")
            for vuln in results['vulnerabilities']:
                print_warning(f"{vuln['name']}: {vuln['description']} (Severity: {vuln['severity']})")
        else:
            print_success("No SSL/TLS vulnerabilities found")
    
    except Exception as e:
        print_error(f"Error analyzing SSL/TLS: {str(e)}")
    
    return results

def create_network_topology(network: str) -> Dict[str, Any]:
    """
    Create a visual map of network topology.
    
    Args:
        network: Network to map (CIDR notation)
    
    Returns:
        Dictionary with topology information and path to generated image
    """
    print_info(f"Creating network topology map for {network}")
    
    results = {
        'devices': [],
        'connections': [],
        'image_path': None
    }
    
    try:
  
        devices = scan_network(network)
        results['devices'] = devices
        
        if not devices:
            print_warning("No devices found on the network")
            return results
        
        print_success(f"Found {len(devices)} devices on the network")
    
        G = nx.Graph()
        
        
        for i, device in enumerate(devices):
            vendor = get_mac_vendor(device['mac'])
            G.add_node(i, ip=device['ip'], mac=device['mac'], vendor=vendor)
            results['devices'][i]['vendor'] = vendor
            print_info(f"Added device: {device['ip']} ({vendor})")
        
       
        gateway_ip = None
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output('ipconfig', shell=True).decode('utf-8', errors='ignore')
                for line in output.split('\n'):
                    if 'Default Gateway' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            gateway_ip = parts[1].strip()
                            break
            else:
                output = subprocess.check_output('ip route | grep default', shell=True).decode('utf-8', errors='ignore')
                parts = output.split()
                if len(parts) > 2:
                    gateway_ip = parts[2]
        except:
            pass
        
        
        if gateway_ip:
            gateway_index = None
            for i, device in enumerate(devices):
                if device['ip'] == gateway_ip:
                    gateway_index = i
                    break
            
            if gateway_index is not None:
                G.nodes[gateway_index]['is_gateway'] = True
                results['devices'][gateway_index]['is_gateway'] = True
                print_success(f"Identified gateway: {gateway_ip}")
        

        center_node = gateway_index if gateway_ip else 0
        
        for i in range(len(devices)):
            if i != center_node:
                G.add_edge(center_node, i)
                results['connections'].append({
                    'source': center_node,
                    'target': i
                })
        
       
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G)
        
    
        node_colors = []
        for i in range(len(devices)):
            if G.nodes[i].get('is_gateway', False):
                node_colors.append('red')
            else:
                node_colors.append('skyblue')
        
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500)
        
       
        nx.draw_networkx_edges(G, pos)
        
      
        labels = {i: f"{G.nodes[i]['ip']}\n{G.nodes[i]['vendor']}" for i in range(len(devices))}
        nx.draw_networkx_labels(G, pos, labels, font_size=8)
        
        
        os.makedirs(REPORTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = os.path.join(REPORTS_DIR, f"network_topology_{timestamp}.png")
        plt.title(f"Network Topology Map for {network}")
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(image_path)
        plt.close()
        
        results['image_path'] = image_path
        print_success(f"Network topology map saved to {image_path}")
        
      
        try:
            if platform.system() == 'Windows':
                os.startfile(image_path)
            elif platform.system() == 'Darwin': 
                subprocess.call(['open', image_path])
            else: 
                subprocess.call(['xdg-open', image_path])
        except:
            print_info("Image saved but could not be opened automatically")
    
    except Exception as e:
        print_error(f"Error creating network topology: {str(e)}")
    
    return results

def perform_fuzzing(url: str, parameter: str = None, wordlist_path: str = None) -> Dict[str, Any]:
    """
    Test applications by sending malformed input.
    
    Args:
        url: Target URL
        parameter: Parameter to fuzz (if None, will try to detect)
        wordlist_path: Path to fuzzing payloads wordlist
    
    Returns:
        Dictionary with fuzzing results
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print_info(f"Starting fuzzing on {url}")
    
    results = {
        'tested_payloads': 0,
        'anomalies': [],
        'vulnerabilities': []
    }
    
  
    if wordlist_path is None:
        wordlist_path = os.path.join(WORDLISTS_DIR, "fuzzing-payloads.txt")
        if not os.path.exists(wordlist_path):
         
            os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
            with open(wordlist_path, 'w') as f:
                f.write("'\n\"\n<script>alert(1)</script>\n../../etc/passwd\n${{7*7}}\n${7*7}\n$(cat /etc/passwd)\n`cat /etc/passwd`\n||ping -c 1 127.0.0.1||")
    
    try:
        with open(wordlist_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Error loading fuzzing payloads: {str(e)}")
        return results
    
    print_info(f"Loaded {len(payloads)} fuzzing payloads")
    
    try:
  
        baseline_response = secure_request(url, timeout=10)
        baseline_status = baseline_response.status_code
        baseline_length = len(baseline_response.content)
        baseline_time = baseline_response.elapsed.total_seconds()
        
        print_info(f"Baseline: Status {baseline_status}, Length {baseline_length}, Time {baseline_time:.2f}s")
        
    
        parameters_to_test = []
        if parameter:
            parameters_to_test.append(parameter)
        else:
         
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in query_params:
                parameters_to_test.append(param)
            
           
            if not parameters_to_test:
                soup = BeautifulSoup(baseline_response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        if 'name' in input_field.attrs:
                            parameters_to_test.append(input_field['name'])
            
          
            if not parameters_to_test:
                parameters_to_test = ['id', 'page', 'file', 'search', 'q', 'query', 'name', 'sort', 'filter']
        
        print_info(f"Testing parameters: {', '.join(parameters_to_test)}")
        
        
        for param in parameters_to_test:
            print_info(f"Fuzzing parameter: {param}")
            
            for payload in payloads:
                results['tested_payloads'] += 1
                
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
               
                query_params[param] = [payload]
                
               
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                try:
                  
                    response = secure_request(test_url, timeout=10)
                    status_code = response.status_code
                    content_length = len(response.content)
                    response_time = response.elapsed.total_seconds()
                    
                  
                    anomaly_detected = False
                    anomaly_type = []
                    
                   
                    if status_code != baseline_status:
                        anomaly_detected = True
                        anomaly_type.append(f"Status code changed: {baseline_status} -> {status_code}")
                    
                   
                    length_diff = abs(content_length - baseline_length)
                    if length_diff > 100:  
                        anomaly_detected = True
                        anomaly_type.append(f"Content length changed: {baseline_length} -> {content_length} (diff: {length_diff})")
                    
                  
                    time_diff = response_time - baseline_time
                    if time_diff > 2:  
                        anomaly_detected = True
                        anomaly_type.append(f"Response time increased: {baseline_time:.2f}s -> {response_time:.2f}s (diff: {time_diff:.2f}s)")
                    
                 
                    error_patterns = [
                        'sql syntax', 'mysql error', 'postgresql error', 'ora-', 'litespring',
                        'warning: include', 'fatal error', 'exception', 'stacktrace',
                        'syntax error', 'undefined index', 'undefined variable'
                    ]
                    
                    for pattern in error_patterns:
                        if pattern in response.text.lower():
                            anomaly_detected = True
                            anomaly_type.append(f"Error message detected: {pattern}")
                            
                            results['vulnerabilities'].append({
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'type': 'Potential injection',
                                'evidence': f"Error message containing '{pattern}'",
                                'severity': 'High'
                            })
                    
                  
                    if payload.startswith('<script>') and payload in response.text:
                        anomaly_detected = True
                        anomaly_type.append("XSS payload reflected in response")
                        
                        results['vulnerabilities'].append({
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'type': 'Reflected XSS',
                            'evidence': "Script tag reflected in response",
                            'severity': 'High'
                        })
                    
               
                    if '../../' in payload and ('root:' in response.text or 'passwd:' in response.text):
                        anomaly_detected = True
                        anomaly_type.append("Path traversal detected")
                        
                        results['vulnerabilities'].append({
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'type': 'Path Traversal',
                            'evidence': "File contents in response",
                            'severity': 'Critical'
                        })
                    
                   
                    if ('{{7*7}}' in payload or '${7*7}' in payload) and '49' in response.text:
                        anomaly_detected = True
                        anomaly_type.append("Template injection detected")
                        
                        results['vulnerabilities'].append({
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'type': 'Template Injection',
                            'evidence': "Expression evaluated in response",
                            'severity': 'High'
                        })
                    
                    if anomaly_detected:
                        results['anomalies'].append({
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'anomaly_type': anomaly_type,
                            'status_code': status_code,
                            'content_length': content_length,
                            'response_time': response_time
                        })
                        
                        print_warning(f"Anomaly detected with payload '{payload}' in parameter '{param}': {', '.join(anomaly_type)}")
                
                except Exception as e:
                    
                    results['anomalies'].append({
                        'parameter': param,
                        'payload': payload,
                        'url': test_url,
                        'anomaly_type': [f"Connection error: {str(e)}"],
                        'status_code': None,
                        'content_length': None,
                        'response_time': None
                    })
                    
                    print_warning(f"Connection error with payload '{payload}' in parameter '{param}': {str(e)}")
        
        print_info(f"Fuzzing completed. Tested {results['tested_payloads']} payloads.")
        print_info(f"Found {len(results['anomalies'])} anomalies and {len(results['vulnerabilities'])} potential vulnerabilities.")
        
    
        if results['vulnerabilities']:
            print_warning("Potential vulnerabilities found:")
            for vuln in results['vulnerabilities']:
                print_warning(f"{vuln['type']} in parameter '{vuln['parameter']}' (Severity: {vuln['severity']})")
                print_warning(f"  Payload: {vuln['payload']}")
                print_warning(f"  Evidence: {vuln['evidence']}")
    
    except Exception as e:
        print_error(f"Error during fuzzing: {str(e)}")
    
    return results

def scan_iot_devices(network: str) -> List[Dict[str, Any]]:
    """
    Specialized scanning for IoT devices.
    
    Args:
        network: Network to scan (CIDR notation)
    
    Returns:
        List of discovered IoT devices with details
    """
    print_info(f"Scanning for IoT devices on {network}")
    
    iot_devices = []
    
    try:
       
        devices = scan_network(network)
        
        if not devices:
            print_warning("No devices found on the network")
            return iot_devices
        
        print_success(f"Found {len(devices)} devices on the network")
        
        
        iot_signatures = {
            'IP Camera': {
                'ports': [80, 443, 554, 8080, 8443, 8554],
                'services': ['rtsp', 'http-server'],
                'patterns': ['ipcam', 'camera', 'webcam', 'netcam', 'hikvision', 'dahua', 'axis']
            },
            'Smart TV': {
                'ports': [80, 443, 8008, 8009, 9080],
                'services': ['dlna', 'upnp'],
                'patterns': ['smart tv', 'samsung', 'lg', 'sony', 'philips', 'roku', 'apple tv']
            },
            'Smart Speaker': {
                'ports': [80, 443, 8009, 8080],
                'services': ['avahi', 'mdns'],
                'patterns': ['google home', 'alexa', 'echo', 'sonos', 'bose']
            },
            'Router/Gateway': {
                'ports': [80, 443, 22, 23, 53, 8080, 8443],
                'services': ['http-server', 'ssh', 'telnet', 'dns'],
                'patterns': ['router', 'gateway', 'modem', 'huawei', 'asus', 'tp-link', 'netgear', 'linksys']
            },
            'Smart Home Hub': {
                'ports': [80, 443, 8080, 8443, 1883, 8883],
                'services': ['http-server', 'mqtt'],
                'patterns': ['hub', 'smart home', 'zigbee', 'z-wave', 'philips hue', 'smartthings', 'wink']
            },
            'Network Storage': {
                'ports': [80, 443, 139, 445, 21, 22],
                'services': ['smb', 'ftp', 'ssh', 'http-server'],
                'patterns': ['nas', 'storage', 'synology', 'qnap', 'wd', 'seagate']
            },
            'Printer': {
                'ports': [80, 443, 515, 631, 9100],
                'services': ['ipp', 'printer', 'http-server'],
                'patterns': ['printer', 'hp', 'canon', 'epson', 'brother', 'lexmark']
            }
        }
        
      
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            vendor = get_mac_vendor(mac)
            
            print_info(f"Checking device: {ip} ({vendor})")
            
        
            device_info = {
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'type': 'Unknown',
                'open_ports': [],
                'services': [],
                'vulnerabilities': []
            }
            
        
            iot_ports = set()
            for device_type, signature in iot_signatures.items():
                iot_ports.update(signature['ports'])
            
            
            iot_ports = sorted(list(iot_ports))
            
         
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                future_to_port = {executor.submit(scan_port, ip, port): port for port in iot_ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port, is_open, service = future.result()
                    
                    if is_open:
                        open_ports.append((port, service))
                        device_info['open_ports'].append(port)
                        device_info['services'].append(service)
                        print_success(f"Port {port} is open - {service}")
            
           
            device_type_scores = {}
            
            for device_type, signature in iot_signatures.items():
                score = 0
                
           
                for port, _ in open_ports:
                    if port in signature['ports']:
                        score += 1
                
              
                for _, service in open_ports:
                    service_lower = service.lower()
                    for sig_service in signature['services']:
                        if sig_service in service_lower:
                            score += 2
                
              
                vendor_lower = vendor.lower()
                for pattern in signature['patterns']:
                    if pattern in vendor_lower:
                        score += 3
                
                if score > 0:
                    device_type_scores[device_type] = score
            
            
            if device_type_scores:
                device_info['type'] = max(device_type_scores.items(), key=lambda x: x[1])[0]
            
         
            if open_ports:
               
                if 23 in device_info['open_ports']:
                    device_info['vulnerabilities'].append({
                        'name': 'Telnet Enabled',
                        'description': 'Telnet is enabled, which transmits data in cleartext',
                        'severity': 'High'
                    })
                
               
                http_ports = [80, 8080, 8000, 8888]
                for port in http_ports:
                    if port in device_info['open_ports']:
                       
                        try:
                            response = secure_request(f"http://{ip}:{port}/", timeout=5)
                            
                          
                            if 'login' in response.text.lower() or 'password' in response.text.lower():
                             
                                common_credentials = [
                                    ('admin', 'admin'),
                                    ('admin', 'password'),
                                    ('admin', ''),
                                    ('root', 'root'),
                                    ('user', 'user')
                                ]
                                
                                
                                device_info['vulnerabilities'].append({
                                    'name': 'Potential Default Credentials',
                                    'description': 'Device has a login page that might accept default credentials',
                                    'severity': 'Medium'
                                })
                        except:
                            pass
                
              
                if 1900 in device_info['open_ports']:
                    device_info['vulnerabilities'].append({
                        'name': 'UPnP Enabled',
                        'description': 'UPnP is enabled, which can expose the device to attacks',
                        'severity': 'Medium'
                    })
            
           
            if device_info['type'] != 'Unknown' or device_info['vulnerabilities']:
                iot_devices.append(device_info)
                print_success(f"Identified as: {device_info['type']}")
                
                if device_info['vulnerabilities']:
                    print_warning(f"Found {len(device_info['vulnerabilities'])} potential vulnerabilities")
                    for vuln in device_info['vulnerabilities']:
                        print_warning(f"  {vuln['name']}: {vuln['description']} (Severity: {vuln['severity']})")
        
        print_info(f"IoT scan completed. Found {len(iot_devices)} IoT devices.")
    
    except Exception as e:
        print_error(f"Error during IoT scan: {str(e)}")
    
    return iot_devices


def port_scanner() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("PORT SCANNER"))
    print()
    
    target = get_input("Enter target IP or hostname")
    
    if not is_valid_ip(target):
        if not is_valid_hostname(target):
            print_error("Invalid IP or hostname")
            time.sleep(2)
            return
        
        ip = get_ip_from_hostname(target)
        if not ip:
            print_error(f"Could not resolve hostname: {target}")
            time.sleep(2)
            return
        
        print_info(f"Resolved {target} to {ip}")
        target = ip
    
    scan_type = get_input("Scan type (1: Quick, 2: Common ports, 3: Full, 4: Custom range)")
    
    ports_to_scan = []
    if scan_type == "1":
        ports_to_scan = [21, 22, 23, 25, 80, 443, 3389]
        print_info(f"Quick scan selected: {len(ports_to_scan)} ports")
    elif scan_type == "2":
        ports_to_scan = DEFAULT_PORTS
        print_info(f"Common ports scan selected: {len(ports_to_scan)} ports")
    elif scan_type == "3":
        ports_to_scan = range(1, 65536)
        print_info("Full scan selected: All 65535 ports (this will take a while)")
    elif scan_type == "4":
        port_range = get_input("Enter port range (e.g., 1-1000 or 80,443,8080)")
        
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports_to_scan = range(start, end + 1)
        else:
            ports_to_scan = list(map(int, port_range.split(",")))
        
        print_info(f"Custom scan selected: {len(ports_to_scan)} ports")
    else:
        print_error("Invalid scan type")
        time.sleep(2)
        return
    
    print_loading(f"Scanning {target}", 2)
    
    start_time = time.time()
    open_ports = []
    
    print_info(f"Starting scan on {target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
  
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in ports_to_scan}
        
        total_ports = len(ports_to_scan)
        completed = 0
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            completed += 1
            
           
            if completed % 100 == 0 or completed == total_ports:
                progress = (completed / total_ports) * 100
                print_info(f"Progress: {progress:.1f}% ({completed}/{total_ports})")
            
            if is_open:
                open_ports.append((port, service))
                print_success(f"Port {port} is open - {service}")
    
    end_time = time.time()
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 60)
    print_gradient_text(f"Scan completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(open_ports)} open ports on {target}")
    print_gradient_text("=" * 60)
    
    if open_ports:
        headers = ["Port", "Status", "Service"]
        rows = [[str(port), "Open", service] for port, service in open_ports]
        print_result_table(headers, rows)
        
      
        save_results = get_input("Save scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("port_scan", {
                'target': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'open_ports': [{'port': port, 'service': service} for port, service in open_ports]
            })
    
    input("\nPress Enter to continue...")

def network_scanner() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("NETWORK SCANNER"))
    print()
    
    
    current_network = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        
    
        ip_parts = ip.split('.')
        current_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except:
        pass
    
    if current_network:
        print_info(f"Detected current network: {current_network}")
        use_current = get_input("Use this network? (y/n)").lower()
        
        if use_current == 'y':
            network = current_network
        else:
            network = get_input("Enter network to scan (e.g., 192.168.1.0/24)")
    else:
        network = get_input("Enter network to scan (e.g., 192.168.1.0/24)")
    
    print_loading(f"Scanning network {network}", 2)
    
    start_time = time.time()
    devices = scan_network(network)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"Scan completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(devices)} devices on {network}")
    print_gradient_text("=" * 80)
    
    if devices:
      
        for device in devices:
            device['vendor'] = get_mac_vendor(device['mac'])
        
        headers = ["IP Address", "MAC Address", "Vendor"]
        rows = [[device['ip'], device['mac'], device['vendor']] for device in devices]
        print_result_table(headers, rows)
        
      
        save_results = get_input("Save scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("network_scan", {
                'network': network,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'devices': devices
            })
        
        
        create_map = get_input("Create network topology map? (y/n)").lower()
        if create_map == 'y':
            create_network_topology(network)
    
    input("\nPress Enter to continue...")

def service_detector() -> None:
 
    print_banner()
    print_gradient_text(Center.XCenter("SERVICE DETECTOR"))
    print()
    
    target = get_input("Enter target IP or hostname")
    
    if not is_valid_ip(target):
        if not is_valid_hostname(target):
            print_error("Invalid IP or hostname")
            time.sleep(2)
            return
        
        ip = get_ip_from_hostname(target)
        if not ip:
            print_error(f"Could not resolve hostname: {target}")
            time.sleep(2)
            return
        
        print_info(f"Resolved {target} to {ip}")
        target = ip
    
    ports_input = get_input("Enter ports to scan (e.g., 80,443,8080) or leave empty for common ports")
    
    if ports_input:
        try:
            ports_to_scan = list(map(int, ports_input.split(",")))
        except:
            print_error("Invalid port format")
            time.sleep(2)
            return
    else:
        ports_to_scan = DEFAULT_PORTS
    
    print_loading(f"Scanning services on {target}", 2)
    
    start_time = time.time()
    services = []
    
 
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in ports_to_scan}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            
            if is_open:
                services.append((port, service))
                print_success(f"Port {port} is open - {service}")
    
    end_time = time.time()
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 60)
    print_gradient_text(f"Scan completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(services)} services on {target}")
    print_gradient_text("=" * 60)
    
    if services:
        headers = ["Port", "Service"]
        rows = [[str(port), service] for port, service in services]
        print_result_table(headers, rows)
        
       
        save_results = get_input("Save scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("service_scan", {
                'target': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'services': [{'port': port, 'service': service} for port, service in services]
            })
    
    input("\nPress Enter to continue...")

def vulnerability_scanner() -> None:
  
    print_banner()
    print_gradient_text(Center.XCenter("VULNERABILITY SCANNER"))
    print()
    
    print_warning("This is a advanced vulnerability scanner and should not be used against anything unless explict permission.")
    print()
    
    target = get_input("Enter target IP or hostname")
    
    if not is_valid_ip(target):
        if not is_valid_hostname(target):
            print_error("Invalid IP or hostname")
            time.sleep(2)
            return
        
        ip = get_ip_from_hostname(target)
        if not ip:
            print_error(f"Could not resolve hostname: {target}")
            time.sleep(2)
            return
        
        print_info(f"Resolved {target} to {ip}")
        target = ip
    
    print_loading(f"Scanning for open ports on {target}", 2)
    
  
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in DEFAULT_PORTS}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            
            if is_open:
                open_ports.append(port)
                print_success(f"Port {port} is open - {service}")
    
    if not open_ports:
        print_warning("No open ports found. Cannot check for vulnerabilities.")
        input("\nPress Enter to continue...")
        return
    
    print_loading(f"Checking for vulnerabilities on {target}", 2)
    
 
    vulnerabilities = check_common_vulnerabilities(target, open_ports)
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"Vulnerability scan completed for {target}")
    print_gradient_text(f"Found {len(vulnerabilities)} potential vulnerabilities")
    print_gradient_text("=" * 80)
    
    if vulnerabilities:
        headers = ["Port", "Service", "Vulnerability", "Severity"]
        rows = [[str(v['port']), v['service'], v['vulnerability'], v['severity']] for v in vulnerabilities]
        print_result_table(headers, rows)
        
     
        print("\nDetailed vulnerability information:")
        for i, vuln in enumerate(vulnerabilities):
            print_gradient_text(f"\nVulnerability #{i+1}:")
            print_info(f"Port: {vuln['port']}")
            print_info(f"Service: {vuln['service']}")
            print_warning(f"Issue: {vuln['vulnerability']}")
            print_warning(f"Severity: {vuln['severity']}")
            print_info(f"Description: {vuln.get('description', 'No description available')}")
            print_success(f"Recommendation: {vuln.get('recommendation', 'No recommendation available')}")
        
        
        save_results = get_input("Save scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("vulnerability_scan", {
                'target': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'open_ports': open_ports,
                'vulnerabilities': vulnerabilities
            })
    else:
        print_info("No obvious vulnerabilities detected.")
    
    input("\nPress Enter to continue...")

def traceroute_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("TRACEROUTE"))
    print()
    
    target = get_input("Enter target IP or hostname")
    
    if not is_valid_ip(target) and not is_valid_hostname(target):
        print_error("Invalid IP or hostname")
        time.sleep(2)
        return
    
    max_hops = get_input("Maximum hops (default: 30)")
    if not max_hops:
        max_hops = 30
    else:
        try:
            max_hops = int(max_hops)
        except:
            print_error("Invalid number of hops")
            time.sleep(2)
            return
    
    print_loading(f"Tracing route to {target}", 2)
    
    try:
        results = perform_traceroute(target, max_hops)
        
        print()
        print_gradient_text("=" * 60)
        print_gradient_text(f"Traceroute to {target}")
        print_gradient_text("=" * 60)
        
        if results:
            headers = ["Hop", "IP Address", "Response Time (ms)"]
            rows = [[str(result['hop']), result['ip'], f"{result['time_ms']:.2f}"] for result in results]
            print_result_table(headers, rows)
            

            save_results = get_input("Save traceroute results? (y/n)").lower()
            if save_results == 'y':
                save_scan_results("traceroute", {
                    'target': target,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'max_hops': max_hops,
                    'hops': results
                })
        else:
            print_warning("No route found.")
    except Exception as e:
        print_error(f"Error performing traceroute: {str(e)}")
    
    input("\nPress Enter to continue...")

def dns_lookup_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("DNS LOOKUP"))
    print()
    
    domain = get_input("Enter domain name")
    
    if not is_valid_hostname(domain):
        print_error("Invalid domain name")
        time.sleep(2)
        return
    
    print_loading(f"Looking up DNS records for {domain}", 2)
    
    try:
        results = perform_dns_lookup(domain)
        
        print()
        print_gradient_text("=" * 60)
        print_gradient_text(f"DNS records for {domain}")
        print_gradient_text("=" * 60)
        

        if results['A']:
            print_gradient_text("\nA Records (IPv4):")
            for record in results['A']:
                print_info(record)
        

        if results['AAAA']:
            print_gradient_text("\nAAAA Records (IPv6):")
            for record in results['AAAA']:
                print_info(record)
        

        if results['MX']:
            print_gradient_text("\nMX Records:")
            for record in results['MX']:
                print_info(record)
        

        if results['NS']:
            print_gradient_text("\nNS Records:")
            for record in results['NS']:
                print_info(record)
        

        if results['TXT']:
            print_gradient_text("\nTXT Records:")
            for record in results['TXT']:
                print_info(record)
        

        if results['CNAME']:
            print_gradient_text("\nCNAME Records:")
            for record in results['CNAME']:
                print_info(record)
        

        if results['SOA']:
            print_gradient_text("\nSOA Records:")
            for record in results['SOA']:
                print_info(record)
        

        if results['PTR']:
            print_gradient_text("\nPTR Records:")
            for record in results['PTR']:
                print_info(record)
        
        if not any(results.values()):
            print_warning("No DNS records found.")
        else:
            save_results = get_input("Save DNS lookup results? (y/n)").lower()
            if save_results == 'y':
                save_scan_results("dns_lookup", {
                    'domain': domain,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'records': results
                })
    except Exception as e:
        print_error(f"Error performing DNS lookup: {str(e)}")
    
    input("\nPress Enter to continue...")

def ping_sweep_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("PING SWEEP"))
    print()
    
    target_range = get_input("Enter IP range (e.g., 192.168.1.1-192.168.1.254)")
    
    if "-" in target_range:
        start_ip, end_ip = target_range.split("-")
        
        if not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
            print_error("Invalid IP address format")
            time.sleep(2)
            return
        
        
        start_int = int(ipaddress.IPv4Address(start_ip))
        end_int = int(ipaddress.IPv4Address(end_ip))
        
        if end_int < start_int:
            print_error("End IP must be greater than start IP")
            time.sleep(2)
            return
        
       
        ips = [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]
    else:
     
        try:
            network = ipaddress.IPv4Network(target_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except:
            print_error("Invalid IP range format")
            time.sleep(2)
            return
    
    print_info(f"Scanning {len(ips)} hosts...")
    print_loading("Pinging hosts", 2)
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip, is_alive, response_time = future.result()
            
            if is_alive:
                print_success(f"{ip} is up ({response_time:.2f} ms)")
                results.append((ip, is_alive, response_time))
            else:
                print_error(f"{ip} is down")
    
    print()
    print_gradient_text("=" * 60)
    print_gradient_text(f"Ping sweep completed")
    print_gradient_text(f"Found {len(results)} active hosts out of {len(ips)}")
    print_gradient_text("=" * 60)
    
    if results:
        headers = ["IP Address", "Status", "Response Time (ms)"]
        rows = [[ip, "Up", f"{response_time:.2f}"] for ip, _, response_time in results]
        print_result_table(headers, rows)
        
       
        save_results = get_input("Save ping sweep results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("ping_sweep", {
                'target_range': target_range,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_hosts': len(ips),
                'active_hosts': [{'ip': ip, 'response_time': response_time} for ip, _, response_time in results]
            })
    
    input("\nPress Enter to continue...")

def website_scanner() -> None:
  
    print_banner()
    print_gradient_text(Center.XCenter("WEBSITE SCANNER"))
    print()
    
    url = get_input("Enter website URL (include http:// or https://)")
    
    if not is_valid_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            if not is_valid_url(url):
                print_error("Invalid URL format")
                time.sleep(2)
                return
        else:
            print_error("Invalid URL format")
            time.sleep(2)
            return
    
    print_info(f"Checking status of {url}...")
    
    try:
       
        response = secure_request(url, method="HEAD", timeout=5)
        print_success(f"Website is up (Status: {response.status_code})")
    except Exception as e:
        print_error(f"Website is down or unreachable: {str(e)}")
        input("\nPress Enter to continue...")
        return
    
  
    scan_type = get_input("Select scan type (1: Basic, 2: Comprehensive, 3: Full Security Audit)")
    
    if scan_type == "1":
        print_loading(f"Performing basic scan on {url}", 2)
        perform_basic_website_scan(url)
    elif scan_type == "2":
        print_loading(f"Performing comprehensive scan on {url}", 2)
        perform_comprehensive_website_scan(url)
    elif scan_type == "3":
        print_loading(f"Performing full security audit on {url}", 2)
        perform_full_website_audit(url)
    else:
        print_error("Invalid scan type")
        time.sleep(2)
        return
    
    input("\nPress Enter to continue...")

def perform_basic_website_scan(url: str) -> Dict[str, Any]:
    results = {
        'url': url,
        'status_code': None,
        'response_time': None,
        'headers': {},
        'server': None,
        'technologies': [],
        'security_headers': {},
        'issues': []
    }
    
    try:
       
        start_time = time.time()
        response = secure_request(url, timeout=10)
        end_time = time.time()
        
      
        results['status_code'] = response.status_code
        results['response_time'] = (end_time - start_time) * 1000  
        results['headers'] = dict(response.headers)
        results['server'] = response.headers.get('Server', 'Unknown')
        
        
        security_headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Missing'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Missing'),
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Missing'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Missing'),
            'Referrer-Policy': response.headers.get('Referrer-Policy', 'Missing')
        }
        results['security_headers'] = security_headers
        
      
        print_gradient_text("\nBasic Information:")
        print_info(f"Status: {results['status_code']} {requests.status_codes._codes[results['status_code']][0].upper()}")
        print_info(f"Response time: {results['response_time']:.2f} ms")
        print_info(f"Server: {results['server']}")
        
       
        print_gradient_text("\nSecurity Headers:")
        for header, value in security_headers.items():
            if value == 'Missing':
                print_warning(f"{header}: {value}")
                results['issues'].append({
                    'type': 'Missing Security Header',
                    'description': f"The {header} security header is missing",
                    'severity': 'Medium'
                })
            else:
                print_success(f"{header}: Present")
        
     
        if response.cookies:
            print_gradient_text("\nCookies:")
            for cookie in response.cookies:
                secure_status = "Secure" if cookie.secure else "Not Secure"
                httponly_status = "HttpOnly" if 'httponly' in cookie._rest else "Not HttpOnly"
                print_info(f"{cookie.name}: {secure_status}, {httponly_status}")
                
                if not cookie.secure:
                    results['issues'].append({
                        'type': 'Insecure Cookie',
                        'description': f"Cookie '{cookie.name}' is not using the Secure flag",
                        'severity': 'Medium'
                    })
                
                if 'httponly' not in cookie._rest:
                    results['issues'].append({
                        'type': 'Insecure Cookie',
                        'description': f"Cookie '{cookie.name}' is not using the HttpOnly flag",
                        'severity': 'Medium'
                    })
        
     
        if results['issues']:
            print_gradient_text("\nPotential Issues:")
            for issue in results['issues']:
                print_warning(f"{issue['type']}: {issue['description']} (Severity: {issue['severity']})")
        else:
            print_success("\nNo obvious issues detected.")
        

        save_results = get_input("Save website scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("website_scan", {
                'url': url,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_type': 'basic',
                'results': results
            })
        
        return results
    
    except Exception as e:
        print_error(f"Error during website scan: {str(e)}")
        return results

def perform_comprehensive_website_scan(url: str) -> Dict[str, Any]:
    results = perform_basic_website_scan(url)
    
   
    print_gradient_text("\nPerforming additional checks...")
    
    try:
       
        print_info("Checking for CMS...")
        cms_results = detect_cms(url)
        results['cms'] = cms_results
        
        if cms_results['cms_detected']:
            print_success(f"CMS detected: {cms_results['cms_detected']} (Confidence: {cms_results['confidence']}%)")
            if cms_results['version']:
                print_info(f"Version: {cms_results['version']}")
            
            if cms_results['vulnerabilities']:
                print_warning(f"Found {len(cms_results['vulnerabilities'])} potential CMS vulnerabilities")
                for vuln in cms_results['vulnerabilities']:
                    print_warning(f"{vuln['component']}: {vuln['description']} (Severity: {vuln['severity']})")
                    results['issues'].append({
                        'type': 'CMS Vulnerability',
                        'description': f"{vuln['component']}: {vuln['description']}",
                        'severity': vuln['severity']
                    })
        
      
        print_info("Checking for WAF...")
        waf_results = detect_waf(url)
        results['waf'] = waf_results
        
        if waf_results['protected']:
            print_success(f"WAF detected: {waf_results['waf_detected']} (Confidence: {waf_results['confidence']}%)")
        else:
            print_warning("No WAF detected")
            results['issues'].append({
                'type': 'No WAF',
                'description': "The website does not appear to be protected by a Web Application Firewall",
                'severity': 'Medium'
            })
        
      
        if url.startswith('https://'):
            print_info("Checking SSL/TLS configuration...")
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.netloc.split(':')[0]
            port = parsed_url.port or 443
            
            ssl_results = analyze_ssl_tls(hostname, port)
            results['ssl_tls'] = ssl_results
            
            print_info(f"SSL/TLS Grade: {ssl_results['grade']}")
            
            if ssl_results['vulnerabilities']:
                print_warning(f"Found {len(ssl_results['vulnerabilities'])} SSL/TLS vulnerabilities")
                for vuln in ssl_results['vulnerabilities']:
                    print_warning(f"{vuln['name']}: {vuln['description']} (Severity: {vuln['severity']})")
                    results['issues'].append({
                        'type': 'SSL/TLS Vulnerability',
                        'description': f"{vuln['name']}: {vuln['description']}",
                        'severity': vuln['severity']
                    })
        
   
        print_gradient_text("\nScan Summary:")
        total_issues = len(results['issues'])
        high_severity = sum(1 for issue in results['issues'] if issue['severity'] == 'High' or issue['severity'] == 'Critical')
        medium_severity = sum(1 for issue in results['issues'] if issue['severity'] == 'Medium')
        low_severity = sum(1 for issue in results['issues'] if issue['severity'] == 'Low')
        
        print_info(f"Total issues found: {total_issues}")
        if high_severity > 0:
            print_error(f"High/Critical severity issues: {high_severity}")
        if medium_severity > 0:
            print_warning(f"Medium severity issues: {medium_severity}")
        if low_severity > 0:
            print_info(f"Low severity issues: {low_severity}")
        
        if total_issues == 0:
            print_success("No issues detected. The website appears to be secure.")
        
 
        save_results = get_input("Save comprehensive scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("website_scan", {
                'url': url,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_type': 'comprehensive',
                'results': results
            })
        
        return results
    
    except Exception as e:
        print_error(f"Error during comprehensive website scan: {str(e)}")
        return results

def perform_full_website_audit(url: str) -> Dict[str, Any]:

   
    results = perform_comprehensive_website_scan(url)
    
 
    print_gradient_text("\nPerforming in-depth security audit...")
    
    try:
       
        print_info("Enumerating subdomains...")
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        
        
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = domain
        
        subdomains = subdomain_enumeration(base_domain)
        results['subdomains'] = subdomains
        
        if subdomains:
            print_success(f"Found {len(subdomains)} subdomains")
            for subdomain in subdomains[:10]:  
                print_info(subdomain)
            if len(subdomains) > 10:
                print_info(f"... and {len(subdomains) - 10} more")
        
       
        print_info("Bruteforcing directories...")
        directories = directory_bruteforce(url, recursion_level=1)
        results['directories'] = directories
        
        if directories:
            print_success(f"Found {len(directories)} directories/files")
            for directory in directories[:10]: 
                print_info(f"{directory['url']} [{directory['status_code']}]")
            if len(directories) > 10:
                print_info(f"... and {len(directories) - 10} more")
        
      
        print_info("Discovering API endpoints...")
        api_endpoints = discover_api_endpoints(url)
        results['api_endpoints'] = api_endpoints
        
        if api_endpoints:
            print_success(f"Found {len(api_endpoints)} API endpoints")
            for endpoint in api_endpoints[:10]: 
                print_info(endpoint['endpoint'])
            if len(api_endpoints) > 10:
                print_info(f"... and {len(api_endpoints) - 10} more")
        
    
        print_info("Performing limited fuzzing...")
        fuzzing_results = perform_fuzzing(url)
        results['fuzzing'] = fuzzing_results
        
        if fuzzing_results['vulnerabilities']:
            print_warning(f"Found {len(fuzzing_results['vulnerabilities'])} potential vulnerabilities through fuzzing")
            for vuln in fuzzing_results['vulnerabilities']:
                print_warning(f"{vuln['type']} in parameter '{vuln['parameter']}' (Severity: {vuln['severity']})")
                results['issues'].append({
                    'type': 'Fuzzing Vulnerability',
                    'description': f"{vuln['type']} in parameter '{vuln['parameter']}': {vuln['evidence']}",
                    'severity': vuln['severity']
                })
        
        
        print_gradient_text("\nGenerating comprehensive security report...")
        
       
        print_gradient_text("\nSecurity Audit Summary:")
        total_issues = len(results['issues'])
        high_severity = sum(1 for issue in results['issues'] if issue['severity'] == 'High' or issue['severity'] == 'Critical')
        medium_severity = sum(1 for issue in results['issues'] if issue['severity'] == 'Medium')
        low_severity = sum(1 for issue in results['issues'] if issue['severity'] == 'Low')
        
        print_info(f"Total issues found: {total_issues}")
        if high_severity > 0:
            print_error(f"High/Critical severity issues: {high_severity}")
        if medium_severity > 0:
            print_warning(f"Medium severity issues: {medium_severity}")
        if low_severity > 0:
            print_info(f"Low severity issues: {low_severity}")
        
       
        security_score = 100
        for issue in results['issues']:
            if issue['severity'] == 'Critical':
                security_score -= 15
            elif issue['severity'] == 'High':
                security_score -= 10
            elif issue['severity'] == 'Medium':
                security_score -= 5
            elif issue['severity'] == 'Low':
                security_score -= 2
        
        security_score = max(0, security_score)
        results['security_score'] = security_score
        
        if security_score >= 90:
            grade = 'A'
        elif security_score >= 80:
            grade = 'B'
        elif security_score >= 70:
            grade = 'C'
        elif security_score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        results['security_grade'] = grade
        
        print_gradient_text(f"\nSecurity Score: {security_score}/100 (Grade: {grade})")
        
        if security_score >= 90:
            print_success("The website appears to be very secure.")
        elif security_score >= 70:
            print_info("The website has acceptable security but could be improved.")
        else:
            print_warning("The website has significant security issues that should be addressed.")
        
    
        save_results = get_input("Save full audit results? (y/n)").lower()
        if save_results == 'y':
            report_path = save_scan_results("website_audit", {
                'url': url,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_type': 'full_audit',
                'security_score': security_score,
                'security_grade': grade,
                'results': results
            }, generate_pdf=True)
            
            if report_path:
                print_success(f"Full audit report saved to {report_path}")
                
                
                open_report = get_input("Open the report? (y/n)").lower()
                if open_report == 'y':
                    try:
                        if platform.system() == 'Windows':
                            os.startfile(report_path)
                        elif platform.system() == 'Darwin': 
                            subprocess.call(['open', report_path])
                        else: 
                            subprocess.call(['xdg-open', report_path])
                    except:
                        print_info("Could not open the report automatically")
        
        return results
    
    except Exception as e:
        print_error(f"Error during full website audit: {str(e)}")
        return results

def advanced_tools_menu() -> None:
    while True:
        print_banner()
        print_advanced_menu()
        
        choice = get_input("Select an option")
        
        if choice == "1":
            subdomain_enumeration_tool()
        elif choice == "2":
            directory_bruteforce_tool()
        elif choice == "3":
            waf_detection_tool()
        elif choice == "4":
            cms_detection_tool()
        elif choice == "5":
            api_discovery_tool()
        elif choice == "6":
            osint_gathering_tool()
        elif choice == "7":
            ssl_tls_analyzer_tool()
        elif choice == "8":
            network_topology_tool()
        elif choice == "9":
            fuzzing_tool()
        elif choice == "10":
            iot_scanner_tool()
        elif choice == "0":
            return
        else:
            print_error("Invalid option")
            time.sleep(1)

def subdomain_enumeration_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("SUBDOMAIN ENUMERATION"))
    print()
    
    domain = get_input("Enter domain name (e.g., example.com)")
    
    if not is_valid_hostname(domain):
        print_error("Invalid domain name")
        time.sleep(2)
        return
    
    techniques = []
    print_info("Select techniques to use:")
    use_dns_brute = get_input("Use DNS brute force? (y/n)").lower() == 'y'
    use_cert = get_input("Use certificate transparency logs? (y/n)").lower() == 'y'
    use_search = get_input("Use search engine results? (y/n)").lower() == 'y'
    
    if use_dns_brute:
        techniques.append("dns_brute")
    if use_cert:
        techniques.append("cert_transparency")
    if use_search:
        techniques.append("search_engines")
    
    if not techniques:
        print_error("No techniques selected")
        time.sleep(2)
        return
    
    wordlist_path = None
    if use_dns_brute:
        custom_wordlist = get_input("Use custom wordlist? (y/n)").lower() == 'y'
        if custom_wordlist:
            wordlist_path = get_input("Enter path to wordlist file")
            if not os.path.exists(wordlist_path):
                print_error("Wordlist file not found")
                time.sleep(2)
                return
    
    print_loading(f"Enumerating subdomains for {domain}", 2)
    
    start_time = time.time()
    subdomains = subdomain_enumeration(domain, techniques, wordlist_path)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 60)
    print_gradient_text(f"Subdomain enumeration completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(subdomains)} subdomains for {domain}")
    print_gradient_text("=" * 60)
    
    if subdomains:
        headers = ["Subdomain"]
        rows = [[subdomain] for subdomain in subdomains]
        print_result_table(headers, rows)
        
        save_results = get_input("Save subdomain enumeration results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("subdomain_enumeration", {
                'domain': domain,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'techniques': techniques,
                'subdomains': subdomains
            })
    
    input("\nPress Enter to continue...")

def directory_bruteforce_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("DIRECTORY BRUTEFORCE"))
    print()
    
    url = get_input("Enter target URL (include http:// or https://)")
    
    if not is_valid_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            if not is_valid_url(url):
                print_error("Invalid URL format")
                time.sleep(2)
                return
        else:
            print_error("Invalid URL format")
            time.sleep(2)
            return
    
    wordlist_path = get_input("Enter path to wordlist file (leave empty for default)")
    if wordlist_path and not os.path.exists(wordlist_path):
        print_error("Wordlist file not found")
        time.sleep(2)
        return
    
    extensions_input = get_input("Enter file extensions to check (comma-separated, leave empty for default)")
    extensions = None
    if extensions_input:
        extensions = ['']  
        for ext in extensions_input.split(','):
            ext = ext.strip()
            if not ext.startswith('.'):
                ext = '.' + ext
            extensions.append(ext)
    
    recursion_level = get_input("Recursion level (1-3, default: 1)")
    if not recursion_level:
        recursion_level = 1
    else:
        try:
            recursion_level = int(recursion_level)
            if recursion_level < 1 or recursion_level > 3:
                print_error("Recursion level must be between 1 and 3")
                time.sleep(2)
                return
        except:
            print_error("Invalid recursion level")
            time.sleep(2)
            return
    
    print_loading(f"Bruteforcing directories on {url}", 2)
    
    start_time = time.time()
    results = directory_bruteforce(url, wordlist_path, extensions, recursion_level)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"Directory bruteforce completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(results)} directories/files on {url}")
    print_gradient_text("=" * 80)
    
    if results:
        headers = ["URL", "Status Code", "Size (bytes)"]
        rows = [[result['url'], result['status_code'], result['content_length']] for result in results]
        print_result_table(headers, rows)
        
        
        save_results = get_input("Save directory bruteforce results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("directory_bruteforce", {
                'url': url,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'recursion_level': recursion_level,
                'results': results
            })
    
    input("\nPress Enter to continue...")

def waf_detection_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("WAF DETECTION"))
    print()
    
    url = get_input("Enter target URL (include http:// or https://)")
    
    if not is_valid_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            if not is_valid_url(url):
                print_error("Invalid URL format")
                time.sleep(2)
                return
        else:
            print_error("Invalid URL format")
            time.sleep(2)
            return
    
    print_loading(f"Detecting WAF on {url}", 2)
    
    start_time = time.time()
    results = detect_waf(url)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 60)
    print_gradient_text(f"WAF detection completed in {scan_time:.2f} seconds")
    print_gradient_text("=" * 60)
    
    if results['protected']:
        print_success(f"WAF detected: {results['waf_detected']}")
        print_info(f"Confidence: {results['confidence']}%")
        
        if results['evidence']:
            print_gradient_text("\nEvidence:")
            for evidence in results['evidence']:
                print_info(f"- {evidence}")
    else:
        print_warning("No WAF detected")
    

    save_results = get_input("Save WAF detection results? (y/n)").lower()
    if save_results == 'y':
        save_scan_results("waf_detection", {
            'url': url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_time': scan_time,
            'results': results
        })
    
    input("\nPress Enter to continue...")

def cms_detection_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("CMS DETECTION"))
    print()
    
    url = get_input("Enter target URL (include http:// or https://)")
    
    if not is_valid_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            if not is_valid_url(url):
                print_error("Invalid URL format")
                time.sleep(2)
                return
        else:
            print_error("Invalid URL format")
            time.sleep(2)
            return
    
    print_loading(f"Detecting CMS on {url}", 2)
    
    start_time = time.time()
    results = detect_cms(url)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 60)
    print_gradient_text(f"CMS detection completed in {scan_time:.2f} seconds")
    print_gradient_text("=" * 60)
    
    if results['cms_detected']:
        print_success(f"CMS detected: {results['cms_detected']}")
        print_info(f"Confidence: {results['confidence']}%")
        
        if results['version']:
            print_info(f"Version: {results['version']}")
        
        if results['evidence']:
            print_gradient_text("\nEvidence:")
            for evidence in results['evidence']:
                print_info(f"- {evidence}")
        
        if results['vulnerabilities']:
            print_gradient_text("\nPotential Vulnerabilities:")
            for vuln in results['vulnerabilities']:
                print_warning(f"{vuln['component']}: {vuln['description']} (Severity: {vuln['severity']})")
    else:
        print_warning("No CMS detected")
    

    save_results = get_input("Save CMS detection results? (y/n)").lower()
    if save_results == 'y':
        save_scan_results("cms_detection", {
            'url': url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_time': scan_time,
            'results': results
        })
    
    input("\nPress Enter to continue...")

def api_discovery_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("API ENDPOINT DISCOVERY"))
    print()
    
    url = get_input("Enter target URL (include http:// or https://)")
    
    if not is_valid_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            if not is_valid_url(url):
                print_error("Invalid URL format")
                time.sleep(2)
                return
        else:
            print_error("Invalid URL format")
            time.sleep(2)
            return
    
    print_loading(f"Discovering API endpoints on {url}", 2)
    
    start_time = time.time()
    results = discover_api_endpoints(url)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"API endpoint discovery completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(results)} API endpoints on {url}")
    print_gradient_text("=" * 80)
    
    if results:
        headers = ["Endpoint", "Source", "Methods", "Status"]
        rows = []
        for endpoint in results:
            methods = ", ".join(endpoint.get('methods', [])) if endpoint.get('methods') else "Unknown"
            status = str(endpoint.get('status_code', 'Unknown'))
            rows.append([endpoint['endpoint'], endpoint['source'], methods, status])
        
        print_result_table(headers, rows)
        
      
        save_results = get_input("Save API endpoint discovery results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("api_discovery", {
                'url': url,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'endpoints': results
            })
    
    input("\nPress Enter to continue...")

def osint_gathering_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("OSINT GATHERING"))
    print()
    
    target = get_input("Enter target (domain, IP, or company name)")
    
    if not target:
        print_error("Invalid target")
        time.sleep(2)
        return
    
    print_gradient_text("\nSelect OSINT sources to use:")
    use_whois = get_input("WHOIS lookup? (y/n)").lower() == 'y'
    use_dns = get_input("DNS records? (y/n)").lower() == 'y'
    use_shodan = get_input("Shodan (requires API key)? (y/n)").lower() == 'y'
    use_censys = get_input("Censys (requires API key)? (y/n)").lower() == 'y'
    use_social = get_input("Social media? (y/n)").lower() == 'y'
    
    if not any([use_whois, use_dns, use_shodan, use_censys, use_social]):
        print_error("No OSINT sources selected")
        time.sleep(2)
        return
    
    print_loading(f"Gathering OSINT for {target}", 2)
    
    results = {
        'target': target,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'whois': None,
        'dns': None,
        'shodan': None,
        'censys': None,
        'social': None
    }
    
  
    if use_whois:
        print_info("Performing WHOIS lookup...")
        try:
            whois_data = whois.whois(target)
            results['whois'] = {
                'registrar': whois_data.registrar,
                'creation_date': str(whois_data.creation_date),
                'expiration_date': str(whois_data.expiration_date),
                'name_servers': whois_data.name_servers,
                'status': whois_data.status,
                'emails': whois_data.emails,
                'org': whois_data.org
            }
            
            print_success("WHOIS information retrieved")
            print_info(f"Registrar: {whois_data.registrar}")
            print_info(f"Organization: {whois_data.org}")
            print_info(f"Creation Date: {whois_data.creation_date}")
            print_info(f"Expiration Date: {whois_data.expiration_date}")
            print_info(f"Name Servers: {', '.join(whois_data.name_servers) if isinstance(whois_data.name_servers, list) else whois_data.name_servers}")
        except Exception as e:
            print_error(f"Error retrieving WHOIS information: {str(e)}")
    
   
    if use_dns and is_valid_hostname(target):
        print_info("Retrieving DNS records...")
        try:
            dns_records = perform_dns_lookup(target)
            results['dns'] = dns_records
            
            print_success("DNS records retrieved")
            
           
            if dns_records['A']:
                print_info(f"A Records: {', '.join(dns_records['A'])}")
            
           
            if dns_records['MX']:
                print_info(f"MX Records: {', '.join(dns_records['MX'])}")
            
          
            if dns_records['NS']:
                print_info(f"NS Records: {', '.join(dns_records['NS'])}")
        except Exception as e:
            print_error(f"Error retrieving DNS records: {str(e)}")
    
    
    if use_shodan:
        print_info("Querying Shodan...")
        if not API_KEYS['shodan']:
            api_key = get_input("Enter Shodan API key")
            if api_key:
                API_KEYS['shodan'] = api_key
        
        if API_KEYS['shodan']:
            try:
                api = shodan.Shodan(API_KEYS['shodan'])
                shodan_results = api.search(target)
                
                results['shodan'] = {
                    'total': shodan_results['total'],
                    'matches': []
                }
                
                print_success(f"Found {shodan_results['total']} results on Shodan")
                
                for match in shodan_results.get('matches', [])[:5]: 
                    result = {
                        'ip': match.get('ip_str', 'Unknown'),
                        'port': match.get('port', 'Unknown'),
                        'org': match.get('org', 'Unknown'),
                        'hostnames': match.get('hostnames', []),
                        'country': match.get('location', {}).get('country_name', 'Unknown')
                    }
                    results['shodan']['matches'].append(result)
                    
                    print_info(f"IP: {result['ip']}, Port: {result['port']}, Org: {result['org']}")
            except Exception as e:
                print_error(f"Error querying Shodan: {str(e)}")
        else:
            print_warning("Shodan API key not provided")
    
 
    if use_censys:
        print_info("Querying Censys...")
        if not API_KEYS['censys_id'] or not API_KEYS['censys_secret']:
            censys_id = get_input("Enter Censys API ID")
            censys_secret = get_input("Enter Censys API Secret")
            if censys_id and censys_secret:
                API_KEYS['censys_id'] = censys_id
                API_KEYS['censys_secret'] = censys_secret
        
        if API_KEYS['censys_id'] and API_KEYS['censys_secret']:
            try:
                censys_api = censys.search.CensysHosts(API_KEYS['censys_id'], API_KEYS['censys_secret'])
                query = f"services.service_name: * AND (ip: {target} OR autonomous_system.name: {target})"
                censys_results = censys_api.search(query, per_page=10)
                
                results['censys'] = {
                    'total': censys_results['total'],
                    'hits': []
                }
                
                print_success(f"Found {censys_results['total']} results on Censys")
                
                for hit in censys_results.get('hits', [])[:5]: 
                    result = {
                        'ip': hit.get('ip', 'Unknown'),
                        'services': [service.get('service_name', 'Unknown') for service in hit.get('services', [])],
                        'location': hit.get('location', {}).get('country', 'Unknown'),
                        'autonomous_system': hit.get('autonomous_system', {}).get('name', 'Unknown')
                    }
                    results['censys']['hits'].append(result)
                    
                    print_info(f"IP: {result['ip']}, Services: {', '.join(result['services'])}, AS: {result['autonomous_system']}")
            except Exception as e:
                print_error(f"Error querying Censys: {str(e)}")
        else:
            print_warning("Censys API credentials not provided")
    
    if use_social:
        print_info("Searching social media profiles...")
        social_platforms = {
            'LinkedIn': f"https://www.linkedin.com/company/{target}",
            'Twitter': f"https://twitter.com/{target}",
            'Facebook': f"https://www.facebook.com/{target}",
            'Instagram': f"https://www.instagram.com/{target}",
            'GitHub': f"https://github.com/{target}"
        }
        
        results['social'] = {}
        
        for platform, url in social_platforms.items():
            try:
                response = secure_request(url, method="HEAD", timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    print_success(f"Found {platform} profile: {url}")
                    results['social'][platform] = url
            except:
                pass
    

    save_results = get_input("Save OSINT gathering results? (y/n)").lower()
    if save_results == 'y':
        save_scan_results("osint_gathering", results)
    
    input("\nPress Enter to continue...")

def ssl_tls_analyzer_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("SSL/TLS ANALYZER"))
    print()
    
    hostname = get_input("Enter hostname to analyze")
    
    if not is_valid_hostname(hostname):
        print_error("Invalid hostname")
        time.sleep(2)
        return
    
    port = get_input("Enter port (default: 443)")
    if not port:
        port = 443
    else:
        try:
            port = int(port)
        except:
            print_error("Invalid port")
            time.sleep(2)
            return
    
    print_loading(f"Analyzing SSL/TLS configuration for {hostname}:{port}", 2)
    
    start_time = time.time()
    results = analyze_ssl_tls(hostname, port)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"SSL/TLS analysis completed in {scan_time:.2f} seconds")
    print_gradient_text("=" * 80)
    

    print_gradient_text("\nCertificate Information:")
    print_info(f"Subject: {results['certificate'].get('subject', {}).get('commonName', 'Unknown')}")
    print_info(f"Issuer: {results['certificate'].get('issuer', {}).get('commonName', 'Unknown')}")
    print_info(f"Valid from: {results['certificate'].get('valid_from', 'Unknown')}")
    print_info(f"Valid until: {results['certificate'].get('valid_until', 'Unknown')}")
    print_info(f"Version: {results['certificate'].get('version', 'Unknown')}")
    
    print_gradient_text("\nSupported Protocols:")
    for protocol, supported in results['protocols'].items():
        if supported:
            if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                print_warning(f"{protocol}: Supported (Insecure)")
            else:
                print_success(f"{protocol}: Supported")
        else:
            print_info(f"{protocol}: Not supported")
    

    if results['cipher_suites']:
        print_gradient_text("\nCipher Suites:")
        for cipher in results['cipher_suites'][:5]: 
            print_info(f"{cipher['protocol']} - {cipher['cipher']} ({cipher['bits']} bits)")
        if len(results['cipher_suites']) > 5:
            print_info(f"... and {len(results['cipher_suites']) - 5} more")
    

    if results['vulnerabilities']:
        print_gradient_text("\nVulnerabilities:")
        for vuln in results['vulnerabilities']:
            print_warning(f"{vuln['name']}: {vuln['description']} (Severity: {vuln['severity']})")
    else:
        print_success("\nNo SSL/TLS vulnerabilities found")
    
    print_gradient_text(f"\nSSL/TLS Security Grade: {results['grade']}")
    

    save_results = get_input("Save SSL/TLS analysis results? (y/n)").lower()
    if save_results == 'y':
        save_scan_results("ssl_tls_analysis", {
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_time': scan_time,
            'results': results
        })
    
    input("\nPress Enter to continue...")

def network_topology_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("NETWORK TOPOLOGY MAP"))
    print()
    
    current_network = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        
        ip_parts = ip.split('.')
        current_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except:
        pass
    
    if current_network:
        print_info(f"Detected current network: {current_network}")
        use_current = get_input("Use this network? (y/n)").lower()
        
        if use_current == 'y':
            network = current_network
        else:
            network = get_input("Enter network to map (e.g., 192.168.1.0/24)")
    else:
        network = get_input("Enter network to map (e.g., 192.168.1.0/24)")
    
    print_loading(f"Creating network topology map for {network}", 2)
    
    start_time = time.time()
    results = create_network_topology(network)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"Network topology mapping completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(results['devices'])} devices on {network}")
    print_gradient_text("=" * 80)
    
    if results['image_path']:
        print_success(f"Network topology map saved to {results['image_path']}")
    
    save_results = get_input("Save network topology results? (y/n)").lower()
    if save_results == 'y':
        save_scan_results("network_topology", {
            'network': network,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_time': scan_time,
            'devices': results['devices'],
            'connections': results['connections'],
            'image_path': results['image_path']
        })
    
    input("\nPress Enter to continue...")

def fuzzing_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("FUZZING TOOL"))
    print()
    
    url = get_input("Enter target URL (include http:// or https://)")
    
    if not is_valid_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            if not is_valid_url(url):
                print_error("Invalid URL format")
                time.sleep(2)
                return
        else:
            print_error("Invalid URL format")
            time.sleep(2)
            return
    
    parameter = get_input("Enter parameter to fuzz (leave empty to auto-detect)")
    
    wordlist_path = get_input("Enter path to fuzzing payloads wordlist (leave empty for default)")
    if wordlist_path and not os.path.exists(wordlist_path):
        print_error("Wordlist file not found")
        time.sleep(2)
        return
    
    print_warning("Fuzzing may cause unexpected behavior on the target application.")
    confirm = get_input("Are you sure you want to continue? (y/n)").lower()
    if confirm != 'y':
        return
    
    print_loading(f"Fuzzing {url}", 2)
    
    start_time = time.time()
    results = perform_fuzzing(url, parameter, wordlist_path)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"Fuzzing completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Tested {results['tested_payloads']} payloads")
    print_gradient_text(f"Found {len(results['anomalies'])} anomalies and {len(results['vulnerabilities'])} potential vulnerabilities")
    print_gradient_text("=" * 80)
    
    if results['vulnerabilities']:
        print_gradient_text("\nPotential Vulnerabilities:")
        for vuln in results['vulnerabilities']:
            print_warning(f"Parameter: {vuln['parameter']}")
            print_warning(f"Type: {vuln['type']}")
            print_warning(f"Payload: {vuln['payload']}")
            print_warning(f"Evidence: {vuln['evidence']}")
            print_warning(f"Severity: {vuln['severity']}")
            print()
    
    save_results = get_input("Save fuzzing results? (y/n)").lower()
    if save_results == 'y':
        save_scan_results("fuzzing", {
            'url': url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_time': scan_time,
            'tested_payloads': results['tested_payloads'],
            'anomalies': results['anomalies'],
            'vulnerabilities': results['vulnerabilities']
        })
    
    input("\nPress Enter to continue...")

def iot_scanner_tool() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("IOT SCANNER"))
    print()
    
  
    current_network = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        
       
        ip_parts = ip.split('.')
        current_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except:
        pass
    
    if current_network:
        print_info(f"Detected current network: {current_network}")
        use_current = get_input("Use this network? (y/n)").lower()
        
        if use_current == 'y':
            network = current_network
        else:
            network = get_input("Enter network to scan (e.g., 192.168.1.0/24)")
    else:
        network = get_input("Enter network to scan (e.g., 192.168.1.0/24)")
    
    print_loading(f"Scanning for IoT devices on {network}", 2)
    
    start_time = time.time()
    results = scan_iot_devices(network)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    print()
    print_gradient_text("=" * 80)
    print_gradient_text(f"IoT scan completed in {scan_time:.2f} seconds")
    print_gradient_text(f"Found {len(results)} IoT devices on {network}")
    print_gradient_text("=" * 80)
    
    if results:
        headers = ["IP Address", "Device Type", "Vendor", "Open Ports", "Vulnerabilities"]
        rows = []
        for device in results:
            open_ports = ", ".join(map(str, device['open_ports'][:3]))
            if len(device['open_ports']) > 3:
                open_ports += f" (+{len(device['open_ports']) - 3} more)"
            
            vulns = str(len(device['vulnerabilities']))
            rows.append([device['ip'], device['type'], device['vendor'], open_ports, vulns])
        
        print_result_table(headers, rows)
        
      
        if any(len(device['vulnerabilities']) > 0 for device in results):
            print_gradient_text("\nVulnerabilities Found:")
            for device in results:
                if device['vulnerabilities']:
                    print_gradient_text(f"\nDevice: {device['ip']} ({device['type']})")
                    for vuln in device['vulnerabilities']:
                        print_warning(f"{vuln['name']}: {vuln['description']} (Severity: {vuln['severity']})")
        
       
        save_results = get_input("Save IoT scan results? (y/n)").lower()
        if save_results == 'y':
            save_scan_results("iot_scan", {
                'network': network,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_time': scan_time,
                'devices': results
            })
    
    input("\nPress Enter to continue...")

def reports_menu() -> None:
    while True:
        print_banner()
        print_gradient_text(Center.XCenter("REPORTS"))
        print()
        
      
        reports = list_scan_reports()
        
        if not reports:
            print_warning("No reports found.")
            input("\nPress Enter to continue...")
            return
        
        print_gradient_text("Available Reports:")
        for i, report in enumerate(reports):
            print_info(f"[{i+1}] {report['scan_type']} - {report['timestamp']} - {report['target']}")
        
        print_info(f"[{len(reports)+1}] Generate PDF report")
        print_info(f"[{len(reports)+2}] Export all reports")
        print_info("[0] Back to Main Menu")
        
        choice = get_input("Select a report to view")
        
        try:
            choice_num = int(choice)
            if choice_num == 0:
                return
            elif choice_num == len(reports) + 1:
                generate_pdf_report()
            elif choice_num == len(reports) + 2:
                export_all_reports()
            elif 1 <= choice_num <= len(reports):
                view_report(reports[choice_num - 1])
            else:
                print_error("Invalid option")
                time.sleep(1)
        except ValueError:
            print_error("Invalid option")
            time.sleep(1)

def list_scan_reports() -> List[Dict[str, Any]]:
    reports = []
    
    try:
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE, 'r') as f:
                scan_history = json.load(f)
                
                for scan_id, scan_data in scan_history.items():
                    target = scan_data.get('target', scan_data.get('url', scan_data.get('domain', scan_data.get('network', 'Unknown'))))
                    reports.append({
                        'id': scan_id,
                        'scan_type': scan_data.get('scan_type', 'Unknown'),
                        'timestamp': scan_data.get('timestamp', 'Unknown'),
                        'target': target,
                        'data': scan_data
                    })
    except Exception as e:
        print_error(f"Error loading scan reports: {str(e)}")
    
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return reports

def view_report(report: Dict[str, Any]) -> None:
    print_banner()
    print_gradient_text(Center.XCenter(f"REPORT: {report['scan_type'].upper()}"))
    print()
    
    print_gradient_text("=" * 80)
    print_gradient_text(f"Scan Type: {report['scan_type']}")
    print_gradient_text(f"Target: {report['target']}")
    print_gradient_text(f"Timestamp: {report['timestamp']}")
    print_gradient_text("=" * 80)
    
   
    scan_data = report['data']
    
    if report['scan_type'] == 'port_scan':
        if 'open_ports' in scan_data:
            print_gradient_text("\nOpen Ports:")
            headers = ["Port", "Service"]
            rows = [[str(port['port']), port['service']] for port in scan_data['open_ports']]
            print_result_table(headers, rows)
    
    elif report['scan_type'] == 'network_scan':
        if 'devices' in scan_data:
            print_gradient_text("\nDevices Found:")
            headers = ["IP Address", "MAC Address", "Vendor"]
            rows = [[device['ip'], device['mac'], device.get('vendor', 'Unknown')] for device in scan_data['devices']]
            print_result_table(headers, rows)
    
    elif report['scan_type'] == 'vulnerability_scan':
        if 'vulnerabilities' in scan_data:
            print_gradient_text("\nVulnerabilities Found:")
            headers = ["Port", "Service", "Vulnerability", "Severity"]
            rows = [[str(v['port']), v['service'], v['vulnerability'], v['severity']] for v in scan_data['vulnerabilities']]
            print_result_table(headers, rows)
    
    elif report['scan_type'] == 'website_scan' or report['scan_type'] == 'website_audit':
        results = scan_data.get('results', {})
        
      
        print_gradient_text("\nBasic Information:")
        print_info(f"Status Code: {results.get('status_code', 'Unknown')}")
        print_info(f"Server: {results.get('server', 'Unknown')}")
        
    
        if 'security_headers' in results:
            print_gradient_text("\nSecurity Headers:")
            for header, value in results['security_headers'].items():
                if value == 'Missing':
                    print_warning(f"{header}: {value}")
                else:
                    print_success(f"{header}: Present")
        
       
        if 'issues' in results and results['issues']:
            print_gradient_text("\nIssues Found:")
            headers = ["Type", "Description", "Severity"]
            rows = [[issue['type'], issue['description'], issue['severity']] for issue in results['issues']]
            print_result_table(headers, rows)
        
      
        if 'security_score' in results:
            print_gradient_text(f"\nSecurity Score: {results['security_score']}/100 (Grade: {results.get('security_grade', 'Unknown')})")
    

    print_gradient_text("\nExport Options:")
    print_info("[1] Export to JSON")
    print_info("[2] Export to PDF")
    print_info("[0] Back to Reports Menu")
    
    export_choice = get_input("Select an option")
    
    if export_choice == "1":
        export_report_json(report)
    elif export_choice == "2":
        export_report_pdf(report)

def export_report_json(report: Dict[str, Any]) -> None:
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        filename = f"{report['scan_type']}_{report['target']}_{report['timestamp'].replace(':', '-').replace(' ', '_')}.json"
        filepath = os.path.join(REPORTS_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report['data'], f, indent=4, default=str)
        
        print_success(f"Report exported to {filepath}")
    except Exception as e:
        print_error(f"Error exporting report: {str(e)}")
    
    input("\nPress Enter to continue...")

def export_report_pdf(report: Dict[str, Any]) -> None:
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        filename = f"{report['scan_type']}_{report['target']}_{report['timestamp'].replace(':', '-').replace(' ', '_')}.pdf"
        filepath = os.path.join(REPORTS_DIR, filename)
        
     
        c = canvas.Canvas(filepath, pagesize=letter)
        width, height = letter
        
       
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, height - 72, f"Winter Scanner Report: {report['scan_type'].upper()}")
        
      
        c.setFont("Helvetica-Bold", 12)
        c.drawString(72, height - 100, "Scan Information")
        c.setFont("Helvetica", 10)
        c.drawString(72, height - 120, f"Target: {report['target']}")
        c.drawString(72, height - 135, f"Timestamp: {report['timestamp']}")
        c.drawString(72, height - 150, f"Scan Type: {report['scan_type']}")
        
    
        c.line(72, height - 165, width - 72, height - 165)
        
       
        scan_data = report['data']
        y_position = height - 185
        
        c.setFont("Helvetica-Bold", 12)
        
        if report['scan_type'] == 'port_scan':
            c.drawString(72, y_position, "Open Ports")
            y_position -= 20
            
            if 'open_ports' in scan_data:
                c.setFont("Helvetica", 10)
                for i, port in enumerate(scan_data['open_ports']):
                    c.drawString(72, y_position, f"Port {port['port']}: {port['service']}")
                    y_position -= 15
                    
                
                    if y_position < 72:
                        c.showPage()
                        y_position = height - 72
                        c.setFont("Helvetica", 10)
        
        elif report['scan_type'] == 'network_scan':
            c.drawString(72, y_position, "Devices Found")
            y_position -= 20
            
            if 'devices' in scan_data:
                c.setFont("Helvetica", 10)
                for i, device in enumerate(scan_data['devices']):
                    c.drawString(72, y_position, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device.get('vendor', 'Unknown')}")
                    y_position -= 15
                    
                  
                    if y_position < 72:
                        c.showPage()
                        y_position = height - 72
                        c.setFont("Helvetica", 10)
        
        elif report['scan_type'] == 'vulnerability_scan':
            c.drawString(72, y_position, "Vulnerabilities Found")
            y_position -= 20
            
            if 'vulnerabilities' in scan_data:
                c.setFont("Helvetica", 10)
                for i, vuln in enumerate(scan_data['vulnerabilities']):
                    c.drawString(72, y_position, f"Port {vuln['port']} ({vuln['service']}): {vuln['vulnerability']} (Severity: {vuln['severity']})")
                    y_position -= 15
                    
                    if 'description' in vuln:
                        c.drawString(90, y_position, f"Description: {vuln['description']}")
                        y_position -= 15
                    
                    if 'recommendation' in vuln:
                        c.drawString(90, y_position, f"Recommendation: {vuln['recommendation']}")
                        y_position -= 15
                    
                    y_position -= 5 
                    
                   
                    if y_position < 72:
                        c.showPage()
                        y_position = height - 72
                        c.setFont("Helvetica", 10)
        
        elif report['scan_type'] == 'website_scan' or report['scan_type'] == 'website_audit':
            results = scan_data.get('results', {})
            
            c.drawString(72, y_position, "Website Scan Results")
            y_position -= 20
            c.setFont("Helvetica", 10)
            
           
            c.drawString(72, y_position, f"Status Code: {results.get('status_code', 'Unknown')}")
            y_position -= 15
            c.drawString(72, y_position, f"Server: {results.get('server', 'Unknown')}")
            y_position -= 15
            
          
            if 'security_headers' in results:
                y_position -= 10
                c.setFont("Helvetica-Bold", 10)
                c.drawString(72, y_position, "Security Headers:")
                y_position -= 15
                c.setFont("Helvetica", 10)
                
                for header, value in results['security_headers'].items():
                    c.drawString(72, y_position, f"{header}: {value}")
                    y_position -= 15
                  
                    if y_position < 72:
                        c.showPage()
                        y_position = height - 72
                        c.setFont("Helvetica", 10)
            
            
            if 'issues' in results and results['issues']:
                y_position -= 10
                c.setFont("Helvetica-Bold", 10)
                c.drawString(72, y_position, "Issues Found:")
                y_position -= 15
                c.setFont("Helvetica", 10)
                
                for issue in results['issues']:
                    c.drawString(72, y_position, f"{issue['type']} (Severity: {issue['severity']})")
                    y_position -= 15
                    c.drawString(90, y_position, f"Description: {issue['description']}")
                    y_position -= 20
                    
                    
                    if y_position < 72:
                        c.showPage()
                        y_position = height - 72
                        c.setFont("Helvetica", 10)
            
           
            if 'security_score' in results:
                y_position -= 10
                c.setFont("Helvetica-Bold", 10)
                c.drawString(72, y_position, f"Security Score: {results['security_score']}/100 (Grade: {results.get('security_grade', 'Unknown')})")
        
      
        c.setFont("Helvetica-Italic", 8)
        c.drawString(72, 40, f"Generated by Winter Scanner {VERSION} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(72, 30, f"Winter Security - {AUTHOR}")
        
        c.save()
        
        print_success(f"Report exported to {filepath}")
        
        
        open_report = get_input("Open the report? (y/n)").lower()
        if open_report == 'y':
            try:
                if platform.system() == 'Windows':
                    os.startfile(filepath)
                elif platform.system() == 'Darwin': 
                    subprocess.call(['open', filepath])
                else:  
                    subprocess.call(['xdg-open', filepath])
            except:
                print_info("Could not open the report automatically")
    
    except Exception as e:
        print_error(f"Error exporting report to PDF: {str(e)}")
    
    input("\nPress Enter to continue...")

def generate_pdf_report() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("GENERATE PDF REPORT"))
    print()
    
    
    reports = list_scan_reports()
    
    if not reports:
        print_warning("No reports found.")
        input("\nPress Enter to continue...")
        return
    
    
    title = get_input("Enter report title")
    if not title:
        title = "Winter Scanner Comprehensive Report"
    
   
    print_gradient_text("\nSelect reports to include (comma-separated numbers, 'all' for all):")
    for i, report in enumerate(reports):
        print_info(f"[{i+1}] {report['scan_type']} - {report['timestamp']} - {report['target']}")
    
    selection = get_input("Reports to include").lower()
    
    selected_reports = []
    if selection == 'all':
        selected_reports = reports
    else:
        try:
            indices = [int(idx.strip()) for idx in selection.split(',')]
            for idx in indices:
                if 1 <= idx <= len(reports):
                    selected_reports.append(reports[idx - 1])
        except:
            print_error("Invalid selection")
            time.sleep(2)
            return
    
    if not selected_reports:
        print_error("No reports selected")
        time.sleep(2)
        return
    
    print_loading("Generating comprehensive PDF report", 2)
    
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Winter_Scanner_Report_{timestamp}.pdf"
        filepath = os.path.join(REPORTS_DIR, filename)
        
      
        c = canvas.Canvas(filepath, pagesize=letter)
        width, height = letter
        
     
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(width / 2, height - 150, title)
        
        c.setFont("Helvetica", 14)
        c.drawCentredString(width / 2, height - 180, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        c.setFont("Helvetica-Bold", 12)
        c.drawCentredString(width / 2, height - 220, f"Winter Scanner {VERSION}")
        c.drawCentredString(width / 2, height - 240, f"by {AUTHOR}")
        
    
        c.line(72, 100, width - 72, 100)
        
        c.setFont("Helvetica-Italic", 10)
        c.drawCentredString(width / 2, 80, "CONFIDENTIAL - FOR AUTHORIZED USE ONLY")
        
        c.showPage()
        
    
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, height - 72, "Table of Contents")
        
        c.setFont("Helvetica", 12)
        y_position = height - 100
        
        for i, report in enumerate(selected_reports):
            c.drawString(72, y_position, f"{i+1}. {report['scan_type'].title()} - {report['target']}")
            y_position -= 20
            
           
            if y_position < 72:
                c.showPage()
                y_position = height - 72
                c.setFont("Helvetica", 12)
        
        c.showPage()
        
      
        for i, report in enumerate(selected_reports):
            
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, height - 72, f"{i+1}. {report['scan_type'].title()} - {report['target']}")
            
           
            c.setFont("Helvetica-Bold", 12)
            c.drawString(72, height - 100, "Scan Information")
            c.setFont("Helvetica", 10)
            c.drawString(72, height - 120, f"Target: {report['target']}")
            c.drawString(72, height - 135, f"Timestamp: {report['timestamp']}")
            c.drawString(72, height - 150, f"Scan Type: {report['scan_type']}")
            
          
            c.line(72, height - 165, width - 72, height - 165)
            
       
            scan_data = report['data']
            y_position = height - 185
            
            c.setFont("Helvetica-Bold", 12)
            
           
            if report['scan_type'] == 'port_scan':
                c.drawString(72, y_position, "Open Ports")
                y_position -= 20
                
                if 'open_ports' in scan_data:
                    c.setFont("Helvetica", 10)
                    for port in scan_data['open_ports']:
                        c.drawString(72, y_position, f"Port {port['port']}: {port['service']}")
                        y_position -= 15
                        
                      
                        if y_position < 72:
                            c.showPage()
                            y_position = height - 72
                            c.setFont("Helvetica", 10)
            
            elif report['scan_type'] == 'network_scan':
                c.drawString(72, y_position, "Devices Found")
                y_position -= 20
                
                if 'devices' in scan_data:
                    c.setFont("Helvetica", 10)
                    for device in scan_data['devices']:
                        c.drawString(72, y_position, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device.get('vendor', 'Unknown')}")
                        y_position -= 15
                        
                      
                        if y_position < 72:
                            c.showPage()
                            y_position = height - 72
                            c.setFont("Helvetica", 10)
            
            
            
            
            c.showPage()
        
      
        c.setFont("Helvetica-Italic", 8)
        c.drawString(72, 40, f"Generated by Winter Scanner {VERSION} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(72, 30, f"Winter Security - {AUTHOR}")
        
        c.save()
        
        print_success(f"Comprehensive report exported to {filepath}")
        
      
        open_report = get_input("Open the report? (y/n)").lower()
        if open_report == 'y':
            try:
                if platform.system() == 'Windows':
                    os.startfile(filepath)
                elif platform.system() == 'Darwin':  
                    subprocess.call(['open', filepath])
                else:  
                    subprocess.call(['xdg-open', filepath])
            except:
                print_info("Could not open the report automatically")
    
    except Exception as e:
        print_error(f"Error generating PDF report: {str(e)}")
    
    input("\nPress Enter to continue...")

def export_all_reports() -> None:
   
    print_banner()
    print_gradient_text(Center.XCenter("EXPORT ALL REPORTS"))
    print()
    
  
    reports = list_scan_reports()
    
    if not reports:
        print_warning("No reports found.")
        input("\nPress Enter to continue...")
        return
    
    
    print_gradient_text("Select export format:")
    print_info("[1] JSON")
    print_info("[2] PDF")
    print_info("[3] Both JSON and PDF")
    
    format_choice = get_input("Export format")
    
    if format_choice not in ["1", "2", "3"]:
        print_error("Invalid choice")
        time.sleep(2)
        return
    
    export_json = format_choice in ["1", "3"]
    export_pdf = format_choice in ["2", "3"]
    
    print_loading("Exporting reports", 2)
    
   
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join(REPORTS_DIR, f"export_{timestamp}")
    os.makedirs(export_dir, exist_ok=True)
    
   
    json_files = []
    pdf_files = []
    
    for report in reports:
        try:
          
            if export_json:
                json_filename = f"{report['scan_type']}_{report['target']}_{report['timestamp'].replace(':', '-').replace(' ', '_')}.json"
                json_filepath = os.path.join(export_dir, json_filename)
                
                with open(json_filepath, 'w') as f:
                    json.dump(report['data'], f, indent=4, default=str)
                
                json_files.append(json_filepath)
            
         
            if export_pdf:
                pdf_filename = f"{report['scan_type']}_{report['target']}_{report['timestamp'].replace(':', '-').replace(' ', '_')}.pdf"
                pdf_filepath = os.path.join(export_dir, pdf_filename)
                
               
                c = canvas.Canvas(pdf_filepath, pagesize=letter)
                width, height = letter
                
          
                c.setFont("Helvetica-Bold", 16)
                c.drawString(72, height - 72, f"Winter Scanner Report: {report['scan_type'].upper()}")
                
               
                c.setFont("Helvetica-Bold", 12)
                c.drawString(72, height - 100, "Scan Information")
                c.setFont("Helvetica", 10)
                c.drawString(72, height - 120, f"Target: {report['target']}")
                c.drawString(72, height - 135, f"Timestamp: {report['timestamp']}")
                c.drawString(72, height - 150, f"Scan Type: {report['scan_type']}")
                
               
                c.line(72, height - 165, width - 72, height - 165)
                
                
                
                
                c.setFont("Helvetica-Italic", 8)
                c.drawString(72, 40, f"Generated by Winter Scanner {VERSION} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                c.drawString(72, 30, f"Winter Security - {AUTHOR}")
                
                c.save()
                
                pdf_files.append(pdf_filepath)
        
        except Exception as e:
            print_error(f"Error exporting report {report['id']}: {str(e)}")
    
  
    print()
    if export_json:
        print_success(f"Exported {len(json_files)} reports to JSON format")
    if export_pdf:
        print_success(f"Exported {len(pdf_files)} reports to PDF format")
    
    print_success(f"All reports exported to {export_dir}")
    
  
    open_dir = get_input("Open the export directory? (y/n)").lower()
    if open_dir == 'y':
        try:
            if platform.system() == 'Windows':
                os.startfile(export_dir)
            elif platform.system() == 'Darwin':  
                subprocess.call(['open', export_dir])
            else: 
                subprocess.call(['xdg-open', export_dir])
        except:
            print_info("Could not open the directory automatically")
    
    input("\nPress Enter to continue...")

def save_scan_results(scan_type: str, data: Dict[str, Any], generate_pdf: bool = False) -> Optional[str]:

    try:
        os.makedirs(os.path.dirname(SCAN_HISTORY_FILE), exist_ok=True)
        
    
        scan_history = {}
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE, 'r') as f:
                scan_history = json.load(f)
        
    
        scan_id = str(uuid.uuid4())
        
      
        data['scan_type'] = scan_type
        
    
        scan_history[scan_id] = data
        
       
        with open(SCAN_HISTORY_FILE, 'w') as f:
            json.dump(scan_history, f, indent=4, default=str)
        
        print_success("Scan results saved successfully")
        
     
        if generate_pdf:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
          
            target = data.get('target', data.get('url', data.get('domain', data.get('network', 'unknown'))))
            target = target.replace(':', '_').replace('/', '_').replace('\\', '_')
            
            filename = f"{scan_type}_{target}_{timestamp}.pdf"
            filepath = os.path.join(REPORTS_DIR, filename)
            
           
            c = canvas.Canvas(filepath, pagesize=letter)
            width, height = letter
            
      
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, height - 72, f"Winter Scanner Report: {scan_type.upper()}")
            
         
            c.setFont("Helvetica-Bold", 12)
            c.drawString(72, height - 100, "Scan Information")
            c.setFont("Helvetica", 10)
            c.drawString(72, height - 120, f"Target: {target}")
            c.drawString(72, height - 135, f"Timestamp: {data.get('timestamp', 'Unknown')}")
            c.drawString(72, height - 150, f"Scan Type: {scan_type}")
            
        
            c.line(72, height - 165, width - 72, height - 165)
            
          
            
        
            c.setFont("Helvetica-Italic", 8)
            c.drawString(72, 40, f"Generated by Winter Scanner {VERSION} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(72, 30, f"Winter Security - {AUTHOR}")
            
            c.save()
            
            print_success(f"PDF report saved to {filepath}")
            return filepath
        
        return None
    
    except Exception as e:
        print_error(f"Error saving scan results: {str(e)}")
        return None

def scheduled_scans_menu() -> None:
 
    while True:
        print_banner()
        print_gradient_text(Center.XCenter("SCHEDULED SCANS"))
        print()
        
       
        scheduled_scans = list_scheduled_scans()
        
        print_gradient_text("Scheduled Scans:")
        if scheduled_scans:
            for i, scan in enumerate(scheduled_scans):
                status = "Active" if scan['active'] else "Inactive"
                print_info(f"[{i+1}] {scan['name']} - {scan['target']} - {scan['schedule']} - {status}")
        else:
            print_warning("No scheduled scans found.")
        
        print()
        print_gradient_text("Options:")
        print_info("[1] Create new scheduled scan")
        print_info("[2] Edit scheduled scan")
        print_info("[3] Delete scheduled scan")
        print_info("[4] Run scheduled scan now")
        print_info("[5] Enable/disable scheduled scan")
        print_info("[0] Back to Main Menu")
        
        choice = get_input("Select an option")
        
        if choice == "1":
            create_scheduled_scan()
        elif choice == "2":
            edit_scheduled_scan()
        elif choice == "3":
            delete_scheduled_scan()
        elif choice == "4":
            run_scheduled_scan()
        elif choice == "5":
            toggle_scheduled_scan()
        elif choice == "0":
            return
        else:
            print_error("Invalid option")
            time.sleep(1)

def list_scheduled_scans() -> List[Dict[str, Any]]:
  
    scheduled_scans = []
    
    try:
        if os.path.exists(SCHEDULED_SCANS_FILE):
            with open(SCHEDULED_SCANS_FILE, 'r') as f:
                scheduled_scans = json.load(f)
    except Exception as e:
        print_error(f"Error loading scheduled scans: {str(e)}")
    
    return scheduled_scans

def save_scheduled_scans(scans: List[Dict[str, Any]]) -> bool:
 
    try:
        os.makedirs(os.path.dirname(SCHEDULED_SCANS_FILE), exist_ok=True)
        
        with open(SCHEDULED_SCANS_FILE, 'w') as f:
            json.dump(scans, f, indent=4)
        
        return True
    except Exception as e:
        print_error(f"Error saving scheduled scans: {str(e)}")
        return False

def create_scheduled_scan() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("CREATE SCHEDULED SCAN"))
    print()
    
    name = get_input("Enter scan name")
    if not name:
        print_error("Scan name cannot be empty")
        time.sleep(2)
        return
    
    scan_type = get_input("Enter scan type (port, network, vulnerability, website)")
    if scan_type not in ["port", "network", "vulnerability", "website"]:
        print_error("Invalid scan type")
        time.sleep(2)
        return
    
    target = get_input("Enter target (IP, hostname, URL, or network)")
    if not target:
        print_error("Target cannot be empty")
        time.sleep(2)
        return
    
    print_gradient_text("\nSchedule Options:")
    print_info("[1] Hourly")
    print_info("[2] Daily")
    print_info("[3] Weekly")
    print_info("[4] Monthly")
    print_info("[5] Custom (cron expression)")
    
    schedule_type = get_input("Select schedule type")
    
    if schedule_type == "1":
        schedule = "hourly"
    elif schedule_type == "2":
        time_of_day = get_input("Enter time (HH:MM)")
        schedule = f"daily at {time_of_day}"
    elif schedule_type == "3":
        day_of_week = get_input("Enter day of week (0-6, where 0 is Monday)")
        time_of_day = get_input("Enter time (HH:MM)")
        schedule = f"weekly on {day_of_week} at {time_of_day}"
    elif schedule_type == "4":
        day_of_month = get_input("Enter day of month (1-31)")
        time_of_day = get_input("Enter time (HH:MM)")
        schedule = f"monthly on {day_of_month} at {time_of_day}"
    elif schedule_type == "5":
        schedule = get_input("Enter cron expression (e.g., '0 * * * *' for hourly)")
    else:
        print_error("Invalid schedule type")
        time.sleep(2)
        return
    

    new_scan = {
        'name': name,
        'scan_type': scan_type,
        'target': target,
        'schedule': schedule,
        'active': True,
        'last_run': None,
        'next_run': calculate_next_run(schedule)
    }
    
 
    scheduled_scans = list_scheduled_scans()

    scheduled_scans.append(new_scan)
    
  
    if save_scheduled_scans(scheduled_scans):
        print_success(f"Scheduled scan '{name}' created successfully")
        
      
        setup_scan_schedule(new_scan)
    
    input("\nPress Enter to continue...")

def edit_scheduled_scan() -> None:
   
    print_banner()
    print_gradient_text(Center.XCenter("EDIT SCHEDULED SCAN"))
    print()
    
    
    scheduled_scans = list_scheduled_scans()
    
    if not scheduled_scans:
        print_warning("No scheduled scans found.")
        input("\nPress Enter to continue...")
        return
    
    for i, scan in enumerate(scheduled_scans):
        status = "Active" if scan['active'] else "Inactive"
        print_info(f"[{i+1}] {scan['name']} - {scan['target']} - {scan['schedule']} - {status}")
    
    scan_index = get_input("Select scan to edit (number)")
    
    try:
        index = int(scan_index) - 1
        if index < 0 or index >= len(scheduled_scans):
            print_error("Invalid selection")
            time.sleep(2)
            return
        
        scan = scheduled_scans[index]
        
      
        print_gradient_text("\nCurrent values:")
        print_info(f"Name: {scan['name']}")
        print_info(f"Scan Type: {scan['scan_type']}")
        print_info(f"Target: {scan['target']}")
        print_info(f"Schedule: {scan['schedule']}")
        print_info(f"Status: {'Active' if scan['active'] else 'Inactive'}")
        
        print_gradient_text("\nEnter new values (leave empty to keep current):")
        
        new_name = get_input("New name")
        if new_name:
            scan['name'] = new_name
        
        new_scan_type = get_input("New scan type (port, network, vulnerability, website)")
        if new_scan_type in ["port", "network", "vulnerability", "website"]:
            scan['scan_type'] = new_scan_type
        
        new_target = get_input("New target")
        if new_target:
            scan['target'] = new_target
        
        print_gradient_text("\nSchedule Options:")
        print_info("[1] Hourly")
        print_info("[2] Daily")
        print_info("[3] Weekly")
        print_info("[4] Monthly")
        print_info("[5] Custom (cron expression)")
        print_info("[0] Keep current")
        
        schedule_type = get_input("Select schedule type")
        
        if schedule_type == "1":
            scan['schedule'] = "hourly"
        elif schedule_type == "2":
            time_of_day = get_input("Enter time (HH:MM)")
            scan['schedule'] = f"daily at {time_of_day}"
        elif schedule_type == "3":
            day_of_week = get_input("Enter day of week (0-6, where 0 is Monday)")
            time_of_day = get_input("Enter time (HH:MM)")
            scan['schedule'] = f"weekly on {day_of_week} at {time_of_day}"
        elif schedule_type == "4":
            day_of_month = get_input("Enter day of month (1-31)")
            time_of_day = get_input("Enter time (HH:MM)")
            scan['schedule'] = f"monthly on {day_of_month} at {time_of_day}"
        elif schedule_type == "5":
            cron_expr = get_input("Enter cron expression (e.g., '0 * * * *' for hourly)")
            scan['schedule'] = cron_expr
        
     
        scan['next_run'] = calculate_next_run(scan['schedule'])
        
       
        if save_scheduled_scans(scheduled_scans):
            print_success(f"Scheduled scan '{scan['name']}' updated successfully")
            
           
            setup_scan_schedule(scan)
    
    except ValueError:
        print_error("Invalid selection")
    
    input("\nPress Enter to continue...")

def delete_scheduled_scan() -> None:
   
    print_banner()
    print_gradient_text(Center.XCenter("DELETE SCHEDULED SCAN"))
    print()

    scheduled_scans = list_scheduled_scans()
    
    if not scheduled_scans:
        print_warning("No scheduled scans found.")
        input("\nPress Enter to continue...")
        return
    
    for i, scan in enumerate(scheduled_scans):
        status = "Active" if scan['active'] else "Inactive"
        print_info(f"[{i+1}] {scan['name']} - {scan['target']} - {scan['schedule']} - {status}")
    
    scan_index = get_input("Select scan to delete (number)")
    
    try:
        index = int(scan_index) - 1
        if index < 0 or index >= len(scheduled_scans):
            print_error("Invalid selection")
            time.sleep(2)
            return
        
        scan = scheduled_scans[index]
        
        confirm = get_input(f"Are you sure you want to delete '{scan['name']}'? (y/n)").lower()
        if confirm != 'y':
            return
        
 
        del scheduled_scans[index]
        
    
        if save_scheduled_scans(scheduled_scans):
            print_success(f"Scheduled scan '{scan['name']}' deleted successfully")
    
    except ValueError:
        print_error("Invalid selection")
    
    input("\nPress Enter to continue...")

def run_scheduled_scan() -> None:
    print_banner()
    print_gradient_text(Center.XCenter("RUN SCHEDULED SCAN"))
    print()
    
   
    scheduled_scans = list_scheduled_scans()
    
    if not scheduled_scans:
        print_warning("No scheduled scans found.")
        input("\nPress Enter to continue...")
        return
    
    for i, scan in enumerate(scheduled_scans):
        status = "Active" if scan['active'] else "Inactive"
        print_info(f"[{i+1}] {scan['name']} - {scan['target']} - {scan['schedule']} - {status}")
    
    scan_index = get_input("Select scan to run (number)")
    
    try:
        index = int(scan_index) - 1
        if index < 0 or index >= len(scheduled_scans):
            print_error("Invalid selection")
            time.sleep(2)
            return
        
        scan = scheduled_scans[index]
        
        print_loading(f"Running scheduled scan '{scan['name']}'", 2)
        
    
        execute_scheduled_scan(scan)
        
       
        scan['last_run'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
   
        save_scheduled_scans(scheduled_scans)
    
    except ValueError:
        print_error("Invalid selection")
    
    input("\nPress Enter to continue...")

def toggle_scheduled_scan() -> None:
  
    print_banner()
    print_gradient_text(Center.XCenter("ENABLE/DISABLE SCHEDULED SCAN"))
    print()
    
  
    scheduled_scans = list_scheduled_scans()
    
    if not scheduled_scans:
        print_warning("No scheduled scans found.")
        input("\nPress Enter to continue...")
        return
    
    for i, scan in enumerate(scheduled_scans):
        status = "Active" if scan['active'] else "Inactive"
        print_info(f"[{i+1}] {scan['name']} - {scan['target']} - {scan['schedule']} - {status}")
    
    scan_index = get_input("Select scan to toggle (number)")
    
    try:
        index = int(scan_index) - 1
        if index < 0 or index >= len(scheduled_scans):
            print_error("Invalid selection")
            time.sleep(2)
            return
        
        scan = scheduled_scans[index]
        
     
        scan['active'] = not scan['active']
        status = "enabled" if scan['active'] else "disabled"
        
      
        if save_scheduled_scans(scheduled_scans):
            print_success(f"Scheduled scan '{scan['name']}' {status} successfully")
            
           
            if scan['active']:
                setup_scan_schedule(scan)
            else:
              
                pass
    
    except ValueError:
        print_error("Invalid selection")
    
    input("\nPress Enter to continue...")

def calculate_next_run(schedule: str) -> str:
    now = datetime.now()
    
    try:
        if schedule == "hourly":
            next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif schedule.startswith("daily at "):
            time_str = schedule.replace("daily at ", "")
            hour, minute = map(int, time_str.split(":"))
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
        elif schedule.startswith("weekly on "):
            parts = schedule.replace("weekly on ", "").split(" at ")
            day_of_week = int(parts[0])
            hour, minute = map(int, parts[1].split(":"))
            
            days_ahead = day_of_week - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=days_ahead)
        elif schedule.startswith("monthly on "):
            parts = schedule.replace("monthly on ", "").split(" at ")
            day_of_month = int(parts[0])
            hour, minute = map(int, parts[1].split(":"))
            
            next_run = now.replace(day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
               
                if now.month == 12:
                    next_run = next_run.replace(year=now.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=now.month + 1)
        else:
          
            next_run = now + timedelta(hours=1) 
    except:
      
        next_run = now + timedelta(hours=1)
    
    return next_run.strftime("%Y-%m-%d %H:%M:%S")

def setup_scan_schedule(scan: Dict[str, Any]) -> None:
   

    
    if not scan['active']:
        return
    
    schedule_str = scan['schedule']
    
   
    if schedule_str == "hourly":
        schedule.every().hour.do(execute_scheduled_scan, scan)
    elif schedule_str.startswith("daily at "):
        time_str = schedule_str.replace("daily at ", "")
        schedule.every().day.at(time_str).do(execute_scheduled_scan, scan)
    elif schedule_str.startswith("weekly on "):
        parts = schedule_str.replace("weekly on ", "").split(" at ")
        day_of_week = int(parts[0])
        time_str = parts[1]
        
        days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        if 0 <= day_of_week < len(days):
            getattr(schedule.every(), days[day_of_week]).at(time_str).do(execute_scheduled_scan, scan)
    elif schedule_str.startswith("monthly on "):
       
        pass
    else:
       
        pass

def execute_scheduled_scan(scan: Dict[str, Any]) -> None:
    scan_type = scan['scan_type']
    target = scan['target']
    
    print_info(f"Executing scheduled scan: {scan['name']} ({scan_type} scan on {target})")
    
    try:
        if scan_type == "port":
           
            if is_valid_ip(target):
                ip = target
            else:
                ip = get_ip_from_hostname(target)
                if not ip:
                    print_error(f"Could not resolve hostname: {target}")
                    return
            
       
            open_ports = []
            for port in DEFAULT_PORTS:
                port_num, is_open, service = scan_port(ip, port)
                if is_open:
                    open_ports.append({'port': port_num, 'service': service})
            
       
            save_scan_results("port_scan", {
                'target': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'open_ports': open_ports
            })
        
        elif scan_type == "network":
       
            devices = scan_network(target)
            
           
            for device in devices:
                device['vendor'] = get_mac_vendor(device['mac'])
            
          
            save_scan_results("network_scan", {
                'network': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'devices': devices
            })
        
        elif scan_type == "vulnerability":
            
            if is_valid_ip(target):
                ip = target
            else:
                ip = get_ip_from_hostname(target)
                if not ip:
                    print_error(f"Could not resolve hostname: {target}")
                    return
            
            
            open_ports = []
            for port in DEFAULT_PORTS:
                port_num, is_open, _ = scan_port(ip, port)
                if is_open:
                    open_ports.append(port_num)
            
       
            vulnerabilities = check_common_vulnerabilities(ip, open_ports)
            
       
            save_scan_results("vulnerability_scan", {
                'target': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'open_ports': open_ports,
                'vulnerabilities': vulnerabilities
            })
        
        elif scan_type == "website":
      
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
         
            results = {}
        
            start_time = time.time()
            response = secure_request(target, timeout=10)
            end_time = time.time()
            
   
            results['status_code'] = response.status_code
            results['response_time'] = (end_time - start_time) * 1000  
            results['headers'] = dict(response.headers)
            results['server'] = response.headers.get('Server', 'Unknown')
            
        
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Missing'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Missing'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Missing'),
                'X-Frame-Options': response.headers.get('X-Frame-Options', 'Missing'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Missing'),
                'Referrer-Policy': response.headers.get('Referrer-Policy', 'Missing')
            }
            results['security_headers'] = security_headers
            
        
            issues = []
            for header, value in security_headers.items():
                if value == 'Missing':
                    issues.append({
                        'type': 'Missing Security Header',
                        'description': f"The {header} security header is missing",
                        'severity': 'Medium'
                    })
            
            results['issues'] = issues
            
            
            save_scan_results("website_scan", {
                'url': target,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'scan_type': 'basic',
                'results': results
            })
        
        print_success(f"Scheduled scan '{scan['name']}' completed successfully")
    
    except Exception as e:
        print_error(f"Error executing scheduled scan '{scan['name']}': {str(e)}")

def settings_menu() -> None:
    global USE_PROXIES, PROXY_LIST, MAX_THREADS, SCAN_TIMEOUT, USE_GRADIENTS, DARK_MODE, TOR_ENABLED, TOR_PORT, RANDOMIZE_SCAN_DELAY, MIN_SCAN_DELAY, MAX_SCAN_DELAY, API_KEYS
    
    while True:
        print_banner()
        print_gradient_text(Center.XCenter("SETTINGS"))
        print()
        
        settings_options = f"""
        [1] Proxy Settings       - Currently: {'Enabled' if USE_PROXIES else 'Disabled'}
        [2] Thread Settings      - Currently: {MAX_THREADS} threads
        [3] Timeout Settings     - Currently: {SCAN_TIMEOUT} seconds
        [4] Load Proxy List      - Currently: {len(PROXY_LIST)} proxies loaded
        [5] Test Connection      - Check your internet connection
        [6] Gradient Display     - Currently: {'Enabled' if USE_GRADIENTS else 'Disabled'}
        [7] Dark/Light Mode      - Currently: {'Dark' if DARK_MODE else 'Light'}
        [8] Tor Settings         - Currently: {'Enabled' if TOR_ENABLED else 'Disabled'}
        [9] Scan Delay Settings  - Currently: {'Enabled' if RANDOMIZE_SCAN_DELAY else 'Disabled'}
        [10] API Keys            - Configure API keys for external services
        [0] Back to Main Menu
        """
        
        print_gradient_text(Center.XCenter(Box.DoubleCube(settings_options)))
        
        choice = get_input("Select an option")
        
        if choice == "1":
            use_proxies = get_input("Enable proxy rotation? (y/n)").lower()
            USE_PROXIES = (use_proxies == 'y')
            print_success(f"Proxy rotation {'enabled' if USE_PROXIES else 'disabled'}")
            time.sleep(1)
        
        elif choice == "2":
            try:
                threads = int(get_input("Enter maximum number of threads (10-500)"))
                if 10 <= threads <= 500:
                    MAX_THREADS = threads
                    print_success(f"Maximum threads set to {MAX_THREADS}")
                else:
                    print_error("Thread count must be between 10 and 500")
            except:
                print_error("Invalid input")
            time.sleep(1)
        
        elif choice == "3":
            try:
                timeout = float(get_input("Enter scan timeout in seconds (0.5-10.0)"))
                if 0.5 <= timeout <= 10.0:
                    SCAN_TIMEOUT = timeout
                    print_success(f"Scan timeout set to {SCAN_TIMEOUT} seconds")
                else:
                    print_error("Timeout must be between 0.5 and 10.0 seconds")
            except:
                print_error("Invalid input")
            time.sleep(1)
        
        elif choice == "4":
            proxy_file = get_input("Enter path to proxy list file (or leave empty to cancel)")
            if proxy_file:
                proxies = load_proxies(proxy_file)
                if proxies:
                    PROXY_LIST = proxies
                    print_success(f"Loaded {len(PROXY_LIST)} proxies")
                else:
                    print_error("No proxies loaded. Check file format (IP:PORT, one per line)")
            time.sleep(1)
        
        elif choice == "5":
            print_loading("Testing connection", 1)
            try:
                start_time = time.time()
                response = secure_request("https://www.google.com", timeout=5)
                end_time = time.time()
                
                if response.status_code == 200:
                    print_success(f"Connection successful! Response time: {(end_time - start_time) * 1000:.2f} ms")
                    
                    if USE_PROXIES and PROXY_LIST:
                        print_info("Testing proxy connection...")
                        try:
                            proxy_response = secure_request("https://api.ipify.org?format=json", timeout=10)
                            ip = proxy_response.json()['ip']
                            print_success(f"Proxy connection successful! Your IP: {ip}")
                        except Exception as e:
                            print_error(f"Proxy connection failed: {str(e)}")
                else:
                    print_error(f"Connection test failed with status code: {response.status_code}")
            except Exception as e:
                print_error(f"Connection test failed: {str(e)}")
            
            input("\nPress Enter to continue...")
        
        elif choice == "6":
            use_gradients = get_input("Enable gradient display? (y/n)").lower()
            USE_GRADIENTS = (use_gradients == 'y')
            print_success(f"Gradient display {'enabled' if USE_GRADIENTS else 'disabled'}")
            time.sleep(1)
        
        elif choice == "7":
            dark_mode = get_input("Use dark mode? (y/n)").lower()
            DARK_MODE = (dark_mode == 'y')
            print_success(f"{'Dark' if DARK_MODE else 'Light'} mode enabled")
            time.sleep(1)
        
        elif choice == "8":
            tor_enabled = get_input("Enable Tor routing? (y/n)").lower()
            TOR_ENABLED = (tor_enabled == 'y')
            
            if TOR_ENABLED:
                try:
                    tor_port = int(get_input("Enter Tor SOCKS port (default: 9050)"))
                    if tor_port > 0:
                        TOR_PORT = tor_port
                except:
                    pass
                
          
                print_loading("Testing Tor connection", 1)
                if setup_tor_connection():
                    print_success("Tor routing enabled and working")
                else:
                    print_error("Tor routing enabled but not working")
                    print_warning("Make sure Tor is running and accessible")
            else:
                print_success("Tor routing disabled")
            
            time.sleep(1)
        
        elif choice == "9":
            randomize_delay = get_input("Randomize scan delay? (y/n)").lower()
            RANDOMIZE_SCAN_DELAY = (randomize_delay == 'y')
            
            if RANDOMIZE_SCAN_DELAY:
                try:
                    min_delay = float(get_input("Enter minimum delay in seconds (0.1-5.0)"))
                    max_delay = float(get_input("Enter maximum delay in seconds (min-10.0)"))
                    
                    if 0.1 <= min_delay <= 5.0 and min_delay <= max_delay <= 10.0:
                        MIN_SCAN_DELAY = min_delay
                        MAX_SCAN_DELAY = max_delay
                        print_success(f"Scan delay set to {MIN_SCAN_DELAY}-{MAX_SCAN_DELAY} seconds")
                    else:
                        print_error("Invalid delay range")
                except:
                    print_error("Invalid input")
            
            print_success(f"Scan delay randomization {'enabled' if RANDOMIZE_SCAN_DELAY else 'disabled'}")
            time.sleep(1)
        
        elif choice == "10":
            api_keys_menu()
        
        elif choice == "0":
            return
        
        else:
            print_error("Invalid option")
            time.sleep(1)

def api_keys_menu() -> None:
   
    global API_KEYS
    
    while True:
        print_banner()
        print_gradient_text(Center.XCenter("API KEYS"))
        print()
        
        print_gradient_text("Current API Keys:")
        for service, key in API_KEYS.items():
            status = "Set" if key else "Not set"
            if key and len(key) > 8:
                masked_key = key[:4] + "*" * (len(key) - 8) + key[-4:]
            else:
                masked_key = ""
            print_info(f"{service}: {status} {masked_key}")
        
        print()
        print_gradient_text("Options:")
        print_info("[1] Set Shodan API Key")
        print_info("[2] Set Censys API ID and Secret")
        print_info("[3] Set VirusTotal API Key")
        print_info("[0] Back to Settings Menu")
        
        choice = get_input("Select an option")
        
        if choice == "1":
            key = get_input("Enter Shodan API Key (leave empty to cancel)")
            if key:
                API_KEYS['shodan'] = key
                print_success("Shodan API Key set successfully")
            time.sleep(1)
        
        elif choice == "2":
            censys_id = get_input("Enter Censys API ID (leave empty to cancel)")
            if censys_id:
                censys_secret = get_input("Enter Censys API Secret")
                if censys_secret:
                    API_KEYS['censys_id'] = censys_id
                    API_KEYS['censys_secret'] = censys_secret
                    print_success("Censys API credentials set successfully")
            time.sleep(1)
        
        elif choice == "3":
            key = get_input("Enter VirusTotal API Key (leave empty to cancel)")
            if key:
                API_KEYS['virustotal'] = key
                print_success("VirusTotal API Key set successfully")
            time.sleep(1)
        
        elif choice == "0":
            return
        
        else:
            print_error("Invalid option")
            time.sleep(1)

def main() -> None:
   

    os.makedirs(os.path.dirname(SCAN_HISTORY_FILE), exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(WORDLISTS_DIR, exist_ok=True)
    os.makedirs(PLUGINS_DIR, exist_ok=True)

    check_for_updates()
    

    if platform.system() == 'Windows':
        os.system('')
    
    while True:
        print_banner()
        print_menu()
        
        choice = get_input("")
        
        if choice == "1":
            port_scanner()
        elif choice == "2":
            network_scanner()
        elif choice == "3":
            service_detector()
        elif choice == "4":
            vulnerability_scanner()
        elif choice == "5":
            traceroute_tool()
        elif choice == "6":
            dns_lookup_tool()
        elif choice == "7":
            ping_sweep_tool()
        elif choice == "8":
            website_scanner()
        elif choice == "9":
            advanced_tools_menu()
        elif choice == "10":
            reports_menu()
        elif choice == "11":
            scheduled_scans_menu()
        elif choice == "12":
            settings_menu()
        elif choice == "0":
            print_gradient_text("\nThank you for using Winter Scanner. Goodbye!\n")
            sys.exit(0)
        else:
            print_error("Invalid option")
            time.sleep(1)

if __name__ == "__main__":
    try:
       
        def signal_handler(sig, frame):
            print_gradient_text("\nOperation cancelled by user. Exiting...\n")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
       
        main()
    except KeyboardInterrupt:
        print_gradient_text("\nOperation cancelled by user. Exiting...\n")
        sys.exit(0)
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
        
        
        import traceback
        traceback.print_exc()
        
        sys.exit(1)
