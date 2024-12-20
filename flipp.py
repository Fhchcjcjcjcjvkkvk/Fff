import pywifi
from pywifi import const
import subprocess
import re

def get_cipher_and_encryption(bssid):
    """
    Use netsh to get encryption and cipher details for a given BSSID.
    """
    try:
        # Run netsh command to get network details
        result = subprocess.check_output(["netsh", "wlan", "show", "network", "mode=bssid"], text=True)
        
        # Extract the details for the specific BSSID
        network_details = result.split(bssid)[1] if bssid in result else None
        if network_details:
            # Match encryption and cipher
            encryption = re.search(r"Authentication\s*:\s*(.*)", network_details)
            cipher = re.search(r"Cipher\s*:\s*(.*)", network_details)
            return encryption.group(1).strip() if encryption else "Unknown", cipher.group(1).strip() if cipher else "Unknown"
        return "Unknown", "Unknown"
    except Exception as e:
        return f"Error: {e}", "Unknown"

def scan_networks():
    """
    Scans for available Wi-Fi networks and displays details like
    BSSID, ESSID, Signal Strength (PWR), Encryption, and Cipher.
    """
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.scan()
    scan_results = iface.scan_results()

    networks = []
    for network in scan_results:
        bssid = network.bssid
        essid = network.ssid
        signal = network.signal

        # Get encryption and cipher information using netsh
        encryption, cipher = get_cipher_and_encryption(bssid)

        networks.append({
            "BSSID": bssid,
            "ESSID": essid,
            "PWR": signal,
            "ENCR": encryption,
            "CIPHER": cipher
        })

    return networks

def display_networks(networks):
    """
    Displays the networks in a tabular format.
    """
    print(f"{'BSSID':<20} {'ESSID':<20} {'PWR':<5} {'ENCR':<10} {'CIPHER':<10}")
    print("-" * 70)
    for network in networks:
        print(f"{network['BSSID']:<20} {network['ESSID']:<20} {network['PWR']:<5} {network['ENCR']:<10} {network['CIPHER']:<10}")

def main():
    print("Scanning for Wi-Fi networks...\n")
    networks = scan_networks()
    if networks:
        display_networks(networks)
    else:
        print("No networks found.")

if __name__ == "__main__":
    main()
