import time
import subprocess
import pywifi
from pywifi import const
from prettytable import PrettyTable

def fetch_cipher_details(bssid):
    """Fetch the encryption and cipher details using netsh command."""
    try:
        output = subprocess.check_output(f'netsh wlan show networks mode=bssid', shell=True, text=True)
        networks = output.split("SSID ")
        for network in networks:
            if bssid in network:
                if "Encryption" in network:
                    encryption = next((line.split(": ")[1] for line in network.splitlines() if "Encryption" in line), "Unknown")
                else:
                    encryption = "Unknown"
                if "Cipher" in network:
                    cipher = next((line.split(": ")[1] for line in network.splitlines() if "Cipher" in line), "Unknown")
                else:
                    cipher = "Unknown"
                return encryption, cipher
    except subprocess.CalledProcessError as e:
        print(f"Error fetching cipher details: {e}")
        return "Unknown", "Unknown"

def scan_networks(iface_name):
    """Scan networks using pywifi on a specific interface."""
    wifi = pywifi.PyWiFi()
    iface = next((i for i in wifi.interfaces() if i.name() == iface_name), None)
    if iface is None:
        print(f"Interface {iface_name} not found.")
        return []

    iface.scan()
    time.sleep(3)  # Allow time for scan to complete
    return iface.scan_results()

def display_networks(iface_name):
    """Display networks in a table format."""
    table = PrettyTable()
    table.field_names = ["BSSID", "ESSID", "PWR", "ENCR", "CIPHER"]

    networks = scan_networks(iface_name)
    for network in networks:
        bssid = network.bssid
        essid = network.ssid
        pwr = network.signal

        # Fetch encryption and cipher details
        encryption, cipher = fetch_cipher_details(bssid)

        table.add_row([bssid, essid, pwr, encryption, cipher])

    print(table)

def live_update(iface_name):
    """Continuously scan and display networks on a specific interface."""
    try:
        while True:
            print(f"\nScanning for networks on interface {iface_name}...\n")
            display_networks(iface_name)
            time.sleep(5)  # Update every 5 seconds
    except KeyboardInterrupt:
        print("\nExiting program.")

if __name__ == "__main__":
    iface_name = input("Enter the interface name (e.g., Wi-Fi): ")
    live_update(iface_name)

