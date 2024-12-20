import subprocess
import pywifi
from pywifi import PyWiFi, const

def get_wifi_interface():
    """Get the first wireless interface."""
    wifi = PyWiFi()
    ifaces = wifi.interfaces()
    if not ifaces:
        print("No wireless interface found!")
        return None
    return ifaces[0]

def scan_networks(interface):
    """Scan for available networks."""
    interface.scan()
    networks = interface.scan_results()
    return networks

def get_cipher_and_encryption():
    """Use netsh to retrieve encryption and cipher details."""
    try:
        result = subprocess.check_output(
            ["netsh", "wlan", "show", "network", "mode=bssid"],
            text=True
        )
        networks = result.split("\n\n")
        network_details = {}
        for network in networks:
            lines = network.splitlines()
            bssid = None
            encryption = "Unknown"
            cipher = "Unknown"
            for line in lines:
                if "BSSID" in line:
                    bssid = line.split(":")[-1].strip()
                if "Authentication" in line:
                    encryption = line.split(":")[-1].strip()
                if "Cipher" in line:
                    cipher = line.split(":")[-1].strip()
            if bssid:
                network_details[bssid] = (encryption, cipher)
        return network_details
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving cipher info: {e}")
    return {}

def main():
    interface = get_wifi_interface()
    if not interface:
        return

    print("Scanning for networks...")
    networks = scan_networks(interface)

    print("\nAvailable Networks:")
    print("{:<20} {:<30} {:<10} {:<10} {:<10}".format("BSSID", "ESSID", "PWR", "ENCR", "CIPHER"))
    print("-" * 80)

    cipher_and_encryption = get_cipher_and_encryption()

    for network in networks:
        bssid = network.bssid
        essid = network.ssid
        pwr = network.signal
        encr, cipher = cipher_and_encryption.get(bssid, ("Unknown", "Unknown"))
        print(f"{bssid:<20} {essid:<30} {pwr:<10} {encr:<10} {cipher:<10}")

if __name__ == "__main__":
    main()
