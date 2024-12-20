#!/usr/bin/env python

import argparse
import os
from scapy.all import *
import threading

# Global variables
bssid_to_monitor = None
interface_to_use = None
output_file = None

def capture_packet(packet):
    """Capture all packets but focus on EAPOL for handshakes"""
    # Check if the packet is an EAPOL frame (used in WPA/WPA2 handshakes)
    if packet.haslayer(EAPOL):
        # If the packet's BSSID matches the target BSSID, log a handshake capture
        if packet.addr3 == bssid_to_monitor:
            print("[ HANDSHAKE ] Captured")
    
    # The packet is saved in the .pcap file regardless of EAPOL or not
    # You can further process the packets here if needed

def start_monitoring():
    """Start sniffing on the specified interface and capture packets"""
    print(f"[*] Monitoring {bssid_to_monitor} on interface {interface_to_use}...")
    
    # Write captured packets to a .pcap file
    if output_file:
        print(f"[*] Saving captured packets to {output_file}")
        sniff(iface=interface_to_use, prn=capture_packet, store=0, timeout=60, wrpcap=output_file)
    else:
        sniff(iface=interface_to_use, prn=capture_packet, store=0, timeout=60)

def main():
    """Main function to parse arguments and start monitoring"""
    global bssid_to_monitor, interface_to_use, output_file

    # Argument parsing using argparse
    parser = argparse.ArgumentParser(description="Wi-Fi network monitor for capturing EAPOL handshakes and all network traffic.")
    parser.add_argument("-b", "--bssid", required=True, help="Target BSSID to monitor (MAC address of the AP)")
    parser.add_argument("interface", help="Network interface to use for sniffing")
    parser.add_argument("--write", dest="output_file", help="File to save captured packets in pcap format")
    
    args = parser.parse_args()

    # Assign parsed arguments to global variables
    bssid_to_monitor = args.bssid
    interface_to_use = args.interface
    output_file = args.output_file

    # Start the monitoring process in a separate thread
    thread = threading.Thread(target=start_monitoring)
    thread.start()

if __name__ == "__main__":
    main()
