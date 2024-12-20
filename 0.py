#!/usr/bin/env python

import argparse
import os
from scapy.all import *
import threading
import signal

# Global variables
bssid_to_monitor = None
interface_to_use = None
output_file = None
packets = []  # List to store captured packets

def capture_packet(packet):
    """Capture all packets but focus on EAPOL for handshakes"""
    # Check if the packet is an EAPOL frame (used in WPA/WPA2 handshakes)
    if packet.haslayer(EAPOL):
        # If the packet's BSSID matches the target BSSID, log a handshake capture
        if packet.addr3 == bssid_to_monitor:
            print("[ HANDSHAKE ] Captured")
    
    # Add the captured packet to the list
    packets.append(packet)

def start_monitoring():
    """Start sniffing on the specified interface and capture packets"""
    print(f"[*] Monitoring {bssid_to_monitor} on interface {interface_to_use}...")
    
    try:
        # Sniff packets and store them in the packets list
        sniff(iface=interface_to_use, prn=capture_packet, store=0)
    except KeyboardInterrupt:
        # Handle keyboard interrupt gracefully (Ctrl+C)
        print("\n[*] Keyboard interrupt detected. Saving captured packets...")
    finally:
        # After sniffing is done or interrupted, save all captured packets to the .pcap file
        if output_file:
            print(f"[*] Saving captured packets to {output_file}")
            wrpcap(output_file, packets)

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

    # Wait for the thread to finish
    thread.join()

if __name__ == "__main__":
    main()
