#!/usr/bin/env python

import sys
import os
from scapy.all import *
import threading

# Global variables
bssid_to_monitor = None
interface_to_use = None
output_file = None

def capture_eapol(packet):
    # Check if the packet is a EAPOL frame (Ethernet frame with EAPOL protocol)
    if packet.haslayer(EAPOL):
        # Check if the frame's BSSID matches the target BSSID
        if packet.addr3 == bssid_to_monitor:
            print("[ HANDSHAKE ] Captured")
            os.kill(os.getpid(), 9)  # Close the script after capturing the handshake
            return  # Stop capturing after the handshake

def start_monitoring():
    # Start sniffing on the specified interface
    print(f"[*] Monitoring {bssid_to_monitor} on interface {interface_to_use}...")
    
    # Write packets to a .pcap file if specified
    if output_file:
        print(f"[*] Saving captured packets to {output_file}")
        sniff(iface=interface_to_use, prn=capture_eapol, store=0, timeout=60, wrpcap=output_file)
    else:
        sniff(iface=interface_to_use, prn=capture_eapol, store=0, timeout=60)

def main():
    global bssid_to_monitor, interface_to_use, output_file

    # Ensure the script is being run with the correct arguments
    if len(sys.argv) != 5:
        print("Usage: airhunter.py -b <bssid> <interface> --write <file.pcap>")
        sys.exit(1)

    # Parse command-line arguments
    for i in range(1, len(sys.argv), 2):
        if sys.argv[i] == "-b":
            bssid_to_monitor = sys.argv[i + 1]
        elif sys.argv[i] == "--write":
            output_file = sys.argv[i + 1]
        elif i == 3:  # Interface argument (directly after bssid)
            interface_to_use = sys.argv[i]
    
    if not bssid_to_monitor or not interface_to_use:
        print("Error: Both BSSID and Interface are required!")
        sys.exit(1)
    
    # Start the monitoring process
    thread = threading.Thread(target=start_monitoring)
    thread.start()

if __name__ == "__main__":
    main()
