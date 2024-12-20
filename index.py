import tkinter as tk
from tkinter import ttk, messagebox
import pyshark
import threading
import os

class NetworkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("GUI Network Analyzer")
        
        self.adapter_label = tk.Label(root, text="Select Network Adapter:")
        self.adapter_label.pack(pady=5)

        self.adapter_combobox = ttk.Combobox(root, state="readonly")
        self.adapter_combobox.pack(pady=5)

        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_capture, state="disabled")
        self.stop_button.pack(pady=5)

        self.tree = ttk.Treeview(root, columns=("BSSID", "ESSID", "PWR", "ENCR", "CIPHER", "NOTE"), show="headings")
        self.tree.heading("BSSID", text="BSSID")
        self.tree.heading("ESSID", text="ESSID")
        self.tree.heading("PWR", text="PWR")
        self.tree.heading("ENCR", text="ENCR")
        self.tree.heading("CIPHER", text="CIPHER")
        self.tree.heading("NOTE", text="NOTE")
        self.tree.pack(fill="both", expand=True, pady=5)

        self.capture_thread = None
        self.running = False
        self.adapter = None
        self.capture_file = "Capture.pcap"

        self.load_adapters()

    def load_adapters(self):
        try:
            capture = pyshark.LiveCapture()
            adapters = capture.interfaces
            self.adapter_combobox["values"] = adapters
            if adapters:
                self.adapter_combobox.current(0)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load adapters: {e}")

    def start_capture(self):
        self.adapter = self.adapter_combobox.get()
        if not self.adapter:
            messagebox.showerror("Error", "Please select a network adapter.")
            return

        self.running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()

        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        messagebox.showinfo("Capture Stopped", f"Capture saved to {self.capture_file}")

    def capture_packets(self):
        try:
            capture = pyshark.LiveCapture(interface=self.adapter, output_file=self.capture_file)
            for packet in capture.sniff_continuously():
                if not self.running:
                    break

                if hasattr(packet, 'wlan'):  # Check for WiFi packets
                    bssid = packet.wlan.ta if hasattr(packet.wlan, 'ta') else "Unknown"
                    essid = packet.wlan_ssid if hasattr(packet, 'wlan_ssid') else "Hidden"
                    pwr = packet.rssi_dbm if hasattr(packet, 'rssi_dbm') else "Unknown"
                    encr = "Unknown"
                    cipher = "Unknown"
                    note = ""

                    if hasattr(packet, 'eapol'):  # Check for EAPOL packets
                        note = "HANDSHAKE!"

                    self.tree.insert("", "end", values=(bssid, essid, pwr, encr, cipher, note))
        except Exception as e:
            messagebox.showerror("Error", f"Error during capture: {e}")
        finally:
            self.running = False

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzer(root)
    root.mainloop()
