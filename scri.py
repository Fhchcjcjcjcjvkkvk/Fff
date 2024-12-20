import os
import tkinter as tk
from tkinter import ttk, messagebox
import pyshark
import threading

# Global variables
capture_thread = None
capture_running = False
capture_file = "Capture.pcap"
capture_data = []
adapters = []

# Function to get network adapters (example: using pyshark)
def get_network_adapters():
    global adapters
    try:
        adapters = pyshark.LiveCapture.get_interfaces()
        return adapters
    except Exception as e:
        messagebox.showerror("Error", f"Unable to fetch network adapters: {str(e)}")
        return []

# Function to start capture
def start_capture(adapter, table):
    global capture_running, capture_data
    capture_running = True
    capture_data = []

    def capture():
        global capture_file
        try:
            capture = pyshark.LiveCapture(interface=adapter, output_file=capture_file)
            for packet in capture.sniff_continuously():
                if not capture_running:
                    break
                # Process packet information here (simplified for display)
                try:
                    if hasattr(packet, 'wlan'):
                        bssid = packet.wlan.ta if hasattr(packet.wlan, 'ta') else "Unknown"
                        essid = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else "Hidden"
                        pwr = "-"  # Power not directly accessible via pyshark
                        encr = "-"  # Encryption detection logic needs implementation
                        cipher = "-"  # Cipher detection logic needs implementation
                        note = "EAPOL" if 'eapol' in packet else ""

                        if note == "EAPOL":
                            note = "HANDSHAKE!"

                        capture_data.append((bssid, essid, pwr, encr, cipher, note))

                        # Update GUI table
                        table.insert("", "end", values=(bssid, essid, pwr, encr, cipher, note))
                except Exception as e:
                    continue
        except Exception as e:
            messagebox.showerror("Error", f"Capture failed: {str(e)}")

    threading.Thread(target=capture, daemon=True).start()

# Function to stop capture
def stop_capture():
    global capture_running
    capture_running = False
    messagebox.showinfo("Capture Stopped", f"Capture saved to {capture_file}")

# Main GUI application
def main():
    global adapters

    root = tk.Tk()
    root.title("Network Analyzer")

    # Select network adapter
    tk.Label(root, text="Select Network Adapter:").pack(pady=5)
    adapter_combo = ttk.Combobox(root, state="readonly")
    adapter_combo.pack(pady=5)

    adapters = get_network_adapters()
    if adapters:
        adapter_combo['values'] = adapters
        adapter_combo.current(0)
    else:
        adapter_combo['values'] = ["No adapters found"]
        adapter_combo.current(0)

    # Start and stop buttons
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    start_button = tk.Button(button_frame, text="START CAPTURE", command=lambda: start_capture(adapter_combo.get(), table))
    start_button.grid(row=0, column=0, padx=5)

    stop_button = tk.Button(button_frame, text="STOP CAPTURE", command=stop_capture)
    stop_button.grid(row=0, column=1, padx=5)

    # Table for displaying capture data
    columns = ("BSSID", "ESSID", "PWR", "ENCR", "CIPHER", "NOTE")
    table = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        table.heading(col, text=col)
    table.pack(pady=10, fill=tk.BOTH, expand=True)

    # Set column widths
    table.column("BSSID", width=150)
    table.column("ESSID", width=150)
    table.column("PWR", width=50)
    table.column("ENCR", width=100)
    table.column("CIPHER", width=100)
    table.column("NOTE", width=100)

    # Start the GUI loop
    root.mainloop()

if __name__ == "__main__":
    main()
