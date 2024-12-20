import sys
import os
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt
import scapy.all as scapy
from threading import Thread

class NetworkAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analyzer")
        self.setGeometry(200, 200, 800, 400)

        self.capture_thread = None
        self.capturing = False
        self.capture_file = "Capture.pcap"

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Adapter Selection
        self.adapter_label = QLabel("Select Network Adapter:")
        self.adapter_dropdown = QComboBox()
        self.refresh_adapters()

        adapter_layout = QHBoxLayout()
        adapter_layout.addWidget(self.adapter_label)
        adapter_layout.addWidget(self.adapter_dropdown)

        # Control Buttons
        self.start_button = QPushButton("START CAPTURE")
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton("STOP CAPTURE")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)

        # Table for network display
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(5)
        self.network_table.setHorizontalHeaderLabels(["BSSID", "ESSID", "PWR", "ENCR", "NOTE"])

        layout.addLayout(adapter_layout)
        layout.addLayout(button_layout)
        layout.addWidget(self.network_table)

        self.setLayout(layout)

    def refresh_adapters(self):
        # Find available network adapters
        try:
            adapters = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
            adapter_names = [line.split(": ")[1].strip() for line in adapters.splitlines() if "Name" in line]
            self.adapter_dropdown.clear()
            self.adapter_dropdown.addItems(adapter_names)
        except Exception as e:
            self.adapter_dropdown.clear()
            self.adapter_dropdown.addItem("No Adapters Found")

    def start_capture(self):
        selected_adapter = self.adapter_dropdown.currentText()
        if "No Adapters Found" in selected_adapter or not selected_adapter:
            self.log("No valid network adapter selected.")
            return

        self.capturing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.network_table.setRowCount(0)

        self.capture_thread = Thread(target=self.capture_packets, args=(selected_adapter,))
        self.capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def capture_packets(self, adapter):
        def packet_handler(packet):
            if packet.haslayer(scapy.Dot11):
                bssid = packet.addr2
                essid = packet.info.decode() if hasattr(packet, 'info') else ""
                pwr = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "-"
                encr = "-"
                note = ""

                if packet.type == 2 and packet.subtype == 8:  # Beacon frame
                    encr = "WEP/WPA/WPA2" if hasattr(packet, 'auth') else "OPEN"

                if packet.haslayer(scapy.EAPOL):
                    note = "HANDSHAKE!"

                self.update_table(bssid, essid, pwr, encr, note)

        scapy.sniff(iface=adapter, prn=packet_handler, stop_filter=lambda x: not self.capturing)
        scapy.wrpcap(self.capture_file, scapy.sniff(iface=adapter))

    def update_table(self, bssid, essid, pwr, encr, note):
        row_count = self.network_table.rowCount()
        self.network_table.insertRow(row_count)
        self.network_table.setItem(row_count, 0, QTableWidgetItem(bssid))
        self.network_table.setItem(row_count, 1, QTableWidgetItem(essid))
        self.network_table.setItem(row_count, 2, QTableWidgetItem(str(pwr)))
        self.network_table.setItem(row_count, 3, QTableWidgetItem(encr))
        self.network_table.setItem(row_count, 4, QTableWidgetItem(note))

    def log(self, message):
        print(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    analyzer = NetworkAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())
