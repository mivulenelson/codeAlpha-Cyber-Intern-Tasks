"""
#####################################################################################################################
Scapy Imports for packet capturing and cracfting
"""

import sys
from datetime import datetime

# Scapy imports
from scapy.all import sniff
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS


try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_AVAILABLE = True
except Exception:
    HTTPRequest = HTTPResponse = None
    HTTP_AVAILABLE = False


# Triggers packet capture from any Network Interface in GUI
from PySide6.QtCore import QObject, Signal
class Signals(QObject):
    packet_captured = Signal(object)


# The sniffer starts sniffing for any available packets
class SnifferEngine:
    def __init__(self, on_packet, iface=None):
        self.on_packet = on_packet
        self.iface = iface  
        self.running = False

    def start(self):
        if self.running:
            return 
        self.running = True
  
        import threading
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            sniff(
                iface=self.iface,
                prn=self.on_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"[SnifferEngine] Error: {e}")

    def stop(self):
        self.running = False


# Function to craft the sniffed packets
def parse_packet(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    length = len(pkt)

    src = "-"
    dst = "-"
    proto = "OTHER"

    # ---- L2: Ethernet / ARP ----
    if Ether in pkt:
        # eth = pkt[Ether]  # keep if you later want MACs: eth.src / eth.dst / eth.type
        pass

    if ARP in pkt:
        arp = pkt[ARP]
        src = getattr(arp, "psrc", "-")
        dst = getattr(arp, "pdst", "-")
        proto = "ARP"
        return ts, src, dst, proto, length

    # ---- L3: IPv4 / IPv6 ----
    is_ipv4 = IP in pkt
    is_ipv6 = IPv6 in pkt

    if is_ipv4:
        src = pkt[IP].src
        dst = pkt[IP].dst
        ip_ver = "IPv4"
    elif is_ipv6:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        ip_ver = "IPv6"
    else:
        # Non-IP non-ARP traffic (e.g., STP, LLDP, etc.)
        proto = "L2"
        return ts, src, dst, proto, length

    # ---- L7/L4 classification helpers (ports) ----
    def classify_by_ports(sport: int | None, dport: int | None) -> str | None:
        if sport is None or dport is None:
            return None

        # Common well-known ports (heuristic)
        PORT_MAP = {
            53:  "DNS",
            67:  "DHCP",
            68:  "DHCP",
            80:  "HTTP",
            443: "HTTPS",
            22:  "SSH",
            21:  "FTP",
            20:  "FTP-DATA",
            25:  "SMTP",
            587: "SMTP-Submission",
            465: "SMTPS",
            110: "POP3",
            995: "POP3S",
            143: "IMAP",
            993: "IMAPS",
            123: "NTP",
            161: "SNMP",
            162: "SNMPTRAP",
            389: "LDAP",
            636: "LDAPS",
            3306:"MySQL",
            5432:"PostgreSQL",
            3389:"RDP",
            5900:"VNC",
            5060:"SIP",
            5061:"SIPS",
            1883:"MQTT",
            8883:"MQTTS",
        }

        return PORT_MAP.get(sport) or PORT_MAP.get(dport)

    # ---- L7: DNS (works for both UDP/TCP DNS) ----
    if DNS in pkt:
        proto = "DNS"
        return ts, src, dst, proto, length

    # ---- L3 control: ICMP / ICMPv6 ----
    if ICMP in pkt and is_ipv4:
        proto = "ICMP"
        return ts, src, dst, proto, length

    if is_ipv6:
        if (ICMPv6EchoRequest in pkt) or (ICMPv6EchoReply in pkt):
            proto = "ICMPv6"
            return ts, src, dst, proto, length
        if (ICMPv6ND_NS in pkt) or (ICMPv6ND_NA in pkt):
            proto = "NDP"
            return ts, src, dst, proto, length

    # ---- L4: TCP / UDP ----
    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        proto = "TCP"

        # HTTP detection (scapy http layer if present) + port heuristic
        if HTTP_AVAILABLE and (HTTPRequest in pkt or HTTPResponse in pkt):
            proto = "HTTP"
        else:
            by_port = classify_by_ports(sport, dport)
            if by_port:
                proto = by_port
            else:
                # Optional: label TLS if common
                if sport == 443 or dport == 443:
                    proto = "TLS/HTTPS"

        return ts, src, dst, proto, length

    if UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        proto = "UDP"

        # DHCP (best via layer if present, otherwise ports)
        if DHCP in pkt or sport in (67, 68) or dport in (67, 68):
            proto = "DHCP"
            return ts, src, dst, proto, length

        by_port = classify_by_ports(sport, dport)
        if by_port:
            proto = by_port

        return ts, src, dst, proto, length

    # If it’s IP but not TCP/UDP/ICMP, keep the IP version label
    proto = ip_ver
    return ts, src, dst, proto, length



# GUI for viewing a specific packet details
from PySide6.QtWidgets import QDialog, QVBoxLayout, QTabWidget, QTreeWidget, QTreeWidgetItem, QPlainTextEdit
class PacketDetailDialog(QDialog):
    def __init__(self, pkt, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.resize(900, 650)

        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        self.layer_tree = QTreeWidget()
        self.layer_tree.setHeaderLabels(["Layer / Field", "Value"])
        tabs.addTab(self.layer_tree, "OSI Layers")

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.hex_view.setFont(mono)
        tabs.addTab(self.hex_view, "Hex")

        self._populate_layers(pkt)
        self._populate_hex(pkt)

    def _populate_layers(self, pkt):
        self.layer_tree.clear()

        for layer_cls in pkt.layers():
            layer = pkt.getlayer(layer_cls)
            if layer is None:
                continue

            layer_item = QTreeWidgetItem([layer_cls.__name__, ""])
            self.layer_tree.addTopLevelItem(layer_item)

            try:
                fields = getattr(layer, "fields", {})
                for k, v in fields.items():
                    QTreeWidgetItem(layer_item, [str(k), str(v)])
            except Exception:
                QTreeWidgetItem(layer_item, ["(fields)", "(unavailable)"])

        self.layer_tree.expandAll()

    def _populate_hex(self, pkt):
        raw = bytes(pkt)
        self.hex_view.setPlainText(format_hexdump(raw))



# Function for hex values of the selected packet
def format_hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width*3}}  |{ascii_part}|")
    return "\n".join(lines)


"""
-------------------------------------------------------------------------------------------------------------------------
Main GUI for all sniffed packets Using PySide6
"""

# PySide6 imports
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QTableWidgetItem, QToolBar, 
    QStatusBar, QTableWidget, QAbstractItemView, QHeaderView, QDialog, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QPlainTextEdit, QMessageBox
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Basic Network Sniffer (PySide6 + Scapy)")
        self.resize(900, 500)

        self.signals = Signals()
        self.signals.packet_captured.connect(self.on_packet_ui)

        self.sniffer = SnifferEngine(on_packet=self.on_packet_background)

        self.packet_count = 0

        self._build_ui()
        self._build_toolbar()
        self._build_status()
        self._packets = []

    def _build_ui(self):
        central = QWidget()
        layout = QVBoxLayout()

        self.table = QTableWidget(0, 5)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  

        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)

        self.table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length"])
        self.table.setSortingEnabled(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)

        layout.addWidget(self.table)
        central.setLayout(layout)
        self.setCentralWidget(central)

        self.table.cellDoubleClicked.connect(self.view_selected_packet)

    def _build_toolbar(self):
        tb = QToolBar("Controls")
        tb.setMovable(False)

        start_action = QAction("Start", self)
        stop_action = QAction("Stop", self)
        clear_action = QAction("Clear", self)

        start_action.triggered.connect(self.start_capture)
        stop_action.triggered.connect(self.stop_capture)
        clear_action.triggered.connect(self.clear_table)

        tb.addAction(start_action)
        tb.addAction(stop_action)
        tb.addSeparator()
        tb.addAction(clear_action)

        self.addToolBar(tb)

        view_action = QAction("View", self)
        view_action.triggered.connect(self.view_selected_packet)

        tb.addSeparator()
        tb.addAction(view_action)

    def _build_status(self):
        sb = QStatusBar()
        sb.showMessage("Ready")
        self.setStatusBar(sb)

    def start_capture(self):
        self.packet_count = 0
        self.statusBar().showMessage("Capturing... (Stop to end)")
        self.sniffer.start()

    def stop_capture(self):
        self.sniffer.stop()
        self.statusBar().showMessage("Stopped")

    def clear_table(self):
        self.table.setRowCount(0)
        self.packet_count = 0
        self.statusBar().showMessage("Cleared")
        self._packets.clear()

    def on_packet_background(self, pkt):
        self.signals.packet_captured.emit(pkt)

    def on_packet_ui(self, pkt):
        ts, src, dst, proto, length = parse_packet(pkt)

        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(ts))
        self.table.setItem(row, 1, QTableWidgetItem(src))
        self.table.setItem(row, 2, QTableWidgetItem(dst))
        self.table.setItem(row, 3, QTableWidgetItem(proto))
        self.table.setItem(row, 4, QTableWidgetItem(str(length)))

        self.packet_count += 1
        self.statusBar().showMessage(f"Capturing... Packets: {self.packet_count}")
        self.table.scrollToBottom()

        self._packets.append(pkt)

    def view_selected_packet(self):
        row = self.table.currentRow()        
        if row < 0 or row >= len(self._packets):
            QMessageBox.warning(self, "No Packet Selected", "Please select a packet to view its details.")
            return

        pkt = self._packets[row]
        dlg = PacketDetailDialog(pkt, self)
        dlg.exec()


# Function that triggers the GUI
def main():
    app = QApplication(sys.argv)    
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

# Runs the whole program
if __name__ == "__main__":
    main()

