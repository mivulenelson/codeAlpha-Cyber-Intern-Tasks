from email import header
import sys
import binascii
from datetime import datetime

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QTableWidgetItem,
    QToolBar, 
    QStatusBar,
    QTableWidget,
    QAbstractItemView,
    QHeaderView,
    QDialog,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QPlainTextEdit, 
    QMessageBox
)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP


try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_AVAILABLE = True
except Exception:
    HTTPRequest = HTTPResponse = None
    HTTP_AVAILABLE = False


class Signals(QObject):
    packet_captured = Signal(object)


class SnifferEngine:
    def __init__(self, on_packet, iface=None):
        self.on_packet = on_packet
        self.iface = iface  
        self.running = False

    def start(self):
        if self.running:
            return 
        self.running = True

        # sniff runs in the current threat;  we call it via Qt-safe signal    
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


def parse_packet(pkt):
    """
    Detect and extract fields for:
    Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, DHCP

    Returns:
        ts, src, dst, proto_label, length
    Where proto_label can be something like:
        ARP, ICMP, DNS, DHCP, HTTP, HTTPS, TCP, UDP, IPv4, IPv6, OTHER
    """
    ts = datetime.now().strftime("%H:%M:%S")
    length = len(pkt)

    src = "-"
    dst = "-"
    proto = "OTHER"

    # -----------------------
    # L2: Ethernet (MACs)
    # -----------------------
    if Ether in pkt:
        eth = pkt[Ether]
        # (optional) keep MACs for internal use / debugging
        # eth.src, eth.dst

    # -----------------------
    # ARP (L2.5)
    # -----------------------
    if ARP in pkt:
        arp = pkt[ARP]
        src = getattr(arp, "psrc", "-")
        dst = getattr(arp, "pdst", "-")
        proto = "ARP"
        return ts, src, dst, proto, length

    # -----------------------
    # L3: IPv4 / IPv6
    # -----------------------
    is_ipv4 = IP in pkt

    if is_ipv4:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "IPv4"
        
    else:
        # Non-IP, Non-ARP packet (rare but possible)
        return ts, src, dst, proto, length

    # -----------------------
    # DNS over UDP or TCP (usually UDP 53)
    # -----------------------
    if DNS in pkt:
        proto = "DNS"
        return ts, src, dst, proto, length

    # -----------------------
    # ICMP / ICMPv6
    # -----------------------
    if ICMP in pkt:
        proto = "ICMP"
        return ts, src, dst, proto, length

    if "ICMPv6EchoRequest" in pkt or "ICMPv6EchoReply" in pkt:
        proto = "ICMPv6"
        return ts, src, dst, proto, length

    # -----------------------
    # L4: TCP / UDP
    # -----------------------
    sport = None
    dport = None

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = "TCP"

        # -----------------------
        # HTTP detection
        # -----------------------
        # If scapy HTTP layer exists: use it.
        # Otherwise fallback to port 80 heuristic.
        if HTTP_AVAILABLE and (HTTPRequest in pkt or HTTPResponse in pkt):
            proto = "HTTP"
        else:
            if sport == 80 or dport == 80:
                proto = "HTTP"
            elif sport == 443 or dport == 443:
                proto = "HTTPS"  # encrypted payload, but still label it

        return ts, src, dst, proto, length

    if UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = "UDP"

        # Heuristic labels (optional):
        if sport == 53 or dport == 53:
            proto = "DNS"
        elif sport in (67, 68) or dport in (67, 68):
            # DHCP is already handled above via BOOTP/DHCP presence,
            # but keep label here as fallback.
            proto = "DHCP"

        return ts, src, dst, proto, length

    # If it was IP but not TCP/UDP/ICMP
    return ts, src, dst, proto, length



class PacketDetailDialog(QDialog):
    def __init__(self, pkt, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.resize(900, 650)

        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # --- Layers / Fields view (Tree) ---
        self.layer_tree = QTreeWidget()
        self.layer_tree.setHeaderLabels(["Layer / Field", "Value"])
        tabs.addTab(self.layer_tree, "OSI Layers")

        # --- Hex view ---
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        mono = QFont("Monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.hex_view.setFont(mono)
        tabs.addTab(self.hex_view, "Hex")

        # Fill contents
        self._populate_layers(pkt)
        self._populate_hex(pkt)

    def _populate_layers(self, pkt):
        self.layer_tree.clear()

        # Scapy layers in order (closest thing to OSI in Scapy)
        for layer_cls in pkt.layers():
            layer = pkt.getlayer(layer_cls)
            if layer is None:
                continue

            layer_item = QTreeWidgetItem([layer_cls.__name__, ""])
            self.layer_tree.addTopLevelItem(layer_item)

            # Show fields for this layer
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



def format_hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width*3}}  |{ascii_part}|")
    return "\n".join(lines)



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
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  # fill available space

        # Optional: make some columns tighter and others stretch (more professional)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Time
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Protocol
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Length
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

    # background thread callback
    def on_packet_background(self, pkt):
        self.signals.packet_captured.emit(pkt)

    # GUI thread handler
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


def main():
    app = QApplication(sys.argv)    
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

