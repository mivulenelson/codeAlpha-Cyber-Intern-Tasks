🛡️ Basic Network Sniffer GUI — PySide6 + Scapy

A lightweight, professional desktop Network Packet Sniffer built with Python, PySide6 (Qt), and Scapy.
This tool captures live network traffic, classifies common protocols, and provides an interactive GUI to inspect packets by OSI layers and raw hex view.

Designed as a clean, educational, and extensible cybersecurity project suitable for internship tasks, coursework, and foundational traffic analysis.

✨ Features

✅ Live packet capture using Scapy

✅ Cross-platform PySide6 desktop GUI

✅ Real-time packet table display

✅ Automatic protocol detection

✅ No interface selection required (uses default / system interface)

✅ Start / Stop / Clear controls

✅ Double-click or View button for deep packet inspection

✅ OSI-style layer breakdown per packet

✅ Field-by-field layer attributes

✅ Full packet hex + ASCII dump

✅ Responsive table layout that scales with window size

✅ Threaded capture engine (GUI remains responsive)

🔬 Protocols Currently Detected

The sniffer includes parsing logic for:

Layer 2

Ethernet

ARP

Layer 3

IPv4

ICMP

Layer 4

TCP

UDP

Application Layer (heuristic + layer detection)

DNS

DHCP

HTTP

HTTPS (port-based detection)

Protocol classification is performed in the packet parsing layer of the application 

main

🖥️ GUI Overview
Main Window

Packet capture table

Auto-resizing columns

Row selection

Packet counter in status bar

Controls Toolbar

▶ Start Capture

⏹ Stop Capture

🧹 Clear Table

🔍 View Packet Details

Packet Detail Dialog

OSI Layers tab

Layer hierarchy

Field/value pairs per layer

Hex tab

Offset

Hex bytes

ASCII representation


Architecture (Single-File Modular Design)

The project is implemented in a clean, modular structure within a single script:

main.py
 ├── SnifferEngine        → threaded scapy capture
 ├── parse_packet()       → protocol detection logic
 ├── PacketDetailDialog   → OSI + hex inspector
 ├── MainWindow           → GUI + controls
 └── format_hexdump()     → hex formatter

INSTALLATION
git clone https://github.com/mivulenelson/.git
https://github.com/mivulenelson/codeAlpha-Cyber-Intern-Tasks/basic
cd 
