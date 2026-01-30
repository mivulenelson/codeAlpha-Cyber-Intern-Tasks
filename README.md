
1. PROJECT
   🛡️ Basic Network Sniffer GUI — PySide6 + Scapy

 A lightweight, professional desktop Network Packet Sniffer built with Python, PySide6 (Qt), and Scapy.
 This tool captures live network traffic, classifies common protocols, and provides an interactive GUI to inspect packets by OSI layers and raw hex view.

 Designed as a clean, educational, and extensible cybersecurity project suitable for internship tasks, coursework, and foundational traffic analysis.


main.py

 ~ SnifferEngine        → threaded scapy capture
 
 ~ parse_packet()       → protocol detection logic
 
 ~ PacketDetailDialog   → OSI + hex inspector
 
 ~ MainWindow           → GUI + controls
 
 ~ format_hexdump()     → hex formatter
 

INSTALLATION


git clone https://github.com/mivulenelson/codeAlpha-Cyber-Intern-Tasks/tree/main/basic_network_sniffer


INSTALL A VIRTUAL ENVIRONMENT


python3 -m venv env

source env/bin/activate

INSTALL DEPENDENCIES

pip install -r requirements.txt
