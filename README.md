# Network Scanner & Monitor 🔍

A local network scanner built with Python and Scapy that detects 
all active devices on your network in real time.

## What it does
- Scans all devices on your local network
- Displays IP address, MAC address and hostname for each device
- Detects new devices connecting to the network
- Works on any network interface (Wi-Fi, Ethernet)

## Technologies
- Python 3
- Scapy
- Socket

## Requirements
- Python 3.x
- Scapy (`pip install scapy`)
- Npcap (Windows) — download at npcap.com
- Run as Administrator (Windows)

## Usage
```bash
python network_scanner.py
```
Then enter your interface name and IP range when prompted.

## Author
Ahmed Meskache — github.com/ahmedmeskache