# Basic Network Sniffer

A Python-based network packet sniffer that captures and analyzes live network traffic using Scapy. It displays packet details such as source and destination IP addresses, protocols, port numbers, packet lengths, timestamps, and payload previews.

## Overview

Network packet sniffing is a technique used to observe and analyze data packets traveling across a network. This project demonstrates the fundamentals of network communication and packet analysis using Python.

## Features

- **Live Packet Capture:** Capture network packets using Scapy.
- **IP Address Analysis:** Display source and destination IPv4 and IPv6 addresses.
- **Protocol Identification:** Identify TCP, UDP, ICMP, and other packet types.
- **Port Information:** Display source and destination ports for TCP and UDP packets.
- **Packet Length:** Display the size of each captured packet in bytes.
- **Payload Inspection:** Display a limited hexadecimal preview of available raw payload data.
- **Timestamps:** Display the time each packet is processed.
- **Packet Structure:** Show a summary of the packet's protocol layers.
- **Graceful Shutdown:** Stop the capture using `Ctrl+C`.

## Technologies Used

- Python 3
- Scapy
- Npcap
- Visual Studio Code
- Windows

## Project Structure

```text
Basic-Network-Sniffer/
├── sniffer.py
└── README.md
```

## Prerequisites

- Python 3 installed on your system.
- Scapy installed.
- Npcap installed on Windows for live packet capture.
- Appropriate permissions to capture network traffic.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/Basic-Network-Sniffer.git
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Navigate to the project directory

```bash
cd Basic-Network-Sniffer
```

### 3. Install Scapy

```bash
python -m pip install scapy
```

### 4. Install Npcap

Download Npcap from the official website:

https://npcap.com/#download

Follow the installation instructions.

## Usage

Run the program from the project directory:

```bash
python sniffer.py
```

The program starts capturing packets and displays their available details in the terminal.

To stop packet capture, press:

```text
Ctrl+C
```

On Windows, live packet capture may require administrator privileges and a correctly configured Npcap installation.

## Example Output

The following is an illustrative example of the output format:

```text
==================================================
PACKET CAPTURED
==================================================
Timestamp: 2026-10-28 14:30:15
Packet Length: 74 bytes
Source IP: 192.168.1.10
Destination IP: 142.250.183.14
Protocol: TCP
Source Port: 52341
Destination Port: 443
Payload: No raw payload available
Packet Structure: IP / TCP / ...
==================================================
```

*Note: The values shown are examples. Actual output depends on the network traffic captured.*

## How It Works

1. **Packet Capture:** Scapy listens for packets on the selected default capture interface.
2. **Packet Analysis:** Each captured packet is passed to a processing function.
3. **Address Extraction:** The program extracts source and destination IP addresses when available.
4. **Protocol Identification:** It examines packet layers to identify protocols and transport ports.
5. **Payload Inspection:** If a raw payload layer is present, the program displays a limited hexadecimal preview.
6. **Packet Structure Analysis:** A packet summary provides a quick view of the protocols and layers present.

## Learning Outcomes

This project explores:

- Fundamentals of network packet capture.
- IPv4 and IPv6 addressing.
- TCP, UDP, and ICMP protocols.
- Source and destination port analysis.
- Network packet structure and protocol layers.
- Payload inspection using hexadecimal representation.
- Basic network troubleshooting and traffic analysis.

## Security and Ethical Use

- Capture only traffic on networks and devices you own or have permission to monitor.
- Treat packet captures as potentially sensitive information.
- Avoid sharing captured data that may expose private information.
- Use the tool for authorized learning, troubleshooting, and network analysis.

## Future Improvements

- Save packet summaries to CSV.
- Add packet filtering by protocol.
- Provide packet statistics and visualizations.
- Support configurable capture interfaces.

## Author

**Your Name:** YOUR-NAME  
**GitHub:** https://github.com/YOUR-USERNAME
