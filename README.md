[README.md](https://github.com/user-attachments/files/34237909/README.md)

# Task 1: Network Traffic Packet Sniffer and Analyzer

**CodeAlpha Cybersecurity Internship**

![Lab architecture](screenshots/01-lab-architecture.png)

## Project Overview

This project implements a Python-based network traffic packet sniffer using Scapy in a Kali Linux virtual machine. The program captures a limited number of packets, displays selected IPv4 and protocol information, previews available raw payload bytes, and saves the captured packets to a PCAP file for further inspection in Wireshark.

## Objectives

- Build a Python program to capture network traffic packets.
- Analyze captured packets to understand their structure and content.
- Observe how data flows through the network and learn basic protocol concepts.
- Use a packet-capture library such as Scapy.
- Display useful information including source and destination IP addresses, protocols, and payload previews.

## Lab Architecture

Packet traffic is captured from the Kali Linux VM by the Python/Scapy program. The program prints selected packet information and saves a PCAP file, and Wireshark is used to inspect packet details and protocol layers.

*Figure 1. Network traffic packet sniffer and analyzer lab architecture (see the image at the top of this page).*

## Tools and Technologies

| Tool | Version (from the lab environment) |
|---|---|
| Kali Linux virtual machine | Kernel 6.19.14+kali-amd64 |
| Python 3 | 3.13.12 |
| Scapy | 2.7.01 (as printed by `scapy.__version__`) |
| Wireshark | 4.6.6 |
| PCAP format | Used to save captured packets |

![Tool versions](screenshots/07-tool-versions.png)

## Implementation

The script uses Scapy's `sniff()` function to capture ten packets. For packets containing an IPv4 layer, it displays the source and destination IP addresses and classifies the packet as TCP, UDP, ICMP, or Other IP. If Scapy identifies a Raw layer, the program displays a preview of up to 50 payload bytes and the size of that Raw-layer payload. After capture completes, `wrpcap()` writes the packets to `captured_traffic.pcap`.

The full script is in [`packet_sniffer.py`](packet_sniffer.py):

```python
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

def analyze_packet(packet):
    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other IP"

        print("Source IP:", source)
        print("Destination IP:", destination)
        print("Protocol:", protocol)

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            print("Payload:", repr(payload[:50]))
            print("Payload size:", len(payload), "bytes")
        else:
            print("Payload: No separate payload layer detected")

        print("-" * 30)

print("Starting packet capture...")
packets = sniff(prn=analyze_packet, count=10)
wrpcap("captured_traffic.pcap", packets)
print("Saved capture to captured_traffic.pcap")
```

## Procedure

1. Run the packet sniffer in Kali Linux with the required privileges:

   ```bash
   sudo python3 packet_sniffer.py
   ```

2. Generate network traffic for observation. An ICMP test was generated from a second terminal using ping to 8.8.8.8:

   ```bash
   ping -c 10 8.8.8.8
   ```

3. Review the terminal output for source and destination IP addresses, protocol classification, and any detected Raw-layer payload preview.
4. Save the captured packets to `captured_traffic.pcap` (done automatically by the script), then fix file ownership because the script ran with `sudo`:

   ```bash
   sudo chown $USER:$USER captured_traffic.pcap
   ```

5. Open the saved capture in Wireshark and inspect the packet list and protocol-layer details:

   ```bash
   capinfos captured_traffic.pcap
   wireshark captured_traffic.pcap &
   ```

## Results and Observations

All screenshots below come from the same capture run, so the terminal output, the PCAP file and the Wireshark view are consistent with each other.

### 1. Terminal output

The script printed the source IP, destination IP, protocol and payload preview for each IPv4 packet. The observed traffic was ICMP between the Kali VM (`10.0.2.15`) and `8.8.8.8`, with a 56-byte payload on each packet, which matches the default ping data size.

![Packet sniffer terminal output](screenshots/02-packet-sniffer-terminal.png)

### 2. Capture saved

The script finished with "Saved capture to captured_traffic.pcap", and the file appears in the project folder (1,074 bytes).

![Capture saved and file listing](screenshots/03-capture-saved-pcap.png)

### 3. PCAP summary

`capinfos` confirms the file contains 10 packets captured over about 3.03 seconds, with Ethernet encapsulation.

![PCAP summary from capinfos](screenshots/06-pcap-summary-capinfos.png)

### 4. Wireshark packet list and layers

Wireshark shows the same 10 packets. Packets 1 and 2 are ARP (address resolution for the gateway). Packets 3 to 10 are four ICMP echo request/reply pairs between `10.0.2.15` and `8.8.8.8`. Frame 5 is expanded to show the Ethernet II and IPv4 layers: a 98-byte frame, IPv4 header length of 20 bytes, total length 84, TTL 64 and protocol ICMP (1).

![Wireshark packet list and details](screenshots/04-wireshark-packet-analysis.png)

### 5. ICMP details

Expanding the ICMP layer on the same packet shows type 8 (Echo (ping) request), code 0, a good checksum, and the sequence number. Wireshark links this request to its reply in frame 6.

![Wireshark ICMP details](screenshots/05-wireshark-icmp-details.png)

### Key points

- The Scapy script captured packets and printed selected details for IPv4 traffic.
- The capture stopped after 10 packets in total. Because the 10 packets included 2 ARP packets, only 4 of the 10 ping exchanges were captured.
- The script prints only packets with an IPv4 layer, so the 2 ARP packets are saved in the PCAP but do not appear in the terminal output.
- `captured_traffic.pcap` was saved for later analysis and opened in Wireshark.

## What the Packet Analysis Demonstrates

The ping test provides a practical example of ICMP request and reply traffic. Packet inspection in Wireshark helps relate the packet summary to the underlying protocol layers. A Raw layer, when present, is a byte sequence exposed by Scapy; it is not necessarily decoded application data.

## Repository Structure

```
Task-1-Network-Traffic-Analyzer/
├── README.md
├── packet_sniffer.py
├── captured_traffic.pcap
└── screenshots/
    ├── 01-lab-architecture.png
    ├── 02-packet-sniffer-terminal.png
    ├── 03-capture-saved-pcap.png
    ├── 04-wireshark-packet-analysis.png
    ├── 05-wireshark-icmp-details.png
    ├── 06-pcap-summary-capinfos.png
    └── 07-tool-versions.png
```

## Limitations

- The current script processes IPv4 packets only; IPv6 packets are not analyzed by this version.
- The program does not currently display TCP/UDP port numbers or total packet lengths.
- Payload output is limited to a 50-byte preview when a Raw layer is present.
- The script captures ten packets per run and does not specify a capture interface or filter.

## Ethical and Responsible Use

Packet capture should be performed only on networks and systems for which the operator has permission. Captures may contain sensitive information, so PCAP files and screenshots should be reviewed before public sharing.

## Conclusion

This task demonstrates a basic packet-capture workflow with Python and Scapy, followed by packet inspection in Wireshark. It covers packet collection, IPv4 address display, basic protocol identification, payload preview where available, and saving a capture for further analysis. The documented limitations identify practical areas for future improvement.
