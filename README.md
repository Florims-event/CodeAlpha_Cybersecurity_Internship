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

# TASK 2
[README.md](https://github.com/user-attachments/files/34239236/README.md)
# Task 2: Phishing Awareness Training

**CodeAlpha Cybersecurity Internship**

![Module home page](screenshots/01-module-home.png)

## Project Overview

This project is an interactive online training module about phishing attacks. It teaches people how to recognize phishing emails and fake websites, explains the social engineering tactics attackers use, gives best practices for staying safe, presents real-world cases, and ends with an interactive quiz.

The module is a single self-contained web page ([`index.html`](index.html)) built with HTML, CSS and JavaScript. It needs no installation and no server. Open the file in any modern browser.

## Task Requirements and How They Were Met

| Requirement | Where it is covered |
|---|---|
| Presentation or online module on phishing | Interactive web module (`index.html`) |
| Recognize phishing emails | "Spot the phish" section: a fake email with five clickable red flags |
| Recognize fake websites | "Recognize fake websites" section: real and fake web addresses explained |
| Social engineering tactics | "Social engineering" section: urgency, authority, fear, reward, familiarity, smishing and vishing |
| Best practices and tips | "Best practices" section: ten practical habits |
| Real-world examples | "Real-world cases" section: three documented attacks |
| Interactive quizzes | "Test yourself" section: eight questions with instant feedback and a final score |

## Module Contents

### 1. Spot the phish
A sample phishing email with five highlighted red flags. Clicking each one explains why it is suspicious and updates a progress counter:

1. A lookalike sender domain (`paypa1-secure.com`, with the number 1 instead of the letter l)
2. Urgency and threat in the subject line
3. A generic greeting ("Dear Customer")
4. A mismatched, fake link
5. A dangerous unexpected attachment (`.zip`)

![Spot the phish](screenshots/02-spot-the-phish.png)

### 2. Recognize fake websites
A table comparing genuine and fake web addresses, showing how to find the real domain, how lookalike characters work, and why shortened links hide the destination. It also explains that the padlock icon only means the connection is encrypted, not that the site is trustworthy.

![Fake websites](screenshots/03-fake-websites.png)

### 3. Social engineering tactics
Six cards explain the pressure techniques attackers rely on: urgency, authority, fear, reward, familiarity, and other channels such as smishing (text message) and vishing (phone call).

![Social engineering tactics](screenshots/04-social-engineering.png)

### 4. Real-world cases
Three documented attacks, each with a lesson:

- **Twitter, July 2020:** a phone spear-phishing attack on employees gave attackers access to internal tools. They targeted 130 accounts, posted from 45 of them, and collected over $100,000 in Bitcoin.
- **Google and Facebook, 2013 to 2015:** a fraudster impersonated the supplier Quanta Computer with forged invoices. Google paid about $23 million and Facebook about $98 million. He pleaded guilty in 2019.
- **Fake Google alert, March 2016:** a senior US political campaign official received a fake Google security alert with a shortened link to a fake sign-in page. Researchers linked the attack to the group known as Fancy Bear.

![Real-world cases](screenshots/05-real-world-cases.png)

### 5. Best practices
A checklist of ten habits: pause, check the sender's domain, hover over links, go direct to websites, never share codes or passwords, use multi-factor authentication, use a password manager, avoid unexpected attachments, verify through a second channel, and report suspicious messages.

### 6. Interactive quiz
Eight multiple-choice questions. After each answer the module marks the correct option and explains why. A final screen shows the score with a short message and a "Try again" button.

![Quiz question 1](screenshots/06-quiz-question-1.png)

![Quiz question 2](screenshots/07-quiz-question-2.png)

![Quiz score](screenshots/08-quiz-score.png)

## How to Run

1. Download or clone this repository.
2. Open `index.html` in a web browser (Chrome, Edge, Firefox or Safari).

The page loads the IBM Plex fonts from Google Fonts when online. Without internet it still works and uses default fonts.

## Technologies Used

- HTML5, CSS3 and vanilla JavaScript (no frameworks or libraries)
- Responsive layout that works on phones and desktops
- Keyboard-accessible buttons with visible focus states

## Sources for the Real-World Cases

The case details were checked against published news reports of the Twitter incident (July 2020), the US Department of Justice case against Evaldas Rimasauskas, and security-industry coverage of the March 2016 phishing email.

## Repository Structure

```
Task-2-Phishing-Awareness-Training/
├── README.md
├── index.html
└── screenshots/
    ├── 01-module-home.png
    ├── 02-spot-the-phish.png
    ├── 03-fake-websites.png
    ├── 04-social-engineering.png
    ├── 05-real-world-cases.png
    ├── 06-quiz-question-1.png
    ├── 07-quiz-question-2.png
    └── 08-quiz-score.png
```

## Limitations

- The quiz has a fixed set of eight questions and does not save scores between visits.
- The sample email is a single scenario. A future version could add more examples, such as fake bank alerts, SMS messages and job-offer scams.
- The module is in English only.

## Ethical and Responsible Use

This module is for education and awareness only. The sample email and web addresses are fictional examples created to teach recognition of phishing, and should not be used to deceive anyone.

## Conclusion

This task delivers an interactive phishing awareness module that teaches people to spot phishing emails and fake websites, understand social engineering, learn from real incidents, and check their knowledge through a quiz.


