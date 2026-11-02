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
