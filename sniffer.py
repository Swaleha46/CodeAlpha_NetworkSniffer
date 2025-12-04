from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    print("\n-------------------- PACKET --------------------")

    # Source & Destination IPs
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

    # Protocol detection
    if packet.haslayer(TCP):
        print("Protocol: TCP")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")
    else:
        print("Protocol: Other")

    # Packet summary
    print("Packet Summary:", packet.summary())

print("Sniffer started... Press CTRL + C to stop.\n")
sniff(prn=analyze_packet, store=False)
