from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
    if IP in packet:
        print("\n[PACKET]")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if TCP in packet:
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        else:
            print(f"Protocol       : {packet[IP].proto}")


print("=" * 50)
print("        BASIC NETWORK SNIFFER")
print("=" * 50)
print("Capturing packets... Press Ctrl+C to stop.\n")

sniff(prn=packet_callback, store=False)