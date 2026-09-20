"""
CodeAlpha Task 1: Basic Network Sniffer
Captures network packets with scapy and shows source/destination IPs,
protocol, ports and payload. Saves everything to capture.pcap.

Run as Administrator on Windows (Npcap must be installed).
Stop with Ctrl+C.
"""

from datetime import datetime
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, Raw

PACKET_COUNT = 30          # how many packets to capture (0 = until Ctrl+C)
OUTPUT_FILE = "capture.pcap"

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
captured = []
counter = 0


def printable(data: bytes, limit: int = 80) -> str:
    """Turn raw bytes into a safe, readable string."""
    text = data[:limit].decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() else "." for ch in text)


def process_packet(pkt):
    global counter
    captured.append(pkt)
    counter += 1

    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = PROTOCOLS.get(pkt[IP].proto, f"Other({pkt[IP].proto})")
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        proto = PROTOCOLS.get(pkt[IPv6].nh, f"Other({pkt[IPv6].nh})")
    else:
        print(f"[{counter}] Non-IP packet: {pkt.summary()}")
        return

    time_now = datetime.now().strftime("%H:%M:%S")
    print("-" * 60)
    print(f"[{counter}] {time_now}")
    print(f"  Source      : {src}")
    print(f"  Destination : {dst}")
    print(f"  Protocol    : {proto}")

    if pkt.haslayer(TCP):
        print(f"  Ports       : {pkt[TCP].sport} -> {pkt[TCP].dport}")
        print(f"  TCP Flags   : {pkt[TCP].flags}")
    elif pkt.haslayer(UDP):
        print(f"  Ports       : {pkt[UDP].sport} -> {pkt[UDP].dport}")
    elif pkt.haslayer(ICMP):
        print(f"  ICMP Type   : {pkt[ICMP].type}")

    if pkt.haslayer(Raw):
        print(f"  Payload     : {printable(bytes(pkt[Raw].load))}")
    else:
        print("  Payload     : (none)")


def main():
    print("Sniffing started... Press Ctrl+C to stop.\n")
    try:
        sniff(prn=process_packet, count=PACKET_COUNT, store=False)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("Permission error: run CMD as Administrator.")
        return

    if captured:
        wrpcap(OUTPUT_FILE, captured)
        print(f"\n{len(captured)} packets saved to {OUTPUT_FILE}")
        print("Open it in Wireshark to compare.")


if __name__ == "__main__":
    main()