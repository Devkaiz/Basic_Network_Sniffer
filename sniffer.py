from datetime import datetime
from collections import Counter

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw


packet_count = 0
protocol_counts = Counter()


def identify_protocol(packet):
    """Identify the most useful protocol for display."""
    if DNS in packet:
        return "DNS"
    elif TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet or packet.haslayer("ICMPv6"):
        return "ICMP"
    elif IP in packet or IPv6 in packet:
        return "IP"
    return "Other"


def describe_packet(packet):
    """Display details of a captured packet."""
    global packet_count

    packet_count += 1
    protocol = identify_protocol(packet)
    protocol_counts[protocol] += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    src_ip = "N/A"
    dst_ip = "N/A"
    src_port = "-"
    dst_port = "-"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    print(f"\n{'-' * 60}")
    print(f"Packet #{packet_count} | Time: {timestamp}")
    print(f"Protocol    : {protocol}")
    print(f"Source      : {src_ip}:{src_port}")
    print(f"Destination : {dst_ip}:{dst_port}")
    print(f"Packet size : {len(packet)} bytes")

    if Raw in packet:
        payload = bytes(packet[Raw].load)
        preview = payload[:24].hex(" ")
        suffix = " ..." if len(payload) > 24 else ""
        print(f"Payload hex : {preview}{suffix}")


def choose_filter():
    """Let the user select a traffic filter."""
    print("\nSelect traffic to capture:")
    print("1. All traffic")
    print("2. TCP")
    print("3. UDP")
    print("4. ICMP")
    print("5. DNS")

    filters = {
        "1": ("All", None),
        "2": ("TCP", "tcp"),
        "3": ("UDP", "udp"),
        "4": ("ICMP", "icmp or icmp6"),
        "5": ("DNS", "port 53"),
    }

    while True:
        choice = input("Enter choice (1-5): ").strip()
        if choice in filters:
            return filters[choice]
        print("Invalid choice. Please enter a number from 1 to 5.")


def main():
    global packet_count

    print("=" * 60)
    print("          CODEALPHA BASIC NETWORK SNIFFER")
    print("=" * 60)

    name, bpf_filter = choose_filter()

    while True:
        try:
            limit = int(
                input("Packet limit (1-10000, or 0 for unlimited): ")
            )
            if 0 <= limit <= 10000:
                break
            print("Enter a number between 0 and 10000.")
        except ValueError:
            print("Please enter a valid whole number.")

    print(f"\nFilter       : {name}")
    print(f"Packet limit : {limit if limit else 'Unlimited'}")
    print("Press Ctrl+C to stop the capture.")
    print("\nWaiting for packets...")

    try:
        sniff(
            filter=bpf_filter,
            prn=describe_packet,
            store=False,
            count=limit
        )
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as error:
        print(f"\nCapture error: {error}")
        print("Check Npcap, permissions, and the selected interface.")
    finally:
        print("\n" + "=" * 60)
        print("                 CAPTURE SUMMARY")
        print("=" * 60)
        print(f"Total packets captured: {packet_count}")

        if protocol_counts:
            print("\nPackets by protocol:")
            for protocol, count in protocol_counts.most_common():
                print(f"  {protocol:<10}: {count}")
        else:
            print("No matching packets were captured.")

        print("=" * 60)


if __name__ == "__main__":
    main()
