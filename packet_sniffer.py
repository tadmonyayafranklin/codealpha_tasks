import scapy.all as scapy

def packet_callback(packet):
    """
    This function is called whenever a packet is captured.
    It prints source/destination IP, protocol, and payload.
    """
    print("\n[Packet Captured]")
    
    # Check if the packet has IP layer
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src  # Source IP
        ip_dst = packet[scapy.IP].dst  # Destination IP
        protocol = packet[scapy.IP].proto  # Protocol type
        
        print("Source IP:", ip_src)
        print("Destination IP:", ip_dst)
        
        # Further inspection based on protocol
        if protocol == 6:  # TCP
            print("Protocol: TCP")
            if packet.haslayer(scapy.TCP):
                payload = packet[scapy.TCP].payload
                print("TCP Payload:", payload)
        elif protocol == 17:  # UDP
            print("Protocol: UDP")
            if packet.haslayer(scapy.UDP):
                payload = packet[scapy.UDP].payload
                print("UDP Payload:", payload)
        elif protocol == 1:  # ICMP (Ping)
            print("Protocol: ICMP")
            if packet.haslayer(scapy.ICMP):
                payload = packet[scapy.ICMP].payload
                print("ICMP Payload:", payload)
        
        # Print raw payload data (e.g., in case of HTTP requests or others)
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load
            print("Raw Data:", raw_data)

# Sniff network traffic
def capture_packets(interface="wlp12s0", count=10):
    """
    Capture a specified number of packets on a given network interface.
    """
    print("Starting packet capture...")
    scapy.sniff(iface=interface, prn=packet_callback, count=count)

# Example usage:
if __name__ == "__main__":
    capture_packets(interface="wlp12s0", count=5)  # Capture 5 packets on interface wlp12s0
