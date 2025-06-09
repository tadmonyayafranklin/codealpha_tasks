from scapy.all import sniff

# Callback function that is called when a packet is captured
def packet_callback(packet):
    print("\nPacket Captured:")
    
    # Check if the packet has an IP layer
    if packet.haslayer('IP'):
        # Extract source and destination IP addresses
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print("Source IP: ", src_ip)
        print("Destination IP: ", dst_ip)

        # Extract protocol type (TCP, UDP, ICMP)
        if packet.haslayer('TCP'):
            print("Protocol: TCP")
        elif packet.haslayer('UDP'):
            print("Protocol: UDP")
        elif packet.haslayer('ICMP'):
            print("Protocol: ICMP")
        else:
            print("Protocol: {packet.proto}")

        # Extract payload (optional, depending on packet size)
        if packet.haslayer('Raw'):
            print("Payload (Raw Data): ", packet['Raw'].load[:50])  # Show first 50 bytes

# Function to start the sniffing process
def start_sniffing(interface="wlp12s0", count=10):
    # Sniff for 'count' packets and use the callback function for each captured packet
    print("Sniffing", count, " packets...")
    sniff(iface=interface, count=count, prn=packet_callback, store=False)

# Main function to initiate packet sniffing
if __name__ == "__main__":
    # You can specify an interface, or leave it as None to use default
    start_sniffing(count=5)
