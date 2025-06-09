# ✅ TASK 1: Basic Network Sniffer

- Build a Python program to capture network traffic packets.
- Analyze captured packets to understand their structure and content.
- Learn how data flows through the network and the basics of protocols.
- I have used `scapy` for packet capturing.
- Display useful information such as source/destination IPs, protocols and payloads.

## Code Explanation:
`sniff()`: This is the main function used to capture packets. It allows you to specify:

`iface`: Network interface (e.g., eth0 for Ethernet or wlan0 for Wi-Fi). Leave it as None to use the default interface.

`count`: Number of packets to capture.

`prn`: A callback function that is called every time a packet is captured.

`store`: If set to False, the packets are not stored in memory.

`packet_callback(packet)`: This function is invoked for every captured packet. It checks if the packet has an IP layer, extracts source and destination IPs, the protocol (TCP, UDP, ICMP), and the payload if present.

`Protocol Handling`: The script identifies common protocols like TCP, UDP, and ICMP. For other protocols, it simply displays the raw protocol number.

`Payload Display`: The script shows the first 50 bytes of the packet payload, which can be useful for inspecting content (e.g., HTTP headers, DNS requests).

## Customizing the Sniffer:
- You can specify a network interface to capture from (e.g., `eth0` for Ethernet or `wlan0` for Wi-Fi).

- You can increase or decrease the number of packets captured (count parameter).

- You can further filter packets based on certain criteria (e.g., IP address, port, protocol).

## Running the Program:
- Clone the repository and go to the directory using `cd codealpha_task_1`
- Run the script in your terminal using `sudo python3 packet_sniffer.py`. You should see the captured packets with details like source/destination IPs, protocols, and part of the payload (if applicable).
