from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP
import socket
import time

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        service = get_hostname(ip_dst)
        print(f"{ip_src} -> {ip_dst} ({service})")
        wrpcap("captured_packets.pcap", packet, append=True)  # Save packets to a file

def capture_packets(duration=30):
    print("Starting packet capture... Press Ctrl+C to stop.")
    start_time = time.time()
    sniff(prn=packet_callback, store=False, timeout=duration)
    print("Packet capture completed.")

if __name__ == "__main__":
    capture_packets(30)
