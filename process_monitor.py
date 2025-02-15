import psutil
import socket
import time
import scapy.all as scapy
import threading

SUSPICIOUS_PROCESSES = {
    "keylogger.exe",
    "ransomware.exe",
}

def monitor_processes(duration=30):
    """Monitor running processes and detect suspicious activity."""
    print("Monitoring processes...")
    start_time = time.time()
    while time.time() - start_time < duration:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_name = proc.info['name']
                if process_name and process_name.lower() in SUSPICIOUS_PROCESSES:
                    print(f"Alert: Suspicious process detected: {process_name} (PID: {proc.info['pid']})")
            except Exception as e:
                print(f"Error reading process info: {e}")
        time.sleep(5)

def monitor_network(duration=30):
    """Monitor network traffic for anomalies."""
    print("Monitoring network traffic...")
    prev_sent = psutil.net_io_counters().bytes_sent
    prev_recv = psutil.net_io_counters().bytes_recv
    start_time = time.time()
    while time.time() - start_time < duration:
        time.sleep(5)
        curr_sent = psutil.net_io_counters().bytes_sent
        curr_recv = psutil.net_io_counters().bytes_recv
        sent_diff = curr_sent - prev_sent
        recv_diff = curr_recv - prev_recv
        if sent_diff > 10**7 or recv_diff > 10**7:  # Threshold of 10MB
            print(f"Alert: Unusual data traffic detected! Sent: {sent_diff} bytes, Received: {recv_diff} bytes")
        prev_sent = curr_sent
        prev_recv = curr_recv

def detect_arp_poisoning(duration=30):
    """Detect potential ARP poisoning or MITM attacks."""
    print("Monitoring for ARP poisoning attacks...")
    start_time = time.time()
    def process_packet(packet):
        if time.time() - start_time >= duration:
            return False  # Stop sniffing after the duration
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = scapy.getmacbyip(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac and real_mac != response_mac:
                print(f"Alert: Possible ARP spoofing detected! IP: {packet[scapy.ARP].psrc} has conflicting MAC addresses")
    scapy.sniff(store=False, prn=process_packet, filter="arp", timeout=duration)

def detect_dns_spoofing(duration=30):
    """Detect potential DNS spoofing attacks."""
    print("Monitoring for DNS spoofing attacks...")
    start_time = time.time()
    def process_packet(packet):
        if time.time() - start_time >= duration:
            return False  # Stop sniffing after the duration
        if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.IP):
            domain = packet[scapy.DNS].qd.qname.decode('utf-8')
            print(f"DNS Query: {domain} -> {packet[scapy.IP].dst}")
    scapy.sniff(store=False, prn=process_packet, filter="udp port 53", timeout=duration)

def detect_port_scanning(duration=30):
    """Detect potential port scanning attacks."""
    print("Monitoring for port scanning attempts...")
    connection_attempts = {}
    start_time = time.time()
    def process_packet(packet):
        if time.time() - start_time >= duration:
            return False  # Stop sniffing after the duration
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 2:  # SYN flag
            src_ip = packet[scapy.IP].src
            connection_attempts[src_ip] = connection_attempts.get(src_ip, 0) + 1
            if connection_attempts[src_ip] > 10:
                print(f"Alert: Possible port scanning detected from {src_ip}")
    scapy.sniff(store=False, prn=process_packet, filter="tcp", timeout=duration)

if __name__ == "__main__":
    threads = [
        threading.Thread(target=monitor_processes, args=(30,)),
        threading.Thread(target=monitor_network, args=(30,)),
        threading.Thread(target=detect_arp_poisoning, args=(30,)),
        threading.Thread(target=detect_dns_spoofing, args=(30,)),
        threading.Thread(target=detect_port_scanning, args=(30,))
    ]
    
    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print("Monitoring completed.")
