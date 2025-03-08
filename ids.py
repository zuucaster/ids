import scapy.all as scapy
from scapy.layers.inet import IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"Potential Threat Detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

scapy.sniff(filter="ip", prn=packet_callback, store=False)
