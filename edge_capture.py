from datetime import datetime
import hashlib
try:
    from scapy.all import sniff, IP, TCP, UDP, Ether
except ImportError:
    raise ImportError("Scapy is required for real-time traffic capture. Install it with 'pip install scapy'.")

def capture_traffic_real_time():
    """
    Capture a single packet with detailed network information in real-time using scapy.
    Requires root privileges (sudo).
    """
    try:
        packet = sniff(count=1, timeout=5)[0]  # Capture one packet, timeout after 5 seconds
        encrypted = bool(packet.haslayer(TCP) and packet[TCP].flags & 0x02)  # Syn flag as proxy
        
        # Determine ports (TCP/UDP) or set to None
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        
        # Traffic direction (simplified: inbound if dest IP is local-like, outbound otherwise)
        direction = "inbound" if packet[IP].dst.startswith("192.168") else "outbound"

        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet[IP].src if IP in packet else "0.0.0.0",
            "dest_ip": packet[IP].dst if IP in packet else "0.0.0.0",
            "source_mac": packet[Ether].src if Ether in packet else "00:00:00:00:00:00",
            "dest_mac": packet[Ether].dst if Ether in packet else "00:00:00:00:00:00",
            "source_port": src_port,
            "dest_port": dst_port,
            "packet_size": len(packet),
            "protocol": packet[IP].proto if IP in packet else 0,
            "flags": packet[TCP].flags if TCP in packet else 0,
            "ttl": packet[IP].ttl if IP in packet else 0,  # New: Time to Live
            "direction": direction,  # New: Inbound/Outbound
            "anomaly": 0,  # Initial value, updated by classifier
            "encrypted": encrypted,
            "hash": hashlib.md5(bytes(packet)).hexdigest() if encrypted else None,
            "active": True  # New: Indicates if the connection is active
        }
        return data
    except Exception as e:
        print(f"Error capturing traffic: {e}")
        return None