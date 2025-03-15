import socket
import time
import json
import threading
import logging
from collections import defaultdict
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
MONITOR_INTERVAL = 60  # interval to check network activity
ALERT_THRESHOLD = 100  # packet threshold for alert
LOG_FILE = 'network_security_log.json'

# Global variables
packet_counts = defaultdict(int)

# Define packet event
class Packet:
    def __init__(self, source_ip, dest_ip, protocol):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'protocol': self.protocol,
            'timestamp': self.timestamp.isoformat()
        }

# Packet capture function
def packet_capture():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind(('0.0.0.0', 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        packet = s.recvfrom(65565)[0]
        source_ip = packet[12:16]
        dest_ip = packet[16:20]
        protocol = packet[9]
        packet_counts[socket.inet_ntoa(source_ip)] += 1
        log_packet(Packet(socket.inet_ntoa(source_ip), socket.inet_ntoa(dest_ip), protocol))

# Log packet to JSON file
def log_packet(packet):
    with open(LOG_FILE, 'a') as log_file:
        json.dump(packet.to_dict(), log_file)
        log_file.write('\n')

# Analyze network activity
def analyze_network_activity():
    while True:
        time.sleep(MONITOR_INTERVAL)
        for ip, count in packet_counts.items():
            if count > ALERT_THRESHOLD:
                alert_admin(ip, count)
            packet_counts[ip] = 0  # Reset count after analysis

# Alerting mechanism
def alert_admin(ip, count):
    logging.warning(f'ALERT: IP {ip} sent {count} packets in the last {MONITOR_INTERVAL} seconds!')
    # You can add additional alerting mechanisms here (e.g. send an email/SMS)

# Start monitoring
def start_monitoring():
    capture_thread = threading.Thread(target=packet_capture)
    analysis_thread = threading.Thread(target=analyze_network_activity)

    capture_thread.start()
    analysis_thread.start()

    capture_thread.join()
    analysis_thread.join()

if __name__ == "__main__":
    logging.info("Starting network security monitor...")
    start_monitoring()