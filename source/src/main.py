import time
from scapy.all import IP,TCP,send,sniff
import ipaddress
import argparse
import sys

#global variables
TIMEOUT = 1
MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_DELAY = 0

def command_line_parser():
    parser = argparse.ArgumentParser(description="TCP SYN Port Scanner")
    parser.add_argument("target", type=str)
    parser.add_argument("--start", type=int,default=MIN_PORT)
    parser.add_argument("--end", type=int, default=MAX_PORT)
    parser.add_argument("--delay", type=int, default=DEFAULT_DELAY)
    return parser.parse_args()

def verify_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def verify_port_range(start_port, end_port):
    if MIN_PORT <= start_port <= MAX_PORT and MIN_PORT <= end_port <= MAX_PORT and start_port <= end_port:
        return True
    else:
        return False

#check the port status of each packet
def packet_callback(pkt):
    if pkt.haslayer(TCP):
        if pkt[TCP].flags == 0x12:  
            return "Open"
        elif pkt[TCP].flags == 0x14:  
            return "Closed"
    return "Filtered"

def scan_ports(ip_address, start_port, end_port, delay):

    #inclusive for end port
    try:
        for port in range(start_port, end_port + 1):
            ip = IP(dst=ip_address)
            syn_packet = TCP(dport=port, flags="S")
            
            print(f"Scanning Port: {port}")
            send(ip/syn_packet)

            # use sniff for response
            resp = sniff(
                filter=f"tcp and host {ip_address} and port {port}",
                timeout=1, count=1
            )

            status = packet_callback(resp[0]) if resp else f"Port {port}: Filtered"
            
            # Print the status of the port
            print(f"Port {port}: {status}")

            # If a delay is set, wait before scanning the next port
            if delay > 0:
                time.sleep(delay / 1000)

    except KeyboardInterrupt:
        print("\nScan interrupted. Exiting...")
        sys.exit(0)  
        

if __name__ == "__main__":

    args = command_line_parser()
    ip_address = args.target
    start_port = args.start
    end_port = args.end
    delay = args.delay

    if not verify_ip_address(ip_address):
        print(f"Error: {ip_address} is not a valid IP address.")
        sys.exit(1)  

    if not verify_port_range(start_port, end_port):
        print("Invalid port range.")
        sys.exit(1)

    print(f"Scanning {ip_address} from port {start_port} to {end_port} with delay of {delay}...\n")
    scan_ports(ip_address, start_port, end_port, delay)
