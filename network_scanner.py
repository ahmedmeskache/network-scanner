from scapy.all import ARP, Ether, srp
import socket
import datetime

def scan_network(ip_range):
    print(f"\n{'='*50}")
    print(f"  Network Scanner - Ahmed Meskache")
    print(f"  Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target: {ip_range}")
    print(f"{'='*50}\n")

    # Create ARP packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and get response
    print("Scanning... please wait\n")
    result = srp(packet, timeout=3, verbose=0)[0]

    # Store devices found
    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except:
            hostname = "Unknown"
        
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": hostname
        })

    # Display results
    print(f"{'No.':<5} {'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
    print("-" * 65)
    
    for i, device in enumerate(devices, 1):
        print(f"{i:<5} {device['ip']:<18} {device['mac']:<20} {device['hostname']}")

    print(f"\n Total devices found: {len(devices)}")
    print(f"{'='*50}\n")
    
    return devices

if __name__ == "__main__":
    from scapy.all import conf
    
    # Force use of Wi-Fi interface
    conf.iface = "Wi-Fi"
    
    ip_range = "172.20.10.1/24"
    
    print(f"Your local IP: 172.20.10.5")
    print(f"Scanning range: {ip_range}")
    
    scan_network(ip_range)
