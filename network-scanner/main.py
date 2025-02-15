import scapy.all as scapy;

def scan(ip_addr):
    arp_request = scapy.ARP(pdst=ip_addr);
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff");
    arp_request_brodcast = broadcast/arp_request;
    print(arp_request_brodcast.summary())
    

scan("192.168.18.1/24");