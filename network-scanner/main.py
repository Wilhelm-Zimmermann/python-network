import scapy.all as scapy; 
import optparse;

def get_arguments():
    parser = optparse.OptionParser();
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range");
    (options, arguments) = parser.parse_args();
    return options;

def scan(ip_addr):
    arp_request = scapy.ARP(pdst=ip_addr);
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff");
    arp_request_brodcast = broadcast/arp_request;
    scan_report = [];
    scan_list = scapy.srp(arp_request_brodcast, timeout=1, verbose=False)[0];

    for el in scan_list:
        scan_report.append({"ip": el[1].psrc, "mac": el[1].hwsrc});

    return scan_report;

def print_scan(scan_list):
    print("");
    print("|IP\t\t|At Mac Address");
    print("-----------------------------------");
    for el in scan_list:
        print(f"|{el["ip"]}\t|{el["mac"]}");

scan_result = scan(get_arguments().target);
print_scan(scan_result);