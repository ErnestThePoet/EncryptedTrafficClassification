from scapy.all import *


def packet_handler(packet):
    print(packet)


sniff(prn=packet_handler, timeout=5, filter="tcp")
