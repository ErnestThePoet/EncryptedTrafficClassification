from scapy.layers.inet import *
from scapy.all import *

qq_dataset = rdpcap("./dataset/qq_10k.pcap")
wx_dataset = rdpcap("./dataset/wx_7k5.pcap")
print(raw(qq_dataset[0])[0:42].hex())

