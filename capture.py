from scapy.all import *
from scapy.layers.inet import *
from utils import get_tcp_udp_slice
import torch
import numpy as np
from model import TCANN

tcann = TCANN()
tcann.load_state_dict(torch.load("./model/tcann.pth"))
tcann.eval()

app_counts = [0, 0, 0]


def packet_handler(pkt: Packet):
    if TCP in pkt or UDP in pkt:
        packet_slice = get_tcp_udp_slice(pkt)
        pred = tcann(torch.tensor(np.array([packet_slice]), dtype=torch.float)).argmax(1)
        app_counts[pred.item()] += 1
        print(f"QQ: {app_counts[0]} WX: {app_counts[1]} HTTPS: {app_counts[2]}")


# Withous filter is also ok
sniff(iface="WLAN", prn=packet_handler, filter="tcp or udp")
