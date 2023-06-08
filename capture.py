import requests
from scapy.all import *
from scapy.layers.inet import *
from utils import get_tcp_udp_slice
import torch
import numpy as np
from model import TCANN

tcann = TCANN()
tcann.load_state_dict(torch.load("./model/tcann.pth"))
tcann.eval()

app_names = ["QQ", "WX", "HTTPS"]
app_counts = [0, 0, 0]

API_HOST = "172.20.39.15"
API_PORT = 12345
API_PREFIX = f"http://{API_HOST}:{API_PORT}/"


def packet_handler(pkt: Packet):
    if TCP in pkt or UDP in pkt:
        packet_slice = get_tcp_udp_slice(pkt)
        pred = tcann(torch.tensor(np.array([packet_slice]), dtype=torch.float)).argmax(1).item()
        app_counts[pred] += 1
        print(", ".join([f"{app_names[x]}: {app_counts[x]}" for x in range(len(app_counts))]))
        requests.post(API_PREFIX + "api/receive_data", data={
            "protocol": "TCP" if TCP in pkt else "UDP",
            "port": pkt[TCP].dport if TCP in pkt else pkt[UDP].dport,
            "catalogue": app_names[pred]
        })


sniff(iface="WLAN",
      prn=packet_handler,
      filter=f"(tcp or udp) and (not port 53) and (not port 1900) and (not port {API_PORT})")
