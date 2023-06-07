from scapy.layers.inet import *
from scapy.all import *
import numpy as np


def get_54_header(pkt: Packet) -> np.ndarray:
    SLICE_LENGTH = 100

    if TCP in pkt or UDP in pkt:
        if len(raw(pkt)) >= SLICE_LENGTH:
            return np.array(np.frombuffer(raw(pkt)[:SLICE_LENGTH], dtype=np.uint8))
        # Pad with trailing zeros
        return np.concatenate([
            np.frombuffer(raw(pkt), dtype=np.uint8),
            np.zeros(SLICE_LENGTH-len(raw(pkt)), dtype=np.uint8)])
    else:
        raise RuntimeError("packet is neither TCP nor UDP")


def get_tcp_udp_headers(packets: PacketList) -> np.ndarray:
    tcp_udp_packets: list[Packet] = list(filter(lambda x: TCP in x or UDP in x, packets))

    if len(tcp_udp_packets) == 0:
        return np.array([])

    result: np.ndarray = np.array([get_54_header(tcp_udp_packets[0])])

    for pkt in tcp_udp_packets[1:]:
        result = np.concatenate([result, np.array([get_54_header(pkt)])])

    return result
