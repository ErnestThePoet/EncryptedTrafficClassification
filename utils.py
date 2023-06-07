from scapy.layers.inet import *
from scapy.all import *
import numpy as np


def get_54_header(pkt: Packet) -> np.ndarray:
    TCP_SLICE_LENGTH = 54
    UDP_SLICE_LENGTH = 42

    if TCP in pkt:
        if len(raw(pkt)) < TCP_SLICE_LENGTH:
            raise RuntimeError(f"TCP packet size < {TCP_SLICE_LENGTH}")
        return np.array(np.frombuffer(raw(pkt)[:TCP_SLICE_LENGTH], dtype=np.uint8))
    elif UDP in pkt:
        if len(raw(pkt)) < UDP_SLICE_LENGTH:
            raise RuntimeError(f"UDP packet size < {UDP_SLICE_LENGTH}")
        # Pad UDP with trailing zeros to make it 54-byte long
        return np.concatenate([
            np.frombuffer(raw(pkt)[:UDP_SLICE_LENGTH], dtype=np.uint8),
            np.zeros(TCP_SLICE_LENGTH - UDP_SLICE_LENGTH, dtype=np.uint8)])
    else:
        raise RuntimeError("packet is neither TCP nor UDP")


def get_header_payload(pkt: Packet) -> np.ndarray:
    SLICE_LENGTH = 100

    if TCP in pkt or UDP in pkt:
        if len(raw(pkt)) >= SLICE_LENGTH:
            return np.array(np.frombuffer(raw(pkt)[:SLICE_LENGTH], dtype=np.uint8))
        # Pad with trailing zeros
        return np.concatenate([
            np.frombuffer(raw(pkt), dtype=np.uint8),
            np.zeros(SLICE_LENGTH - len(raw(pkt)), dtype=np.uint8)])
    else:
        raise RuntimeError("packet is neither TCP nor UDP")


def get_tcp_udp_header(pkt: Packet) -> np.ndarray:
    if TCP in pkt or UDP in pkt:
        return get_header_payload(pkt)
    else:
        raise RuntimeError("packet is neither TCP nor UDP")


def get_tcp_udp_headers(packets: PacketList) -> np.ndarray:
    tcp_udp_packets: list[Packet] = list(filter(lambda x: TCP in x or UDP in x, packets))

    if len(tcp_udp_packets) == 0:
        return np.array([])

    result: np.ndarray = np.array([get_tcp_udp_header(tcp_udp_packets[0])])

    for pkt in tcp_udp_packets[1:]:
        result = np.concatenate([result, np.array([get_tcp_udp_header(pkt)])])

    return result
