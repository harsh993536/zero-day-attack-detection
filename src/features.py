from scapy.all import IP, TCP, UDP
import time
import numpy as np


class Flow:
    def __init__(self, packet):
        self.start_time = time.time()
        self.last_time = self.start_time

        self.total_fwd_packets = 0
        self.total_bwd_packets = 0

        self.total_fwd_bytes = 0
        self.total_bwd_bytes = 0

        self.packet_lengths = []

        self.syn_count = 0
        self.ack_count = 0

        self.protocol = 0
        self.src_ip = None
        self.dst_ip = None

        self.src_port = 0
        self.dst_port = 0

        self.update(packet)

    def update(self, packet):

        if not packet.haslayer(IP):
            return

        self.last_time = time.time()

        ip = packet[IP]

        packet_length = len(packet)
        self.packet_lengths.append(packet_length)

        self.protocol = ip.proto

        if self.src_ip is None:
            self.src_ip = ip.src
            self.dst_ip = ip.dst

        # TCP information
        if packet.haslayer(TCP):

            tcp = packet[TCP]

            if self.src_port == 0:
                self.src_port = tcp.sport
                self.dst_port = tcp.dport

            if ip.src == self.src_ip:
                self.total_fwd_packets += 1
                self.total_fwd_bytes += packet_length
            else:
                self.total_bwd_packets += 1
                self.total_bwd_bytes += packet_length

            # TCP flags
            if tcp.flags & 0x02:
                self.syn_count += 1

            if tcp.flags & 0x10:
                self.ack_count += 1

        # UDP information
        elif packet.haslayer(UDP):

            udp = packet[UDP]

            if self.src_port == 0:
                self.src_port = udp.sport
                self.dst_port = udp.dport

            if ip.src == self.src_ip:
                self.total_fwd_packets += 1
                self.total_fwd_bytes += packet_length
            else:
                self.total_bwd_packets += 1
                self.total_bwd_bytes += packet_length

    def get_features(self):

        duration = self.last_time - self.start_time

        # Avoid division by zero
        if duration <= 0:
            duration = 0.000001

        total_packets = (
            self.total_fwd_packets +
            self.total_bwd_packets
        )

        total_bytes = (
            self.total_fwd_bytes +
            self.total_bwd_bytes
        )

        # Packet statistics
        if self.packet_lengths:
            packet_mean = np.mean(self.packet_lengths)
            packet_std = np.std(self.packet_lengths)
        else:
            packet_mean = 0
            packet_std = 0

        flow_bytes_per_second = total_bytes / duration
        flow_packets_per_second = total_packets / duration

        average_packet_size = (
            total_bytes / total_packets
            if total_packets > 0
            else 0
        )

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": self.total_fwd_packets,
            "Total Backward Packets": self.total_bwd_packets,
            "Total Length of Fwd Packets": self.total_fwd_bytes,
            "Total Length of Bwd Packets": self.total_bwd_bytes,
            "Flow Bytes/s": flow_bytes_per_second,
            "Flow Packets/s": flow_packets_per_second,
            "Packet Length Mean": packet_mean,
            "Packet Length Std": packet_std,
            "SYN Flag Count": self.syn_count,
            "ACK Flag Count": self.ack_count,
            "Average Packet Size": average_packet_size
        }