import threading
from scapy.all import IP, TCP
from report import IDSReport
from record import IDSRecord
import time

class FloodDetection:

    _packet_type = None
    _max_len = 0
    _max_count = 0
    _registry = {}
    _report: IDSReport
    _timer = None

    def __init__(self, report: IDSReport, packet_type, max_packet_count: int, max_packet_len: int = 0):
        self._packet_type = packet_type
        self._max_len = max_packet_len
        self._max_count = max_packet_count
        self._report = report

    def set_interval(self, func, sec, args):
        def func_wrapper():
            self._timer.cancel()
            self._timer = self.set_interval(func, sec, args)
            func(args[0])
        self._timer = threading.Timer(sec, func_wrapper)
        self._timer.start()
        return self._timer

    def start(self, interval: int = 1):
        def clean(r):
            for k in r.keys():
                r[k] = 0

        return self.set_interval(clean, interval, [self._registry])

    def _is_flood(self, packet):
        if not IP in packet:
            return
        # Check if the packet is the type we are looking for
        if self._packet_type in packet:
            # Check if the packet has a high number of repetitions
            if packet[IP].dst not in self._registry.keys():
                self._registry[packet[IP].dst] = 1
            else:
                self._registry[packet[IP].dst] += 1

            if self._registry[packet[IP].dst] > self._max_count:
                return True
            # Check if the packet has a large payload
            elif packet[IP].len > self._max_len and self._max_len > 0:
                return True
        return False

    # Define the is_flood() method to detect UDP and ICMP flood attacks
    def handler(self, packet):
        if self._is_flood(packet):
            self._report.add_record(
                IDSRecord(
                    packet,
                    "Flood Attack",
                    packet[IP].src,
                    packet[IP].dst,
                    "A large number of packets have been detected going int the direction of {}"
                    .format(packet[IP].dst)
                )
            )

class HTTPFloodDetection(FloodDetection):
    def _is_flood(self, packet):
        if not IP in packet:
            return
        # Check if the packet is a UDP or ICMP packet
        if self._packet_type in packet and packet[TCP].dport == 80:
            # Check if the packet has a high number of repetitions
            if packet[IP].dst not in self._registry.keys():
                self._registry[packet[IP].dst] = 1
            else:
                self._registry[packet[IP].dst] += 1

            if self._registry[packet[IP].dst] > self._max_count:
                return True
            # Check if the packet has a large payload
            elif packet[IP].len > self._max_len and self._max_len > 0:
                return True
        return False

class SYNFloodDetection(FloodDetection):
    def _is_flood(self, packet):
        if not IP in packet:
            return
        # Check if the packet is a UDP or ICMP packet
        if self._packet_type in packet and packet[TCP].flags == 2:
            # Check if the packet has a high number of repetitions
            if packet[IP].dst not in self._registry.keys():
                self._registry[packet[IP].dst] = 1
            else:
                self._registry[packet[IP].dst] += 1

            if self._registry[packet[IP].dst] > self._max_count:
                return True
            # Check if the packet has a large payload
            elif packet[IP].len > self._max_len and self._max_len > 0:
                return True
        return False

class ACKFloodDetection(FloodDetection):
    def _is_flood(self, packet):
        if not IP in packet:
            return
        # Check if the packet is a UDP or ICMP packet
        if self._packet_type in packet and packet[TCP].flags == 16:
            # Check if the packet has a high number of repetitions
            if packet[IP].dst not in self._registry.keys():
                self._registry[packet[IP].dst] = 1
            else:
                self._registry[packet[IP].dst] += 1

            if self._registry[packet[IP].dst] > self._max_count:
                return True
            # Check if the packet has a large payload
            elif packet[IP].len > self._max_len and self._max_len > 0:
                return True
        return False

class FINFloodDetection(FloodDetection):
    def _is_flood(self, packet):
        if not IP in packet:
            return
        # Check if the packet is a UDP or ICMP packet
        if self._packet_type in packet and packet[TCP].flags == 17:
            # Check if the packet has a high number of repetitions
            if packet[IP].dst not in self._registry.keys():
                self._registry[packet[IP].dst] = 1
            else:
                self._registry[packet[IP].dst] += 1

            if self._registry[packet[IP].dst] > self._max_count:
                return True
            # Check if the packet has a large payload
            elif packet[IP].len > self._max_len and self._max_len > 0:
                return True
        return False