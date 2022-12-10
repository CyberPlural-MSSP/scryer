import threading
from scapy.all import IP
from report import IDSReport
from record import IDSRecord

class MaliciousComms:

    _iptable = {}
    _report: IDSReport = None

    def __init__(self, report: IDSReport, iptable: dict[str, str]) -> None:
        self._iptable = iptable
        self._report = report

    def handler(self, packet):
        if IP not in packet:
            return
            
        if packet[IP].src in self._iptable.keys():
            self._report.add_record(
                IDSRecord(
                    packet,
                    "Malicous incoming communication",
                    packet[IP].src,
                    packet[IP].dst,
                    "The device at {} is receiving communication from an external malicious device at {}"
                    .format(packet[IP].dst, packet[IP].src)
                )
            )
        elif packet[IP].dst in self._iptable.keys():
            self._report.add_record(
                IDSRecord(
                    packet,
                    "Malicous outgoing communication",
                    packet[IP].src,
                    packet[IP].dst,
                    "The device at {} is communicating with an external malicious device at {}"
                    .format(packet[IP].src, packet[IP].dst)
                )
            )