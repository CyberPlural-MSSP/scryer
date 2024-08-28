import fnmatch
from record import IDSRecord
from report import IDSReport

from scapy.all import IP
from typing import Dict, Any, List, Generator

Resource = Dict[str, List[str]]
class Resources:
    _report: IDSReport = None

    _resources: Dict[str, Resource]

    def __init__(self, report: IDSReport, resources: Dict[str, Resource]) -> None:
        self._report = report
        self._resources = resources

    def _get_packet_layers(self, packet) -> Generator[List[str], None, None]:
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break

            yield layer.name
            counter += 1

    def handle_segment(self, packet, inward: bool, resource: Resource):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        layers = [l for l in self._get_packet_layers(packet)]

        allowed = resource['allow'] if 'allow' in resource else []
        disallowed = resource['disallow'] if 'disallow' in resource else []

        for l in layers:
            # print(allowed, disallowed, l)
            if l in disallowed and not l in allowed:
                if inward:
                    self._report.add_record(
                        IDSRecord(
                            packet,
                            "External access of restrcited resource",
                            src_ip,
                            dst_ip,
                            "An external IP address attempted to make a connection with an internal restricted resource"
                        )
                    )
                else:
                    self._report.add_record(
                        IDSRecord(
                            packet,
                            "Internal access of restrcited resource",
                            src_ip,
                            dst_ip,
                            "An internal IP address attempted to make a connection with an internal restricted resource"
                        )
                    )


    def handler(self, packet):
        if not IP in packet:
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        for glob, resource in self._resources.items():
            dst_in_network = fnmatch.fnmatch(dst_ip, glob)
            src_in_network = fnmatch.fnmatch(src_ip, glob)

            if dst_in_network or src_in_network:
                self.handle_segment(packet, dst_in_network is True, resource)
