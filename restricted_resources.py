import fnmatch
from record import IDSRecord
from report import IDSReport

from scapy.all import IP

class RestrictedResources:

    _int_res: str = ""
    _ext_res: str = ""

    _int_allow_list: str = ""

    _report: IDSReport = None

    _network_glob = ""

    def __init__(self, report: IDSReport, network, internal_resources, external_resources, internal_allow_list) -> None:
        self._ext_res = external_resources
        self._int_res = internal_resources
        self._int_allow_list = internal_allow_list

        self._report = report
        self._network_glob = network


    def handler(self, packet):
        if not IP in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        dst_in_network = fnmatch.fnmatch(dst_ip, self._network_glob)
        src_in_network = fnmatch.fnmatch(src_ip, self._network_glob)

        if dst_in_network:
            is_external_resource = fnmatch.fnmatch(dst_ip, self._ext_res)
            is_internal_resource = fnmatch.fnmatch(dst_ip, self._int_res)
            src_in_allow_list = fnmatch.fnmatch(src_ip, self._int_allow_list)

            if not src_in_network and not is_external_resource:
                self._report.add_record(
                    IDSRecord(
                        packet,
                        "External access of restrcited resource",
                        src_ip,
                        dst_ip,
                        "An external IP address attempted to make a connection with an internal restricted resource"
                    )
                )

            if not src_in_allow_list and is_internal_resource:
                self._report.add_record(
                    IDSRecord(
                        packet,
                        "Internal access of restrcited resource",
                        src_ip,
                        dst_ip,
                        "An internal IP address attempted to make a connection with an internal restricted resource"
                    )
                )
