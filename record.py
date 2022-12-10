import time
from datetime import datetime

def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer.name
        counter += 1

class IDSRecord:
    _type: str = ""
    _src_ip: str = ""
    _dst_ip: str = ""
    _description: str = ""
    _layers: str = ""

    _time: float = 0.0

    def __init__(self, packet, type, src_ip, dst_ip = "", description = ""):
        self._type = type
        self._src_ip = src_ip
        self._dst_ip = dst_ip
        self._description = description
        self._layers = [l for l in get_packet_layers(packet)]
        self._time = time.time()

    def get_dict(self):
        return {
            'type': self._type,
            'src_ip': self._src_ip,
            'dst_ip': self._dst_ip,
            'layers': self._layers,
            'description': self._description,
            'time': datetime.fromtimestamp(self._time).strftime("%m/%d/%Y, %H:%M:%S")
        }
