import threading
from scapy.all import IP
from report import IDSReport
from record import IDSRecord

# Define a function that converts a file size to bytes
def file_size_to_bytes(file_size, extension):
    # Parse the file size string and convert it to bytes
    if extension == "GB":
        return int(file_size) * (1 << 30)
    elif extension == "MB":
        return int(file_size) * (1 << 20)
    elif extension == "KB":
        return int(file_size) * (1 << 10)
    elif extension == "TB":
        return int(file_size) * (1 << 40)
    else:
        return int(file_size)

class DataTransfer:

    _limit: int = 0
    _report: IDSReport = None
    _registry = {}

    def __init__(self, report: IDSReport, limit) -> None:
        number = limit[:-2]
        extension = limit[-2:]

        self._limit = file_size_to_bytes(number, extension)
        self._report = report

    def set_interval(self, func, sec, args):
        def func_wrapper():
            self.set_interval(func, sec, args)
            func(args[0])
        t = threading.Timer(sec, func_wrapper)
        t.start()
        return t

    def start(self, interval: int = 1):
        def clean(r):
            print(r)
            for k in r.keys():
                r[k] = 0

        self.set_interval(clean, interval, [self._registry])

    def handler(self, packet):
        if IP not in packet:
            return

        if packet[IP].src not in self._registry.keys():
            self._registry[packet[IP].src] = len(packet)
        else:
            self._registry[packet[IP].src] += len(packet)

        if self._registry[packet[IP].src] > self._limit:
            self._report.add_record(
                IDSRecord(
                    packet,
                    "Unusually large data transfer",
                    packet[IP].src,
                    packet[IP].dst,
                    "The device at {} is transferring a large amount of data"
                    .format(packet[IP].src)
                )
            )