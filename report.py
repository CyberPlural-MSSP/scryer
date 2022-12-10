from record import IDSRecord
import time

class IDSReport:
    _start_time = time.time()
    _records: list[IDSRecord] = []

    def add_record(self, record: IDSRecord):
        self._records.append(record)

    def generate(self):
        report = ""

        for record in self._records:
            obj = record.get_dict()

            report += obj['time'] + '\t' + obj['type'] + '\t' + '/'.join(obj['layers']) + '\t' + obj['src_ip'] + '\t' + obj['dst_ip'] + '\t' + obj['description'] + '\n\n'

        return report
    
    def stats(self):
        return len(self._records)