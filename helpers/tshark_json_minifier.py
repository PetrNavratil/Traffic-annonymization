import json
import sys

from helpers.packet import Packet


class TsharkJsonMinifier:

    def __init__(self, file_name):
        self.file_name = file_name
        self.inside_packet = False
        self.packet_data = []
        self.packet_count = 0
        self.write_file = open(f"../dataset/altered/extracted-{file_name.split('/')[-1]}", 'w')

    def minify_file(self, rules):
        with open(self.file_name, 'r') as f:
            # skip initial array json symbol
            f.readline()

            while line := f.readline():
                if self.inside_packet:
                    if line in ['  }\n', '  },\n']:
                        self.inside_packet = False
                        self.packet_count += 1
                        self.packet_data.append(line.replace(',', ''))
                        self.parse_packet(self.packet_data)
                        self.packet_data = []
                    else:
                        self.packet_data.append(line)
                else:
                    if line == '  {\n':
                        self.inside_packet = True
                        self.packet_data.append(line)
        print(f'Packet count {self.packet_count}')
        self.write_file.close()

    def parse_packet(self, packet_lines):
        # print('Parsing packet', packet_lines)
        packet_raw = json.loads(''.join(packet_lines))
        packet = {}
        packet_bytes = packet_raw['_source']['layers']['frame_raw'][0]
        packet_length = packet_raw['_source']['layers']['frame_raw'][2]
        # layers = filter(lambda layer: type(layer) is dict, packet_raw['_source']['layers'])
        protocols = list(filter(lambda key: key != 'frame' and not key.endswith('_raw'), packet_raw['_source']['layers'].keys()))
        protocol_fields = {}

        packet_header_bytes = self.parse_packet_header(packet_raw['_source']['layers']['frame'])

        packet.update([
            (
                'raw_bytes', packet_bytes
            ),
            (
                'header_bytes', packet_header_bytes
            ),
            (
                'length', packet_length
            ),
            (
                'protocols', protocols
            )
        ])

        self.write_file.write(json.dumps(packet))
        self.write_file.write('\n')


        # p = Packet(json.loads(''.join(packet_lines)))
        # print(p.protocols)
        return []

    def parse_packet_header(self, frame):
        # print(frame)
        time_epoch = frame['frame.time_epoch'].split('.')
        timestamp = time_epoch[0]
        timestamp_microseconds = time_epoch[1].rstrip('0')
        origin_size = frame['frame.cap_len']
        current_size = frame['frame.len']
        return (int(timestamp).to_bytes(4, sys.byteorder) \
                             + int(timestamp_microseconds).to_bytes(4, sys.byteorder, signed=True) \
                             + int(current_size).to_bytes(4, sys.byteorder) \
                             + int(origin_size).to_bytes(4, sys.byteorder)).hex()
