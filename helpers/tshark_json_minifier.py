import json
import sys

from jsonslicer import JsonSlicer

from helpers.packet import Packet


class TsharkJsonMinifier:

    def __init__(self, file_name):
        self.file_name = file_name
        self.inside_packet = False
        self.packet_data = []
        self.packet_count = 0
        self.write_file = open(f"{self.file_name.replace('.json', '.extracted.json')}", 'w')

    def minify_file_slicer(self, rules):
        print(f'Extracting packets from {self.file_name} to {self.file_name.replace(".json", ".extracted.json")}')
        with open(self.file_name) as f:
            for raw_packet in JsonSlicer(f, (None, None, 'layers')):
                parsed_packet = self.parse_packet_slicer(raw_packet, rules)
                self.write_file.write(json.dumps(parsed_packet))
                self.write_file.write('\n')

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

    def parse_packet_slicer(self, packet_raw, rules):
        packet = {}
        packet_bytes = packet_raw['frame_raw'][0]
        packet_length = packet_raw['frame_raw'][2]
        # layers = filter(lambda layer: type(layer) is dict, packet_raw['_source']['layers'])
        protocols = list(filter(lambda key: key != 'frame' and not key.endswith('_raw'), packet_raw.keys()))
        protocol_fields = {}

        packet_header_bytes = self.parse_packet_header(packet_raw['frame'])

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
        # print(protocols)
        for rule in rules:
            if rule.field_path_for_shark[0] in protocols:
                print(protocols)
                print(f'Rule: {rule.field_path_for_shark}')
                packet.update([
                    (
                        '.'.join(rule.field_path_for_shark),
                        packet_raw[rule.field_path_for_shark[0]][f"{'.'.join(rule.field_path_for_shark)}"]
                    )
                ])
        # for rule in rules:
        #     last_valid_protocol = None
        #     for i, path in enumerate(rule.field_path[:-1]):
        #         if path in protocols:
        #             last_valid_protocol = 'adad'
        #         if path not in protocols:
        #             if path in packet_raw[rule.field_path[i - 1]]

        return packet

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
        return []

    def parse_packet_header(self, frame):
        time_epoch = frame['frame.time_epoch'].split('.')
        timestamp = time_epoch[0]
        timestamp_microseconds = time_epoch[1].rstrip('0')
        if timestamp_microseconds == '':
            timestamp_microseconds = '0'
        origin_size = frame['frame.cap_len']
        current_size = frame['frame.len']
        return (int(timestamp).to_bytes(4, sys.byteorder) \
                             + int(timestamp_microseconds).to_bytes(4, sys.byteorder, signed=True) \
                             + int(current_size).to_bytes(4, sys.byteorder) \
                             + int(origin_size).to_bytes(4, sys.byteorder)).hex()
