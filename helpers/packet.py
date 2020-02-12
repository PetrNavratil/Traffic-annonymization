import sys

from helpers.packet_field import PacketField


class Packet:

    def __init__(self, packet):
        self.packet_bytes = bytearray.fromhex(packet['_source']['layers']['frame_raw'][0])
        self.packet_length = packet['_source']['layers']['frame_raw'][2]
        self.protocols = list(filter(lambda key: key != 'frame' and not key.endswith('_raw'), packet['_source']['layers'].keys()))
        self.protocol_fields = {}
        self.packet_header = bytearray()
        self.parse_packet_header(packet['_source']['layers']['frame'])
        # print('protocol', self.protocols)
        for protocol in self.protocols:
            protocol_fields = {}
            print(f"PARSING PROTOCOL {protocol} {packet['_source']['layers'][protocol]}")
            for protocol_field in  list(filter(lambda key: key.endswith('_raw') and type(packet['_source']['layers'][protocol][key]) is list, packet['_source']['layers'][protocol].keys())):
                print(f'PROTOCOL {protocol}, field {protocol_field}')
                protocol_fields.update([(
                    protocol_field,
                    self.parse_packet_field(packet['_source']['layers'][protocol][protocol_field])
                )])
            self.protocol_fields.update([(
                protocol,
                protocol_fields
            )])

        print(f'FIelds {self.protocol_fields}')


    def parse_packet_field(self, field):
        return PacketField(field)

    def parse_packet_header(self, frame):
        print(frame)
        time_epoch = frame['frame.time_epoch'].split('.')
        timestamp = time_epoch[0]
        timestamp_microseconds = time_epoch[1].rstrip('0')
        origin_size = frame['frame.cap_len']
        current_size = frame['frame.len']
        self.packet_header = int(timestamp).to_bytes(4, sys.byteorder) \
                             + int(timestamp_microseconds).to_bytes(4, sys.byteorder, signed=True) \
                             + int(current_size).to_bytes(4, sys.byteorder) \
                             + int(origin_size).to_bytes(4, sys.byteorder)

    def has_protocol(self, protocol):
        return protocol in self.protocols

    def get_packet_field(self, field_path):
        return self.protocol_fields[field_path[0]]['.'.join(field_path) + '_raw']

    def modify_packet_field(self, field: PacketField, value):
        # TODO: add mask fields (IP verze apod)
        for byte_count in range(field.length):
            self.packet_bytes[field.position + byte_count] &= 0
        for byte_count in range(field.length):
            self.packet_bytes[field.position + byte_count] |= value[byte_count]

    def get_packet_layer(self, layer):
        return None