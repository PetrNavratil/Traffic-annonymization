import sys
from typing import Union

from helpers.packet_field import PacketField


class SharkPacket:

    def __init__(self, packet, rules):
        self.packet_bytes = bytearray.fromhex(packet['frame_raw'][0])
        self.packet_length = packet['frame_raw'][2]
        self.protocol_fields = {}
        self.packet_header = self.parse_packet_header(packet['frame'])

        for rule in rules:
            parsed_field = self.__get_packet_field(packet, rule.field_path)
            if parsed_field is not None:
                self.protocol_fields[rule.field] = parsed_field

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
                             + int(origin_size).to_bytes(4, sys.byteorder))

    def __get_packet_field(self, packet, field_path) -> Union[PacketField, None]:
        last_index, last_layer = self.__get_attribute_layer(packet, field_path)
        if last_layer is None:
            return None
        remaining_field_path = field_path[last_index + 1::]
        field = packet[last_layer]
        if type(field) is str:
            print("SEGMENTED PACKET")
            return None
        field_prefix = last_layer
        for path in remaining_field_path:
            if type(field) is list:
                print('What mate', field_prefix)
                return None
            prefixed_field_path = f'{field_prefix}.{path}'
            if prefixed_field_path not in field:
                # print(f'Not found {prefixed_field_path} in {field}')
                return None
            field = field[prefixed_field_path]
            field_prefix = prefixed_field_path
        packet_field = PacketField(field)
        if packet_field.is_invalid():
            return None
        return PacketField(field)

    def __get_attribute_layer(self, packet, layer_path):
        last_layer = None
        for i, path in enumerate(layer_path):
            if path not in packet:
                return i - 1, last_layer
            last_layer = path

    def modify_packet_field(self, field: PacketField, value):
        # TODO: add mask fields (IP verze apod)
        for byte_count in range(field.length):
            self.packet_bytes[field.position + byte_count] &= 0
        for byte_count in range(field.length):
            self.packet_bytes[field.position + byte_count] |= value[byte_count]

    def get_packet_field(self, field_name):
        try:
            return self.protocol_fields.get(field_name)
        except AttributeError:
            return None

    def get_packet_bytes(self):
        return self.packet_header + self.packet_bytes
