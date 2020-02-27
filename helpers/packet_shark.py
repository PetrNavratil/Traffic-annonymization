import sys
from typing import Union, List

from helpers.packet_field import PacketField


class SharkPacket:

    def __init__(self, packet, rules):
        self.packet_bytes = bytearray.fromhex(packet['frame_raw'][0])
        self.packet_length = packet['frame_raw'][2]
        self.protocol_fields = {}
        self.packet_header = self.parse_packet_header(packet['frame'])
        self.protocols = list(filter(lambda key: not key.endswith('_raw') and  type(packet[key]) is dict, packet.keys()))

        for rule in rules:
            parsed_fields = self.__get_packet_fields(packet, rule.field_path)
            if parsed_fields is not None:
                self.protocol_fields[rule.field] = parsed_fields

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

    # def __get_packet_field(self, packet, field_path) -> Union[PacketField, None]:
    #     last_index, last_layer = self.__get_attribute_layer(field_path)
    #     if last_layer is None:
    #         return None
    #     remaining_field_path = field_path[last_index + 1::]
    #     field = packet[last_layer]
    #     if type(field) is str:
    #         print("SEGMENTED PACKET")
    #         return None
    #     field_prefix = last_layer
    #     print('last layer', last_layer)
    #     for path in remaining_field_path:
    #         if type(field) is list:
    #             print('What mate', field_prefix)
    #             return None
    #         prefixed_field_path = f'{field_prefix}.{path}'
    #         if prefixed_field_path not in field:
    #             print('prefixed_field_path', prefixed_field_path, field)
    #             # print(f'Not found {prefixed_field_path} in {field}')
    #             return None
    #         field = field[prefixed_field_path]
    #         field_prefix = prefixed_field_path
    #     packet_field = PacketField(field)
    #     if packet_field.is_invalid():
    #         return None
    #     return PacketField(field)

    def __get_packet_fields(self, packet, field_path) -> Union[List[PacketField], None]:
        if field_path[0] not in self.protocols:
            return None
        remaining_field_path = field_path[1::]
        field = packet[field_path[0]]
        if type(field) is str:
            print("SEGMENTED PACKET")
            return None
        field_prefix = field_path[0]
        return self.__find_nested_field(field,field_prefix, remaining_field_path)

    def __find_nested_field(self, field, prefix_path, remaining_path) -> Union[List[PacketField], None]:
        field_prefix = prefix_path
        for i, path in enumerate(remaining_path):
            if type(field) is str:
                print('String field', field)
                return None
            if type(field) is list:
                found_fields = []
                for f in field:
                    resolved_field = self.__find_nested_field(f, field_prefix,remaining_path[i:])
                    if resolved_field is None:
                        continue
                    found_fields.extend(resolved_field)
                return found_fields
            prefixed_field_path = f'{field_prefix}.{path}'
            prefixed_full_field_path = f'{field_prefix}.{".".join(remaining_path[i:])}'
            if prefixed_full_field_path in field:
                return [PacketField(field[prefixed_full_field_path])]
            if prefixed_field_path not in field:
                return None
            field = field[prefixed_field_path]
            field_prefix = prefixed_field_path
        return None

    def __get_attribute_layer(self, layer_path):
        last_layer = None
        available_protocols = self.protocols.copy()
        for i, path in enumerate(layer_path):
            if path not in available_protocols:
                return i - 1, last_layer
            available_protocols.remove(path)
            last_layer = path

    def modify_packet_field(self, field: PacketField, value):
        if field.has_mask():
            self.packet_bytes[field.position] &= field.get_complementary_mask()
            shifted_value = value[0] << field.shift_count()
            self.packet_bytes[field.position] |= shifted_value
            return
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
