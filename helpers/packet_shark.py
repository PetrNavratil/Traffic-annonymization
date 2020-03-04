import sys
from typing import Union, List, Dict

from helpers.packet_field import PacketField


class SharkPacket:

    def __init__(self, packet, rules):
        self.packet_bytes = bytearray.fromhex(packet['frame_raw'][0])
        self.packet_length = packet['frame_raw'][2]
        self.protocol_fields = {}
        self.packet_header = self.parse_packet_header(packet['frame'])
        self.protocols = list(filter(lambda key: not key.endswith('_raw') and type(packet[key]) is not str, packet.keys()))
        self.is_tcp = 'tcp' in packet
        self.is_segmented = 'tcp.segments' in packet
        self.tcp_segment_indexes = self.__get_tcp_segment_indexes(packet)
        self.tcp_segment_locations = self.__get_tcp_segments_location(packet)
        self.tcp_reassembled_data = self.__get_tcp_reassembled_data(packet)
        self.tcp_payload_length = self.__get_tcp_payload_length(packet)
        self.tcp_retransmission = self.__get_tcp_retransmission(packet)
        self.tcp_lost = self.__get_tcp_lost(packet)
        self.tcp_stream = self.__get_tcp_stream(packet)
        # print(self.tcp_stream)

        for rule in rules:
            parsed_fields = self.__get_packet_fields(packet, rule.field_path)
            if parsed_fields is not None:
                if self.is_segmented:
                    for field in parsed_fields:
                        field.validate_segmented_field(packet)
                self.protocol_fields[rule.field] = parsed_fields

        self.has_segmented_field_modifications = self.__has_segmented_field_modifications()

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

    def __get_tcp_segment_indexes(self, packet):
        if self.is_segmented:
            return packet['tcp.segments']['tcp.segment']
        return None

    def __get_tcp_segments_location(self, packet) -> Union[Dict[int, PacketField], None]:
        if self.is_segmented:
            locations = {}
            for i, packet_index in enumerate(self.tcp_segment_indexes):
                locations[int(packet_index)] = PacketField(packet['tcp.segments']['tcp.segment_raw'][i])
            return locations
        return None

    def __get_tcp_reassembled_data(self, packet):
        if self.is_segmented:
            return bytearray.fromhex(packet['tcp.segments']['tcp.reassembled.data_raw'][0])
        return None

    def __get_tcp_payload_length(self, packet):
        if self.is_segmented:
            return PacketField(packet['tcp']['tcp.payload_raw']).length
        return None

    def __get_tcp_retransmission(self, packet):
        if self.is_tcp:
            tcp_analysis = packet['tcp']
            for path in ['tcp.analysis', 'tcp.analysis.flags', '_ws.expert', 'tcp.analysis.retransmission']:
                if path not in tcp_analysis:
                    return False
                tcp_analysis = tcp_analysis[path]
            return True
        return False

    def __get_tcp_lost(self, packet):
        if self.is_tcp:
            tcp_analysis = packet['tcp']
            for path in ['tcp.analysis', 'tcp.analysis.flags', '_ws.expert', 'tcp.analysis.lost_segment']:
                if path not in tcp_analysis:
                    return False
                tcp_analysis = tcp_analysis[path]
            return True
        return False

    def __get_tcp_stream(self, packet):
        if self.is_tcp:
            if 'tcp.stream' in packet['tcp']:
                return packet['tcp']['tcp.stream']
            return None
        return None

    def __has_segmented_field_modifications(self):
        for protocol_field in self.protocol_fields.values():
            for field in protocol_field:
                if field.is_segmented:
                    return True
        return False

    def __get_packet_fields(self, packet, field_path) -> Union[List[PacketField], None]:
        if field_path[0] not in self.protocols:
            return None
        remaining_field_path = field_path[1::]
        field = packet[field_path[0]]
        if type(field) is str:
            print("SEGMENTED PACKET")
            return None
        field_prefix = field_path[0]
        json_path = [field_path[0]]
        return self.__find_nested_field(field,field_prefix, remaining_field_path, json_path)

    def __find_nested_field(self, field, prefix_path, remaining_path, json_path) -> Union[List[PacketField], None]:
        field_prefix = prefix_path
        for i, path in enumerate(remaining_path):
            if type(field) is str:
                print('String field', field, remaining_path)
                return None
            if type(field) is list:
                # print('NESTED', field)
                found_fields = []
                for j, f in enumerate(field):
                    json_path_update = json_path.copy()
                    json_path_update.append(j)
                    resolved_field = self.__find_nested_field(f, field_prefix,remaining_path[i:], json_path_update)
                    if resolved_field is None:
                        continue
                    found_fields.extend(resolved_field)
                return found_fields
            prefixed_field_path = f'{field_prefix}.{path}'
            prefixed_full_field_path = f'{field_prefix}.{".".join(remaining_path[i:])}'
            if prefixed_full_field_path in field:
                return [PacketField(field[prefixed_full_field_path], prefixed_full_field_path, json_path)]
            if prefixed_field_path not in field:
                return None
            field = field[prefixed_field_path]
            field_prefix = prefixed_field_path
            json_path.append(field_prefix)
        return None

    def __get_attribute_layer(self, layer_path):
        last_layer = None
        available_protocols = self.protocols.copy()
        for i, path in enumerate(layer_path):
            if path not in available_protocols:
                return i - 1, last_layer
            available_protocols.remove(path)
            last_layer = path

    def modify_packet_field(self, field: PacketField, value, packet_bytes):
        if field.has_mask():
            packet_bytes[field.position] &= field.get_complementary_mask()
            shifted_value = value[0] << field.shift_count()
            packet_bytes[field.position] |= shifted_value
            return
        for byte_count in range(field.length):
            packet_bytes[field.position + byte_count] &= 0

        # field is 2B but value can fit to 1B but cant exceed original length
        write_size = min(len(value), field.length)
        for byte_count in range(write_size):
            packet_bytes[field.position + byte_count] |= value[byte_count]


    def get_packet_field(self, field_name):
        try:
            return self.protocol_fields.get(field_name)
        except AttributeError:
            return None

    def get_packet_bytes(self):
        return self.packet_header + self.packet_bytes
