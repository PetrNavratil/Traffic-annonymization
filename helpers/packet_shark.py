import sys
from typing import Union, List, Dict

from helpers.packet_field import PacketField


class SharkPacket:

    def __init__(self, packet, rules, index):
        self.index = index
        self.packet_bytes = bytearray.fromhex(packet['frame_raw'][0])
        self.packet_length = int(packet['frame_raw'][2])
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
        self.tcp_seq = self.__get_tcp_sequence(packet)
        self.tcp_next_seq = self.__get_tcp_next_sequence(packet)
        self.tcp_payload_field = self.__get_tcp_payload_field(packet)
        self.tcp_has_segment = self.__get_tcp_has_segment(packet)
        self.tcp_segment_field = self.__get_tcp_segment_field(packet)
        self.last_protocol_from_frame = self.__get_last_protocol_from_frame(packet)
        self.last_protocol = self.__get_last_protocol_from_frame(packet)
        self.last_protocol_parsed = self.last_protocol in self.protocols and self.last_protocol != 'tcp'
        self.tcp_segment_clear_length = self.__get_tcp_segment_clear_length(packet)
        self.unknown_tcp = self.tcp_payload_field is not None and self.last_protocol_parsed

        if self.is_tcp:
            print(self.index, 'has segment', self.tcp_has_segment)
            print(self.index, 'last protocol parsed', self.last_protocol_parsed)
            print(self.index, 'segments clear length', self.tcp_segment_clear_length)
            # TODO: comment and do better
            if self.tcp_segment_field:
                print(self.index, self.tcp_segment_clear_length)
                self.tcp_segment_field.length = self.tcp_segment_clear_length

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
        return bytearray((int(timestamp).to_bytes(4, sys.byteorder) \
                             + int(timestamp_microseconds).to_bytes(4, sys.byteorder, signed=True) \
                             + int(current_size).to_bytes(4, sys.byteorder) \
                             + int(origin_size).to_bytes(4, sys.byteorder)))

    def __get_tcp_segment_indexes(self, packet):
        if self.is_segmented:
            print('PACKET INDEX', self.index, 'segments', packet['tcp.segments']['tcp.segment'])
            return [int(item) for item in packet['tcp.segments']['tcp.segment']]
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
            for path in ['tcp.analysis', 'tcp.analysis.flags', '_ws.expert']:
                if path not in tcp_analysis:
                    return False
                tcp_analysis = tcp_analysis[path]

            if type(tcp_analysis) is list:
                for info in tcp_analysis:
                    if 'tcp.analysis.retransmission' in info:
                        return True
                return False
            return 'tcp.analysis.retransmission' in tcp_analysis
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

    def __get_tcp_sequence(self, packet):
        if self.is_tcp:
            if 'tcp.seq' in packet['tcp']:
                return packet['tcp']['tcp.seq']
            return None
        return None

    # TODO: ask MARTIN about finding same packet
    def __get_tcp_next_sequence(self, packet):
        if self.is_tcp:
            if 'tcp.nxtseq' in packet['tcp']:
                return packet['tcp']['tcp.nxtseq']
            return None
        return None

    def __get_tcp_payload_field(self, packet):
        if self.is_tcp:
            tcp_payload_fields = self.__get_packet_fields(packet, ['tcp', 'payload_raw'])
            if tcp_payload_fields is not None:
                return tcp_payload_fields[0]
            return None
        return None

    def __get_tcp_segment_field(self, packet):
        if self.tcp_has_segment:
            tcp_segment_fields = self.__get_packet_fields(packet, ['tcp', 'segment_data_raw'])
            if tcp_segment_fields is not None:
                return tcp_segment_fields[0]
            return None
        return None

    def __get_tcp_segment_ends_packet(self):
        if self.tcp_has_segment:
            print('segment', self.tcp_segment_field.position, 'payload',  self.tcp_payload_field.position)
            return self.tcp_segment_field.position != self.tcp_payload_field.position
        # better delete end of packet
        return True

    def __get_tcp_segment_clear_length(self, packet):
        if self.tcp_has_segment:
            # definitely end
            if self.tcp_segment_field.position != self.tcp_payload_field.position:
                print('DEFINITELY END')
                return self.tcp_segment_field.length
            # can be start but also whole packet
            else:
                if self.last_protocol_parsed:
                    last_protocols = packet[f'{self.last_protocol}_raw']
                    # get first last protocol parsed
                    if type(last_protocols[0]) is list:
                        field = PacketField(last_protocols[0])
                        # TODO: NENI DORESENE, SPATNE TO PARSUJE PRVNI POSLEDNI
                        print('heeer', field.position, self.tcp_segment_field.position)
                        return field.position - self.tcp_segment_field.position
                    field = PacketField(last_protocols)
                    return field.position - self.tcp_segment_field.position
                #     nothing but TCP - only payload - segment is all over payload
                else:
                    return self.tcp_segment_field.length
        return 0

    def __get_tcp_has_segment(self, packet):
        if self.is_tcp:
            return 'tcp.segment_data' in packet['tcp']
        return False

    def __get_last_protocol_from_frame(self, packet):
        return packet['frame']['frame.protocols'].split(':')[-1]

    def __has_segmented_field_modifications(self):
        for protocol_field in self.protocol_fields.values():
            for field in protocol_field:
                if field.is_segmented:
                    return True
        return False

    def __get_packet_fields(self, packet, field_path) -> Union[List[PacketField], None]:
        if '.'.join(field_path) == PacketField.FRAME_TIME_PATH:
            return [PacketField([None, 0, 8, 0, 0], PacketField.FRAME_TIME_PATH)]
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
                if type(field[prefixed_full_field_path]) is list:
                    # field is array and no search is needed as its full_field_path_match
                    if type(field[prefixed_full_field_path][0]) is list:
                        print("LIST")
                        resolved_fields = []
                        for j, f in enumerate(field[prefixed_full_field_path]):
                            resolved_fields.append(PacketField(f, prefixed_full_field_path, json_path))
                        return resolved_fields
                    return [PacketField(field[prefixed_full_field_path], prefixed_full_field_path, json_path)]
                # it has to be list with field info
                return None
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

    def get_field_possible_segments(self, field: PacketField):
        for j, packet_index in enumerate(self.tcp_segment_indexes):
            segment_info = self.tcp_segment_locations[packet_index]
            if field.position >= segment_info.position and field.position < segment_info.position + segment_info.length:
                return self.tcp_segment_indexes[j:]
