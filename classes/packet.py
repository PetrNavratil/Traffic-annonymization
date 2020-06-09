from typing import Union, List, Dict
from copy import deepcopy

from classes.packet_field import PacketField


class Packet:

    def __init__(self, packet, rules, index, search_all_protocols, byteorder):
        self.index = index
        self.packet_bytes = bytearray.fromhex(packet['frame_raw'][0])
        self.packet_length = int(packet['frame_raw'][2])
        self.protocol_fields = {}
        self.packet_header = self.parse_packet_header(packet['frame'], byteorder)
        self.protocols = list(filter(lambda key: not key.endswith('_raw') and type(packet[key]) is not str, packet.keys()))
        self.is_tcp = 'tcp' in packet
        self.is_udp = 'udp' in packet
        self.udp_stream = self.__get_udp_stream(packet)
        self.is_segmented = 'tcp.segments' in packet
        self.tcp_field = self.__get_tcp_field(packet)
        self.tcp_segment_indexes = self.__get_tcp_segment_indexes(packet)
        self.tcp_segment_locations = self.__get_tcp_segments_location(packet)
        self.tcp_reassembled_data = self.__get_tcp_reassembled_data(packet)
        self.tcp_retransmission = self.__get_tcp_retransmission(packet)
        self.tcp_lost = self.__get_tcp_lost(packet)
        self.tcp_stream = self.__get_tcp_stream(packet)
        self.tcp_seq = self.__get_tcp_sequence(packet)
        self.tcp_next_seq = self.__get_tcp_next_sequence(packet)
        self.tcp_payload_field = self.__get_tcp_payload_field(packet)
        self.tcp_has_segment = self.__get_tcp_has_segment(packet)
        self.tcp_segment_fields = self.__get_tcp_segment_field(packet)
        self.last_protocol = self.__get_last_protocol_from_frame(packet)
        self.last_protocol_parsed = self.last_protocol in self.protocols and self.last_protocol != 'tcp'
        self.tcp_segments_clear_fields = self.__get_tcp_segment_clear_fields(packet)

        for rule in rules:
            parsed_fields = self.__get_packet_fields(packet, rule.field_path, search_all=search_all_protocols)
            if parsed_fields is not None:
                if self.is_segmented:
                    for field in parsed_fields:
                        field.validate_segmented_field(packet)
                self.protocol_fields[rule.field] = parsed_fields

    def parse_packet_header(self, frame, byteorder):
        time_epoch = frame['frame.time_epoch'].split('.')
        timestamp = time_epoch[0]
        timestamp_microseconds = time_epoch[1].rstrip('0')
        if timestamp_microseconds == '':
            timestamp_microseconds = '0'
        origin_size = frame['frame.cap_len']
        current_size = frame['frame.len']
        return bytearray((int(timestamp).to_bytes(4, byteorder) \
                             + int(timestamp_microseconds).to_bytes(4, byteorder, signed=True) \
                             + int(current_size).to_bytes(4, byteorder) \
                             + int(origin_size).to_bytes(4, byteorder)))

    def __get_tcp_field(self, packet):
        if self.is_tcp:
            tcp_field = self.__get_packet_fields(packet, ['tcp_raw'], allow_wildcard=False)
            if tcp_field is not None:
                return tcp_field[0]
        return None

    def __get_tcp_segment_indexes(self, packet):
        if self.is_segmented:
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

    def __get_udp_stream(self, packet):
        if self.is_udp:
            if 'udp.stream' in packet['udp']:
                print( packet['udp']['udp.stream'])
                return packet['udp']['udp.stream']
            return None
        return None

    def __get_tcp_sequence(self, packet):
        if self.is_tcp:
            if 'tcp.seq' in packet['tcp']:
                return packet['tcp']['tcp.seq']
            return None
        return None

    def __get_tcp_next_sequence(self, packet):
        if self.is_tcp:
            if 'tcp.nxtseq' in packet['tcp']:
                return packet['tcp']['tcp.nxtseq']
            return None
        return None

    def __get_tcp_payload_field(self, packet):
        if self.is_tcp:
            tcp_payload_fields = self.__get_packet_fields(packet, ['tcp', 'payload_raw'], allow_wildcard=False)
            if tcp_payload_fields is not None:
                return tcp_payload_fields[0]
            return None
        return None

    def __get_tcp_segment_field(self, packet):
        if self.tcp_has_segment:
            tcp_segment_fields = self.__get_packet_fields(packet, ['tcp', 'segment_data_raw'], allow_wildcard=False)
            if tcp_segment_fields is not None:
                return tcp_segment_fields
            return None
        return None

    def __get_tcp_segment_clear_fields(self, packet):
        if self.tcp_retransmission:
            return []
        if self.tcp_has_segment:
            fields = [deepcopy(item) for item in self.tcp_segment_fields]
            # definitely end
            if len(self.tcp_segment_fields) == 1:
                if self.tcp_segment_fields[0].position != self.tcp_payload_field.position:
                    return fields
                # can be start but also whole packet
                else:
                    if self.last_protocol_parsed:
                        last_protocol_field = self.__get_last_protocol_field(packet)
                        if last_protocol_field is not None:
                            fields[0].length = last_protocol_field.position - self.tcp_segment_fields[0].position
                            return fields
                        else:
                        # objekt obsahuje pouze slouceny protokol, tudiz, musel byt pouzity cely segmnent, jinak by se to chytlo uz nahore
                            return []
                    #     nothing but TCP - only payload - segment is all over payload
                    else:
                        return self.tcp_segment_fields.copy()
            else:
                fields = self.tcp_segment_fields.copy()
                last_protocol_field = self.__get_last_protocol_field(packet)
                if last_protocol_field is not None:
                    fields[0].length = last_protocol_field.position - self.tcp_segment_fields[0].position
                    return fields
                else:
                    # objekt obsahuje pouze slouceny protokol, tudiz, musel byt pouzity cely segmnent, jinak by se to chytlo uz nahore
                    # tshark does whatever tshark wants
                    return []
        return []

    def __get_last_protocol_field(self, packet):
        last_protocols = packet[f'{self.last_protocol}_raw']
        if type(last_protocols[0]) is list:
            for f in last_protocols:
                field = PacketField(f)
                if field.position != 0:
                    return field
            return None
        field = PacketField(last_protocols)
        if field.position != 0:
            return field
        return None

    def __get_tcp_has_segment(self, packet):
        if self.is_tcp:
            return 'tcp.segment_data' in packet['tcp']
        return False

    def __get_last_protocol_from_frame(self, packet):
        protocols = packet['frame']['frame.protocols'].split(':')
        if 'tcp' not in protocols:
            return 'tcp'
        tcp_index = protocols.index('tcp')
        if tcp_index + 1 == len(protocols):
            return 'tcp'
        return protocols[tcp_index + 1]

    def __get_packet_fields(self, packet, field_path, allow_wildcard=True, search_all=False) -> Union[List[PacketField], None]:
        if '.'.join(field_path) == PacketField.FRAME_TIME_PATH:
            return [PacketField([None, 0, 8, 0, 0], PacketField.FRAME_TIME_PATH)]
        if len(field_path) == 1:
            if field_path[0] in packet:
                return [PacketField(packet[field_path[0]], field_path[0], field_path)]
            return None
        if search_all:
            fields = []
            for protocol in self.protocols:
                remaining_path_modifier = 1 if protocol == field_path[0] else 0
                result = self.__find_nested_field(packet[protocol], field_path[0], field_path[remaining_path_modifier:], [protocol], not allow_wildcard)
                if result is not None:
                    fields.extend(result)
            if len(fields) == 0:
                return None
            return fields
        else:
            if field_path[0] not in self.protocols:
                return None
            remaining_field_path = field_path[1::]
            field = packet[field_path[0]]
            if type(field) is str:
                return None
            field_prefix = field_path[0]
            json_path = [field_path[0]]
            return self.__find_nested_field(field,field_prefix, remaining_field_path, json_path, not allow_wildcard)

    def __find_nested_field(self, field, prefix_path, remaining_path, json_path, wild_card_used) -> Union[List[PacketField], None]:
        field_prefix = prefix_path
        for i, path in enumerate(remaining_path):
            if type(field) is str:
                return None
            if type(field) is int:
                return None
            if type(field) is list:
                found_fields = []
                for j, f in enumerate(field):
                    json_path_update = json_path.copy()
                    json_path_update.append(j)
                    resolved_field = self.__find_nested_field(f, field_prefix,remaining_path[i:], json_path_update, wild_card_used)
                    if resolved_field is None:
                        continue
                    found_fields.extend(resolved_field)
                if len(found_fields) == 0:
                    return None
                return found_fields
            prefixed_field_path = f'{field_prefix}.{path}'
            prefixed_full_field_path = f'{field_prefix}.{".".join(remaining_path[i:])}'
            if prefixed_full_field_path in field:
                if type(field[prefixed_full_field_path]) is list:
                    # field is array and no search is needed as its full_field_path_match
                    if type(field[prefixed_full_field_path][0]) is list:
                        resolved_fields = []
                        for j, f in enumerate(field[prefixed_full_field_path]):
                            resolved_fields.append(PacketField(f, prefixed_full_field_path, json_path))
                        if len(resolved_fields) == 0:
                            return None
                        return resolved_fields
                    return [PacketField(field[prefixed_full_field_path], prefixed_full_field_path, json_path)]
                # it has to be list with field info
                return None
            # validate that you can continue in path
            # can be in the middle of path but matching
            # final path would match above
            if prefixed_field_path in field and (type(field[prefixed_field_path]) in [list, dict]):
                field = field[prefixed_field_path]
                field_prefix = prefixed_field_path
                json_path.append(field_prefix)
            else:
                if not wild_card_used:
                    found_fields = []
                    for k, f in field.items():
                        json_path_update = json_path.copy()
                        json_path_update.append(k)
                        prefix, _, tail = prefixed_field_path.rpartition('.')
                        cut_index = remaining_path.index(tail) if tail in remaining_path else 0
                        resolved_field = self.__find_nested_field(f, prefix, remaining_path[cut_index:], json_path_update, False)
                        if resolved_field is None:
                            continue
                        found_fields.extend(resolved_field)
                    if len(found_fields) == 0:
                        return None
                    return found_fields
                return None
        return None

    def modify_packet(self, field: PacketField, value, packet_bytes):
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

    def get_field_possible_segments(self, field: PacketField):
        for j, packet_index in enumerate(self.tcp_segment_indexes):
            segment_info = self.tcp_segment_locations[packet_index]
            if field.position >= segment_info.position and field.position < segment_info.position + segment_info.length:
                return self.tcp_segment_indexes[j:]
