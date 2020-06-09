from typing import List
import operator

from classes.field_modification import FieldModification


class PacketModification:

    BEFORE_TCP_PAYLOAD = ['frame', 'eth', 'ip', 'tcp']

    def __init__(self, packet_index, packet_start, packet_length, tcp_payload_field, last_protocol_parsed, has_tcp_segment, tcp_segment_field, tcp_clear_segments, tcp_field):
        self.packet_index = packet_index
        self.packet_origin = None
        self.modifications: List[FieldModification] = []
        self.packet_start = packet_start
        self.packet_length = packet_length
        self.tcp_payload_field = tcp_payload_field
        self.last_protocol_parsed = last_protocol_parsed
        self.has_tcp_segment = has_tcp_segment
        self.tcp_clear_segments = tcp_clear_segments
        self.tcp_segment_used = False
        self.tcp_segment_field = tcp_segment_field[0] if tcp_segment_field is not None else None
        self.tcp_unknown = self.tcp_payload_field is not None and not self.has_tcp_segment and not self.last_protocol_parsed
        self.tcp_field = tcp_field
        # if self.tcp_unknown:
        #     print('IN', packet_index, self.tcp_payload_field, self.has_tcp_segment, self.last_protocol_parsed)

    def add_modification(self, modification: FieldModification):
        self.modifications.append(modification)

    def append_modifications(self, modifications):
        self.modifications.extend(modifications.copy())

    def remove_modifications(self, key):
        self.modifications = [modification for modification in self.modifications if key not in modification.field.field_path]

    def remove_all_modifications_after_tcp(self):
        self.modifications = [modification for modification in self.modifications if
                              any(modification.field_path.startswith(before_application)
                                  for before_application in PacketModification.BEFORE_TCP_PAYLOAD)]

    def add_tcp_payload_clear_modification(self):
        # TCP packet does not need to have PAYLOAD -ACK packety atd
        if self.tcp_payload_field is not None:
            self.modifications.append(FieldModification(bytearray(self.tcp_payload_field.length), self.tcp_payload_field, 1000))

    def add_tcp_segment_clear_modification(self):
        if self.tcp_segment_field is not None:
            print(self.tcp_segment_field.length)
            self.modifications.append(
                FieldModification(bytearray(self.tcp_segment_field.length), self.tcp_segment_field, 1000))

    def add_tcp_segments_clear_modifications(self):
        for field in self.tcp_clear_segments:
                # print('field', field.length)
                self.modifications.append(
                    FieldModification(bytearray(field.length), field, 1000))

    def sort_modification(self):
        # print([(item.position, item.field_path) for item in self.modifications])
        s = sorted(self.modifications, key=operator.attrgetter('position', 'rule_order'))
        # print([(item.position, item.field_path) for item in s])
        self.modifications = s

    def get_tcp_and_after_tcp_modifications(self):
        return [modification for modification in self.modifications if modification.position >= self.tcp_field.position]

    def validate_segments(self, length):
        for segment in self.tcp_clear_segments:
            if length == segment.length:
                # print(self.tcp_unused_segments, [(item.length, item.position) for item in self.tcp_clear_segments], self.packet_index)
                # self.tcp_unused_segments.remove(i)
                self.tcp_clear_segments.remove(segment)
                break