from typing import List

from helpers.modification import FieldModification


class PacketModification:

    BEFORE_TCP_PAYLOAD = ['eth', 'ip', 'tcp']

    def __init__(self, packet_index, packet_start, packet_length, tcp_payload_field):
        self.packet_index = packet_index
        self.modifications: List[FieldModification] = []
        self.packet_start = packet_start
        self.packet_length = packet_length
        self.tcp_payload_field = tcp_payload_field

    def add_modification(self, modification: FieldModification):
        self.modifications.append(modification)

    def append_modifications(self, modifications):
        self.modifications.extend(modifications.copy())

    def remove_modifications(self, key):
        self.modifications = [modification for modification in self.modifications if key not in modification.field.field_path]

    def remove_all_modifications_after_tcp(self):
        self.modifications = [modification for modification in self.modifications if
                              any(modification.field.field_path.startswith(before_application)
                                  for before_application in PacketModification.BEFORE_TCP_PAYLOAD)]

    def add_tcp_payload_clear_modification(self):
        # TCP packet does not need to have PAYLOAD -ACK packety atd
        if self.tcp_payload_field is not None:
            self.modifications.append(FieldModification(bytearray(self.tcp_payload_field.length), self.tcp_payload_field))


