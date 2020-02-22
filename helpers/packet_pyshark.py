import sys
from typing import Union

from pyshark.packet.fields import LayerFieldsContainer
from pyshark.packet.layer import JsonLayer

from helpers.packet_field import PacketField


class PySharkPacket:

    def __init__(self, packet):
        self.packet = packet
        self.packet_bytes = bytearray(packet.get_raw_packet())

    def get_packet_field(self, field_path) -> Union[PacketField, None]:
        # try:
        last_index, last_layer = self.__get_attribute_layer(self.packet, field_path)
        if last_layer is None:
            return None
        remaining_field_path = field_path[last_index + 1::]
        field = self.packet[last_layer]
        for path in remaining_field_path:
            if type(field) is list:
                # print('What mate')
                return None
            # if path not in field.field_names:
            if not field.has_field(path):
                return None
            field = field.get_field(path)
        packet_field = PacketField(field)
        if packet_field.is_invalid():
            return None
        return PacketField(field)
        # except RuntimeError:
        #     return None

    def __get_attribute_layer(self, packet, layer_path):
        last_layer = None
        for i, path in enumerate(layer_path):
            if path not in packet:
                return i - 1, last_layer
            last_layer = path


    def __parse_packet_header(self):
        frame_info = self.packet.frame_info
        time_epoch = frame_info.get_field('time_epoch').split('.')
        timestamp = time_epoch[0]
        timestamp_microseconds = time_epoch[1].rstrip('0')
        origin_size = frame_info.get_field('cap_len')
        current_size = frame_info.get_field('len')
        return int(timestamp).to_bytes(4, sys.byteorder) \
                             + int(timestamp_microseconds).to_bytes(4, sys.byteorder, signed=True) \
                             + int(current_size).to_bytes(4, sys.byteorder) \
                             + int(origin_size).to_bytes(4, sys.byteorder)

    def modify_packet_field(self, field: PacketField, value):
        # TODO: add mask fields (IP verze apod)
        for byte_count in range(field.length):
            self.packet_bytes[field.position + byte_count] &= 0
        for byte_count in range(field.length):
            self.packet_bytes[field.position + byte_count] |= value[byte_count]

    def get_write_packet_data(self):
        return self.__parse_packet_header() + self.packet_bytes
