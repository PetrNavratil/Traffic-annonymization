"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
import json
from typing import List, Dict

from helpers.helpers import load_modifier_class, modifier_class_name
from classes.field_modification import FieldModification
from classes.packet_field import PacketField
from classes.packet_modification import PacketModification
from classes.packet import Packet
from classes.pool import SharedPool
from classes.rule import Rule
from classes.tshark_adapter import TsharkAdapter
from enums.tcp_stream_enum import TcpStream


class ModifierController:

    def __init__(self, rules, adapter: TsharkAdapter, tcp_stream_strategy, reset_pools, generate_meta_files, search_all_protocols):
        self.rules = rules
        self.modifiers = {}
        self.pools: Dict[str, SharedPool] = {}
        self.parsed_rules = self.__prepare_rules(rules)
        self.adapter = adapter
        self.packets: Dict[int, PacketModification] = {}
        self.position = TsharkAdapter.PCAP_GLOBAL_HEADER + TsharkAdapter.PCAP_PACKET_HEADER
        self.streams = {}
        self.tcp_stream_strategy = tcp_stream_strategy
        self.reset_pools = reset_pools
        self.generate_meta_files = generate_meta_files
        self.search_all_protocols = search_all_protocols

    def reset_file_information(self):
        if self.reset_pools:
            for pool in self.pools.values():
                pool.reset_pool()
        self.packets = {}
        self.streams = {}
        self.position = TsharkAdapter.PCAP_GLOBAL_HEADER + TsharkAdapter.PCAP_PACKET_HEADER

    def modify_files(self):
        while self.adapter.open_next_file():
            print(f'Modification of {self.adapter.file_name}')
            self.reset_file_information()
            packets = self.adapter.get_packets()
            file_info = self.adapter.get_file_additional_info()
            for j, a in enumerate(packets):
                shark_packet = Packet(a, self.parsed_rules, j + 1, self.search_all_protocols, self.adapter.endianness)
                if shark_packet.is_tcp:
                    if shark_packet.tcp_stream not in self.streams:
                        self.streams[shark_packet.tcp_stream] = {
                            'valid': True,
                            'packets': []
                        }
                    self.streams[shark_packet.tcp_stream]['packets'].append({'index': shark_packet.index, 'seq':shark_packet.tcp_seq, 'next_seq': shark_packet.tcp_next_seq})
                    if shark_packet.tcp_lost:
                        self.streams[shark_packet.tcp_stream]['valid'] = False
                self.packets[j+1] = PacketModification(
                    j+1,
                    self.position,
                    shark_packet.packet_length,
                    shark_packet.tcp_payload_field,
                    shark_packet.last_protocol_parsed,
                    shark_packet.tcp_has_segment,
                    shark_packet.tcp_segment_fields,
                    shark_packet.tcp_segments_clear_fields,
                    shark_packet.tcp_field
                )
                self.position += shark_packet.packet_length + TsharkAdapter.PCAP_PACKET_HEADER
                self.run_packet_modifiers(shark_packet, self.packets[j+1], {**file_info, 'packet_index': shark_packet.index})
                if shark_packet.tcp_retransmission:
                    duplicate_packet_index = self.find_retransmission_packet(shark_packet.tcp_stream, shark_packet.index, shark_packet.tcp_seq, shark_packet.tcp_next_seq)
                    self.packets[j+1].packet_origin = duplicate_packet_index
                    self.packets[j+1].remove_all_modifications_after_tcp()
                    continue

                # validate packet segments
                if shark_packet.tcp_segment_indexes:
                    for packet_index in shark_packet.tcp_segment_indexes:
                        segment_info = shark_packet.tcp_segment_locations[packet_index]
                        self.packets[packet_index].validate_segments(segment_info.length)
            print("End of modification")
            print("Validating TCP stream")
            self.validate_tcp_streams()
            print("Copying files")
            self.adapter.copy_file()
            self.adapter.open_output_file()
            print("Writing changes")
            for key in sorted(self.packets):
                modifying_packet: PacketModification = self.packets[key]
                modifying_packet.sort_modification()
                for modification in modifying_packet.modifications:
                    packet_start = modifying_packet.packet_start \
                        if not modification.frame_modification \
                        else modifying_packet.packet_start - TsharkAdapter.PCAP_PACKET_HEADER
                    offset = packet_start + modification.position
                    self.adapter.write_field_data(modification.data, offset)
            print("Writing changes ended")
            if self.reset_pools and self.generate_meta_files:
                self.write_pool_to_file(self.adapter.metadata_file_name)
        if self.generate_meta_files and not self.reset_pools:
            self.write_pool_to_file(self.adapter.general_metadata_file_name)

    def find_retransmission_packet(self, stream_index, packet_index, sequence, next_sequence):
        if stream_index not in self.streams:
            return None
        for info in self.streams[stream_index]['packets']:
            if info['seq'] == sequence and info['next_seq'] == next_sequence and info['index'] != packet_index:
                return info['index']
        return None

    def validate_tcp_streams(self):
        invalid_streams_packets = [packet['index'] for item in self.streams.items() if item[1]['valid'] is False for packet in item[1]['packets']] \
            if self.tcp_stream_strategy == TcpStream.CLEAR.value else \
            []

        for packet in self.packets.values():
            if packet.packet_origin is not None:
                origin_packet = self.packets[packet.packet_origin]
                modifications = origin_packet.get_tcp_and_after_tcp_modifications()
                packet.append_modifications(modifications)
            if self.tcp_stream_strategy == TcpStream.NONE.value:
                continue

            if self.tcp_stream_strategy == TcpStream.CLEAR.value and packet.packet_index in invalid_streams_packets:
                packet.remove_all_modifications_after_tcp()
                packet.add_tcp_payload_clear_modification()
            else:
                if packet.tcp_clear_segments:
                    packet.add_tcp_segments_clear_modifications()
                if packet.tcp_unknown:
                    packet.remove_all_modifications_after_tcp()
                    packet.add_tcp_payload_clear_modification()

    def run_packet_modifiers(self, packet: Packet, packet_modification: PacketModification, file_info):
        for rule in self.parsed_rules:
            fields = packet.get_packet_field(rule.field)
            if fields is None:
                continue
            for i, field in enumerate(fields):
                # CHOOSE PACKET DATA OR REASSEMBLED DATA
                packet_bytes = self.__get_bytes_for_modification(packet, field)
                value = field.get_field_value(packet_bytes)
                modified_value = rule.run_rule(value, packet.udp_stream, packet.tcp_stream, file_info)
                # not modified, skip its field modification
                if modified_value is None:
                    continue
                field_modification = FieldModification(modified_value, field, rule.order)
                # mask return value with current value and retrieve write value
                # this is done so no read is performed while writing values to the output file
                packet.modify_packet(field, modified_value, packet_bytes)
                if field.has_mask():
                    modified_value = field.get_unmasked_field(packet_bytes)
                    field_modification.set_value(modified_value)
                # field is segmented - need to determine, where to write it (segment data and packet)
                if field.is_segmented:
                    possible_segments = packet.get_field_possible_segments(field)
                    field_remaining_length = field.length
                    for j, packet_index in enumerate(possible_segments):
                        if field_remaining_length == 0:
                            break
                        segment_info = packet.tcp_segment_locations[packet_index]
                        segment_position = field.position - segment_info.position if j == 0 else 0
                        modified_packet = self.packets[packet_index]
                        tcp_start = self.get_tcp_segment_start(packet.index, modified_packet, segment_info.length)
                        new_offset = tcp_start + segment_position
                        write_length = min(segment_info.length - segment_position, field_remaining_length)
                        mod = self.create_tcp_segment_field_modification(modified_value, field_remaining_length, write_length, new_offset, field)
                        modified_packet.add_modification(mod)
                        field_remaining_length -= write_length
                else:
                    packet_modification.add_modification(field_modification)

    def __get_bytes_for_modification(self, packet: Packet, field: PacketField) -> bytearray:
        if field.frame_field:
            return packet.packet_header
        if field.is_segmented:
            return packet.tcp_reassembled_data
        return packet.packet_bytes

    def __prepare_rules(self, rules) -> List[Rule]:
        parsed_rules = []
        for i, rule in enumerate(rules):
            pool, new_pool = self.__get_pool(rule, i)
            field = rule['field']
            if new_pool:
                modifier = self.__get_modifier(rule['modifier'])
                self.modifiers[pool.used_by] = modifier
                pool.set_transform_method(modifier.transform_output_value)
            parsed_rules.append(
                Rule(field, rule, self.modifiers[pool.used_by], pool, i))
        return parsed_rules

    def __get_pool(self, rule, order):
        field = rule['field']
        value_group = 'value_group' in rule
        pool_key = rule['value_group'] if value_group else field
        class_name = rule['modifier']
        if pool_key in self.pools:
            if value_group:
                assert class_name == self.pools[pool_key].class_name, f"Modifier name must match for shared `value_group`, {pool_key}"
                return self.pools[pool_key], False
            else:
                new_key = f'{pool_key}_{order}'
                self.pools[new_key] = SharedPool(new_key, class_name)
                return self.pools[new_key], True
        else:
            self.pools[pool_key] = SharedPool(pool_key, class_name)
            return self.pools[pool_key], True

    def __get_modifier(self, class_name):
        return load_modifier_class(modifier_class_name(class_name))()

    def pools_dump(self):
        pool_info = {}
        for pool in self.pools.items():
            pool[1].transform(Rule.STREAM_KEY_DELIMITER)
            pool_info.update([(
                pool[0],
                {
                    'meta': self.modifiers[pool[0]].meta,
                    'values': pool[1].pool
                }
            )])
        return pool_info

    def write_pool_to_file(self, file_name):
        with open(file_name, 'w') as f:
            json.dump(self.pools_dump(), f)

    def get_tcp_segment_start(self, current_packet_index, modified_packet: PacketModification, segment_length):
        if current_packet_index == modified_packet.packet_index:
            return modified_packet.packet_length - modified_packet.tcp_payload_field.length
        else:
            return modified_packet.packet_length - segment_length

    def create_tcp_segment_field_modification(self, modified_value, remaining_length, write_length, position, field):
        modification_data = modified_value[-remaining_length:] \
            if remaining_length <= write_length \
            else modified_value[-remaining_length:-remaining_length+write_length]
        modification = FieldModification(modification_data, field, 1000)
        modification.set_position(position)
        return modification

