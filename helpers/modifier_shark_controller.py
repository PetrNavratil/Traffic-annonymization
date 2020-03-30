import json
import sys
from typing import List, Dict

from helpers.basic_modifier import BasicModifier
from helpers.helpers import load_modifier_class
from helpers.modification import FieldModification
from helpers.packet_field import PacketField
from helpers.packet_modification import PacketModification
from helpers.packet_shark import SharkPacket
from helpers.pool import SharedPool
from helpers.rule import Rule
from helpers.tshark_adapter import TsharkAdapter
from parser.tcp_stream_enum import TcpStream


class ModifierSharkController:

    def __init__(self, rules, adapter: TsharkAdapter, logger, tcp_stream_strategy, reset_pools, generate_meta_files):
        self.rules = rules
        self.modifier = BasicModifier()
        self.custom_classes = {}
        self.logger = logger
        self.pools = {}
        self.parsed_rules = self.__prepare_rules(rules)
        self.adapter = adapter
        self.tcp_packets = {}
        self.packets: Dict[int, PacketModification] = {}
        self.position = TsharkAdapter.PCAP_GLOBAL_HEADER + TsharkAdapter.PCAP_PACKET_HEADER
        self.streams = {}
        self.tcp_stream_strategy = tcp_stream_strategy
        self.reset_pools = reset_pools
        self.generate_meta_files = generate_meta_files

    def reset_file_information(self):
        if self.reset_pools:
            print('clearing')
            for pool in self.pools.values():
                pool.reset_pool()
        self.tcp_packets = {}
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
                # print(j)
                shark_packet = SharkPacket(a, self.parsed_rules, j+1)
                if shark_packet.is_tcp:
                    if shark_packet.tcp_stream not in self.streams:
                        self.streams[shark_packet.tcp_stream] = {
                            'valid': True,
                            'packets': []
                        }
                    self.streams[shark_packet.tcp_stream]['packets'].append({'index': shark_packet.index, 'seq':shark_packet.tcp_seq, 'next_seq': shark_packet.tcp_next_seq})
                    if shark_packet.tcp_lost:
                        self.streams[shark_packet.tcp_stream]['valid'] = False
                self.packets[j+1] = PacketModification(j+1, self.position, shark_packet.packet_length, shark_packet.tcp_payload_field, shark_packet.last_protocol_parsed, shark_packet.tcp_has_segment, shark_packet.tcp_segment_field)
                self.position += shark_packet.packet_length + TsharkAdapter.PCAP_PACKET_HEADER
                if shark_packet.tcp_retransmission:
                    # print('retransmission')
                    duplicate_packet_index = self.find_retransmission_packet(shark_packet.tcp_stream, shark_packet.index, shark_packet.tcp_seq, shark_packet.tcp_next_seq)
                    # print('duplicate', duplicate_packet_index)
                    if duplicate_packet_index is not None:
                        # copy all actions as it is TCP retransmission
                        self.packets[j+1].append_modifications(self.packets[duplicate_packet_index].modifications)
                        print(f'{j+1} copied from {duplicate_packet_index}')
                        continue
                # print('Running  modifiers for ', j+1)
                self.run_packet_modifiers(shark_packet, self.packets[j+1], file_info)
                # validate packet segments
                if shark_packet.tcp_segment_indexes:
                    for index in shark_packet.tcp_segment_indexes:
                        self.packets[index].tcp_segment_used = True
            print("END OF MODIFYING PHASE")
            print("VALIDATING TCP STREAMS")
            self.validate_tcp_streams()
            print("COPYING FILE")
            self.adapter.copy_file()
            # print(self.streams.keys())
            print("FILE COPIED")
            self.adapter.open_output_file()
            print("Writing changes")
            for key in sorted(self.packets):
                modifying_packet: PacketModification = self.packets[key]
                print('INDEX', modifying_packet.tcp_segment_used)
                modifying_packet.sort_modification()
                if len(modifying_packet.modifications) > 0:
                    print('INDEX ', modifying_packet.packet_index)
                for modification in modifying_packet.modifications:
                    # print('modifying', modification.field.field_path)
                    modification.info()
                    packet_start = modifying_packet.packet_start \
                        if not modification.frame_modification \
                        else modifying_packet.packet_start - TsharkAdapter.PCAP_PACKET_HEADER
                    offset = packet_start + modification.position
                    self.adapter.write_modified_field_data(modification.data, offset)
            print("Writing changes ended")
            # print(self.streams)
            if self.reset_pools and self.generate_meta_files:
                print('SHOULD BE HERE', self.adapter.metadata_file_name)
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
        invalid_streams_packets = [] if self.tcp_stream_strategy == TcpStream.CLEVER.value else \
            [packet['index'] for item in self.streams.items() if item[1]['valid'] is False for packet in item[1]['packets']]
        for packet in self.packets.values():
            if self.tcp_stream_strategy == TcpStream.CLEAR.value and packet.packet_index in invalid_streams_packets:
                packet.remove_all_modifications_after_tcp()
                packet.add_tcp_payload_clear_modification()
            else:
                if not packet.tcp_segment_used:
                    print(packet.packet_index)
                    packet.add_tcp_segment_clear_modification()
                if packet.tcp_unknown:
                    packet.remove_all_modifications_after_tcp()
                    packet.add_tcp_payload_clear_modification()

    def run_packet_modifiers(self, packet: SharkPacket, packet_modification: PacketModification, file_info):
        for rule in self.parsed_rules:
            fields = packet.get_packet_field(rule.field)
            if fields is None:
                continue
            for i, field in enumerate(fields):
                # CHOOSE PACKET DATA OR REASSEMBLED DATA
                packet_bytes = self.__get_bytes_for_modification(packet, field)
                value = field.get_field_value(packet_bytes)
                modified_value = rule.run_rule(value, file_info)
                field_modification = FieldModification(modified_value, field, rule.order)
                # mask return value with current value and retrieve write value
                # this is done so no read is performed while writing values to the output file
                packet.modify_packet_field(field, modified_value, packet_bytes)
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

    def __get_bytes_for_modification(self, packet: SharkPacket, field: PacketField) -> bytearray:
        if field.frame_field:
            return packet.packet_header
        if field.is_segmented:
            return packet.tcp_reassembled_data
        return packet.packet_bytes

    def __get_method(self, instance, method_name, field):
        try:
            attr = getattr(instance, method_name)
            return attr
        except AttributeError:
            print(f"Could not load method {method_name} for field '{field}'", file=sys.stderr)
            sys.exit(1)

    def __prepare_rules(self, rules) -> List[Rule]:
        parsed_rules = []
        for i, rule in enumerate(rules):
            field = rule['field']
            pool_key = rule['value_group'] if 'value_group' in rule else field
            if pool_key in self.pools:
                self.pools[pool_key].append_field(field)
            else:
                self.pools[pool_key] = SharedPool(field)
            modifier = self.__get_modifier(rule)
            method = self.__get_method(modifier, rule['method'], field)
            parsed_rules.append(
                Rule(field, rule["params"], method, self.pools[pool_key], self.logger, i)
            )
        return parsed_rules

    def __get_modifier(self, rule):
        if 'class' in rule:
            if rule['class'] in self.custom_classes:
                return self.custom_classes[rule['class']]
            else:
                custom_class = load_modifier_class(rule['class'])()
                self.custom_classes[rule['class']] = custom_class
                return custom_class
        return self.modifier

    def unused_rules(self):
        return list(
            map(lambda rule: rule.field, filter(lambda rule: rule.unused(), self.parsed_rules))
        )

    def rules_info(self):
        for rule in self.parsed_rules:
            rule.print_rule()

    def pools_dump(self):
        pool_info = {}
        for pool in self.pools.items():
            print(pool[1].used_by)
            pool_info.update([(pool[0], pool[1].pool)])
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

