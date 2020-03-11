import json
import sys
from typing import List, Dict

from helpers.basic_modifier import BasicModifier
from helpers.helpers import load_modifier_class
from helpers.modification import FieldModification
from helpers.packet_modification import PacketModification
from helpers.packet_shark import SharkPacket
from helpers.pool import SharedPool
from helpers.rule import Rule
from helpers.tshark_adapter import TsharkAdapter


class ModifierSharkController:

    def __init__(self, rules, adapter: TsharkAdapter, logger):
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

    def modify_files(self):
        while self.adapter.open_next_file():
            print(f'Modification of {self.adapter.file_name}')
            packets = self.adapter.get_packets()
            self.tcp_packets = {}
            self.packets = {}
            self.streams = {}
            self.position = TsharkAdapter.PCAP_GLOBAL_HEADER + TsharkAdapter.PCAP_PACKET_HEADER
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
                self.packets[j+1] = PacketModification(j+1, self.position, shark_packet.packet_length, shark_packet.tcp_payload_field)
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
                self.run_packet_modifiers(shark_packet, self.packets[j+1])
            print("END OF MODIFYING PHASE")
            print("VALIDATING TCP STREAMS")
            self.validate_tcp_streams()
            print("COPYING FILE")
            self.adapter.copy_file()
            print(self.streams.keys())
            print("FILE COPIED")
            self.adapter.open_output_file()
            print("Writting changes")
            for key in sorted(self.packets):
                modifying_packet: PacketModification = self.packets[key]
                if len(modifying_packet.modifications) > 0:
                    print('INDEX ', modifying_packet.packet_index)
                for modification in modifying_packet.modifications:
                    # print('modifying', modification.field.field_path)
                    modification.info()
                    offset = modifying_packet.packet_start + modification.position
                    self.adapter.write_modified_field_data(modification.data, offset)
            print("Writting changes ended")

    def find_retransmission_packet(self, stream_index, packet_index, sequence, next_sequence):
        if stream_index not in self.streams:
            return None
        for info in self.streams[stream_index]['packets']:
            if info['seq'] == sequence and info['next_seq'] == next_sequence and info['index'] != packet_index:
                return info['index']
        return None

    def validate_tcp_streams(self):
        invalid_streams = [item[0] for item in self.streams.items() if item[1]['valid'] is False]
        for invalid_stream in invalid_streams:
            print('CURRUPTED STREAM INDEX', invalid_stream, len(self.streams[invalid_stream]['packets']))
            for packet in self.streams[invalid_stream]['packets']:
                invalid_packet = self.packets[packet['index']]
                invalid_packet.remove_all_modifications_after_tcp()
                invalid_packet.add_tcp_payload_clear_modification()


    def run_packet_modifiers(self, packet: SharkPacket, packet_modification: PacketModification):
        for rule in self.parsed_rules:
            fields = packet.get_packet_field(rule.field)
            if fields is None:
                continue
            for i, field in enumerate(fields):
                # CHOOSE PACKET DATA OR REASSEMBLED DATA
                packet_bytes = packet.packet_bytes if not field.is_segmented else packet.tcp_reassembled_data
                value = field.get_field_value(packet_bytes)
                modified_value = rule.run_rule(value)
                field_modification = FieldModification(modified_value, field)
                # mask return value with current value and retrieve write value
                # this is done so no read is performed while writing values to the output file
                packet.modify_packet_field(field, modified_value, packet_bytes)
                if field.has_mask():
                    modified_value = field.get_unmasked_field(packet_bytes)
                    field_modification.set_value(modified_value)
                #     field is segmented - need to determine, where to write it (segment data and packet)
                if field.is_segmented:
                    print(i, 'segmented', packet.index, field.position)
                    possible_segments = packet.get_field_possible_segments(field)
                    print(possible_segments)
                    field_remaining_length = field.length
                    print('remaining length', field_remaining_length)
                    for j, packet_index in enumerate(possible_segments):
                        # TODO: data jsou pres vice segmentu
                        segment_info = packet.tcp_segment_locations[packet_index]
                        segment_position = field.position - segment_info.position if j == 0 else 0
                        print(f'segment position {segment_position}')
                        if segment_position + field_remaining_length <= segment_info.length:
                            print('can fit into whole segment')
                            # writing to current packet
                            if packet_index == packet.index:
                                print('same inxed', packet_index)
                                tcp_start = packet.packet_length - packet.tcp_payload_length
                                new_offset = tcp_start + segment_position
                                aaaa = FieldModification(modified_value[-field_remaining_length:], field)
                                aaaa.set_position(new_offset)
                                packet_modification.add_modification(aaaa)
                            else:
                                print('different inxed', packet_index)
                                origin_packet = self.packets[packet_index]
                                tcp_start = origin_packet.packet_length - segment_info.length
                                new_offset = tcp_start + segment_position
                                aaaa = FieldModification(modified_value[-field_remaining_length:], field)
                                aaaa.set_position(new_offset)
                                origin_packet.add_modification(aaaa)
                            break
                        else:
                            print('can not fit into whole segment')
                            write_length = min(segment_info.length - segment_position, field_remaining_length)
                            print('write ', write_length)
                            if packet_index == packet.index:
                                print('same inxed', packet_index)
                                tcp_start = packet.packet_length - packet.tcp_payload_length
                                new_offset = tcp_start + segment_position
                                aaaa = FieldModification(modified_value[-field_remaining_length:-field_remaining_length+write_length], field)
                                print('wrrrint segment of length', aaaa.data_length)
                                aaaa.set_position(new_offset)
                                packet_modification.add_modification(aaaa)
                            else:
                                print('different inxed', packet_index)
                                origin_packet = self.packets[packet_index]
                                tcp_start = origin_packet.packet_length - segment_info.length
                                new_offset = tcp_start + segment_position
                                aaaa = FieldModification(modified_value[-field_remaining_length:-field_remaining_length+write_length], field)
                                print('wrrrint segment of length', aaaa.data_length)
                                aaaa.set_position(new_offset)
                                origin_packet.add_modification(aaaa)
                            field_remaining_length -= write_length

                        print('remaining length end of cycle', field_remaining_length)

                        #
                        #
                        # if field_remaining_length > segment_info.length:
                        #     print('cant fit here reamining -- ', field_remaining_length - segment_info.length)
                        # else:
                        #     break
                        #
                        # if packet_index == packet.index:
                        #     # print(segment_info)
                        #     tcp_start = packet.packet_length - packet.tcp_payload_length
                        #     new_offset = tcp_start + field.position
                        #     field_modification.set_position(new_offset)
                        #     packet_modification.add_modification(field_modification)
                        #     print('part of current packet', i)
                        # else:
                        #     print('part of different index', segment_info.position + segment_info.length)
                        #     origin_packet = self.packets[packet_index]
                        #     # print(origin_packet.packet_length)
                        #     segment_start = origin_packet.packet_length - segment_info.length
                        #     # print(segment_start)
                        #     new_offset = segment_start + field.position
                        #     field_modification.set_position(new_offset)
                        #     origin_packet.add_modification(field_modification)

                    # for packet_index, segment_info in packet.tcp_segment_locations.items():
                    #     if field.position >= segment_info.position and field.position < segment_info.position + segment_info.length:
                    #         # TODO: data jsou pres vice segmentu
                    #         if field.length > segment_info.length - segment_info.position:
                    #             print('cant fit here reamining -- ', field.length - segment_info.length)
                    #
                    #         if packet_index == packet.index:
                    #             # print(segment_info)
                    #             tcp_start = packet.packet_length - packet.tcp_payload_length
                    #             new_offset = tcp_start + field.position
                    #             field_modification.set_position(new_offset)
                    #             packet_modification.add_modification(field_modification)
                    #             print('part of current packet', i)
                    #         else:
                    #             print('part of different index', packet_index, segment_info.position + segment_info.length)
                    #             origin_packet = self.packets[packet_index]
                    #             # print(origin_packet.packet_length)
                    #             segment_start = origin_packet.packet_length - segment_info.length
                    #             print(segment_start)
                    #             new_offset = segment_start + field.position
                    #             print(new_offset)
                    #             field_modification.set_position(new_offset)
                    #             origin_packet.add_modification(field_modification)
                    #         break
                else:
                    packet_modification.add_modification(field_modification)

    def __get_method(self, instance, method_name, field):
        try:
            attr = getattr(instance, method_name)
            return attr
        except AttributeError:
            print(f"Could not load method {method_name} for field '{field}'", file=sys.stderr)
            sys.exit(1)

    def __prepare_rules(self, rules) -> List[Rule]:
        parsed_rules = []
        for rule in rules:
            field = rule['field']
            pool_key = rule['value_group'] if 'value_group' in rule else field
            if pool_key in self.pools:
                self.pools[pool_key].append_field(field)
            else:
                self.pools[pool_key] = SharedPool(field)
            modifier = self.__get_modifier(rule)
            method = self.__get_method(modifier, rule['method'], field)
            parsed_rules.append(
                Rule(field, rule["params"], method, self.pools[pool_key], self.logger)
            )
        return parsed_rules

    def __get_modifier(self, rule):
        if 'class' in rule:
            if rule['class'] in self.custom_classes:
                return self.custom_classes[rule['class']]
            else:
                custom_class = load_modifier_class(rule['class'])
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

    def write_pool_to_file(self):
        with open('metadata/meta.json', 'w') as f:
            json.dump(self.pools_dump(), f)
