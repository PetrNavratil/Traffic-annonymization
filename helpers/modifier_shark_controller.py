import json
import sys
from typing import List

from helpers.basic_modifier import BasicModifier
from helpers.helpers import load_modifier_class
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

    def modify_files(self):
        while self.adapter.open_next_file():
            print(f'Modification of {self.adapter.file_name}')
            packets = self.adapter.get_packets()
            for j, a in enumerate(packets):
                print(j)
                shark_packet = SharkPacket(a, self.parsed_rules)
                # if shark_packet.is_segmented:
                #     print('SEGMENTED')
                self.run_packet_modifiers(shark_packet)
                # write current file (without changes for segmented TCP)
                self.adapter.write_modified_packet(shark_packet.get_packet_bytes())
                # store TCP reference
                if shark_packet.is_tcp:
                    self.tcp_packets[j+1] = self.adapter.get_current_file_position()
                # handle segmented TCP modifications
                if shark_packet.has_segmented_field_modifications:
                    for packet_index, segment_info in shark_packet.tcp_segment_locations.items():
                        packet_end_position = self.tcp_packets[packet_index]
                        # changing current packet
                        if packet_index == j+1:
                            self.adapter.go_to_nth_byte_position_from_end(shark_packet.tcp_payload_length)
                        else:
                            self.adapter.go_to_file_position(packet_end_position - segment_info.length)
                        segment_bytes = shark_packet.tcp_reassembled_data[segment_info.position:segment_info.position + segment_info.length]
                        self.adapter.write_modified_packet(segment_bytes)
                self.adapter.go_to_end_of_file()
            print(self.tcp_packets)

    def run_packet_modifiers(self, packet: SharkPacket):
        for rule in self.parsed_rules:
            fields = packet.get_packet_field(rule.field)
            if fields is None:
                continue
            for field in fields:
                # CHOOSE PACKET DATA OR REASSEMBLED DATA
                packet_bytes = packet.packet_bytes if not field.is_segmented else packet.tcp_reassembled_data
                value = field.get_field_value(packet_bytes)
                modified_value = rule.run_rule(value)
                # CAN BE PROBLEM WITH MODIFYING packet bytes
                packet.modify_packet_field(field, modified_value, packet_bytes)

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
            print('key', pool_key)
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
