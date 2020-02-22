import json
import sys
from typing import List

from helpers.basic_modifier import BasicModifier
from helpers.helpers import load_modifier_class
from helpers.packet_field import PacketField
from helpers.pool import SharedPool
from helpers.rule import Rule


class ModifierPySharkController:

    def __init__(self, rules, logger):
        self.rules = rules
        self.modifier = BasicModifier()
        self.custom_classes = {}
        self.logger = logger
        self.pools = {}
        self.parsed_rules = self.__prepare_rules(rules)

    def run_packet_modifiers(self, packet):
        for rule in self.parsed_rules:
            field: PacketField = packet.get_packet_field(rule.field_path)
            if field is None:
                continue
            modified_value = rule.run_rule(field.original_value)
            packet.modify_packet_field(field, modified_value)

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
            # print(rule)
            field = rule['field']
            pool = SharedPool(field)
            self.pools.update([(field, pool)])
            modifier = self.__get_modifier(rule)
            method = self.__get_method(modifier, rule['method'], field)
            parsed_rules.append(
                Rule(field, rule["params"], method, pool, self.logger)
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
            pool_info.update([(pool[0], pool[1].pool)])
        return pool_info

    def write_pool_to_file(self):
        with open('metadata/meta.json', 'w') as f:
            json.dump(self.pools_dump(), f)
