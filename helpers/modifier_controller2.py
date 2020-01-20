import sys

from helpers.basic_modifier import BasicModifier
from helpers.helpers import create_modifier_class, load_modifier_class



class ModifierController2:

    def __init__(self, rules, logger):
        self.rules = rules
        self.modifier = BasicModifier()
        self.custom_classes = {}
        self.parsed_rules = self.__prepare_rules(rules)

    def run_packet_modifiers(self, packet):
        for rule in self.parsed_rules:
            attribute = self.__get_packet_attribute(packet, rule["field_path"])
            if attribute is None:
                continue
            modified_attribute = rule['method'](attribute, rule['params']['value'], [])
            self.__set_packet_attribute(packet, rule["field_path"], modified_attribute)

    def __get_method(self, instance, method_name, field):
        try:
            attr = getattr(instance, method_name)
            return attr
        except AttributeError:
            print(f"Could not load method {method_name} for field '{field}'", file=sys.stderr)
            sys.exit(1)

    def __prepare_rules(self, rules):
        parsed_rules = []
        for rule in rules:
            modifier = self.__get_modifier(rule)
            method = self.__get_method(modifier, rule['method'], rule['field'])
            parsed_rules.append({
                "method": method,
                "field": rule["field"],
                "field_path": rule["field"].split("."),
                "params": rule["params"]
            })
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

    def __get_packet_attribute(self, packet, field_path):
        layer = self.__get_attribute_layer(packet, field_path[:-1])
        if layer is None:
            return None
        try:
            return layer.getfieldval(field_path[-1])
        except (AttributeError, IndexError):
            return None

    def __set_packet_attribute(self, packet, field_path, value):
        layer = self.__get_attribute_layer(packet, field_path[:-1])
        if layer is None:
            return None
        try:
            return layer.setfieldval(field_path[-1], value)
        except (AttributeError, IndexError):
            return None

    def __get_attribute_layer(self, packet, layer_path):
        print(layer_path, packet.fields)
        if len(layer_path) == 1:
            try:
                return packet[layer_path[0]]
            except IndexError:
                return None
        else:
            return self.__get_attribute_layer(packet.payload, layer_path[1:])
