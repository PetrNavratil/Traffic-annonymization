from jsonslicer import JsonSlicer
from pyshark.capture.capture import Capture

from helpers.modifier_controller2 import ModifierController2
from helpers.modifier_shark_controller import ModifierSharkController
from helpers.packet_controller import PacketController
from helpers.packet_field import PacketField
from helpers.tshark_adapter import TsharkAdapter
from helpers.tshark_json_minifier import TsharkJsonMinifier
from logger.logger import Logger
from parser.config_parser import ConfigParser

if __name__ == '__main__':

    parser = ConfigParser()

    # packet_controller = PacketController(parser.file_names)
    # packet_controller2 = PacketControllerShark(parser.file_names)
    # pcap_reader = scapy.PcapReader(parser.file_names[0])
    # pcap_writer = scapy.PcapWriter(f"../dataset/altered/{parser.file_names[0].split('/')[-1]}")

    logger = Logger(parser.verbose)
    controller = ModifierController2(parser.get_rules_config(), logger)
    # controller = ModifierSharkController(parser.get_rules_config(), logger)
    #
    # shark = TsharkAdapter(parser.file_names[0])

    with open(parser.file_names[0]) as f:
        for a in JsonSlicer(f, (None, None, 'layers')):
            print(a)

    # for rule in controller.parsed_rules:
    #     print(f'Rule {rule.field_path_for_shark}')
    #
    # minifier = TsharkJsonMinifier(parser.file_names[0])
    # minifier.minify_file(controller.parsed_rules)
    # # print(shark.get_packets())
    #
    # for packet in shark.packets:
    #     for rule in controller.parsed_rules:
    #         if packet.has_protocol(rule.field_path_for_shark[0]):
    #             print(f'BEFORE {packet.packet_bytes}')
    #             # print(f'Has protocol {rule.field_path_for_shark[0]}')
    #             value: PacketField = packet.get_packet_field(rule.field_path_for_shark)
    #             # print(f'PAcket value {value.original_value}')
    #             modified = rule.run_rule(value.original_value)
    #             # print(f'PAcket modified value {modified}')
    #             packet.modify_packet_field(value, modified)
    #             print(f'Value {packet.packet_bytes}')
    #         else:
    #             print(f'Has no protocol {rule.field_path_for_shark[0]}')
    # shark.write_modified_file()
    # for i, packet in enumerate(packet_controller.scapy_reader):
    #     controller.run_packet_modifiers(packet)
    #     packet_controller.set_packet(packet)

    # for i, packet in packet_controller2.get_packets():
    #     a: Capture = packet
    #     print(a['DHCP'])
        # controller.run_packet_modifiers(packet)
        # packet_controller.set_packet(packet)

    # for i, packet in enumerate(pcap_reader):
    #     controller.run_packet_modifiers(packet)
    #     pcap_writer.write(packet)

    # print(f'Nemodifikovane parametry: {controller.unused_rules()}')
    # controller.rules_info()
    # controller.write_pool_to_file()
