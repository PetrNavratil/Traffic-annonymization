import asyncio
import fcntl
import json
import multiprocessing
import os
import subprocess
import sys
import threading
import time
from asyncio.subprocess import PIPE

import pyshark
from jsonslicer import JsonSlicer
from pyshark.capture.capture import Capture

from helpers.modifier_controller2 import ModifierController2
from helpers.modifier_pyshark_controller import ModifierPySharkController
from helpers.modifier_shark_controller import ModifierSharkController
from helpers.packet import Packet
from helpers.packet_controller import PacketController
from helpers.packet_field import PacketField
from helpers.packet_pyshark import PySharkPacket
from helpers.py_shark_adapter import PySharkAdapter
from helpers.tshark_adapter import TsharkAdapter
from helpers.tshark_json_minifier import TsharkJsonMinifier
from logger.logger import Logger
from parser.config_parser import ConfigParser
import ijson
import naya

from json_stream_parser import load_iter

from parser.no_idea import NoIdea

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    parser = ConfigParser()
    logger = Logger(parser.verbose)
    adapter = TsharkAdapter(parser.file_names[0])
    controller = ModifierPySharkController(parser.get_rules_config(), logger)
    slicer = adapter.get_packets()
    i = 0
    for a in slicer:
        i += 1
        print(i)
        Packet(a, controller.parsed_rules)
    # controller = ModifierPySharkController(parser.get_rules_config(), logger)
    # a = pyshark.FileCapture(parser.file_names[0], use_json=True, include_raw=True)
    # for packet in adapter.packets:
    #     pyshark_packet = PySharkPacket(packet)
    #     controller.run_packet_modifiers(pyshark_packet)
        # adapter.write_to_output_file(pyshark_packet.get_write_packet_data())
        # if 'tls' in packet:
        #     print(packet.frame_info.get_field('time_epoch'))
        #     packet_field_path = 'eth.ip.tcp.tls.record.content_type_raw'
        #     b = PySharkPacket(packet)
        #     print(b.get_packet_attribute(packet_field_path.split('.')))
        #     # last_index, last_layer = get_last_layer(packet_field_path, packet)
        #     # print(last_layer, last_index)
        #     # print(packet_field_path.split('.')[last_index + 1::])
        #     # # first_layer_not_found_index = None
        #     # # paths = 'eth.ip.tcp.tls.record.content_type'.split('.')
        #     # # for i, path in enumerate(paths):
        #     # #     first_layer_not_found_index = i
        #     # #     if path not in packet:
        #     # #         break
        #     # #
        #     # # last_layer = packet[paths[first_layer_not_found_index - 1]]
        #     # # last_field = None
        #     # # for i, path in enumerate(paths[first_layer_not_found_index:]):
        #     # #     last_field = packet[path]
        #     # #     if path not in last_field:
        #     # #         break
        #     # b = packet['tls']
        #     # print(b.field_names)
        #     # print(b.get_field('record').field_names)
        #     # print(b.record.content_type_raw)
        #     #
        #     # print(find_field(packet_field_path.split('.')[last_index + 1::], packet[last_layer]))
        #     # print('tls' in b)
        # # print(packet.frame_raw.value)

    # # packet_controller = PacketController(parser.file_names)
    # # packet_controller2 = PacketControllerShark(parser.file_names)
    # # pcap_reader = scapy.PcapReader(parser.file_names[0])
    # # pcap_writer = scapy.PcapWriter(f"../dataset/altered/{parser.file_names[0].split('/')[-1]}")
    #
    # logger = Logger(parser.verbose)
    # controller = ModifierController2(parser.get_rules_config(), logger)
    # # controller = ModifierSharkController(parser.get_rules_config(), logger)
    # #
    # shark = TsharkAdapter(parser.file_names[0])

    # for rule in controller.parsed_rules:
    #     print(f'Rule {rule.field_path_for_shark}')

    # minifier = TsharkJsonMinifier(shark.file_name.replace('.pcap', '.json'))
    # minifier.minify_file_slicer(controller.parsed_rules)
    # print(shark.get_packets())
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
