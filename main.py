from typing import List

import scapy.all as scapy

from helpers.modifier_controller import ModifierController
from helpers.modifier_controller2 import ModifierController2
from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier
from logger.logger import Logger
import helpers.helpers as helpers
from parser.config_parser import ConfigParser


if __name__ == '__main__':

    parser = ConfigParser()
    # pcap_reader = scapy.PcapReader('../dataset/single_pcaps/test.pcapng')
    pcap_reader = scapy.PcapReader('../dataset/single_pcaps/http/http.pcap')
    # pcap_writer = scapy.PcapWriter('../dataset/altered/test.altered.pcapng')
    pcap_writer = scapy.PcapWriter('../dataset/altered/http.altered.pcap')

    logger = Logger()
    modifier = helpers.load_ether_modifier(parser.network_access_layer_class, logger)
    modifierIP = helpers.load_ip_modifier(parser.internet_layer_class, logger)

    network_layer: ModifierController[EtherModifier] = ModifierController(parser.network_access_layer_config, logger)
    internet_layer: ModifierController[IPModifier] = ModifierController(parser.internet_layer, logger)

    controller = ModifierController2(parser.config['rules'], logger)

    a = pcap_reader.read_packet()
    controller.run_packet_modifiers(a)
    #
    # for i, packet in enumerate(pcap_reader):
    #     # print(packet.summary())
    #     # network_layer.run_packet_modifiers(packet)
    #     controller.run_packet_modifiers(packet)
    #     # e = packet['Ethernet']
    #     # # print(e.name, e.payload.name)
    #     # e.dst = modifier.modify_dst(dst=e.dst)
    #     # e.src = modifier.modify_src(src=e.src)
    #     #
    #     # if 'IP' in packet:
    #     #     ip = packet['IP']
    #     #     ip.src = modifierIP.modify_src(src=ip.src)
    #     #     ip.dst = modifierIP.modify_dst(dst=ip.dst)
    #     # else:
    #     #     print(f"Divny packet  {i} - {packet.show()}")
    #     pcap_writer.write(packet)


