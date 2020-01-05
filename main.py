# from typing import List

import scapy.all as scapy

# from helpers.modifier_controller import ModifierController
# from interfaces.ether_modifier import EtherModifier
# from interfaces.ip_modifier import IPModifier
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

    # test: ModifierController[List[EtherModifier]] = ModifierController(parser.config)
    # test2: ModifierController[List[IPModifier]] = ModifierController('TEST')
    # test.print_politic()


    #
    #
    for i, packet in enumerate(pcap_reader):
        e = packet['Ethernet']
        e.dst = modifier.modify_dst(dst=e.dst)
        e.src = modifier.modify_src(src=e.src)

        if 'IP' in packet:
            ip = packet['IP']
            ip.src = modifierIP.modify_src(src=ip.src)
            ip.dst = modifierIP.modify_dst(dst=ip.dst)
        else:
            print(f"Divny packet  {i} - {packet.show()}")
        pcap_writer.write(packet)


