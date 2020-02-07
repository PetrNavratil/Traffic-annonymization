import scapy.all as scapy
from helpers.modifier_controller2 import ModifierController2
from logger.logger import Logger
from parser.config_parser import ConfigParser


if __name__ == '__main__':

    parser = ConfigParser()
    pcap_reader = scapy.PcapReader(parser.file_names[0])
    pcap_writer = scapy.PcapWriter(f"../dataset/altered/{parser.file_names[0].split('/')[-1]}")

    logger = Logger(parser.verbose)
    controller = ModifierController2(parser.get_rules_config(), logger)

    for i, packet in enumerate(pcap_reader):
        controller.run_packet_modifiers(packet)
        pcap_writer.write(packet)

    print(f'Nemodifikovane parametry: {controller.unused_rules()}')
    controller.rules_info()
    controller.write_pool_to_file()
