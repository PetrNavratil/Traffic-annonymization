import scapy.all as scapy
from logger.logger import Logger
import helpers.helpers as helpers
import argparse


if __name__ == '__main__':
    # scapy.load_layer('http')
    parser = argparse.ArgumentParser()
    parser.parse_args()

    pcap_reader = scapy.PcapReader('../dataset/single_pcaps/test.pcapng')
    pcap_writer = scapy.PcapWriter('../dataset/altered/test.altered.pcapng')
    #
    logger = Logger()
    modifier = helpers.load_ether_modifier('custom_ethsader_modifier.CustomEtherModifier', logger)
    modifierIP = helpers.load_ip_modifier('default_ip_modifier.DefaultIPModifier', logger)
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


