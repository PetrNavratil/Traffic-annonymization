from scapy.all import RandMAC
import scapy.layers.l2 as l2
from logger.logger import Logger
from interfaces.ether_modifier import EtherModifier


class CustomEtherModifier(EtherModifier):

    def __init__(self, protocol: str, logger: Logger):
        self.logger = logger
        self.protocol = protocol

    def modify_dst(self, dst: l2.DestMACField):
        value = l2.Ether(src='aa:aa:aa:aa:aa:aa').src
        self.logger.log('ETHER_dst', dst, value)
        return value
        # return RandMAC()

    def modify_src(self, src: l2.SourceMACField):
        value = l2.Ether(src='aa:aa:aa:aa:aa:aa').src
        self.logger.log('ETHER_src', src, value)
        return value
        # return RandMAC()
