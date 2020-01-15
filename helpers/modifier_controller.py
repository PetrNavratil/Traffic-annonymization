from collections import OrderedDict
from typing import Generic, TypeVar, List

from helpers.helpers import  create_modifier_class
from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier

T = TypeVar('T', EtherModifier, IPModifier)


class ModifierController(Generic[T]):

    modifiers: [T]
    politic: str

    def __init__(self, politic, logger):
        self.modifiers = OrderedDict()
        self.politic = politic
        self.protocol_names = ModifierController.parse_protocol_names(politic)
        for protocol in self.protocol_names:
            self.modifiers[protocol] = (create_modifier_class(self.politic[protocol]['class'], protocol, logger))

    @staticmethod
    def parse_protocol_names(config) -> List[str]:
        return config.keys()

    def run_packet_modifiers(self, packet):
        for protocol, modifier in self.modifiers.items():
            print(f'Running modifier {protocol}')



