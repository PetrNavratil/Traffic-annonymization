"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import generate_random_mac_preserve_flags
from modifiers.mac_random import MACRandom


class MACRandomPreserveFlags(MACRandom):
    """
    Modifikator nahradi MAC adresu nahodnou hodnotou, pricemz zachova flagy adresy (multicast, spravovani)
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_random_mac_preserve_flags(original_value)