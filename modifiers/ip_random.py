"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import random_ip_address
from modifiers.ip_marker import IPMarker


class IPRandom(IPMarker):
    """
    Modifikator nahradi IP adresu nahodne vygenerovanou IP adresou
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return random_ip_address()

