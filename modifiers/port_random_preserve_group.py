"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import random_port_from_its_category
from modifiers.number_marker import NumberMarker


class PortRandomPreserveGroup(NumberMarker):
    """
    Modifikator nahradi cislo portu atributu za nahodnou hodnotu, pricemz zustava zachovane rozdeleni portu na
    rezervovane apod.
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return random_port_from_its_category(original_value)