"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import generate_random_k_prefixed_or_suffixed_mac
from modifiers.mac_random import MACRandom


class MACRandomPreserveNSuffix(MACRandom):
    """
      Modifikator nahradi cast MAC adresy nahodnou hodnotou, pricemz zachova N bitu suffixu, ktere definuje value.
      :value - delka zachovaneho suffixu
      Priklad:
      value: 8
      """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_random_k_prefixed_or_suffixed_mac(original_value, int(value), prefix=False)