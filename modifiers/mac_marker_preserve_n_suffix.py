"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import generate_marked_k_prefixed_or_suffixed_mac
from modifiers.mac_marker import MACMarker


class MACMarkerPreserveNSuffix(MACMarker):
    """
      Modifikator nahradi cast MAC adresy predem definovanou hodnotou pravidla `value`, pricemz zachova N bitu suffixu,
      ktere opet definuje value.
      :value - nova hodnota v atributu `value`, delka prefixu v `preserve`.
      Priklad:
      value:
          value: 'ff:ff:ff:ff:ff'
          preserve: 8
      """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_marked_k_prefixed_or_suffixed_mac(
            original_value,
            value['preserve'],
            value['value'],
            prefix=False
        )
