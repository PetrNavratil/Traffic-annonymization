"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import generate_marked_k_prefixed_or_suffixed_ip
from modifiers.ip_marker import IPMarker


class IPMarkerPreserveNSuffix(IPMarker):
    """
    Modifikator nahradi cast IP adresy predem definovanou hodnotou pravidla `value`, pricemz zachova N bitu suffixu,
    ktere opet definuje value.
    :value - nova hodnota v atributu `value`, delka suffixu v `preserve`.
    Priklad:
    value:
        value: '255.255'
        preserve: 16
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_marked_k_prefixed_or_suffixed_ip(
            original_value,
            value['preserve'],
            value['value'],
            prefix=False
        )


