"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import string_mac_to_byte_array
from helpers.validator import Validator
from interfaces.modifier import Modifier


class MACMarker(Modifier):
    """
    Modifikator nahradi MAC adresu predem definovanou hodnotou pravidla `value`.
    :value MAC adresa v hexa notaci
    Priklad
    value: 'ff:ff:ff:ff:ff:ff'
    """

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return string_mac_to_byte_array(value)

    def validate_field(self, value, additional_parameters) -> bool:
        return Validator.validate_mac(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}