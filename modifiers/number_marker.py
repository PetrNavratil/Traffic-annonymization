"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import number_to_byte_array
from modifiers.number_random import NumberRandom


class NumberMarker(NumberRandom):
    """
    Modifikator nahradi cislo atributu za predem definovanou hodnotu v atributu `value`. Delka bytu puvodniho cisla je
    zachovana.
    :value- cislo
    Priklad
    value: 10
    """

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return number_to_byte_array(int(value), len(original_value))

