"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from modifiers.number_marker import NumberMarker


class ClearTextMarker(NumberMarker):
    """
    Modifikator nahradi cislo nulami
    """

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return bytearray(len(original_value))

