"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import parse_string_time, time_stamp_to_byte_array
from helpers.validator import Validator
from interfaces.modifier import Modifier


class FrameTimeMarker(Modifier):
    """
    Modifikator nastavi vsechna casova razitka na hodnotu `value` pravidla
    value: - casove razitko sekundy.mili/nano sekundy
    Priklad
    value: 0.500000
    """

    def __init__(self):
        super().__init__()
        self.start_time = None
        self.time_increment = None
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        timestamp = parse_string_time(value, additional_parameters['nano_resolution'])
        return time_stamp_to_byte_array(timestamp, additional_parameters['endianness'])

    def validate_field(self, value, additional_arguments) -> bool:
        return True

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}

