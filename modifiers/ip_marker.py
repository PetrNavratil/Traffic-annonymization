from helpers.helpers import string_ip_to_byte_array
from helpers.validator import Validator
from interfaces.modifier import Modifier


class IPMarker(Modifier):

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return string_ip_to_byte_array(value)

    def validate_field(self, value,  additional_arguments) -> bool:
        return Validator.validate_ip(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.ip_network_convert, {}

