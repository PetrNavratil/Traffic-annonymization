from helpers.helpers import string_mac_to_byte_array
from helpers.validator import Validator
from interfaces.modifier import Modifier


class MACMarker(Modifier):

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return string_mac_to_byte_array(value)

    def validate_field(self, value, additional_parameters) -> bool:
        validation = additional_parameters['validation'] if 'validation' in additional_parameters else ''
        if validation == 'prefix':
            return Validator.validate_value_mac_prefix(value, self.exclude, self.include)
        if validation == 'suffix':
            return Validator.validate_value_mac_suffix(value, self.exclude, self.include)
        return Validator.validate_value_mac_in(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}