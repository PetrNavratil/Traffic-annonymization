import os

from helpers.validator import Validator
from interfaces.modifier import Modifier


class NumberRandom(Modifier):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return bytearray(os.urandom(len(original_value)))

    def validate_field(self, value, additional_arguments) -> bool:
        return Validator.validate_value_int_in(value, self.exclude.value, self.include.value)

    def transform_exclude_include_method(self, additional_params):
        return Validator.convert_range, {}

    def transform_output_value(self, value: bytearray):
        return int().from_bytes(value, byteorder='big')

