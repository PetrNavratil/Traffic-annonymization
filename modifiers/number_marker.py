from helpers.helpers import number_to_byte_array
from helpers.validator import Validator
from modifiers.number_random import NumberRandom


class NumberMarker(NumberRandom):

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return number_to_byte_array(int(value), len(original_value))

    def validate_field(self, value, additional_arguments) -> bool:
        return Validator.validate_value_int_in(value, self.exclude.value, self.include.value)

    def transform_exclude_include_method(self, additional_params):
        return Validator.convert_range, {}
