from helpers.helpers import number_to_byte_array
from helpers.validator import Validator
from interfaces.modifier import Modifier


class NumberMarker(Modifier):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return number_to_byte_array(int(value), len(original_value))

    def validate_field(self, value, additional_arguments) -> bool:
        return Validator.validate_value_int_in(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.convert_range, {}

