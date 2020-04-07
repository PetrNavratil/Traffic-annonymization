from helpers.helpers import string_to_byte_array, validate_string_field, generate_prefixed_marker_text
from helpers.validator import Validator
from interfaces.modifier import Modifier


class TextMarker(Modifier):

    def __init__(self):
        super().__init__()
        self.suffix = None
        self.prefix = None
        self.delimiter = None
        self.prefix_length = None

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        new_value = generate_prefixed_marker_text(original_value, value,  self.delimiter, self.prefix_length)
        return string_to_byte_array(validate_string_field(new_value, len(original_value), suffix=self.suffix, prefix=self.prefix))

    def validate_field(self, value, additional_arguments) -> bool:
        validation = additional_arguments['validation'] if 'validation' in additional_arguments else ''
        if validation == 'prefix':
            return Validator.validate_value_string_prefix(value, self.exclude, self.include)
        if validation == 'suffix':
            return Validator.validate_value_string_suffix(value, self.exclude, self.include)
        return Validator.validate_value_string_in(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}

