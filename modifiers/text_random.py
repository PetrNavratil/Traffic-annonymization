from helpers.helpers import string_to_byte_array, generate_random_text, validate_string_field, \
    generate_prefixed_marker_text, byte_array_to_string
from helpers.validator import Validator
from interfaces.modifier import Modifier


class TextRandom(Modifier):
    """
    Modifikator nahradi textovou hodnotu za nahodny text.
    """

    def __init__(self):
        super().__init__()
        # hodnota, ktera je vzdy doplnena na konec retezce
        self.suffix = None
        # hodnota, ktera je vzdy doplnena na zacatek retezce
        self.prefix = None
        # oddelovac pro metody zachovavajici prefix, napr. HTTP preserve prefix
        self.delimiter = None
        # delka pro zachovani prefixu
        self.prefix_length = None

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        random_value = generate_random_text(len(original_value))
        new_value = generate_prefixed_marker_text(original_value, random_value,  self.delimiter, self.prefix_length)
        return string_to_byte_array(
            validate_string_field(
                new_value,
                len(original_value),
                suffix=self.suffix,
                prefix=self.prefix
            ))

    def validate_field(self, value, additional_arguments) -> bool:
        return Validator.validate_string(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}

    def transform_output_value(self, value: bytearray):
        return byte_array_to_string(value)
