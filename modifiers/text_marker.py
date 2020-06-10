"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import string_to_byte_array, validate_string_field, generate_prefixed_marker_text
from helpers.validator import Validator
from modifiers.text_random import TextRandom


class TextMarker(TextRandom):
    """
    Modifikator nahradi textovou hodnotu za definovanou hodnotu atributu `value` anonymizacniho pravidla.
    :value - nova hodnota retezce
    Priklad:
    value: 'text marker'
    """

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        new_value = generate_prefixed_marker_text(original_value, value,  self.delimiter, self.prefix_length)
        return string_to_byte_array(validate_string_field(new_value, len(original_value), suffix=self.suffix, prefix=self.prefix))

    def validate_field(self, value, additional_arguments) -> bool:
        return Validator.validate_string(value, self.exclude, self.include)

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}

