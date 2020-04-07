from helpers.helpers import string_to_byte_array, generate_random_text, validate_string_field, \
    generate_prefixed_marker_text
from modifiers.text_marker import TextMarker


class TextRandom(TextMarker):

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
