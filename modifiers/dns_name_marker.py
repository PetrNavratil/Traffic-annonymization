from helpers.helpers import string_to_byte_array, validate_string_field, generate_prefixed_marker_text, \
    dns_cname_string_to_byte_array, dns_cname_byte_array_to_string
from helpers.validator import Validator
from modifiers.text_marker import TextMarker


class DnsNameMarker(TextMarker):

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        cname = dns_cname_byte_array_to_string(original_value)
        return dns_cname_string_to_byte_array(validate_string_field(value, len(cname)))
