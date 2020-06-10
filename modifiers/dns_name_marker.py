from helpers.helpers import  validate_string_field, dns_cname_string_to_byte_array, dns_cname_byte_array_to_string
from modifiers.text_marker import TextMarker


class DnsNameMarker(TextMarker):
    """
    Modifikator nahradi domenove jmeno statickym jmenem uvedenem v anonymizacnim pravidle jako "value"
    value: domenove jmeno
    Priklad:
    value: google.com
    """

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        cname = dns_cname_byte_array_to_string(original_value)
        return dns_cname_string_to_byte_array(validate_string_field(value, len(cname)))
