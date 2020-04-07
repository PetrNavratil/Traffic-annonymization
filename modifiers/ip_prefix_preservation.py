from yacryptopan import CryptoPAn

from helpers.helpers import byte_array_ip_to_string, string_ip_to_byte_array
from modifiers.ip_marker import IPMarker


class IPPrefixPreservation(IPMarker):

    def __init__(self):
        super().__init__()
        self.keys['crypto_pan'] = '32-char-str-for-AES-key-and-pad.'
        self.crypto_pan = CryptoPAn(self.keys['crypto_pan'].encode())

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return string_ip_to_byte_array(self.crypto_pan.anonymize(byte_array_ip_to_string(original_value)))


