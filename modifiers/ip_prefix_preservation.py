import string
import random
from yacryptopan import CryptoPAn

from helpers.helpers import byte_array_ip_to_string, string_ip_to_byte_array
from modifiers.ip_marker import IPMarker


class IPPrefixPreservation(IPMarker):
    """
    Modifikator pouziva algoritmus CryptoPAn pro permutaci vstupnich IP adres.
    Modifikovane IP adresy, ktere sdili prefix pred anonymizaci, jej sdili i po anonymizaci, pricemz hostid je nahodny.
    napr -  192.168.0.1  -> 222.144.3.55
            192.168.0.10 -> 222.144.3.78
    """

    def __init__(self):
        super().__init__()
        letters = string.printable
        self.meta['crypto_pan'] = ''.join(random.choice(letters) for i in range(32))
        self.crypto_pan = CryptoPAn(self.meta['crypto_pan'].encode())

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return string_ip_to_byte_array(self.crypto_pan.anonymize(byte_array_ip_to_string(original_value)))


