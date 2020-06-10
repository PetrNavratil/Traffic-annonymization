from helpers.helpers import generate_random_bits, generate_random_number_in_range, get_ip_class_range
from modifiers.ip_random import IPRandom


class IPRandomPreserveClass(IPRandom):
    """
    Modifikator nahradi IP adresu nahodne vygenerovanou IP adresou, ktera spada do puvodni tridy IP adresy, podle
    tridniho deleni.
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        random_bits = bytearray(generate_random_bits(24).to_bytes(3, 'little'))
        first_octet_randomized = generate_random_number_in_range(get_ip_class_range(original_value[0]))
        randomized_ip = bytearray(4)
        randomized_ip[0] = first_octet_randomized
        randomized_ip[1:] = random_bits
        return randomized_ip

