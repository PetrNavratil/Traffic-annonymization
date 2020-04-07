from helpers.helpers import generate_random_bits
from modifiers.ip_random import IPRandom


class IPRandomPreserveClassOctet(IPRandom):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        random_bits = bytearray(generate_random_bits(24).to_bytes(3, 'little'))
        copied_ip = original_value.copy()
        copied_ip[1:] = random_bits
        return copied_ip

