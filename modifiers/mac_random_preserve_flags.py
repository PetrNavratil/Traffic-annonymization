from helpers.helpers import generate_random_mac_preserve_flags
from modifiers.mac_random import MACRandom


class MACRandomPreserveFlags(MACRandom):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_random_mac_preserve_flags(original_value)