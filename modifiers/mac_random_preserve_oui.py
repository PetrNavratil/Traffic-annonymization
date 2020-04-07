from helpers.helpers import generate_random_k_prefixed_or_suffixed_mac
from modifiers.mac_random import MACRandom


class MACRandomPreserveOUI(MACRandom):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_random_k_prefixed_or_suffixed_mac(original_value, 24, prefix=True)