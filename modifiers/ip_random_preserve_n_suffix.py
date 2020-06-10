from helpers.helpers import generate_random_k_prefixed_or_suffixed_ip
from modifiers.ip_random import IPRandom


class IPRandomPreserveNSuffix(IPRandom):
    """
    Modifikator nahradi cast IP adresy nahodnou hodnotou, pricemz zachova N bitu suffixu, ktere  definuje value.
    :value - delka zachovaneho suffixu
    Priklad:
    value: 16
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_random_k_prefixed_or_suffixed_ip(original_value, int(value), prefix=False)


