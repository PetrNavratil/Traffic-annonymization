from helpers.helpers import generate_random_mac
from modifiers.mac_marker import MACMarker


class MACRandom(MACMarker):
    """
    Modifikator nahradi MAC adresu nahodnou hodnotou
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_random_mac()
