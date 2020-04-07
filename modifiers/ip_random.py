from helpers.helpers import random_ip_address
from modifiers.ip_marker import IPMarker


class IPRandom(IPMarker):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return random_ip_address()

