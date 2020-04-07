from helpers.helpers import random_port_from_its_category
from modifiers.number_marker import NumberMarker


class PortRandomPreserveGroup(NumberMarker):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return random_port_from_its_category(original_value)