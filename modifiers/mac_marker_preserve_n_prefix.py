from helpers.helpers import generate_marked_k_prefixed_or_suffixed_mac
from modifiers.mac_marker import MACMarker


class MACMarkerPreserveNPrefix(MACMarker):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_marked_k_prefixed_or_suffixed_mac(
            original_value,
            value['preserve'],
            value['value'],
            prefix=True
        )
