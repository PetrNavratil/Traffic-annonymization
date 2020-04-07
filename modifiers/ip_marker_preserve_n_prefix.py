from helpers.helpers import generate_marked_k_prefixed_or_suffixed_ip
from modifiers.ip_marker import IPMarker


class IPMarkerPreserveNPrefix(IPMarker):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_marked_k_prefixed_or_suffixed_ip(
            original_value,
            value['preserve'],
            value['value'],
            prefix=True
        )


