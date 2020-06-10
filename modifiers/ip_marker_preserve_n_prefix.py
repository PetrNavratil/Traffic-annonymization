from helpers.helpers import generate_marked_k_prefixed_or_suffixed_ip
from modifiers.ip_marker import IPMarker


class IPMarkerPreserveNPrefix(IPMarker):
    """
    Modifikator nahradi cast IP adresy predem definovanou hodnotou pravidla `value`, pricemz zachova N bitu prefixu,
    ktere opet definuje value.
    :value - nova hodnota v atributu `value`, delka prefixu v `preserve`.
    Priklad:
    value:
        value: '255.255'
        preserve: 16
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return generate_marked_k_prefixed_or_suffixed_ip(
            original_value,
            value['preserve'],
            value['value'],
            prefix=True
        )


