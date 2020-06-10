from modifiers.ip_marker import IPMarker


class ClearIPMarker(IPMarker):
    """
    Modifikator vymaze IP adresu
    """

    def __init__(self):
        super().__init__()
        self.unique = False
        self.store_value = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return bytearray(len(original_value))


