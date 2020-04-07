from modifiers.ip_marker import IPMarker


class ClearIPMarker(IPMarker):

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return bytearray(len(original_value))

