from helpers.validator import Validator
from interfaces.modifier import Modifier


class ClearMarker(Modifier):

    def __init__(self):
        super().__init__()
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        return bytearray(len(original_value))

    def validate_field(self, value, additional_arguments) -> bool:
        return True

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}
