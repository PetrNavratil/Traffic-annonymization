from helpers.helpers import parse_string_time, time_stamp_to_byte_array
from helpers.validator import Validator
from interfaces.modifier import Modifier


class FrameTimeMarker(Modifier):

    def __init__(self):
        super().__init__()
        self.start_time = None
        self.time_increment = None
        self.unique = False

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        timestamp = parse_string_time(value, additional_parameters['nano_resolution'])
        return time_stamp_to_byte_array(timestamp, additional_parameters['endianness'])

    def validate_field(self, value, additional_arguments) -> bool:
        return True

    def transform_exclude_include_method(self, additional_params):
        return Validator.no_transform, {}

