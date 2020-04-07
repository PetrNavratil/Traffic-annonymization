from helpers.helpers import parse_string_time, increment_time_stamp, time_stamp_to_byte_array, \
    Timestamp
from modifiers.frame_time_marker import FrameTimeMarker


class FrameTimeMarkerClearIncrement(FrameTimeMarker):

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        if self.start_time is None:
            self.start_time = Timestamp(0,0)
            self.time_increment = parse_string_time(value, additional_parameters['nano_resolution'])
        self.start_time = increment_time_stamp(self.start_time, self.time_increment, additional_parameters['nano_resolution'])
        return time_stamp_to_byte_array(self.start_time, additional_parameters['endianness'])
