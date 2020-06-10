from helpers.helpers import parse_string_time, byte_array_to_timestamp, increment_time_stamp, time_stamp_to_byte_array
from modifiers.frame_time_marker import FrameTimeMarker


class FrameTimeMarkerIncrement(FrameTimeMarker):
    """
    Modifikator ke vsem casovym razitkum pricte prirustek definovany hodnotou `value` pravida
    :value - casove razitko prirustku sekundy.mili/nano sekundy
    Priklad
    value: 0.500000
    """

    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        if self.time_increment is None:
            self.time_increment = parse_string_time(value, additional_parameters['nano_resolution'])
        original_time_stamp = byte_array_to_timestamp(original_value, additional_parameters['endianness'])
        new_time_stamp = increment_time_stamp(original_time_stamp, self.time_increment, additional_parameters['nano_resolution'])
        return time_stamp_to_byte_array(new_time_stamp, additional_parameters['endianness'])
