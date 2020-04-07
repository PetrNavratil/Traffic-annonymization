from socket import socket

from netaddr import IPNetwork

from helpers.helpers import byte_array_ip_to_string, byte_array_to_number, byte_array_to_string, \
    byte_array_mac_to_string


class Validator:

    @staticmethod
    def convert_options(options, fn, **kwargs):
        print(kwargs)
        if fn:
            return [fn(item, **kwargs) for item in options]
        return options

    @staticmethod
    def validate_field_in(value, exclude, include) -> bool:
        for exclude_item in exclude:
            if value in exclude_item:
                return False
        if include:
            for include_item in include:
                if value in include_item:
                    return True
            return False
        return True

    @staticmethod
    def validate_field_prefix(value: str, exclude, include) -> bool:
        for item in exclude:
            if value.startswith(item):
                return False
        if include:
            for item in include:
                if value.startswith(item):
                    return True
            return False
        return True

    @staticmethod
    def validate_field_suffix(value: str, exclude, include) -> bool:
        for item in exclude:
            if value.endswith(item):
                return False
        if include:
            for item in include:
                if value.endswith(item):
                    return True
            return False
        return True

    @staticmethod
    def validate_value_string_suffix(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_to_string(value)
        return Validator.validate_field_suffix(modified_value, exclude, include)

    @staticmethod
    def validate_value_string_prefix(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_to_string(value)
        return Validator.validate_field_prefix(modified_value, exclude, include)

    @staticmethod
    def validate_value_string_in(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def validate_value_int_in(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is int else byte_array_to_number(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def validate_value_mac_in(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_mac_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def validate_value_mac_suffix(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_mac_to_string(value)
        return Validator.validate_field_suffix(modified_value, exclude, include)

    @staticmethod
    def validate_value_mac_prefix(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_mac_to_string(value)
        return Validator.validate_field_prefix(modified_value, exclude, include)


    @staticmethod
    def convert_range(value, base=10):
        if type(value) is list:
            start = Validator.convert_number(value[0], base)
            end = Validator.convert_number(value[1], base)
            return range(start, end + 1)
        converted_value = Validator.convert_number(value, base)
        return range(converted_value, converted_value + 1)

    @staticmethod
    def convert_number_ranges(value, **kwargs):
        return Validator.convert_options(value, Validator.convert_range, **kwargs)

    @staticmethod
    def convert_number(value, base=10):
        if type(value) is str:
            return int(value, base=base)
        return value

    @staticmethod
    def ip_network_convert(value, **kwargs):
        return IPNetwork(value)

    @staticmethod
    def convert_ip_ranges(value, **kwargs):
        return Validator.convert_options(value, Validator.ip_network_convert, **kwargs)

    @staticmethod
    def validate_ip(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_ip_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def validate_mac(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_mac_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include)


    @staticmethod
    def no_transform(value, **kwargs):
        return value

