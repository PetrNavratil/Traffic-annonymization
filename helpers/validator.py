from socket import socket

from netaddr import IPNetwork

from helpers.helpers import byte_array_ip_to_string, byte_array_to_number


class Validator:

    @staticmethod
    def convert_options(options, fn, **kwargs):
        if fn:
            return [fn(item, **kwargs) for item in options]
        return options

    @staticmethod
    def validate_field_in(value, exclude, include, fn=None, **kwargs) -> bool:
        converted_exclude = Validator.convert_options(exclude, fn, **kwargs)
        for exclude_item in converted_exclude:
            if value in exclude_item:
                return False
        if include:
            converted_include = Validator.convert_options(include, fn, **kwargs)
            for include_item in converted_include:
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
    def validate_value_string_suffix(value: str, exclude, include, **kwargs) -> bool:
        return Validator.validate_field_suffix(value, exclude, include)

    @staticmethod
    def validate_value_string_prefix(value: str, exclude, include, **kwargs) -> bool:
        return Validator.validate_field_prefix(value, exclude, include)

    @staticmethod
    def validate_value_string_in(value, exclude, include, **kwargs) -> bool:
        return Validator.validate_field_in(value, exclude, include, **kwargs)

    @staticmethod
    def validate_value_int_in(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is int else byte_array_to_number(value)
        return Validator.validate_field_in(modified_value, exclude, include, Validator.convert_ranges, base=10)

    @staticmethod
    def convert_ranges(value, base):
        if type(value) is list:
            start = Validator.convert_number(value[0], base)
            end = Validator.convert_number(value[1], base)
            return range(start, end + 1)
        converted_value = Validator.convert_number(value, base)
        return range(converted_value, converted_value + 1)

    @staticmethod
    def convert_number(value, base):
        if type(value) is str:
            return int(value, base=base)
        return value

    @staticmethod
    def ip_network_convert(value, **kwargs):
        return IPNetwork(value)

    @staticmethod
    def validate_ip(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_ip_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include, Validator.ip_network_convert, **kwargs)