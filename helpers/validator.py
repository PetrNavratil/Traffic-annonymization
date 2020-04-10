from netaddr import IPNetwork

from helpers.helpers import byte_array_ip_to_string, byte_array_to_number, byte_array_to_string, \
    byte_array_mac_to_string, ExcludeInclude


class Validator:

    @staticmethod
    def convert_options(options, fn, kwargs):
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
    def validate_in(value, options) -> bool:
        return value in options

    @staticmethod
    def validate_prefix(value, options) -> bool:
        for item in options:
            if value.startswith(item):
                return True
        return False

    @staticmethod
    def validate_suffix(value, options) -> bool:
        for item in options:
            if value.endswith(item):
                return True
        return False


    @staticmethod
    def validate_string_field(value: str, options: ExcludeInclude) -> bool:
        if options.validation == 'prefix':
            return Validator.validate_prefix(value, options.value)
        if options.validation == 'suffix':
            return Validator.validate_suffix(value, options.value)
        return Validator.validate_in(value, options.value)

    @staticmethod
    def validate_string(value, exclude: ExcludeInclude, include: ExcludeInclude, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_to_string(value)
        if exclude.value:
            if Validator.validate_string_field(modified_value, exclude):
                return False
        if include.value:
            return Validator.validate_string_field(modified_value, include)
        return True


    @staticmethod
    def validate_value_int_in(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is int else byte_array_to_number(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def validate_mac(value, exclude: ExcludeInclude, include: ExcludeInclude, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_mac_to_string(value)
        if exclude.value:
            if Validator.validate_string_field(modified_value, exclude):
                return False
        if include.value:
            return Validator.validate_string_field(modified_value, include)
        return True

    @staticmethod
    def convert_range(value, base=10):
        if type(value) is list:
            start = Validator.convert_number(value[0], base)
            end = Validator.convert_number(value[1], base)
            return range(start, end + 1)
        converted_value = Validator.convert_number(value, base)
        return range(converted_value, converted_value + 1)

    @staticmethod
    def convert_number(value, base=10):
        if type(value) is str:
            return int(value, base=base)
        return value

    @staticmethod
    def ip_network_convert(value, **kwargs):
        return IPNetwork(value)

    @staticmethod
    def validate_ip(value, exclude, include, **kwargs) -> bool:
        modified_value = value if type(value) is str else byte_array_ip_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def no_transform(value, **kwargs):
        return value

