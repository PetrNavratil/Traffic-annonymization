"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from netaddr import IPNetwork

from helpers.helpers import byte_array_ip_to_string, byte_array_to_number, byte_array_to_string, \
    byte_array_mac_to_string, ExcludeInclude


class Validator:

    @staticmethod
    def validate_string(value, exclude: ExcludeInclude, include: ExcludeInclude, **kwargs) -> bool:
        """
        Metoda pro validaci textoveho retezce
        :param value: hodnota
        :param exclude: polozka exclude
        :param include: polozka include
        :param kwargs:
        :return:
        """
        modified_value = value if type(value) is str else byte_array_to_string(value)
        if exclude.value:
            if Validator.validate_string_field(modified_value, exclude):
                return False
        if include.value:
            return Validator.validate_string_field(modified_value, include)
        return True

    @staticmethod
    def validate_value_int_in(value, exclude, include, **kwargs) -> bool:
        """
        Metoda pro validaci ciselneho atributu
        :param value: hodnota
        :param exclude: polozka exclude
        :param include: polozka include
        :param kwargs:
        :return:
        """
        modified_value = value if type(value) is int else byte_array_to_number(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def validate_mac(value, exclude: ExcludeInclude, include: ExcludeInclude, **kwargs) -> bool:
        """
        Metoda pro validaci MAC adresy. Lze uzit prefix i suffix validaci
        :param value: hodnota
        :param exclude: polozka exclude
        :param include: polozka include
        :param kwargs:
        :return:
        """
        modified_value = value if type(value) is str else byte_array_mac_to_string(value)
        if exclude.value:
            if Validator.validate_string_field(modified_value, exclude):
                return False
        if include.value:
            return Validator.validate_string_field(modified_value, include)
        return True

    @staticmethod
    def validate_ip(value, exclude, include, **kwargs) -> bool:
        """
        Validace, zda IP adresa spada do definovane site
        :param value: hodnota
        :param exclude: polozka exclude
        :param include: polozka include
        :param kwargs:
        :return:
        """
        modified_value = value if type(value) is str else byte_array_ip_to_string(value)
        return Validator.validate_field_in(modified_value, exclude, include)

    @staticmethod
    def convert_options(options, fn, kwargs):
        """
        Metoda slouzi pro transformaci hodnot exclude a include
        """
        if fn:
            return [fn(item, **kwargs) for item in options]
        return options

    @staticmethod
    def validate_field_in(value, exclude, include) -> bool:
        """
        Obecna metoda pro vyhodnoceni include a exclude
        """
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
        """
        Validace zda hodnota patri mezi zadane moznosti
        """
        return value in options

    @staticmethod
    def validate_prefix(value, options) -> bool:
        """
        Validace zda retezec zacina prefixem
        """
        for item in options:
            if value.startswith(item):
                return True
        return False

    @staticmethod
    def validate_suffix(value, options) -> bool:
        """
        Validace zda retezec konci suffixem
        """
        for item in options:
            if value.endswith(item):
                return True
        return False


    @staticmethod
    def validate_string_field(value: str, options: ExcludeInclude) -> bool:
        """
        Metoda pro validaci textoveho retezce
        :param value: retezec
        :param options: moznosti pro validaci -- obsah exclude nebo include
        :return:
        """
        if options.validation == 'prefix':
            return Validator.validate_prefix(value, options.value)
        if options.validation == 'suffix':
            return Validator.validate_suffix(value, options.value)
        return Validator.validate_in(value, options.value)


    @staticmethod
    def convert_range(value, base=10):
        """
        Funkce uzita pro transformaci cistelnych hodnot exclude a include
        :param value:
        :param base:
        :return:
        """
        if type(value) is list:
            start = Validator.__convert_number(value[0], base)
            end = Validator.__convert_number(value[1], base)
            return range(start, end + 1)
        converted_value = Validator.__convert_number(value, base)
        return range(converted_value, converted_value + 1)

    @staticmethod
    def __convert_number(value, base=10):
        if type(value) is str:
            return int(value, base=base)
        return value

    @staticmethod
    def ip_network_convert(value, **kwargs):
        """
        Konverzace IP adres na IP site
        :param value:
        :param kwargs:
        :return:
        """
        return IPNetwork(value)

    @staticmethod
    def no_transform(value, **kwargs):
        return value

