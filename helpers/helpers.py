import sys
from importlib import import_module
from typing import Tuple

from netaddr import IPNetwork
from scapy.utils import mac2str

from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier
from logger.logger import Logger

from lorem.text import TextLorem

HTML_LINE_PREFIX_DELIMITER = ': '


def load_modifier_class(class_name: str):
    class_str: str = f"modifiers.{class_name}"
    try:
        module_path, class_name = class_str.rsplit('.', 1)
        module = import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        print(f"Could not load class {class_str}", file=sys.stderr)
        print(f"Could not load class {e}", file=sys.stderr)
        sys.exit(1)


def load_ether_modifier(class_name: str, logger) -> EtherModifier:
    class_constructor = load_modifier_class(class_name)
    return class_constructor('Ether', logger)


def load_ip_modifier(class_name: str, logger) -> IPModifier:
    class_constructor = load_modifier_class(class_name)
    return class_constructor('IP', logger)


def create_modifier_class(class_name: str, protocol: str, logger: Logger):
    class_constructor = load_modifier_class(class_name)
    return class_constructor(protocol, logger)


def ip_in_range(ip, network_definition):
    ip_range = IPNetwork(network_definition)
    return ip in ip_range


def excluded_ip(value, exclude):
    for exclude_definition in exclude:
        if ip_in_range(value, exclude_definition):
            return True
    return False


def string_mac_to_bytes(string_mac):
    return mac2str(string_mac)


def validate_string_field(value: str, original_length, suffix=None):
    modified_field_length = len(value)
    if modified_field_length == original_length:
        return validate_string_suffix(value, suffix)
    if modified_field_length < original_length:
        return validate_string_suffix(value.ljust(original_length, value[-1]), suffix)
    else:
        return validate_string_suffix(value[:original_length], suffix)


def validate_string_suffix(value: str, suffix=None):
    if suffix is None:
        return value
    if value.endswith(suffix):
        return value
    return value[:-len(suffix)] + suffix


def generate_random_text(length: int) -> str:
    generator = TextLorem(srange=(3, 10))
    generated_text = ''
    while len(generated_text) < length:
        generated_text += generator.sentence()
    return generated_text[:length]


def string_to_bytearray(string: str) -> bytearray:
    return bytearray(string.encode())


def string_split_prefix(text, delimiter) -> Tuple[str, str]:
    decoded_text = text if type(text) is str else text.decode()
    head, sep, tail = decoded_text.partition(delimiter)
    return head+sep, tail


def generate_prefixed_random_text(text, delimiter) -> str:
    prefix, rest = string_split_prefix(text, delimiter)
    value = generate_random_text(len(rest))
    return prefix + value


def clear_byte_array(value: bytearray, start: int, end: int) -> bytearray:
    value_length = len(value)
    assert 0 <= start < value_length
    assert value_length >= end >= 0
    copied_value = value.copy()
    for i in range(start, end):
        copied_value[i] &= 0
    return copied_value


def clear_byte_array_prefix(value: bytearray, length: int) -> bytearray:
    return clear_byte_array(value, 0, length)


def clear_byte_array_suffix(value: bytearray, length: int) -> bytearray:
    return clear_byte_array(value, len(value) - length, len(value))


def create_byte_clear_mask(start: int, end: int) -> int:
    return int(''.join(['0' if item in range(start, end) else '1' for item in range(8)]), base=2)


def clear_byte_bits(value: bytearray, start: int, end: int) -> bytearray:
    value_length = len(value) * 8
    assert value_length == 8
    assert 0 <= start < value_length
    assert value_length >= end >= 0
    mask = create_byte_clear_mask(start, end)
    copied_value = value.copy()
    copied_value[0] &= mask
    return copied_value


def clear_byte_bits_prefix(value: bytearray, length: int) -> bytearray:
    return clear_byte_bits(value, 0, length)


def clear_byte_bits_suffix(value: bytearray, length: int) -> bytearray:
    return clear_byte_bits(value, 8 - length, 8)



