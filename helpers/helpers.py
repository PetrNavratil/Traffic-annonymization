import random
import socket
import sys
from collections import namedtuple
from importlib import import_module
from typing import Tuple

from netaddr import IPNetwork
from scapy.utils import mac2str

from helpers.ip_class import IpClass
from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier
from logger.logger import Logger

from lorem.text import TextLorem

HTML_LINE_PREFIX_DELIMITER = ': '

Timestamp = namedtuple('Timestamp', ['seconds', 'decimal'])
MICROSECONDS_MAX = 1000000
NANOSECONDS_MAX = 1000000000


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


def ip_bytes_to_int(value: bytearray) -> int:
    # IP is always in big endien (network order)
    return int().from_bytes(value, 'big')


def ip_int_to_bytes(value: int) -> bytearray:
    return bytearray(value.to_bytes(4, 'big'))


def get_ip_class_range(first_octet: int):
    if first_octet in IpClass.A.value:
        return IpClass.A.value
    if first_octet in IpClass.B.value:
        return IpClass.B.value
    if first_octet in IpClass.C.value:
        return IpClass.C.value
    if first_octet in IpClass.D.value:
        return IpClass.D.value
    if first_octet in IpClass.E.value:
        return IpClass.E.value


def generate_random_number_in_range(interval) -> int:
    return random.randrange(interval.start, interval.stop)


def generate_random_bits(count) -> int:
    return random.getrandbits(count)


def parse_string_time(value: str, nano_resolution) -> Timestamp:
    split_value = value.split('.')
    seconds, decimal = split_value if len(split_value) == 2 else [split_value[0], '0']
    decimal = int(decimal) if decimal != '' else 0
    seconds = int(seconds)
    validate_time(decimal, nano_resolution)
    return Timestamp(seconds, decimal)


def time_stamp_to_byte_array(timestamp: Timestamp, byte_order) -> bytearray:
    return bytearray(timestamp.seconds.to_bytes(4, byte_order) + timestamp.decimal.to_bytes(4, byte_order, signed=False))


def byte_array_to_timestamp(value: bytearray, byte_order) -> Timestamp:
    seconds = int().from_bytes(value[0:4], byte_order)
    decimal = int().from_bytes(value[4:], byte_order)
    return Timestamp(seconds, decimal)


def validate_time(decimal: int, nano_resolution: bool):
    if nano_resolution:
        assert decimal < NANOSECONDS_MAX, 'Decimal part for nanoseconds file must be less than 1 000 000 000'
        return
    assert decimal < MICROSECONDS_MAX, 'Decimal part for microseconds file must be less than 1 000 000'


def correct_time_stamp_decimal(timestamp: Timestamp, nano_resolution: bool) -> Timestamp:
    if timestamp.decimal < 0:
        new_seconds = timestamp.seconds - 1
        assert new_seconds >= 0
        return Timestamp(new_seconds, (NANOSECONDS_MAX if nano_resolution else MICROSECONDS_MAX) + timestamp.decimal)
    else:
        if nano_resolution and timestamp.decimal >= NANOSECONDS_MAX:
            return Timestamp(timestamp.seconds + 1, timestamp.decimal - NANOSECONDS_MAX)
        if not nano_resolution and timestamp.decimal >= MICROSECONDS_MAX:
            return Timestamp(timestamp.seconds + 1, timestamp.decimal - MICROSECONDS_MAX)
    return timestamp


def increment_time_stamp(start: Timestamp, increment: Timestamp, nano_resolution: bool) -> Timestamp:
    new_seconds = start.seconds + increment.seconds
    new_decimal = start.decimal + increment.decimal
    return correct_time_stamp_decimal(Timestamp(new_seconds, new_decimal), nano_resolution)
