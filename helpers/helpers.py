import random
import socket
import sys
from collections import namedtuple
from importlib import import_module
from typing import Tuple, Union, List

from netaddr import IPNetwork
from scapy.utils import mac2str

from helpers.ip_class import IpClass
from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier
from logger.logger import Logger

from lorem.text import TextLorem

HTML_LINE_PREFIX_DELIMITER = ': '

Timestamp = namedtuple('Timestamp', ['seconds', 'decimal'])
LengthValue = namedtuple('LengthValue', ['length', 'value'])
MICROSECONDS_MAX = 1000000
NANOSECONDS_MAX = 1000000000
WELL_KNOWN_PORTS = range(0, 1024)
REGISTERED_PORTS = range(1024, 49152)
DYNAMIC_PORTS = range(49152, 65535)


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


def string_mac_to_bytes(string_mac):
    return mac2str(string_mac)


def validate_string_field(value: str, original_length, suffix=None, prefix=None):
    modified_field_length = len(value)
    if modified_field_length == original_length:
        return validate_string_prefix_suffix(value, suffix, prefix)
    if modified_field_length < original_length:
        return validate_string_prefix_suffix(value.ljust(original_length, value[-1]), suffix, prefix)
    else:
        return validate_string_prefix_suffix(value[:original_length], suffix, prefix)


def string_to_length_label_byte_array(value: str, delimiter: str):
    labels = value.split(delimiter)
    final_array = bytearray(len(value))
    available_length = len(value) - 1
    array_index = 0
    for label in labels:
        write_length = min((len(label) , available_length - array_index - 1))
        final_array[array_index] = write_length
        array_index += 1
        final_array[array_index: array_index + write_length] = label.encode()[:write_length]
        array_index += write_length
    final_array[-1] = 0
    return final_array


def label_byte_array_to_array_length_value_tuples(value: bytearray, convert_fn=None) -> Union[List[LengthValue], None]:
    if len(value) == 0:
        return None
    index = 1
    length = value[0]
    output = []
    while length > 0 and index < len(value):
        data = value[index: index + length]
        data = data if convert_fn is None else convert_fn(data)
        output.append(LengthValue(length, data))
        index += length
        if index >= len(value):
            break
        length = value[index]
        index += 1
    return output


def convert_length_value_tuple(value: LengthValue, convert_type, encoding='utf-8', byte_order='big'):
    if convert_type is int:
        return value.value.to_bytes(value.length, byte_order)
    if convert_type is str:
        return value.value.decode(encoding)
    return value.value


def dns_cname_string_to_byte_array(value: str) -> bytearray:
    return string_to_length_label_byte_array(value, '.')


def dns_cname_byte_array_to_string(value: bytearray) -> str:
    label_tuples = label_byte_array_to_array_length_value_tuples(value)
    return '.'.join([convert_length_value_tuple(label, str) for label in label_tuples])


def byte_array_to_string(value: bytearray):
    return value.decode()


def number_to_byte_array(value: int, byte_count: int, order='big'):
    return bytearray(value.to_bytes(byte_count, order))


def byte_array_to_number(value: bytearray, order='big'):
    return int().from_bytes(value, order)


def validate_string_prefix_suffix(value: str, suffix=None, prefix=None):
    return validate_string_suffix(validate_string_prefix(value, prefix), suffix)


def validate_string_prefix(value: str, prefix=None):
    if prefix is None:
        return value
    if value.startswith(prefix):
        return value
    return prefix + value[:-len(prefix)]


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


def string_to_byte_array(string: str) -> bytearray:
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


def string_ip_to_byte_array(ip: str) -> bytearray:
    return bytearray(socket.inet_aton(ip))


def byte_array_ip_to_string(ip: bytearray) -> str:
    return socket.inet_ntoa(ip)


def generate_32bit_mask(length: int, prefix: bool):
    if length == 0:
        return 0
    bit_mask = ''.join(['1' for _ in range(length)])
    if prefix:
        return int(bit_mask.ljust(32, '0'), base=2)
    else:
        return int(bit_mask, base=2)


def generate_random_k_prefixed_or_suffixed_ip(value: bytearray, length: int, prefix: bool) -> bytearray:
    ip = ip_bytes_to_int(value)
    if prefix:
        random_bits = generate_random_bits(32 - length)
        mask = generate_32bit_mask(length, True)
        return ip_int_to_bytes((ip & mask) | random_bits)
    else:
        random_bits = generate_random_bits(32)
        mask = generate_32bit_mask(32 - length, True)
        ip_mask = generate_32bit_mask(length, False)
        return ip_int_to_bytes((random_bits & mask) | (ip & ip_mask))


def generate_marked_k_prefixed_or_suffixed_ip(value: bytearray, length: int, marker, prefix: bool) -> bytearray:
    ip = ip_bytes_to_int(value)
    transformed_marker = parse_partial_ip(marker)
    assert 32 - length >= transformed_marker.bit_length(), "Marker length is larger than preserving length"
    if prefix:
        mask = generate_32bit_mask(length, True)
        print(f'mask {mask:b}')
        return ip_int_to_bytes((ip & mask) | transformed_marker)
    else:
        ip_mask = generate_32bit_mask(length, False)
        return ip_int_to_bytes((transformed_marker << length) | (ip & ip_mask))


def parse_partial_ip(value) -> int:
    if type(value) is int:
        return value
    split_values = [int(item) for item in value.split('.')]
    partial = 0
    number_of_values = len(split_values)
    for i, split_value in enumerate(split_values):
        partial += split_value * (256 ** (number_of_values - i - 1))
    return partial


def get_port_range(port: int):
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS
    if port in REGISTERED_PORTS:
        return REGISTERED_PORTS
    return DYNAMIC_PORTS


def random_port_from_its_category(port) -> bytearray:
    transformed_port = port if type(port) is int else byte_array_to_number(port)
    port_range = get_port_range(transformed_port)
    return number_to_byte_array(generate_random_number_in_range(port_range), 2)