import binascii
import socket
import struct
import sys
from yacryptopan import CryptoPAn
from random import getrandbits

from scapy.volatile import RandIP, RandMAC

from helpers.helpers import excluded_ip, string_mac_to_bytes, validate_string_field, generate_random_text, \
    string_to_bytearray, string_split_prefix, generate_prefixed_random_text, HTML_LINE_PREFIX_DELIMITER, \
    generate_random_bits, generate_random_number_in_range, get_ip_class_range, parse_string_time, validate_time


class BasicModifier:

    def __init__(self):
        self.crypto_pan = CryptoPAn('32-char-str-for-AES-key-and-pad.'.encode())

    # DEFAULT
    def default_number_marker(self, original_value, value, exclude, include, additional_parameters):
        original_value_length = len(original_value)
        return bytearray(int(value).to_bytes(length=original_value_length, byteorder=sys.byteorder))

    def do_not_modify(self, original_value, value, exclude, include, additional_parameters):
        return original_value

    def default_text_marker(self, original_value, value:str, exclude, include, additional_parameters):
        return f'{value}'.encode('utf-8')

    def random_text(self, original_value, value:str, exclude, include, additional_parameters):
        return generate_random_text(len(original_value)).encode('utf-8')

    def http_random_text(self, original_value, value:str, exclude, include, additional_parameters):
        return string_to_bytearray(validate_string_field(generate_random_text(len(original_value)), len(original_value), '\r\n'))

    def default_http_marker(self, original_value, value: str, exclude, include, additional_parameters):
        return bytearray(validate_string_field(value, len(original_value), '\r\n').encode())

    def http_random_text_preserve_prefix(self, original_value, value: str, exclude, include, additional_parameters):
        value = generate_prefixed_random_text(original_value, HTML_LINE_PREFIX_DELIMITER)
        return string_to_bytearray(validate_string_field(value, len(original_value), '\r\n'))

    def default_http_marker_preserve_prefix(self, original_value, value: str, exclude, include, additional_parameters):
        prefix, rest = string_split_prefix(original_value, HTML_LINE_PREFIX_DELIMITER)
        return string_to_bytearray(validate_string_field(prefix + value, len(original_value), '\r\n'))

    def default_clear_all(self, original_value, value, exclude, include, additional_parameters):
        return bytearray(len(original_value))

    # FRAME
    def default_time_marker(self, original_value, value: str, exclude, include, additional_parameters):
        # print('ADD', additional_parameters)
        # split_value = value.split('.')
        # milliseconds, microseconds = split_value if len(split_value) == 2 else [split_value[0], '0']
        # microseconds = microseconds.rstrip('0')
        # microseconds = microseconds if microseconds != '' else '0'
        # print(int().from_bytes(original_value[-4:], 'little'))
        # print(float(value).hex())
        # print(microseconds)
        # print(binascii.hexlify(int(microseconds).to_bytes(4, sys.byteorder)))
        # print(sys.byteorder)
        # print(binascii.hexlify(bytearray(int(milliseconds).to_bytes(4, sys.byteorder) + int(microseconds).to_bytes(4, sys.byteorder, signed=False))))
        # print(binascii.hexlify(original_value))
        seconds, microseconds = parse_string_time(value)
        validate_time(microseconds, additional_parameters['nano_resolution'])
        byte_order = additional_parameters['endianness']
        return bytearray(int(seconds).to_bytes(4, byte_order) + int(microseconds).to_bytes(4, byte_order, signed=False))

    # ETH
    def eth_marker(self, eth, value, exclude, include, additional_parameters):
        # fixed_random_mac = RandMAC()
        # fixed_random_ip = RandIP()
        return string_mac_to_bytes(value)

    # IP
    def ip_marker(self, ip, value: str, exclude, include, additional_parameters):
        return bytearray(socket.inet_aton(value))

    def ip_prefix_preservation(self, ip, value: str, exclude, include, additional_parameters):
        return bytearray(socket.inet_aton(self.crypto_pan.anonymize(socket.inet_ntoa(ip))))

    def ip_random(self, ip, value: str, exclude, include, additional_parameters):
        random_bits: int = getrandbits(32)
        return random_bits.to_bytes(4, sys.byteorder)

    def ip_random_preserve_class_octet(self, ip, value: str, exclude, include, additional_parameters):
        random_bits = bytearray(generate_random_bits(24).to_bytes(3, 'little'))
        copied_ip = ip.copy()
        copied_ip[1:] = random_bits
        return copied_ip

    def ip_random_preserve_class(self, ip, value: str, exclude, include, additional_parameters):
        random_bits = bytearray(generate_random_bits(24).to_bytes(3, 'little'))
        first_octet_randomized = generate_random_number_in_range(get_ip_class_range(ip[0]))
        randomized_ip = bytearray(4)
        randomized_ip[0] = first_octet_randomized
        randomized_ip[1:] = random_bits
        return randomized_ip




