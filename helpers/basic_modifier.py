import binascii
import socket
import struct
import sys
from yacryptopan import CryptoPAn
from random import getrandbits

from scapy.volatile import RandIP, RandMAC

from helpers.helpers import validate_string_field, generate_random_text, \
    string_to_byte_array, string_split_prefix, generate_prefixed_random_text, HTTP_LINE_PREFIX_DELIMITER, \
    generate_random_bits, generate_random_number_in_range, get_ip_class_range, parse_string_time, validate_time, \
    time_stamp_to_byte_array, Timestamp, increment_time_stamp, byte_array_to_timestamp, \
    string_to_length_label_byte_array, number_to_byte_array, byte_array_to_string, \
    label_byte_array_to_array_length_value_tuples, convert_length_value_tuple, dns_cname_byte_array_to_string, \
    dns_cname_string_to_byte_array, load_modifier_class, byte_array_to_number, generate_32bit_mask, \
    generate_random_k_prefixed_or_suffixed_ip, generate_marked_k_prefixed_or_suffixed_ip, random_port_from_its_category, \
    string_mac_to_byte_array
from helpers.validator import Validator


class BasicModifier:

    def __init__(self):
        self.crypto_pan = CryptoPAn('32-char-str-for-AES-key-and-pad.'.encode())
        self.start_timestamp = None
        self.timestamp_increment = None

    # # DEFAULT
    # def default_number_marker(self, original_value, value, exclude, include, validator, additional_parameters):
    #     parsed_value = byte_array_to_number(original_value)
    #     if Validator.validate_value_int_in(parsed_value, exclude, include):
    #         return number_to_byte_array(int(value), len(original_value))
    #     return None

    def do_not_modify(self, original_value, value, exclude, include, validator, additional_parameters):
        return original_value

    # def default_text_marker(self, original_value, value:str, exclude, include, validator, additional_parameters):
    #     return string_to_byte_array(validate_string_field(value, len(original_value)))

    def dns_query_name_marker(self, original_value, value:str, exclude, include, validator, additional_parameters):
        cname = dns_cname_byte_array_to_string(original_value)
        # print(validator)
        validate = getattr(Validator, validator) if validator is not None else Validator.validate_value_string_in
        if validate(cname, exclude, include, base='hexa'):
            # print(cname)
            return dns_cname_string_to_byte_array(validate_string_field(value, len(original_value)))
        return None

    # def random_text(self, original_value, value:str, exclude, include, validator, additional_parameters):
    #     return string_to_byte_array(generate_random_text(len(original_value)))

    # def http_random_text(self, original_value, value:str, exclude, include, validator, additional_parameters):
    #     return string_to_byte_array(validate_string_field(generate_random_text(len(original_value)), len(original_value), '\r\n'))

    # def random_text_preserve_prefix(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     value = generate_prefixed_random_text(original_value, HTTP_LINE_PREFIX_DELIMITER)
    #     return string_to_byte_array(value)

    # def default_http_marker(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     return bytearray(validate_string_field(value, len(original_value), '\r\n').encode())

    # def http_random_text_preserve_prefix(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     value = generate_prefixed_random_text(original_value, HTTP_LINE_PREFIX_DELIMITER)
    #     return string_to_byte_array(validate_string_field(value, len(original_value), '\r\n'))

    # def default_http_marker_preserve_prefix(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     prefix, rest = string_split_prefix(original_value, HTTP_LINE_PREFIX_DELIMITER)
    #     return string_to_byte_array(validate_string_field(prefix + value, len(original_value), '\r\n'))

    # def default_clear_all(self, original_value, value, exclude, include, validator, additional_parameters):
    #     return bytearray(len(original_value))

    # FRAME
    # def default_time_marker(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     # if additional_parameters['packet'] != additional_parameters['packet_index']:
    #     #     return None
    #     timestamp = parse_string_time(value, additional_parameters['nano_resolution'])
    #     return time_stamp_to_byte_array(timestamp, additional_parameters['endianness'])

    # def time_stamp_increment(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     if self.timestamp_increment is None:
    #         self.timestamp_increment = parse_string_time(value, additional_parameters['nano_resolution'])
    #     original_time_stamp = byte_array_to_timestamp(original_value, additional_parameters['endianness'])
    #     new_time_stamp = increment_time_stamp(original_time_stamp, self.timestamp_increment, additional_parameters['nano_resolution'])
    #     return time_stamp_to_byte_array(new_time_stamp, additional_parameters['endianness'])

    # def time_stamp_clear_and_increment(self, original_value, value: str, exclude, include, validator, additional_parameters):
    #     if self.start_timestamp is None:
    #         self.start_timestamp = Timestamp(0,0)
    #         self.timestamp_increment = parse_string_time(value, additional_parameters['nano_resolution'])
    #     self.start_timestamp = increment_time_stamp(self.start_timestamp, self.timestamp_increment, additional_parameters['nano_resolution'])
    #     return time_stamp_to_byte_array(self.start_timestamp, additional_parameters['endianness'])

    # ETH
    def eth_marker(self, eth, value, exclude, include, validator, additional_parameters):
        # fixed_random_mac = RandMAC()
        # fixed_random_ip = RandIP()
        return string_mac_to_byte_array(value)

    # IP
    # def ip_marker(self, ip, value: str, exclude, include, validator, additional_parameters):
    #     if Validator.validate_ip(ip, exclude, include):
    #         return bytearray(socket.inet_aton(value))
    #     return None

    # def ip_prefix_preservation(self, ip, value: str, exclude, include, validator, additional_parameters):
    #     return bytearray(socket.inet_aton(self.crypto_pan.anonymize(socket.inet_ntoa(ip))))

    # def ip_random(self, ip, value: str, exclude, include, validator, additional_parameters):
    #     random_bits: int = getrandbits(32)
    #     return random_bits.to_bytes(4, sys.byteorder)

    # def ip_random_preserve_class_octet(self, ip, value: str, exclude, include, validator, additional_parameters):
    #     random_bits = bytearray(generate_random_bits(24).to_bytes(3, 'little'))
    #     copied_ip = ip.copy()
    #     copied_ip[1:] = random_bits
    #     return copied_ip

    # def ip_random_preserve_class(self, ip, value: str, exclude, include, validator, additional_parameters):
    #     random_bits = bytearray(generate_random_bits(24).to_bytes(3, 'little'))
    #     first_octet_randomized = generate_random_number_in_range(get_ip_class_range(ip[0]))
    #     randomized_ip = bytearray(4)
    #     randomized_ip[0] = first_octet_randomized
    #     randomized_ip[1:] = random_bits
    #     return randomized_ip

    # def ip_random_preserve_n_prefix(self, ip, value, exclude, include, validator, additional_parameters):
    #     if Validator.validate_ip(ip, exclude, include):
    #         return generate_random_k_prefixed_or_suffixed_ip(ip, int(value), prefix=True)
    #     return None

    # def ip_random_preserve_n_suffix(self, ip, value, exclude, include, validator, additional_parameters):
    #     if Validator.validate_ip(ip, exclude, include):
    #         return generate_random_k_prefixed_or_suffixed_ip(ip, int(value), prefix=False)
    #     return None

    # def ip_marker_preserve_n_prefix(self, ip, value, exclude, include, validator, additional_parameters):
    #     if Validator.validate_ip(ip, exclude, include):
    #         return generate_marked_k_prefixed_or_suffixed_ip(ip, value['preserve_length'], value['value'], prefix=True)
    #     return None

    def ip_marker_preserve_n_suffix(self, ip, value, exclude, include, validator, additional_parameters):
        if Validator.validate_ip(ip, exclude, include):
            return generate_marked_k_prefixed_or_suffixed_ip(ip, value['preserve_length'], value['value'], prefix=False)
        return None

    # def port_random_preserve_group(self, port, value, exclude, include, validator, additional_parameters):
    #     if Validator.validate_value_int_in(port, exclude, include):
    #         return random_port_from_its_category(port)
    #     return None




