import binascii
import struct
import sys

from scapy.volatile import RandIP, RandMAC

from helpers.helpers import excluded_ip, string_mac_to_bytes, validate_string_field


class BasicModifier:

    # DEFAULT
    def default_number_marker(self, original_value, value, exclude, include):
        original_value_length = len(original_value)
        return bytearray(int(value).to_bytes(length=original_value_length, byteorder=sys.byteorder))

    def do_not_modify(self, original_value, value, exclude, include):
        print(self)
        return original_value

    def default_text_marker(self, original_value, value:str, exclude, include):
        return f'{value}'.encode('utf-8')

    def default_http_marker(self, original_value, value: str, exclude, include):
        return bytearray(validate_string_field(value, len(original_value), '\r\n').encode())

    def default_http_marker_preserve_prefix(self, original_value, value: str, exclude, include):
        decoded_value = original_value.decode()
        head, sep, tail = decoded_value.partition(': ')
        return bytearray(validate_string_field(head + sep + value, len(original_value), '\r\n').encode())

    def default_clear_all(self, original_value, value, exclude, include):
        return bytearray(len(original_value))

    # FRAME
    def default_time_marker(self, original_value, value: str, exclude, include):
        split_value = value.split('.')
        milliseconds, microseconds = split_value if len(split_value) == 2 else [split_value[0], '0']
        microseconds = microseconds.rstrip('0')
        microseconds = microseconds if microseconds != '' else '0'
        print(int().from_bytes(original_value[-4:], 'little'))
        print(float(value).hex())
        print(microseconds)
        print(binascii.hexlify(int(microseconds).to_bytes(4, sys.byteorder)))
        print(sys.byteorder)
        print(binascii.hexlify(bytearray(int(milliseconds).to_bytes(4, sys.byteorder) + int(microseconds).to_bytes(4, sys.byteorder, signed=False))))
        print(binascii.hexlify(original_value))
        return bytearray(int(milliseconds).to_bytes(4, sys.byteorder) + int(microseconds).to_bytes(4, sys.byteorder, signed=False))

    # ETH
    def eth_marker(self, eth, value, exclude, include):
        # fixed_random_mac = RandMAC()
        # fixed_random_ip = RandIP()
        return string_mac_to_bytes(value)

    # IP
    def ip_marker(self, ip, value: str, exclude, include):
        return bytearray(map(lambda val: int(val), value.split('.')))


