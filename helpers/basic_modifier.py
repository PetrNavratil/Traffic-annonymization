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

    # ETH
    def eth_marker(self, eth, value, exclude, include):
        # fixed_random_mac = RandMAC()
        # fixed_random_ip = RandIP()
        return string_mac_to_bytes(value)

    # IP
    def ip_marker(self, ip, value: str, exclude, include):
        return bytearray(map(lambda val: int(val), value.split('.')))


