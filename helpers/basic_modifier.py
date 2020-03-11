import sys

from scapy.volatile import RandIP, RandMAC

from helpers.helpers import excluded_ip, string_mac_to_bytes


class BasicModifier:

    # DEFAULT
    def default_number_marker(self, original_value, value, exclude, include):
        original_value_length = len(original_value)
        return bytearray(int(value).to_bytes(length=original_value_length, byteorder=sys.byteorder))

    def do_not_modify(self, original_value, value, exclude, include):
        return original_value

    def default_text_marker(self, original_value, value:str, exclude, include):
        return f'{value}'.encode('utf-8')

    def default_http_marker(self, original_value, value: str, exclude, include):
        original_value_length = len(original_value)
        passed_value_length = len(value)
        copied_value = value[:len(original_value)] \
            if passed_value_length >= original_value_length \
            else value[:len(original_value)] + ''.join([' ' for _ in range(original_value_length - passed_value_length)])
        return (copied_value[:-2] + '\r\n').encode('utf-8')

    def default_clear_all(self, original_value, value, exclude, include):
        print(len(original_value))
        return bytearray(len(original_value))

    # ETH
    def eth_marker(self, eth, value, exclude, include):
        # fixed_random_mac = RandMAC()
        # fixed_random_ip = RandIP()
        return string_mac_to_bytes(value)

    # IP
    def ip_marker(self, ip, value: str, exclude, include):
        return bytearray(map(lambda val: int(val), value.split('.')))


