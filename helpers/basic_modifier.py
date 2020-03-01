import sys

from scapy.volatile import RandIP, RandMAC

from helpers.helpers import excluded_ip, string_mac_to_bytes


class BasicModifier:

    def ip_marker(self, ip, value, exclude):
        if excluded_ip(ip, exclude):
            return ip
        return value

    def ip_random(self, ip, value, exclude):
        if excluded_ip(ip, exclude):
            return ip
        fixed_random_ip = RandIP()
        return str(fixed_random_ip)

    def eth_marker(self, eth, value, exclude):
        if excluded_ip(eth, exclude):
            return eth
        return value

    def eth_random(self, eth, value, exclude):
        if excluded_ip(eth, exclude):
            return eth
        fixed_random_mac = RandMAC()
        return str(fixed_random_mac)

    def eth_marker_shark(self, eth, value, exclude):
        return string_mac_to_bytes(value)

    def ip_marker_shark(self, ip, value: str, exclude):
        return bytearray(map(lambda val: int(val), value.split('.')))

    def default_marker(self, ip, value, exclude):
        print(value)
        return value

    def default_number_marker(self, original_value, value, exclude):
        original_value_length = len(original_value)
        return bytearray(int(value).to_bytes(length=original_value_length, byteorder=sys.byteorder))

    def dont_change(self, original_value, value, exclude):
        return original_value

    def default_text_marker(self, original_value, value:str, exclude):
        return f'{value}'.encode('utf-8')

    def default_http_marker(self, original_value, value: str, exclude):
        original_value_length = len(original_value)
        passed_value_length = len(value)
        copied_value = value[:len(original_value)] \
            if passed_value_length >= original_value_length \
            else value[:len(original_value)] + ''.join([' ' for _ in range(original_value_length - passed_value_length)])
        return (copied_value[:-2] + '\r\n').encode('utf-8')
