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