from scapy.volatile import RandIP, RandMAC

from helpers.helpers import excluded_ip


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

    # def default_marker(self, original, ):