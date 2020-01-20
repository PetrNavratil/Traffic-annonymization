
class BasicModifier:

    def ip_marker(self, ip, value, exclude):
        print('Calling ip marker')
        return value

    def ip_random(self, ip, value, exclude):
        print('Calling ip random')
        return ip

    def eth_marker(self, eth, value, exclude):
        print('Calling eth marker')
        return value

    def eth_random(self, eth, value, exclude):
        print('Calling eth random')
        return eth
