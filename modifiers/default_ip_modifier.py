from logger.logger import Logger
from interfaces.ip_modifier import IPModifier


class DefaultIPModifier(IPModifier):

    def __init__(self, logger: Logger):
        self.logger = logger

    def modify_src(self, src: str):
        value = self.retrieve_ip(src)
        self.logger.log('IP_src', src, value)
        return value

    def modify_dst(self, dst: str):
        value = self.retrieve_ip(dst)
        self.logger.log('IP_dst', dst, value)
        return value

    def retrieve_ip(self, ip: str):
        if ip in self.ip_pool:
            return self.ip_pool[ip]
        else:
            self.ip_pool[ip] = '255.255.255.255'
            return '255.255.255.255'
