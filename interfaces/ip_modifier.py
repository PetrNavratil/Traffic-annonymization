from abc import ABC, abstractmethod


class IPModifier(ABC):

    ip_pool = {}

    @abstractmethod
    def modify_src(self, src: str) -> str:
        pass

    @abstractmethod
    def modify_dst(self, dst: str) -> str:
        pass

    @abstractmethod
    def retrieve_ip(self, ip: str) -> str:
        pass

