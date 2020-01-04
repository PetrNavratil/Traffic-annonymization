from abc import ABC, abstractmethod


class EtherModifier(ABC):

    @abstractmethod
    def modify_dst(self, dst: str) -> str:
        pass

    @abstractmethod
    def modify_src(self, src: str) -> str:
        pass

