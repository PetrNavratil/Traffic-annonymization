from abc import ABC, abstractmethod
from typing import List


class CustomModifier(ABC):

    @abstractmethod
    def modify_field(self, original_value: bytearray, value, exclude: List, include: List) -> bytearray:
        pass
