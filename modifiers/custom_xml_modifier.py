from typing import List, Union

from helpers.helpers import validate_string_field
from interfaces.custom_modifier import CustomModifier


class CustomXMLModifier(CustomModifier):

    def modify_field(self, original_value: bytearray, value: Union[str, int], exclude: List, include: List) -> bytearray:
        decoded_value = original_value.decode()
        if decoded_value.startswith('X-Powered-By'):
            modified_value = validate_string_field(value, len(original_value), '\r\n')
            return bytearray(modified_value.encode())
        return original_value
