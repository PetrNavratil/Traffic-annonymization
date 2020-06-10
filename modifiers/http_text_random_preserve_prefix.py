from helpers.helpers import HTTP_LINE_PREFIX_DELIMITER
from modifiers.http_text_random import HttpTextRandom


class HttpTextRandomPreservePrefix(HttpTextRandom):
    """
    Modifikator nahradi radek HTTP protokolu nahodnou hodnotou. Na konec dosadi \n\r, aby
    nebyl porusen HTTP format.
    Modifikator zachovava prefix HTTP protokolu - napr. `Host: `
    :value - nova hodnota radku
    Priklad:
    value: 'marker text'
    """

    def __init__(self):
        super().__init__()
        self.delimiter = HTTP_LINE_PREFIX_DELIMITER
