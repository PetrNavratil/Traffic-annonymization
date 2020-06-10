"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from helpers.helpers import HTTP_LINE_PREFIX_DELIMITER
from modifiers.http_text_marker import HttpTextMarker


class HttpTextMarkerPreservePrefix(HttpTextMarker):
    """
    Modifikator nahradi radek HTTP protokolu hodnotou definovanou jako `value` pravidla. Na konec dosadi \n\r, aby
    nebyl porusen HTTP format.
    Modifikator zachovava prefix HTTP protokolu - napr. `Host: `
    :value - nova hodnota radku
    Priklad:
    value: 'marker text'
    """

    def __init__(self):
        super().__init__()
        self.delimiter = HTTP_LINE_PREFIX_DELIMITER
