"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from modifiers.text_random import TextRandom


class HttpTextRandom(TextRandom):
    """
    Modifikator nahradi radek HTTP protokolu nahodnym retezcem. Na konec dosadi \n\r, aby
    nebyl porusen HTTP format
    """

    def __init__(self):
        super().__init__()
        self.suffix = '\r\n'
