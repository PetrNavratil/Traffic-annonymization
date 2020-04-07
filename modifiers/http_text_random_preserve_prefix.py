from helpers.helpers import HTTP_LINE_PREFIX_DELIMITER
from modifiers.http_text_random import HttpTextRandom


class HttpTextRandomPreservePrefix(HttpTextRandom):

    def __init__(self):
        super().__init__()
        self.delimiter = HTTP_LINE_PREFIX_DELIMITER
