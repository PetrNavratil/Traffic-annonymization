from modifiers.text_random import TextRandom


class HttpTextRandom(TextRandom):

    def __init__(self):
        super().__init__()
        self.suffix = '\r\n'
