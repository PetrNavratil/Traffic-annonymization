from modifiers.text_marker import TextMarker


class HttpTextMarker(TextMarker):

    def __init__(self):
        super().__init__()
        self.suffix = '\r\n'
