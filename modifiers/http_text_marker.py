from modifiers.text_marker import TextMarker


class HttpTextMarker(TextMarker):
    """
    Modifikator nahradi radek HTTP protokolu hodnotou definovanou jako `value` pravidla. Na konec dosadi \n\r, aby
    nebyl porusen HTTP format
    :value - nova hodnota radku
    Priklad:
    value: 'marker text'
    """

    def __init__(self):
        super().__init__()
        self.suffix = '\r\n'
