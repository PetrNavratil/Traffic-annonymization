from helpers.helpers import HTTP_LINE_PREFIX_DELIMITER
from modifiers.http_text_marker import HttpTextMarker


class HttpTextMarkerPreservePrefix(HttpTextMarker):

    def __init__(self):
        super().__init__()
        self.delimiter = HTTP_LINE_PREFIX_DELIMITER
