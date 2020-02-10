class PacketField:

    def __init__(self, field):
        self.original_value = field[0]
        self.position = field[1]
        self.length = field[2]
        self.bitmask = field[3]
        self.type = field[4]