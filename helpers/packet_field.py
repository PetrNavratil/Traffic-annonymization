import sys


class PacketField:

    def __init__(self, field):
        if len(field) != 5:
            print(f"WRONG PACKET {field}")
            sys.exit(1)
        self.original_value = field[0]
        self.position = field[1]
        self.length = field[2]
        self.bitmask = field[3]
        self.type = field[4]