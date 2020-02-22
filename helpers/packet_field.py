import sys


class PacketField:

    def __init__(self, field):
        # print(field)
        if len(field) != 5:
            print(f"WRONG PACKET {field}")
            sys.exit(1)
        self.original_value = field[0]
        self.position = self.get_field(field[1])
        self.length = self.get_field(field[2])
        self.bitmask = self.get_field(field[3])
        self.type = self.get_field(field[4])
        if self.is_invalid():
            print('ERROR FIELD')

    def get_field(self, field):
        if field == 'None':
            return None
        return int(field)

    def is_invalid(self):
        return self.position is None or self.length is None
