import sys


class PacketField:

    def __init__(self, field):
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

    def get_field_value(self, packet_bytes):
        retrieved = packet_bytes[self.position:self.position+self.length]
        if self.has_mask():
            return self.__get_masked_value(retrieved)
        return retrieved

    def shift_count(self):
        reversed_string_mask = f'{self.bitmask:b}'[::-1]
        count = 0
        for mask_bit in reversed_string_mask:
            if mask_bit == '1':
                break
            count += 1
        return count

    def __get_masked_value(self, value):
        mask_shift = self.shift_count()
        unmasked_value = value[0] & self.bitmask
        shifted_value = unmasked_value >> mask_shift
        result = bytearray(1)
        result[0] = shifted_value
        return result

    def get_complementary_mask(self):
        return self.bitmask ^ 255

    def has_mask(self):
        return self.bitmask != 0
