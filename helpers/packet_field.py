import sys


class PacketField:

    # only valid field with position 0
    ETH_DST_PATH = 'eth.dst_raw'
    FRAME_TIME_PATH = 'frame.time_epoch_raw'

    def __init__(self, field, field_path=None, json_path=None):
        if len(field) != 5:
            print(f"WRONG PACKET {field}")
            sys.exit(1)
        self.field_path = field_path
        self.position = self.get_field(field[1])
        self.length = self.get_field(field[2])
        self.bitmask = self.get_field(field[3])
        self.type = self.get_field(field[4])
        self.is_segmented = False
        self.json_path = json_path
        self.frame_field = field_path == PacketField.FRAME_TIME_PATH

    def get_field(self, field):
        if field == 'None':
            return None
        return int(field)

    def get_field_value(self, packet_bytes):
        retrieved = packet_bytes[self.position:self.position+self.length]
        if self.has_mask():
            return self.__get_masked_value(retrieved)
        return retrieved

    def get_unmasked_field(self, packet_bytes):
        retrieved = packet_bytes[self.position:self.position+self.length]
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

    def validate_segmented_field(self, packet):
        if self.field_path.startswith('eth') or self.field_path.startswith('frame'):
            self.is_segmented = False
            return
        raw_field = packet
        print('raw', self.__get_raw_parent_field_path())
        for path in self.__get_raw_parent_field_path():
            raw_field = raw_field[path]
        self.is_segmented = self.get_field(raw_field[1]) == 0

    def __get_raw_parent_field_path(self):
        # path_copy = self.json_path.copy()
        # path_copy.reverse()
        # print('path', self.json_path)
        # for i, path in enumerate(path_copy):
        #     if type(path) is str:
        #         path_copy[i] += '_raw'
        #         break
        # path_copy.reverse()
        # return path_copy
        first_two = self.json_path[:2]
        if len(first_two) == 2:
            if type(first_two[1]) is int:
                first_two[0] += '_raw'
                return first_two
        first_two[0] += '_raw'
        return first_two[:1]
