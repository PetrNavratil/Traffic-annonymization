from helpers.packet_field import PacketField


class FieldModification:

    def __init__(self, data, field: PacketField):
        self.data = data
        self.data_length = len(data)
        self.position = field.position
        self.original_position = field.position
        self.field_path = field.field_path
        self.original_length = field.length
        self.frame_modification = field.frame_field

    def set_value(self, data):
        self.data = data
        self.data_length = len(data)

    def set_position(self, position):
        self.position = position

    def info(self):
        print(f'Modifying {self.field_path}, position {self.position}, original pos {self.original_position}, '
              f'original len {self.original_length}, current {self.data_length}, frame field {self.frame_modification}')
