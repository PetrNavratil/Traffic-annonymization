from helpers.packet_field import PacketField


class FieldModification:

    def __init__(self, data, field: PacketField):
        self.data = data
        self.data_length = len(data)
        self.position = field.position
        self.field_path = field.field_path
        self.original_length = field.length

    def set_value(self, data):
        self.data = data
        self.data_length = len(data)

    def set_position(self, position):
        self.position = position

    def info(self):
        print(f'Modifying {self.field_path}, original len {self.original_length}, current {self.data_length}')
