from classes.packet_field import PacketField


class FieldModification:

    def __init__(self, data, field: PacketField, rule_order):
        self.data = data
        self.data_length = len(data)
        self.position = field.position
        self.original_position = field.position
        self.field_path = field.field_path
        self.original_length = field.length
        self.frame_modification = field.frame_field
        self.rule_order = rule_order

    def set_value(self, data):
        self.data = data
        self.data_length = len(data)

    def set_position(self, position):
        self.position = position

