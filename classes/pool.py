"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""


class SharedPool:

    def __init__(self, field, class_name):
        self.pool = {}
        self.used_by = field
        self.transform_method = None
        self.class_name = class_name

    def set_transform_method(self, method):
        self.transform_method = method

    def get_value(self, key):
        return self.pool.get(key)

    def set_value(self, key, value):
        self.pool.update([(key, value)])

    def append_field(self, field):
        self.used_by.append(field)

    def reset_pool(self):
        self.pool = {}

    def is_used(self, value: bytearray) -> bool:
        return value in self.pool.values()

    def transform(self, delimiter: str):
        data = {}
        for key, value in self.pool.items():
            prefix, valid_key = self.get_transformed_key(key, delimiter)
            transformed_key = self.transform_method(bytearray().fromhex(valid_key))
            data[prefix + str(transformed_key)] = self.transform_method(value)
        self.pool = data

    def get_transformed_key(self, key, delimiter):
        result = key.split(delimiter)
        if len(result) == 1:
            return '', result[0]
        result[0] += '|'
        return result
