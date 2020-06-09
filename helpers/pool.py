
class SharedPool:

    def __init__(self, field, transform_method):
        self.pool = {}
        self.used_by = [field]
        self.transform_method = transform_method

    def get_value(self, key):
        return self.pool.get(key)

    def set_value(self, key, value):
        self.pool.update([(key, value)])

    def print_pool(self):
        print(self.pool)

    def dump_pool(self):
        return {
            ','.join(self.used_by): self.pool
        }

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
        return result
