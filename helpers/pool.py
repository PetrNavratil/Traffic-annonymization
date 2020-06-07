class SharedPool:

    def __init__(self, field):
        self.pool = {}
        self.used_by = [field]

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

    def transform(self):
        for key, value in self.pool.items():
            self.pool[key] = value.hex()