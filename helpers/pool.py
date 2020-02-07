class SharedPool:

    def __init__(self, field):
        self.field = field
        self.pool = {}

    def get_value(self, key):
        return self.pool.get(key)

    def set_value(self, key, value):
        self.pool.update([(key, value)])

    def print_pool(self):
        print(self.pool)

    def dump_pool(self):
        return {
            self.field: self.pool
        }
