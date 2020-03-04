from helpers.pool import SharedPool


class Rule:

    pool: SharedPool

    def __init__(self, field, params, method, pool, logger):
        self.appearance = 0
        self.field = field
        self.field_path = self.parse_rule_path(field)
        self.field_path_for_shark = self.field_path[(len(self.field_path) -2):]
        self.params = params
        self.method = method
        self.pool = pool
        self.logger = logger

    def run_rule(self, value: bytearray):
        hex_value = value.hex()
        self.appearance += 1
        stored_value = self.pool.get_value(hex_value)
        if stored_value is not None:
            self.logger.log(self.field, hex_value, stored_value)
            return bytearray().fromhex(stored_value)
        modified_value = self.method(value, self.params['value'], self.params['exclude'], self.params['include'])
        modified_value_hex = modified_value.hex()
        self.logger.log(self.field, hex_value, modified_value_hex)
        self.pool.set_value(hex_value, modified_value_hex)
        return modified_value

    def unused(self):
        return self.appearance == 0

    def print_rule(self):
        print(f'\n{self.field}\nUsed: {self.appearance}\nPool:\n{self.pool.pool}')

    def parse_rule_path(self, field_path):
        path = field_path.split('.')
        path[-1] += '_raw'
        return path

