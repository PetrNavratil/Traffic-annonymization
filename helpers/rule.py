from helpers.pool import SharedPool


class Rule:

    pool: SharedPool
    DEFAULT_PARAMS = {
        'value': None,
        'exclude': [],
        'include': [],
        'additional': {}
    }

    def __init__(self, field, params, method, pool, logger, order):
        self.appearance = 0
        self.field = field
        self.field_path = self.parse_rule_path(field)
        self.field_path_for_shark = self.field_path[(len(self.field_path) -2):]
        self.params = self.validate_params(params)
        self.method = method
        self.pool = pool
        self.logger = logger
        self.order = order

    def run_rule(self, value: bytearray, file_info):
        hex_value = value.hex()
        self.appearance += 1
        stored_value = self.pool.get_value(hex_value)
        if stored_value is not None:
            print("FOUND")
            self.logger.log(self.field, hex_value, stored_value)
            return bytearray().fromhex(stored_value)
        modified_value = self.method(value, self.params['value'], self.params['exclude'], self.params['include'], {**file_info, **self.params['additional']})
        if modified_value is None:
            return None
        modified_value_hex = modified_value.hex()
        self.logger.log(self.field, hex_value, modified_value_hex)
        self.pool.set_value(hex_value, modified_value_hex)
        return modified_value

    def validate_params(self, params):
        return {**Rule.DEFAULT_PARAMS, **params}

    def unused(self):
        return self.appearance == 0

    def print_rule(self):
        print(f'\n{self.field}\nUsed: {self.appearance}\nPool:\n{self.pool.pool}')

    def parse_rule_path(self, field_path):
        path = field_path.split('.')
        path[-1] += '_raw'
        return path

