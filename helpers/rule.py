from helpers.pool import SharedPool
from interfaces.modifier import Modifier


class Rule:

    pool: SharedPool
    DEFAULT_PARAMS = {
        'value': None,
        'exclude': [],
        'include': [],
        'validator': None,
        'additional': {}
    }

    def __init__(self, field, params, method: Modifier, pool: SharedPool, logger, order):
        self.appearance = 0
        self.field = field
        self.field_path = self.parse_rule_path(field)
        self.params = self.validate_params(params)
        self.method = method
        self.pool = pool
        self.logger = logger
        self.order = order
        self.method.transform_exclude_include(self.params['exclude'], self.params['include'], self.params['additional'])

    def run_rule(self, value: bytearray, file_info):
        self.appearance += 1
        if not self.method.validate_field(value, {**file_info, **self.params['additional']}):
            return None
        hex_value = value.hex()
        stored_value = self.pool.get_value(hex_value)
        if stored_value is not None:
            # print("FOUND")
            self.logger.log(self.field, hex_value, stored_value)
            # TODO: validate, might cause problems as its not immutable
            return stored_value
        while True:
            modified_value = self.method.modify_field(value, self.params['value'], {**file_info, **self.params['additional']})
            if modified_value is None:
                return None
            if self.method.unique and self.pool.is_used(modified_value):
                continue
            else:
                break
        modified_value_hex = modified_value.hex()
        self.logger.log(self.field, hex_value, modified_value_hex)
        self.pool.set_value(hex_value, modified_value)
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

