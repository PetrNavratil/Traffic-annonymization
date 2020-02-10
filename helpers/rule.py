from helpers.pool import SharedPool


class Rule:

    pool: SharedPool

    def __init__(self, field, params, method, pool, logger):
        self.appearance = 0
        self.field = field
        self.field_path = field.split('.')
        self.field_path_for_shark = self.field_path[(len(self.field_path) -2):]
        self.params = params
        self.method = method
        self.pool = pool
        self.logger = logger

    def run_rule(self, value):
        self.appearance += 1
        stored_value = self.pool.get_value(value)
        if stored_value is not None:
            self.logger.log(self.field, value, stored_value)
            return stored_value
        modified_value = self.method(value, self.params['value'], self.params['exclude'])
        self.logger.log(self.field, value, modified_value)
        self.pool.set_value(value, modified_value)
        return modified_value

    def unused(self):
        return self.appearance == 0

    def print_rule(self):
        print(f'\n{self.field}\nUsed: {self.appearance}\nPool:\n{self.pool.pool}')
