from classes.pool import SharedPool
from interfaces.modifier import Modifier


class Rule:

    STREAM_KEY_DELIMITER = '++E++'

    pool: SharedPool
    DEFAULT_PARAMS = {
        'value': None,
        'exclude': [],
        'include': [],
        'validator': None,
        'additional': {},
        'stream_unique': False
    }

    def __init__(self, field, rule, method: Modifier, pool: SharedPool, order):
        self.appearance = 0
        self.field = field
        self.field_path = self.parse_rule_path(field)
        self.params = self.validate_params(rule)
        self.method = method
        self.pool = pool
        self.order = order
        self.method.transform_exclude_include(self.params['exclude'], self.params['include'], self.params['additional'])

    def run_rule(self, value: bytearray, udp_stream_index, tcp_stream_index, file_info):
        self.appearance += 1
        if not self.method.validate_field(value, {**file_info, **self.params['additional']}):
            return None
        hex_value = value.hex()
        lookup_value = self.get_lookup_value(hex_value, udp_stream_index, tcp_stream_index)
        print('look', lookup_value)
        stored_value = self.pool.get_value(lookup_value)
        if stored_value is not None:
            # print("FOUND")
            # self.logger.log(self.field, hex_value, stored_value)
            # TODO: validate, might cause problems as its not immutable
            return stored_value
        while True:
            modified_value = self.method.modify_field(value, self.params['value'], {**file_info, **self.params['additional']})
            if modified_value is None:
                return None
            # mozna by bylo lepsi nenechavat to v tomto pripade unique, aby to zmatlo
            if self.params['stream_unique']:
                break
            if self.method.unique and self.pool.is_used(modified_value):
                continue
            else:
                break
        self.pool.set_value(lookup_value, modified_value)
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

    def get_lookup_value(self, value, udp_stream_index, tcp_stream_index):
        if self.params['stream_unique']:
            udp = udp_stream_index if udp_stream_index is not None else ''
            tcp = tcp_stream_index if tcp_stream_index is not None else ''
            return f'u:{udp}t:{tcp}{Rule.STREAM_KEY_DELIMITER}{value}'
        return value

