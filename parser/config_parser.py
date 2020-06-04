import argparse
import yaml

from parser.tcp_stream_enum import TcpStream


class ConfigParser:

    config = {}
    verbose = False

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--config', required=True)
        parser.add_argument('--files', nargs='+', help='Files for the anonymization', required=True)
        arguments = vars(parser.parse_args())
        self.config = ConfigParser.__load_config_file(arguments['config'])
        self.verbose = self.config['verbose'] if 'verbose' in self.config else self.verbose
        self.reset_pools = self.config['reset_pools'] if 'reset_pools' in self.config else False
        self.tpc_stream_strategy = self.config['tcp_stream'] if 'tcp_stream' in self.config else TcpStream.CLEAR
        self.generate_meta_files = self.config['generate_meta_files'] if 'generate_meta_files' in self.config else False
        self.search_all_protocols = self.config['search_all_protocols'] if 'search_all_protocols' in self.config else False
        assert self.tpc_stream_strategy in [item.value for item in TcpStream]
        self.file_names = arguments['files']

    @staticmethod
    def __load_config_file(config_path: str):
        with open(config_path, mode='r') as f:
            doc = yaml.load(f, yaml.FullLoader)
            return doc

    def get_rules_config(self):
        return self.config['rules']