import argparse
import yaml


class ConfigParser:

    config = {}
    verbose = True

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--config')
        arguments = vars(parser.parse_args())
        self.config = ConfigParser.__load_config_file(arguments['config'])
        self.verbose = self.config['verbose'] if 'verbose' in self.config else self.verbose
        self.file_names = self.config['files']

    @staticmethod
    def __load_config_file(config_path: str):
        with open(config_path, mode='r') as f:
            doc = yaml.load(f, yaml.FullLoader)
            return doc

    def get_rules_config(self):
        return self.config['rules']