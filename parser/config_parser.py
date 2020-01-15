import argparse
import json


class ConfigParser:

    config = {}
    verbose = True

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--config')
        arguments = vars(parser.parse_args())
        self.config = ConfigParser.__load_config_file(arguments['config'])
        self.verbose = self.config['verbose'] if 'verbose' in self.config else self.verbose
        print(self.verbose)

        self.network_access_layer_class = self.config['network_access_layer']['Ethernet']['class']
        self.internet_layer_class = self.config['internet_layer']['IP']['class']

        self.network_access_layer_config = self.config['network_access_layer']
        self.internet_layer = self.config['internet_layer']

    @staticmethod
    def __load_config_file(config_path: str):
        with open(config_path, mode='r') as f:
            return json.load(f)


