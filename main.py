from helpers.modifier_shark_controller import ModifierSharkController
from helpers.tshark_adapter import TsharkAdapter
from logger.logger import Logger
from parser.config_parser import ConfigParser

if __name__ == '__main__':
    parser = ConfigParser()
    logger = Logger(parser.verbose)
    adapter = TsharkAdapter(parser.file_names)
    controller = ModifierSharkController(
        parser.get_rules_config(),
        adapter,
        logger,
        parser.tpc_stream_strategy,
        parser.reset_pools,
        parser.generate_meta_files,
        parser.search_all_protocols
    )
    controller.modify_files()

