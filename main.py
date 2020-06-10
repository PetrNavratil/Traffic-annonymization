"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from classes.modifier_controller import ModifierController
from classes.tshark_adapter import TsharkAdapter
from classes.parser import Parser

if __name__ == '__main__':
    parser = Parser()
    adapter = TsharkAdapter(parser.file_names)
    controller = ModifierController(
        parser.get_rules_config(),
        adapter,
        parser.tpc_stream_strategy,
        parser.reset_pools,
        parser.generate_meta_files,
        parser.search_all_protocols
    )
    controller.modify_files()

