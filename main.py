from helpers.modifier_shark_controller import ModifierSharkController
from helpers.packet_shark import SharkPacket
from helpers.tshark_adapter import TsharkAdapter
from logger.logger import Logger
from parser.config_parser import ConfigParser

if __name__ == '__main__':
    parser = ConfigParser()
    logger = Logger(parser.verbose)
    adapter = TsharkAdapter(parser.file_names[0])
    controller = ModifierSharkController(parser.get_rules_config(), logger)
    slicer = adapter.get_packets()
    i = 0
    for a in slicer:
        i += 1
        print(i)
        shark_packet = SharkPacket(a, controller.parsed_rules)
        controller.run_packet_modifiers(shark_packet)
        adapter.write_modified_packet(shark_packet.get_packet_bytes())
    adapter.close_output_file()

