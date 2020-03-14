import sys
from importlib import import_module

from netaddr import IPNetwork
from scapy.utils import mac2str

from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier
from logger.logger import Logger


def load_modifier_class(class_name: str):
    class_str: str = f"modifiers.{class_name}"
    try:
        module_path, class_name = class_str.rsplit('.', 1)
        module = import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        print(f"Could not load class {class_str}", file=sys.stderr)
        print(f"Could not load class {e}", file=sys.stderr)
        sys.exit(1)


def load_ether_modifier(class_name: str, logger) -> EtherModifier:
    class_constructor = load_modifier_class(class_name)
    return class_constructor('Ether', logger)


def load_ip_modifier(class_name: str, logger) -> IPModifier:
    class_constructor = load_modifier_class(class_name)
    return class_constructor('IP', logger)


def create_modifier_class(class_name: str, protocol: str, logger: Logger):
    class_constructor = load_modifier_class(class_name)
    return class_constructor(protocol, logger)


def ip_in_range(ip, network_definition):
    ip_range = IPNetwork(network_definition)
    return ip in ip_range


def excluded_ip(value, exclude):
    for exclude_definition in exclude:
        if ip_in_range(value, exclude_definition):
            return True
    return False


def string_mac_to_bytes(string_mac):
    return mac2str(string_mac)


def validate_string_field(value: str, original_length, suffix=None):
    modified_field_length = len(value)
    if modified_field_length == original_length:
        return validate_string_suffix(value, suffix)
    if modified_field_length < original_length:
        return validate_string_suffix(value.ljust(original_length, value[-1]), suffix)
    else:
        return validate_string_suffix(value[:original_length], suffix)


def validate_string_suffix(value: str, suffix=None):
    if suffix is None:
        return value
    if value.endswith(suffix):
        return value
    return value[:-len(suffix)] + suffix

