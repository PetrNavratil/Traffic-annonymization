import sys
from importlib import import_module
from interfaces.ether_modifier import EtherModifier
from interfaces.ip_modifier import IPModifier


def load_modifier_class(class_name: str):
    class_str: str = f"modifiers.{class_name}"
    try:
        module_path, class_name = class_str.rsplit('.', 1)
        module = import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        print(f"Could not load class {class_str}", file=sys.stderr)
        sys.exit(1)


def load_ether_modifier(class_name: str, logger) -> EtherModifier:
    class_constructor = load_modifier_class(class_name)
    return class_constructor(logger)


def load_ip_modifier(class_name: str, logger) -> IPModifier:
    class_constructor = load_modifier_class(class_name)
    return class_constructor(logger)
