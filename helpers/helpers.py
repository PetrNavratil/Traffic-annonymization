import random
import re
import socket
import sys
from collections import namedtuple
from importlib import import_module
from typing import Tuple, Union, List


from enums.ip_class_enum import IpClass
from lorem.text import TextLorem

HTTP_LINE_PREFIX_DELIMITER = ': '
MAC_FLAGS_INDEX = 0

Timestamp = namedtuple('Timestamp', ['seconds', 'decimal'])
LengthValue = namedtuple('LengthValue', ['length', 'value'])
ExcludeInclude = namedtuple('ExcludeInclude', ['value', 'validation'])
MICROSECONDS_MAX = 1000000
NANOSECONDS_MAX = 1000000000
WELL_KNOWN_PORTS = range(0, 1024)
REGISTERED_PORTS = range(1024, 49152)
DYNAMIC_PORTS = range(49152, 65535)


def random_port_from_its_category(port) -> bytearray:
    """
    Funkce vrati nahodny port z kategorie portu, do kterych patri
    """
    transformed_port = port if type(port) is int else byte_array_to_number(port)
    port_range = get_port_range(transformed_port)
    return number_to_byte_array(generate_random_number_in_range(port_range), 2)


def generate_random_mac() -> bytearray:
    """
    Funkce pro generovani nahodne MAC adresy
    """
    return number_to_byte_array(generate_random_bits(48), 6)


def generate_random_mac_preserve_flags(original_value: bytearray) -> bytearray:
    """
    Funkce pro generovani nahodne MAC adresy, ktera zachova priznaky MAC adresy
    """
    random_mac = generate_random_mac()
    original_flags_mask = generate_n_bit_mask(8, 2, prefix=False)
    generated_flags_mask = generate_n_bit_mask(8, 6, prefix=True)
    random_mac[MAC_FLAGS_INDEX] &= generated_flags_mask
    random_mac[MAC_FLAGS_INDEX] |= original_value[MAC_FLAGS_INDEX] & original_flags_mask
    return random_mac


def generate_random_k_prefixed_or_suffixed_mac(value: bytearray, length: int, prefix: bool) -> bytearray:
    """
    Funkce pro vygenerovani nahodne casti MAC adresy, ktera je pripojena k prefixu nebo suffixu puvodni adresy
    :param value: originalni MAC adresa
    :param length: delka zachovani
    :param prefix: prefix nebo suffix
    :return:
    """
    return generate_random_k_prefixed_or_suffixed(value, length, prefix, 48)


def generate_marked_k_prefixed_or_suffixed_mac(value: bytearray, length: int, marker, prefix: bool) -> bytearray:
    """
    Funkce pro vygenerovani MAC adresy, kde je cast adresy nahrazena danym prefixem nebo suffixem
    :param value: originalni MAC adresa
    :param length: delka zachovani
    :param marker: nahrazena hodnota
    :param prefix: prefix nebo suffix
    :return:
    """
    transformed_marker = string_mac_to_int(marker)
    return generate_marked_k_prefixed_or_suffixed(value, length, transformed_marker, prefix, 48)


def random_ip_address() -> bytearray:
    """
    Generovani nahodne IP adresy
    """
    random_bits: int = generate_random_bits(32)
    return bytearray(random_bits.to_bytes(4, 'big'))


def generate_random_k_prefixed_or_suffixed_ip(value: bytearray, length: int, prefix: bool ) -> bytearray:
    """
    Funkce pro vygenerovani nahodne IP adresy, ktera zachovava prefix nebo suffix dane delky
    """
    return generate_random_k_prefixed_or_suffixed(value, length, prefix, 32)


def generate_marked_k_prefixed_or_suffixed_ip(value: bytearray, length: int, marker, prefix: bool) -> bytearray:
    """
    Funkce pro vygenerovani IP adresy, ktera ma prefix nebo sufix definovane delky nahrazen markerem
    """
    transformed_marker = parse_partial_ip(marker)
    return generate_marked_k_prefixed_or_suffixed(value, length, transformed_marker, prefix, 32)


def generate_random_text(length: int) -> str:
    """
    Generovani nahodneho textu Lorem Ipsum dane delky znaku.
    """
    generator = TextLorem(srange=(3, 10))
    generated_text = ''
    while len(generated_text) < length:
        generated_text += generator.sentence()
    return generated_text[:length]


def generate_prefixed_random_text(text, delimiter=None) -> str:
    """
    Funkce pro generovani nahodnoteho textu, pricemz zachova prefix definovany oddelovacem.
    Neni li uvedeny, vrati pouze nahodny text
    Napr pro "Host: {nahodne}"
    """
    if delimiter is None:
        return generate_random_text(len(text))
    prefix, rest = string_split_prefix(text, delimiter)
    value = generate_random_text(len(rest))
    return prefix + value


def generate_prefixed_marker_text(original_text, marker,  delimiter=None, prefix_length=None) -> str:
    """
    Funkce vrati prefix puvodniho textu, ktery urcuje delimiter nebo delka prefixu, doplneny o marker text.
    Pokud neni specifikovany prefix, vraci jen marker
    """
    modified_value = original_text if type(original_text) is str else byte_array_to_string(original_text)
    if delimiter is not None:
        prefix, rest = string_split_prefix(modified_value, delimiter)
        return prefix + marker[:len(rest)]
    if prefix_length is not None:
        return modified_value[:prefix_length] + marker[:len(modified_value) - prefix_length]
    return marker


def validate_string_field(value: str, original_length, suffix=None, prefix=None):
    """
    Funkce upravi vstupni hodnotu value tak, aby splnovala puvodni delku. Pokud je definovany suffix nebo prefix, overi
    a pripadne nahradi castu hodnotz value tak, aby doplnila suffix nebo preffix
    :param value: overovana hodnota
    :param original_length: puvodni delka
    :param suffix: vyzadovany suffix (napr. \r\n)
    :param prefix: vyzadovany prefix
    :return:
    """
    modified_field_length = len(value)
    if modified_field_length == original_length:
        return validate_string_prefix_suffix(value, suffix, prefix)
    if modified_field_length < original_length:
        return validate_string_prefix_suffix(value.ljust(original_length, value[-1]), suffix, prefix)
    else:
        return validate_string_prefix_suffix(value[:original_length], suffix, prefix)


def generate_random_number_in_range(interval: range) -> int:
    """
    Funkce vygenereruje nahodne cislo v intervalu
    """
    return random.randrange(interval.start, interval.stop)


def generate_random_bits(count) -> int:
    """
    Funkce vygeneruje nahodny pocet bitu
    :param count:
    :return:
    """
    return random.getrandbits(count)


def increment_time_stamp(start: Timestamp, increment: Timestamp, nano_resolution: bool) -> Timestamp:
    """
    Zvyseni casoveho razitka o pocet sekund a mili/nano sekund
    """
    new_seconds = start.seconds + increment.seconds
    new_decimal = start.decimal + increment.decimal
    return correct_time_stamp_decimal(Timestamp(new_seconds, new_decimal), nano_resolution)


def string_ip_to_byte_array(ip: str) -> bytearray:
    """
    Prevod IP adresy v teckove notaci na pole bytu
    """
    return bytearray(socket.inet_aton(ip))


def byte_array_ip_to_string(ip: bytearray) -> str:
    """
    Prevod IP adresy z bytoveho pole na teckovou notaci
    :param ip:
    :return:
    """
    return socket.inet_ntoa(ip)


def generate_n_bit_mask(length: int, mask_length: int, prefix: bool) -> int:
    """
    Funkce pro vygenerovani cisla, predstavujici bitovou masku, ktera je umistena jako suffix nebo preffix
    """
    if length == 0:
        return 0
    bit_mask = ''.join(['1' for _ in range(mask_length)])
    if prefix:
        return int(bit_mask.ljust(length, '0'), base=2)
    else:
        return int(bit_mask, base=2)


def generate_32bit_mask(length: int, prefix: bool):
    """
    Funkce pro  generovani 32 bitove masky
    """
    return generate_n_bit_mask(32, length, prefix)


def generate_random_k_prefixed_or_suffixed(value: bytearray, length: int, prefix: bool, bit_length: int, order='big') -> bytearray:
    """
    Funkce vygeneruje definovany pocet nahodnych bitu, ktere nahradi puvodni hodnotu jako prefix nebo suffix
    """
    value_int = byte_array_to_number(value, order)
    if prefix:
        random_bits = generate_random_bits(bit_length - length)
        mask = generate_n_bit_mask(bit_length,length, True)
        return number_to_byte_array((value_int & mask) | random_bits, len(value), order)
    else:
        random_bits = generate_random_bits(bit_length)
        mask = generate_n_bit_mask(bit_length, bit_length - length, True)
        value_int_mask = generate_n_bit_mask(bit_length, length, False)
        return number_to_byte_array((random_bits & mask) | (value_int & value_int_mask), len(value), order)


def generate_marked_k_prefixed_or_suffixed(value: bytearray, length: int, marker, prefix: bool, bit_length: int, order='big') -> bytearray:
    """
    Funkce upravi vstupni hodnotu tak, ze nahradi definovanou cast prefixu nebo suffixu statickym markerem
    """
    ip = byte_array_to_number(value, order)
    assert bit_length - length >= marker.bit_length(), "Marker length is larger than preserving length"
    if prefix:
        mask = generate_n_bit_mask(bit_length, length, True)
        return number_to_byte_array((ip & mask) | marker, len(value), order)
    else:
        ip_mask = generate_n_bit_mask(bit_length, length, False)
        return number_to_byte_array((marker << (bit_length - max(length, marker.bit_length()))) | (ip & ip_mask), len(value), order)


def parse_partial_ip(value) -> int:
    """
    Funkce prevede castecnou IP adresu v teckove notaci na cislo
    """
    if type(value) is int:
        return value
    split_values = [int(item) for item in value.split('.')]
    partial = 0
    number_of_values = len(split_values)
    for i, split_value in enumerate(split_values):
        partial += split_value * (256 ** (number_of_values - i - 1))
    return partial


def get_port_range(port: int):
    """
    Funkce vrati range daneho portu
    """
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS
    if port in REGISTERED_PORTS:
        return REGISTERED_PORTS
    return DYNAMIC_PORTS


def string_mac_to_byte_array(string_mac: str) -> bytearray:
    """
    Konverze MAC adresy ze stringove podoby do bytearray
    """
    return bytearray().fromhex(''.join(string_mac.split(':')))


def byte_array_mac_to_string(value: bytearray) -> str:
    """
    Konverze MAC adresy z bytearray do stringu
    """
    return ':'.join(format(b, '02x') for b in value)


def string_mac_to_int(string_mac: str) -> int:
    """
    MAC adresa ve stringu prevedena na cislo
    """
    return int().from_bytes(string_mac_to_byte_array(string_mac), 'big')


def dns_cname_string_to_byte_array(value: str) -> bytearray:
    """
    Prevod domenoveho jmena uziteho napr  v DNS do bytoveho pole typu [delka][hodnota][delka][hodnota]
    """
    return string_to_length_label_byte_array(value, '.')


def dns_cname_byte_array_to_string(value: bytearray) -> str:
    """
    Prevod domenoveho jmena v bytovem poli na textovy retezec
    """
    label_tuples = label_byte_array_to_array_length_value_tuples(value)
    return '.'.join([convert_length_value_tuple(label, str) for label in label_tuples])


def byte_array_to_string(value: bytearray) -> str:
    """
    Prevod bytoveho pole na textovy retezec
    """
    return value.decode()


def string_to_byte_array(string: str) -> bytearray:
    """
    Prevod retezce na bytove pole
    """
    return bytearray(string.encode())


def number_to_byte_array(value: int, byte_count: int, order='big'):
    """
    Prevod cisla na bytove pole definovane delky
    """
    return bytearray(value.to_bytes(byte_count, order))


def byte_array_to_number(value: bytearray, order='big'):
    """
    Prevod bytoveho pole na cislo
    """
    return int().from_bytes(value, order)


def parse_string_time(value: str, nano_resolution) -> Timestamp:
    """
    Funkce prevede casove razitko ve stringu na Timestamp
    """
    split_value = value.split('.')
    seconds, decimal = split_value if len(split_value) == 2 else [split_value[0], '0']
    decimal = int(decimal) if decimal != '' else 0
    seconds = int(seconds)
    validate_time(decimal, nano_resolution)
    return Timestamp(seconds, decimal)


def time_stamp_to_byte_array(timestamp: Timestamp, byte_order) -> bytearray:
    """
    Funkce prevede casove razitko na pole bytu
    """
    return bytearray(timestamp.seconds.to_bytes(4, byte_order) + timestamp.decimal.to_bytes(4, byte_order, signed=False))


def byte_array_to_timestamp(value: bytearray, byte_order) -> Timestamp:
    """
    Funkce prevede bytove pole na timestamp
    """
    seconds = int().from_bytes(value[0:4], byte_order)
    decimal = int().from_bytes(value[4:], byte_order)
    return Timestamp(seconds, decimal)


def string_to_length_label_byte_array(value: str, delimiter: str):
    """
    Prevede vstupni retezev na bytove pole typu  [delka][hodnota][delka][hodnota].
    Uzite napriklad pro dns.qry.name
    :param value: vstupni retezec
    :param delimiter: rozdelovac  - napr "." pro domenova jmena DNS protokolu
    """
    labels = value.split(delimiter)
    final_array = bytearray(len(value))
    available_length = len(value) - 1
    array_index = 0
    for label in labels:
        write_length = min((len(label) , available_length - array_index - 1))
        final_array[array_index] = write_length
        array_index += 1
        final_array[array_index: array_index + write_length] = label.encode()[:write_length]
        array_index += write_length
    final_array[-1] = 0
    return final_array


def label_byte_array_to_array_length_value_tuples(value: bytearray, convert_fn=None) -> Union[List[LengthValue], None]:
    """
    Interni funkce pro prevod bytoveho pole typu [delka][hodnota][delka][hodnota] na pole dvojic (delka, hodnota)
    datoveho typu LengthValue
    """
    if len(value) == 0:
        return None
    index = 1
    length = value[0]
    output = []
    while length > 0 and index < len(value):
        data = value[index: index + length]
        data = data if convert_fn is None else convert_fn(data)
        output.append(LengthValue(length, data))
        index += length
        if index >= len(value):
            break
        length = value[index]
        index += 1
    return output


def convert_length_value_tuple(value: LengthValue, convert_type, encoding='utf-8', byte_order='big'):
    """
    Interni metoda pro prevod hodnot LengthValue na datove typy z bytove reprezentace
    """
    if convert_type is int:
        return value.value.to_bytes(value.length, byte_order)
    if convert_type is str:
        return value.value.decode(encoding)
    return value.value


def validate_string_prefix_suffix(value: str, suffix=None, prefix=None):
    """
    Validace zda retezec obsahuje pozadovany suffix nebo preffix a pripadna korektura
    """
    return validate_string_suffix(validate_string_prefix(value, prefix), suffix)


def validate_string_prefix(value: str, prefix=None):
    """
    Validace prefixu retezec a jeho pripadne doplneni
    """
    if prefix is None:
        return value
    if value.startswith(prefix):
        return value
    return prefix + value[:-len(prefix)]


def validate_string_suffix(value: str, suffix=None):
    """
    Validace suffixu retezec a jeho pripadne doplneni
    """
    if suffix is None:
        return value
    if value.endswith(suffix):
        return value
    return value[:-len(suffix)] + suffix


def string_split_prefix(text, delimiter) -> Tuple[str, str]:
    """
    Funkce rozdeli retezec na prefix a zbytek
    """
    decoded_text = text if type(text) is str else text.decode()
    head, sep, tail = decoded_text.partition(delimiter)
    return head+sep, tail


def validate_time(decimal: int, nano_resolution: bool):
    """
    Validace casoveho razitka na spravnou presnost
    """
    if nano_resolution:
        assert decimal < NANOSECONDS_MAX, 'Decimal part for nanoseconds file must be less than 1 000 000 000'
        return
    assert decimal < MICROSECONDS_MAX, 'Decimal part for microseconds file must be less than 1 000 000'


def correct_time_stamp_decimal(timestamp: Timestamp, nano_resolution: bool) -> Timestamp:
    """
    Upraveni casoveho razitka na spravnou presnost
    """
    if timestamp.decimal < 0:
        new_seconds = timestamp.seconds - 1
        assert new_seconds >= 0
        return Timestamp(new_seconds, (NANOSECONDS_MAX if nano_resolution else MICROSECONDS_MAX) + timestamp.decimal)
    else:
        if nano_resolution and timestamp.decimal >= NANOSECONDS_MAX:
            return Timestamp(timestamp.seconds + 1, timestamp.decimal - NANOSECONDS_MAX)
        if not nano_resolution and timestamp.decimal >= MICROSECONDS_MAX:
            return Timestamp(timestamp.seconds + 1, timestamp.decimal - MICROSECONDS_MAX)
    return timestamp


def clear_byte_array(value: bytearray, start: int, end: int) -> bytearray:
    """
    Funkce vynuluje definovany vysek bytoveho pole
    """
    value_length = len(value)
    assert 0 <= start < value_length
    assert value_length >= end >= 0
    copied_value = value.copy()
    for i in range(start, end):
        copied_value[i] &= 0
    return copied_value


def create_byte_clear_mask(start: int, end: int) -> int:
    """
    Funkce vytvori bitovou masku pro 1B, ktera nuluje definovany interval
    """
    return int(''.join(['0' if item in range(start, end) else '1' for item in range(8)]), base=2)


def clear_byte_bits(value: bytearray, start: int, end: int) -> bytearray:
    """
    Funkce vynuluje 1B vstupnich dat na definovanem useku
    """
    value_length = len(value) * 8
    assert value_length == 8
    assert 0 <= start < value_length
    assert value_length >= end >= 0
    mask = create_byte_clear_mask(start, end)
    copied_value = value.copy()
    copied_value[0] &= mask
    return copied_value


def clear_byte_bits_prefix(value: bytearray, length: int) -> bytearray:
    """
    Funkce vynuluje prefix vstupniho bytu
    """
    return clear_byte_bits(value, 0, length)


def clear_byte_bits_suffix(value: bytearray, length: int) -> bytearray:
    """
    Funkce vynuluje suffix vstupniho bytu
    """
    return clear_byte_bits(value, 8 - length, 8)


def get_ip_class_range(first_octet: int):
    """
    Funkce vrati range pro jednotlive tridy IP adress
    """
    if first_octet in IpClass.A.value:
        return IpClass.A.value
    if first_octet in IpClass.B.value:
        return IpClass.B.value
    if first_octet in IpClass.C.value:
        return IpClass.C.value
    if first_octet in IpClass.D.value:
        return IpClass.D.value
    if first_octet in IpClass.E.value:
        return IpClass.E.value


def camel_case_to_snake_case(path: str) -> str:
    """
    Prevod came case na snake case
    """
    # source
    # https://stackoverflow.com/questions/1175208/elegant-python-function-to-convert-camelcase-to-snake-case
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', path)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def modifier_class_name(name: str) -> str:
    """
    Funkce vytvnori nazev tridy pro jeji nacteni
    format nazev_tridy.NazevTridy
    """
    return f'{camel_case_to_snake_case(name)}.{name}'

def load_modifier_class(class_name: str):
    """
    Funkce pro dynamicke nacitani modifikatoru
    """
    class_str: str = f"modifiers.{class_name}"
    try:
        module_path, class_name = class_str.rsplit('.', 1)
        module = import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        print(f"Could not load class {class_str}", file=sys.stderr)
        print(f"Could not load class {e}", file=sys.stderr)
        sys.exit(1)