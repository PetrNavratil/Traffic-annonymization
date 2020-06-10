"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from abc import ABC, abstractmethod
from typing import Union

from helpers.helpers import ExcludeInclude
from helpers.validator import Validator


class Modifier(ABC):
    """
    Rozhraní pro tvorbu modifikatorů určených k anonymizaci síťových atributů

    ...

    Atributy
    ----------

    unique: bool
        definuje, zda má být anonymizovaná hodnota unikátní. Lze tak zajistit, že probíhá mapování vstupní hodnoty na
        anonymizovanou v poměru jedna ku jedné

    store_value: bool
        definuje, zda má být mapování vstupní a anonymizované hodnoty ukládáno. Mapování je možné exportovat v meta
        souborech, což pro některé případy nedává smysl, např. při smazání dat anonymizovaného atributu. Pokud je
        hodnota false, nelze zaručit správnou funkci atributu unique.

    exclude: ExcludeInclude
        obsahuje transformovaná data položky exclude anonymizačního pravidla metodou transform_exclude_include_method

    include: ExcludeInclude
        obsahuje transformovaná data položky include anonymizačního pravidla metodou transform_exclude_include_method

    meta: dict
        obsahují data, které jsou exportovány do meta souborů. Lze tu uvést např. kryptografický klíč užitý při
        anonymizaci
    """

    def __init__(self):
        self.unique = True
        self.store_value = True
        self.exclude: ExcludeInclude = ExcludeInclude([], None)
        self.include: ExcludeInclude = ExcludeInclude([], None)
        self.meta = {}

    @abstractmethod
    def modify_field(self, original_value: bytearray, value, additional_parameters) -> Union[bytearray, None]:
        """
        Metoda je zodpovědná za samotnou anonymizaci, resp. za získání anonymizované hodnoty. Očekávanou návratovou
        hodnotou je bytearray představující anonymizovanou hodnotu. Případně lze vrátit None, čímž lze aplikaci říci,
        že hodnota nebyla anonymizovaná a nemá být vytvořena modifikace.

        :param original_value: neanonymizovana hodnota
        :param value: value specifikovaná v anonymizačním pravidle
        :param additional_parameters: objekt obsahující byteorder, nanoresolution a packet index
        :return: bytearray | None
            anonymizovaá data jako bytearray
        """
        pass

    @abstractmethod
    def validate_field(self, value: bytearray, additional_parameters) -> bool:
        """
        Metoda je je zodpovědná za validaci hodnoty atributu před jeho anonymizací.
        Očekávanou návratovou hodnotou validační funkce je hodnota datového typu bool. V případě logické pravdy je
        atribut připuštěn k anonymizaci, v případě nepravdy je z anonymizace vyloučen.

        :param value: neanonymizovana hodnota
        :param additional_parameters: objekt obsahující byteorder, nanoresolution a packet index
        :return: bool
        """
        pass

    @abstractmethod
    def transform_exclude_include_method(self, additional_params):
        """
        Metoda je použita aplikací pro transformaci položek exclude a include anonymizační pravidel do interní
        reprezentace vhodné pro validaci.
        Očekávanou návratovou hodnotou je funkce, která je aplikovatelná na každou hodnotu atributu exclude a include.

        Funkce pro transformaci lze nalezt na konci tridy Validator

        :param additional_params: objekt obsahující byteorder, nanoresolution
        :return: Funkce, dodatecne parametry (kwargs), rozbalene do vracene funkce
        """
        pass

    def transform_output_value(self, value: bytearray):
        """
        Metoda slouží pro transformaci hodnot v bytové reprezentaco do datových typů, které jsou použity při generování
        meta souborů. Lze tak převést např. IP adresu v bytearray na tečkovou notaci.
        :param value: hodnota atributu jako bytearray
        :return:
        """
        return value.hex()

    def transform_exclude_include(self, exclude, include, additional_params):
        """
        Metoda slouží k transformaci exclude a include do interní podoby
        NEMĚLA BY BÝT MĚNĚNA

        :param exclude:
        :param include:
        :param additional_params:
        :return:
        """
        method, params = self.transform_exclude_include_method(additional_params)
        meta_exclude = self.__get_include_exclude(exclude)
        self.exclude = ExcludeInclude(Validator.convert_options(meta_exclude.value, method, params), meta_exclude.validation)
        meta_include = self.__get_include_exclude(include)
        self.include = ExcludeInclude(Validator.convert_options(meta_include.value, method, params), meta_include.validation)

    def __get_include_exclude(self, value) -> ExcludeInclude:
        """
        Transformace exclude a include do interního datového typu
        NEMĚLA BY BÝT MĚNĚNA
        :param value:
        :return:
        """
        if type(value) is dict:
            return ExcludeInclude(value['value'], value['validation'])
        if type(value) is list:
            return ExcludeInclude(value, None)
        return ExcludeInclude(value, None)






