from abc import ABC, abstractmethod
from helpers.helpers import ExcludeInclude
from helpers.validator import Validator


class Modifier(ABC):

    def __init__(self):
        self.unique = True
        self.store_value = True
        self.exclude: ExcludeInclude = ExcludeInclude([], None)
        self.include: ExcludeInclude = ExcludeInclude([], None)
        # rename to meta
        self.keys = {}

    @abstractmethod
    def modify_field(self, original_value, value, additional_parameters) -> bytearray:
        pass

    @abstractmethod
    def validate_field(self, value, additional_parameters) -> bool:
        pass

    @abstractmethod
    def transform_exclude_include_method(self, additional_params):
        pass

    def transform_exclude_include(self, exclude, include, additional_params):
        method, params = self.transform_exclude_include_method(additional_params)
        meta_exclude = self.__get_include_exclude(exclude)
        self.exclude = ExcludeInclude(Validator.convert_options(meta_exclude.value, method, params), meta_exclude.validation)
        meta_include = self.__get_include_exclude(include)
        self.include = ExcludeInclude(Validator.convert_options(meta_include.value, method, params), meta_include.validation)
        # print('EX', self.exclude)
        # print('IN', self.include)

    def __get_include_exclude(self, value) -> ExcludeInclude:
        if type(value) is dict:
            print(value)
            return ExcludeInclude(value['value'], value['validation'])
        if type(value) is list:
            return ExcludeInclude(value, None)
        return ExcludeInclude(value, None)






