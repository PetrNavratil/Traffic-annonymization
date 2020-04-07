from abc import ABC, abstractmethod

from helpers.validator import Validator


class Modifier(ABC):

    def __init__(self):
        self.unique = True
        self.exclude = []
        self.include = []
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
        self.exclude = Validator.convert_options(exclude, method, **params)
        self.include = Validator.convert_options(include, method, **params)
        print('EX', self.exclude)
        print('IN', self.include)





