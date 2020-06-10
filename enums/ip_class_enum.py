"""
Autor: Petr Navratil (xnavra53)
Rok: 2019/2020
"""
from enum import Enum


class IpClass(Enum):
    A = range(0, 128)
    B = range(128, 192)
    C = range(192, 224)
    D = range(224, 240)
    E = range(240, 256)
