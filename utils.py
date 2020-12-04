#coding:utf-8
from enum import Enum

def printableFlags(flagsEnum, flag) -> str:
    """
    """
    assert issubclass(flagsEnum, Enum)
    assert isinstance(flag, int)
    res = ''
    for e in flagsEnum:
        if (e.value & flag) != 0:
            res += (e. name + " | ")
    if len(res) > 0:
        res = res[:-3]
    return res
