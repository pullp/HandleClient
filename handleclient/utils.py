
from enum import Enum
import logging
from datetime import datetime
from struct import pack, unpack

from handleclient import common

# unpack int from bytes
def u8(payload):
    assert isinstance(payload, bytes)
    return unpack("!B", payload[:1])[0]

def u16(payload):
    assert isinstance(payload, bytes)
    return unpack("!H", payload[:2])[0]

def u32(payload):
    assert isinstance(payload, bytes)
    return unpack("!I", payload[:4])[0]

def u64(payload):
    assert isinstance(payload, bytes)
    return unpack("!Q", payload[:8])[0]

def unpackString(payload: bytes) -> bytes:
    """unpack utf8 byte array from payload
    """
    assert isinstance(payload, bytes)
    strLen = u32(payload)
    return payload[4:4+strLen]

# pack int to bytes
def p8(val):
    assert isinstance(val, int)
    return pack("!B", val)

def p16(val):
    assert isinstance(val, int)
    return pack("!H", val)

def p32(val):
    assert isinstance(val, int)
    return pack("!I", val)

def p64(val):
    assert isinstance(val, int)
    return pack("!Q", val)

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

def printableCode(codeEnum, val) -> str:
    """
    """
    assert issubclass(codeEnum, Enum)
    assert isinstance(val, int)
    for e in codeEnum:
        if e.value == val:
            return e.name
    return f"unknown ({val})"

def formatTimestamp(timestamp):
    return datetime\
            .utcfromtimestamp(timestamp)\
            .strftime('%Y-%m-%d %H:%M:%S')

def formatIpAddress(addr: bytes) -> str:
    assert isinstance(addr, bytes)

    if addr.startswith(b'\x00'*(common.IPV6_SIZE_IN_BYTES - common.IPV4_SIZE_IN_BYTES)):
        # ipv4
        res = f"{addr[-4]:d}.{addr[-3]:d}.{addr[-2]:d}.{addr[-1]:d}"
    else:
        addrHex = addr.hex()
        res = ""
        for i in range(0, common.IPV6_SIZE_IN_BYTES, 4):
            res += addrHex[i: i+4] + ":"
        res = res[:-1]
    return res

    

################################################################
# below codes are just for fun XD
################################################################

import os

def countLine(suffixes=[".py"]):
    g = os.walk(".")
    files = []
    for path, _dirList, fileList in g:
        for fileName in fileList:
            # if fileName.endswith
            for sufix in suffixes:
                if fileName.endswith(sufix):
                    print(fileName)
                    files.append(os.path.join(path, fileName))
    print(files)
    totalCnt = 0
    for file in files:
        lines = open(file, 'r', encoding='utf8').readlines()
        # print(lines[0])
        lineCnt = len([l for l in lines if not l.startswith("#")])
        # lineCnt = len([l for l in lines if len(l) < 0])
        # lineCnt = len(lines )
        # del lines
        totalCnt += lineCnt
        print(f"{file}({lineCnt} lines); totoal {totalCnt} lines")

