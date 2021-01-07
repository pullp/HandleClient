
import logging
import hashlib
import struct

from enum import Enum
from datetime import datetime
# from struct import pack, unpack

from handleclient import common
from handleclient.handlevalue import HandleValue

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

# unpack int from bytes
def u8(payload):
    assert isinstance(payload, bytes)
    return struct.unpack("!B", payload[:1])[0]

def u16(payload):
    assert isinstance(payload, bytes)
    return struct.unpack("!H", payload[:2])[0]

def u32(payload):
    assert isinstance(payload, bytes)
    return struct.unpack("!I", payload[:4])[0]

def u64(payload):
    assert isinstance(payload, bytes)
    return struct.unpack("!Q", payload[:8])[0]

def uba(payload: bytes) -> bytes:
    """unpack utf8 byte array from payload
    """
    assert isinstance(payload, bytes)
    strLen = u32(payload)
    return payload[4:4+strLen]

def u32List(payload):
    assert isinstance(payload, bytes)
    indexList = []
    offset = 0

    indexCount = u32(payload[offset:])
    offset += 4

    for _i in range(indexCount):
        index = u32(payload[offset:])
        offset += 4
        indexList.append(index)
    
    return indexList, offset


def unpackValueList(payload):
    assert isinstance(payload, bytes)
    valueList = []
    offset = 0
    
    valueCount = u32(payload[offset:])
    offset += 4

    for _i in range(valueCount):
        valueSize = HandleValue.calcHandleValueSize(payload[offset:])
        value = HandleValue.parse(payload[offset:offset+valueSize])
        offset += valueSize
        valueList.append(value)
    
    return valueList, offset

def ubaList(payload):
    assert isinstance(payload, bytes)

    baList = []
    offset = 0
    
    baCount = u32(payload[offset:])
    offset += 4

    for _i in range(baCount):
        ba = uba(payload[offset:])
        offset += 4 + len(ba)
        baList.append(ba)
    return (baList, offset)

# pack int to bytes
def p8(val):
    assert isinstance(val, int)
    return struct.pack("!B", val)

def p16(val):
    assert isinstance(val, int)
    return struct.pack("!H", val)

def p32(val):
    assert isinstance(val, int)
    return struct.pack("!I", val)

def p64(val):
    assert isinstance(val, int)
    return struct.pack("!Q", val)

def pba(ba: bytes) -> bytes:
    assert isinstance(ba, bytes)
    payload = b''
    payload += p32(len(ba))
    payload += ba
    return payload

def packValueList(valueList):
    payload = p32(len(valueList))
    for value in valueList:
        payload += value.pack()
    return payload

def p32List(indexList):
    payload = p32(len(indexList))
    for index in indexList:
        payload += p32(index)
    return payload

def pbaList(baList):
    assert isinstance(baList, list)
    assert all(isinstance(ba, bytes) for ba in baList)

    payload = p32(len(baList))
    for ba in baList:
        payload += pba(ba)
    return payload



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


def doDigest(hashType, datas):
    assert isinstance(hashType, int)
    assert isinstance(datas, list)
    assert all(isinstance(item, bytes) for item in datas)
    if hashType == common.HASH_CODE.OLD_FORMAT.value:
        logger.critical("doDigest for OLD_FORMAT unimpl")
        return
    elif hashType == common.HASH_CODE.MD5.value:
        m = hashlib.md5()
    elif hashType == common.HASH_CODE.SHA1.value:
        m = hashlib.sha1()
    elif hashType == common.HASH_CODE.SHA256.value:
        m = hashlib.sha256()
    elif hashType == common.HASH_CODE.HMAC_SHA1.value:
        logger.critical("doDigest for HMAC_SHA1")
        return
    elif hashType == common.HASH_CODE.HMAC_SHA256.value:
        logger.critical("doDigest for HMAC_SHA256")
        return
    else:
        logger.critical(f"un implement digest type {hashType:#x}")
        return
    
    for data in datas:
        m.update(data)
    
    return m.digest()

def hexdump(payload, mod=16):
    assert isinstance(payload, bytes)
    res = ""
    for i in range(0, len(payload), mod):
        l = f"{i:#04x}: "
        for j in range(mod):
            if (i+j) >= len(payload):
                break
            l += f" {payload[i+j]:02X}"
        res += l + '\n'
    return res
