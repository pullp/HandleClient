from enum import Enum
from struct import pack, unpack
import logging

from handleclient import common
from handleclient import utils
# from handleclient import message
# from handleclient import request
# from handleclient import response
# from handleclient import handlevalue

# from handleclient.handlevalue import HandleValue
# from handleclient.message import Envelope, Header, Body, Credential


logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)

logger.addHandler(common.ch)

# supported (predefined) handle value types
# query new type by 0.TYPE todo

class Reference(object):
    def __init__(self, handle, index):
        assert isinstance(handle, bytes)
        assert isinstance(index, int)

        self.handle = handle
        self.index = index
    
    def __str__(self):
        res = f"{self.handle.decode()} ({self.index})\n"
        return res


class HandleValue(object):
    # permission
    class PERM(Enum):
        PUBLIC_WRITE    = 1
        PUBLIC_READ     = 1 << 1
        ADMIN_WRITE     = 1 << 2
        ADMIN_READ      = 1 << 3
        PUBLIC_EXECUTE  = 1 << 4
        ADMIN_EXECUTE   = 1 << 5

    class TTLType(Enum):
        RELA = 0 # relative
        ABS = 1 # absolute

    def __init__(self):
        self.valueType  = b''
        self.index      = 0
        self.data       = b''
        self.ttlType    = 0
        self.ttl        = 0
        self.permission  = 0

    def setVals(self, valueType, index, data, ttlType, ttl, 
                permission, timestamp, refs):
        assert isinstance(valueType, bytes)
        assert isinstance(index, int)
        assert isinstance(data, bytes)
        assert isinstance(ttlType, int)
        assert isinstance(ttl, int)
        assert isinstance(permission, int)
        assert isinstance(timestamp, int)
        assert isinstance(refs, list)
        assert all(isinstance(item, bytes) for item in refs)

        self.valueType  = valueType
        self.index      = index & 0xffffffff
        self.data       = data
        self.ttlType    = ttlType & 0xff
        self.ttl        = ttl & 0xffffffff
        self.permission  = permission & 0xff

        # timestamp is a 8-byte long type accroding to rfc3651, but is 4-byte int in official implementation
        self.timestamp  = timestamp & 0xffffffff
        # self.timestamp  = timestamp & 0xffffffffffffffff 
        self.refs = refs

        # self.value      = None # parse from self.data

    def pack(self):
        payload = b''
        # offset = 
        # valuesCnt =  
        return payload
    
    @classmethod
    def parse(cls, payload):
        # refer to `calcHandleValueSize`
        assert isinstance(payload, bytes)
        
        offset = 0
        index      = utils.u32(payload[offset:])
        offset += 4
        timestamp  = utils.u32(payload[offset:])
        offset  += 4
        ttlType    = utils.u8(payload[offset:])
        offset  += 1
        ttl        = utils.u32(payload[offset:])
        offset += 4
        permission  = utils.u8(payload[offset:])
        offset += 1

        valueType  = utils.unpackString(payload[offset:])
        offset += 4 + len(valueType)

        data  = utils.unpackString(payload[offset:])
        offset += 4 + len(data)

        refs = []
        refCnt          = utils.u32(payload[offset:])
        offset += 4
        for _i in range(0, refCnt):
            handle = utils.unpackString(payload[offset:])
            offset += 4 + len(handle)
            index = utils.u32(payload[offset:])
            offset += 4
            ref = Reference(handle, index)
            refs.append(ref)

        valueType = valueType.upper()
        logger.debug(f"value type : {valueType}")

        if valueType == b"":
            raise Exception(f"unimplemented for empty value type")
        elif valueType == b"URL" or valueType.startswith(b"URL.") \
            or valueType == b"EMAIL" or valueType.startswith(b"EMAIL.") \
            or valueType == b"HS_ALIAS" or valueType.startswith(b"HS_ALIAS.") \
            or valueType == b"HS_SERV" or valueType.startswith(b"HS_SERV.") \
            or valueType == b"DESC" or valueType.startswith(b"DESC.") \
            or valueType == b"HS_SECKEY" or valueType.startswith(b"HS_SECKEY."):
            hv = HS_STRING()

        elif valueType == b"HS_SITE" \
            or valueType.startswith(b"HS_SITE.") \
            or valueType == b"HS_NA_DELEGATE":
            hv = HS_SITE()
        elif valueType == b"HS_ADMIN" or valueType.startswith(b"HS_ADMIN."):
            hv = HS_ADMIN()
        elif valueType == b"HS_DSAPUBKEY" or valueType.startswith(b"HS_DSAPUBKEY.") \
            or valueType == b"HS_PUBKEY" or valueType.startswith(b"HS_PUBKEY."):
            hv = HS_PUBKEY()
        elif valueType == b"HS_VLIST" or valueType.startswith(b"HS_VLIST."):
            hv = HS_VLIST()
        elif valueType == b"HS_CERT":
            hv = HS_CERT()
        else:
            logger.warn(f"unsupported value type {valueType}")
            hv = HandleValue()

        # hv.index = index
        # hv.valueType = valueType
        # hv.data = data
        # hv.ttlType = ttlType
        # hv.ttl = ttl
        # hv.timestamp = timestamp
        # hv.permission = permission
        # hv.refs = refs
        hv._setBasicVals(valueType=valueType, index=index, data=data,
            ttlType=ttlType, ttl=ttl, permission=permission,
            timestamp=timestamp, refs=refs)
        hv._parseData(data)
        return hv
    
    def _setBasicVals(self, *args, **kwargs):
        self.setVals(*args, **kwargs)
    
    def _parseData(self, data):
        return

    def __str__(self):
        res = "HandleValue:\n"
        res += f" type : {self.valueType.decode()}\n"
        res += f" index : {self.index}\n"
        res += f" TTL   : {self.ttl}({utils.printableFlags(HandleValue.TTLType, self.ttlType)})\n"
        res += f" permission : {utils.printableFlags(HandleValue.PERM, self.permission)}\n"
        res += f" timestamp : {utils.formatTimestamp(self.timestamp)}({self.timestamp})\n"
        res += f" references:\n"
        for ref in self.refs:
            res == "  " + str(ref)
        return res

    @staticmethod
    def calcHandleValueSize(payload: bytes, offset: int) -> int:
        """Calculate the number of bytes required to store the specified value
        """
        assert isinstance(payload, bytes)
        assert isinstance(offset, int)

        originalOffset = offset
        offset += 4 # index
        offset += 4 # timestamp
        offset += 1 # ttl type
        offset += 4 # ttl
        offset += 1 # permission

        # type field
        fieldLen = utils.u32(payload[offset:])
        offset += (4 + fieldLen)
        logger.debug(f"{offset}/{len(payload)} ({offset-originalOffset})")

        # data field
        fieldLen = utils.u32(payload[offset:])
        offset += (4 + fieldLen)
        logger.debug(f"{offset}/{len(payload)} ({offset-originalOffset})")
        
        # refs
        refCnt = utils.u32(payload[offset:])
        offset += 4
        logger.debug(f"{offset}/{len(payload)} ({offset-originalOffset})")
        logger.debug(f"ref count: {refCnt}")
        for i in range(refCnt):
            refLen = utils.u32(payload[offset:])
            offset += (4 + refLen + 4) # each reference - hdl length + hdl + index
            logger.debug(f"ref{i} : {offset}/{len(payload)} ({offset-originalOffset})")
        
        return offset - originalOffset


class ServiceInterface(object):
    class ServiceType(Enum):
        RESL = 1 # handle resolution
        ADMIN = 2 # handle administration

    class Protocol(Enum):
        TCP = 1
        UDP = 2
        HTTP = 4
    
    def __init__(self):
        self.serviceType = None
        self.protocol = None
        self.portNumber = 0
    
    def setVals(self, serviceType, protocol, portNumber):
        self.serviceType = serviceType
        self.protocol = protocol
        self.portNumber = portNumber
    
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        logger.warning("todo")


class ServerRecord(object):

    def __init__(self):
        self.serverID = 0
        self.address = b'' # ipv6 address
        self.publicKey = b''
        self.interfaces = []

    def setVals(self, serverID, address, 
                publicKey, interfaces):
        assert isinstance(serverID, int)
        assert isinstance(address, bytes)
        assert isinstance(publicKey, bytes)
        assert isinstance(interfaces, list)
        assert all(isinstance(item, ServiceInterface) \
                    for item in interfaces)
        self.serverID = serverID
        self.address = address
        self.publicKey = publicKey
        self.interfaces = interfaces
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)


class HS_SITE(HandleValue):
    def __init__(self):
        super().__init__()
        """<Version>
        A 2-byte value that identifies the version number of the HS_SITE.
        The version number identifies the data format used by the HS_SITE
        value.  It is defined to allow backward compatibility over time.
        This document defines the HS_SITE with version number 0.
        """
        self.version = 0
        """<ProtocolVersion>
        A 2-byte integer value that identifies the handle protocol version.
        The higher byte of the value identifies the major version and the
        lower byte the minor version.  Details of the Handle System
        protocol is specified in [8].
        """
        self.majorProtocolVersion = 0
        self.minorVersion = 0
        """<SerialNumber>
        A 2-byte integer value that increases by 1 (and may wrap around
        through 0) each time the HS_SITE value gets changed.  It is used in
        the Handle System protocol to synchronize the HS_SITE values
        between client and server.
        """
        self.serialNumber = 0
        """<PrimaryMask>
        An 8-bit mask that identifies the primary site(s) of the handle
        service.  The first bit of the octet is the <MultiPrimary> bit.  It
        indicates whether the handle service has multiple primary sites.
        The second bit of the octet is the <PrimarySite> bit.  It indicates
        whether the HS_SITE value is a primary site.  A primary site is the
        one that supports administrative operations for its handles.  A
        <MultiPrimary> entry with zero value indicates that the handle
        service has a single primary site and all handle administration has
        to be done at that site.  A non-zero <MultiPrimary> entry indicates
        that the handle service has multiple primary sites.  Each primary
        site may be used to administrate handles managed under the handle
        service.  Handles managed by such service may identify its primary
        sites using an HS_PRIMARY value, as described in section 3.2.5.
        """
        self.primaryMask = 0
        """<HashOption>
        An 8-bit octet that identifies the hash option used by the service
        site to distribute handles among its servers.  Valid options
        include HASH_BY_NA (0x00), HASH_BY_LOCAL (0x01), or HASH_BY_HANDLE
        (0x02).  These options indicate whether the hash operation should
        only be applied to the naming authority portion of the handle, or
        only the local name portion of the handle, or the entire handle,
        respectively.  The standard MD5 hashing algorithm [14] is used by
        each service site to distribute handles among its servers.
        """
        self.hashOption = 0
        """<HashFilter>
        An UTF8-string entry reserved for future use.
        """
        self.hashFilter = b''

        """<AttributeList>
        A 4-byte integer followed by a list of UTF8-string pairs.  The
        integer indicates the number of UTF8-string pairs that follow.
        Each UTF8-string pair is an <attribute>:<value> pair.  They are
        used to add literal explanations of the service site.  For example,
        if the <attribute> is "Organization", the <value> should contain a
        description of the organization hosting the service site.  Other
        <attribute>s may be defined to help distinguish the service sites
        from each other.
        """
        self.attributeList = []

        self.servers = []
    
    # primary mask
    class PM(Enum):
        IS_PRIMARY = 0x80
        MULTI_PRIMARY = 0x40
    
    def setVals(self, version, protocolVersion, serialNumber,
                primaryMask, hashOption, hashFilter, attributeList,
                servers):
        assert isinstance(version, int)
        assert isinstance(protocolVersion, tuple)
        assert all(isinstance(item, int) for item in protocolVersion)
        assert isinstance(serialNumber, int)
        assert isinstance(primaryMask, int)
        assert isinstance(hashOption, int)
        assert isinstance(hashFilter, bytes)
        assert isinstance(attributeList, list)
        # assert all(isinstance(item, bytes) for item in attributeList)
        assert isinstance(servers, list)
        assert all(isinstance(item, ServerRecord) for item in servers)

        self.version = version
        self.majorProtocolVersion = protocolVersion[0]
        self.minorprotocolVersion = protocolVersion[1]
        self.serialNumber = serialNumber
        self.primaryMask = primaryMask
        self.hashOption = hashOption
        self.hashFilter = hashFilter
        self.attributeList = attributeList
        self.servers = servers
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        logger.debug("start parsing data for HS_SITE")
        offset = 0
        self.version = utils.u16(data[offset:])
        offset += 2
        self.majorProtocolVersion = utils.u8(data[offset:])
        offset += 1
        self.minorProtocolVersion = utils.u8(data[offset:])
        offset += 1

        self.serialNumber  = utils.u16(data[offset:])
        offset += 2

        self.primaryMask = utils.u8(data[offset:])
        offset += 1

        self.hashOption = utils.u8(data[offset:])
        offset += 1

        hashOptionLen = utils.u32(data[offset:])
        offset += 4
        self.hashOption = data[offset:offset + hashOptionLen]
        offset += hashOptionLen

        attributeCnt = utils.u32(data[offset:])
        offset += 4

        for _i in range(attributeCnt):
            name = utils.unpackString(data[offset:])
            offset += 4 + len(name)

            value = utils.unpackString(data[offset:])
            offset += 4 + len(value)
            self.attributeList.append((name, value))
        
        serverCnt = utils.u32(data[offset:])
        offset += 4
        servers = []
        for _i in range(serverCnt):
            serverID = utils.u32(data[offset:])
            offset += 4
            address = data[offset:offset + common.IP_ADDRESS_LENGTH]
            offset += common.IP_ADDRESS_LENGTH
            publicKey = utils.unpackString(data[offset:])
            offset += 4 + len(publicKey)

            intfCnt = utils.u32(data[offset:])
            offset += 32

            intfs = []
            for _i in range(intfCnt):
                intfType = utils.u8(data[offset:])
                offset += 1
                intfProtocol = utils.u8(data[offset:])
                offset += 1
                intfPort = utils.u32(data[offset:])
                offset += 4

                intf = ServiceInterface()
                intf.setVals(intfType, intfProtocol, intfPort)
                intfs.append(intf)

            serverRecord = ServerRecord()
            serverRecord.setVals(
                serverID, address, publicKey, intfs
            )
            servers.append(serverRecord)
        
        self.servers = servers
        logger.debug(f"{offset}/{len(data)}")
        logger.debug("end parsing data for HS_SITE")
        assert offset == len(data)

    def __str__(self):
        res = super().__str__()
        res += "data:"
        res += f"  data format ersion : {self.version}\n"
        res += f"  protocol version : {self.majorProtocolVersion}.{self.minorProtocolVersion}\n"
        res += f"  serial number : {self.serialNumber}\n"
        res += f"  primary mask : {utils.printableFlags(HS_SITE.PM, self.primaryMask)}\n"
        res += f"  hash option : {self.hashOption}\n"
        res += f"  hash filter : {self.hashFilter.decode()}\n"
        res += f"attribute list:\n"
        for attribute in self.attributeList:
            res += f"  {attribute[0].decode()} : {attribute[1].decode()}\n"
        res += "servers:"
        for server in self.servers:
            res += str(server)
        return res


class HS_ADMIN(HandleValue):
    class PERM(Enum):
        ADD_HANDLE      = 0x0001
        DELETE_HANDLE   = 0x0002
        ADD_NA          = 0x0004
        DELETE_NA       = 0x0008
        MODIFY_VALUD    = 0x0010
        DELETE_VALU     = 0x0020
        ADD_VALUE       = 0x0040
        MODIFY_ADMIN    = 0x0080
        REMOVE_ADMIN    = 0x0100
        ADD_ADMIN       = 0x0200
        AUTHORIZED_READ = 0x0400
        LIST_HANDLE     = 0x0800
        LIST_NA         = 0x1000

    def __init__(self):
        super().__init__()
        self.permission = 0
        self.adminID = b''
        self.adminIndex = b''
    
    def setVals(self,):
        pass
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        offset = 0
        self.permission = utils.u16(data[offset:])
        offset += 2
        
        self.adminID = utils.unpackString(data[offset:])
        offset += 4 + len(self.adminID)

        self.adminIndex = utils.u32(data[offset:])
        offset += 4

        assert offset == len(data) # todo legacyByteLength

    def __str__(self):
        res = super().__str__()
        res += "data:\n"
        res += f"  permission : {utils.printableFlags(HS_ADMIN.PERM, self.permission)}\n"
        res += f"  admin ref : {self.adminID.decode()} ({self.adminIndex})\n"
        return res


class HS_STRING(HandleValue):
    """parser for URL, EMAIL, HS_ALIAS, HS_SERV, DESC, HS_SECKEY and types with these prefixes.
    """
    def __init__(self):
        super().__init__()
    
    def setVals(self,):
        pass
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        self.info = data.decode(common.TEXT_ENCODING)

    def __str__(self):
        res = super().__str__()
        res += f"data: {self.info}\n"
        return res


class HS_PUBKEY(HandleValue):
    def __init__(self):
        super().__init__()
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        offset = 0

        self.keyType = utils.unpackString(data[offset:])
        offset += 4 + len(self.keyType)

        # unused currently
        self.flags = utils.u16(data[offset:])
        offset += 2

        # todo

    def __str__(self):
        res = super().__str__()
        res += "data:\n"
        res += f"  public key type : {self.keyType}\n"
        return res


class HS_VLIST(HandleValue):
    def __init__(self):
        super().__init__()
    
    def setVals(self):
        pass
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        offset = 0

        refCnt = utils.u32(data[offset:])
        offset += 4
        
        refs = []

        for _i in range(refCnt):
            handle = utils.unpackString(data[offset:])
            offset += 4 + len(handle)
            index = utils.u32(data[offset:])
            offset += 4
            refs.append(Reference(handle, index))
        
        self.refs = refs
        assert offset == len(data)

    def __str__(self):
        res = super().__str__()
        res += "data:\n"
        for ref in self.refs:
            res += "  " + str(ref)
        return res


class HS_CERT(HandleValue):
    def __init__(self):
        super().__init__()
    
    def setVals(self,):
        pass
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        # offset = 0

        return

    def __str__(self):
        res = super().__str__()

        return res

class HS_SIGNATURE(HandleValue):
    def __init__(self):
        super().__init__()
    
    def setVals(self,):
        pass
    
    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def _parseData(self, data):
        assert isinstance(data, bytes)
        # offset = 0

        return

    def __str__(self):
        res = super().__str__()

        return res