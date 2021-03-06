from struct import pack, unpack
import logging

from handleclient import common
from handleclient import utils
# from handleclient import message
# from handleclient import request
# from handleclient import response
# from handleclient import handlevalue

# from handleclient.handlevalue import HandleValue
# from handleclient.message import Message, Envelope, Header, Body, Credential


logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

# supported (predefined) handle value types
# query new type by 0.TYPE todo

class Reference(object):
    def __init__(self):
        self.handle = b''
        self.index = 0

    def setVals(self, handle, index):
        assert isinstance(handle, bytes)
        assert isinstance(index, int)

        self.handle = handle
        self.index = index
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        ref = Reference()
        offset = 0
        ref.handle = utils.uba(payload[offset:])
        offset += 4 + len(ref.handle)
        ref.index = utils.u32(payload[offset:])
        offset += 4
        return ref

    def pack(self):
        payload = utils.pba(self.handle) + utils.p32(self.index)
        # payload += utils.p32(len(self.handle)) + self.handle
        # payload += utils.p32(len(self.index))
        return payload

    def __str__(self):
        res = f"{self.handle.decode()} ({self.index})"
        return res

    @staticmethod
    def calcReferenceSize(payload):
        assert isinstance(payload, bytes)

        offset = 0
        handleSize = utils.u32(payload[offset:])
        offset += 4 + handleSize # handle
        offset += 4 # index
        return offset

class HandleValue(object):
    """https://tools.ietf.org/html/rfc3651#section-3.1
    """

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
        assert all(isinstance(item, Reference) for item in refs)

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
        # logger.debug(f"self.refs cnt : {len(self.refs)}")

        # self.value      = None # parse from self.data

    def pack(self):
        self.data = self.packData()
        payload = b''
        payload += utils.p32(self.index)
        payload += utils.p32(self.timestamp)
        payload += utils.p8(self.ttlType)
        payload += utils.p32(self.ttl)
        payload += utils.p8(self.permission)
        payload += utils.p32(len(self.valueType)) + self.valueType
        payload += utils.p32(len(self.data)) + self.data
        payload += utils.p32(len(self.refs)) # ref count
        for ref in self.refs:
            payload += ref.pack()
        # offset = 
        # valuesCnt =  
        return payload
    
    def packData(self):
        return self.data

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

        valueType  = utils.uba(payload[offset:])
        offset += 4 + len(valueType)

        data  = utils.uba(payload[offset:])
        offset += 4 + len(data)

        refs = []
        refCnt = utils.u32(payload[offset:])
        offset += 4
        for _i in range(0, refCnt):
            refLen = Reference.calcReferenceSize(payload[offset:])
            ref = Reference.parse(payload[offset:])
            offset += refLen
            refs.append(ref)
            logger.debug(str(ref))
        assert offset == len(payload)
        
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
        logger.debug(f"before setBasicVals {valueType} : {index} {permission:#x}")
        hv.setBasicVals(valueType=valueType, index=index, data=data,
            ttlType=ttlType, ttl=ttl, permission=permission,
            timestamp=timestamp, refs=refs)
        hv.parseData(data)
        return hv
    
    def setBasicVals(self, *args, **kwargs):
        self.setVals(*args, **kwargs)
    
    def parseData(self, data):
        return

    def __str__(self):
        res = "HandleValue:\n"
        res += f" type : {self.valueType.decode()}\n"
        res += f" index : {self.index}\n"
        res += f" TTL   : {self.ttl}({utils.printableCode(common.HV_TTLTYPE, self.ttlType)})\n"
        res += f" permission : {utils.printableFlags(common.HV_PERM, self.permission)} ({self.permission:#x})\n"
        res += f" timestamp : {utils.formatTimestamp(self.timestamp)}({self.timestamp})\n"
        res += f" references:\n"
        for ref in self.refs:
            res += "  " + str(ref) + '\n'
        return res[:-1]

    @staticmethod
    def calcHandleValueSize(payload: bytes, offset: int = 0) -> int:
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

    def __str__(self):
        res = f"interface : {utils.printableCode(common.SI_TYPE, self.serviceType)} {utils.printableCode(common.SI_PROTOCOL, self.protocol)} {self.portNumber:d}"
        return res

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
        assert len(address) == common.IPV6_SIZE_IN_BYTES
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
    
    def __str__(self):
        res = "ServerRecord:\n"
        res += f" server id : {self.serverID}\n"
        res += f" address : {utils.formatIpAddress(self.address)}\n"
        logger.warning("publicKey todo")
        res += f" public key : todo\n"
        res += " interfaces:\n"
        for intf in self.interfaces:
            res += f"  {str(intf)}\n"
        return res


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
    
    def setDataVals(self, version, protocolVersion, serialNumber,
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
    
    def setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def parseData(self, data):
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
            name = utils.uba(data[offset:])
            offset += 4 + len(name)

            value = utils.uba(data[offset:])
            offset += 4 + len(value)
            self.attributeList.append((name, value))
        
        serverCnt = utils.u32(data[offset:])
        offset += 4
        servers = []
        for _i in range(serverCnt):
            serverID = utils.u32(data[offset:])
            offset += 4
            address = data[offset:offset + common.IPV6_SIZE_IN_BYTES]
            offset += common.IPV6_SIZE_IN_BYTES
            publicKey = utils.uba(data[offset:])
            offset += 4 + len(publicKey)

            intfCnt = utils.u32(data[offset:])
            offset += 4

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

    def packData(self):
        payload = b''
        logger.warning("HS_SITE packData unimplemented")
        return payload

    def __str__(self):
        res = super().__str__() + '\n'
        res += "data:"
        res += f"  data format ersion : {self.version}\n"
        res += f"  protocol version : {self.majorProtocolVersion}.{self.minorProtocolVersion}\n"
        res += f"  serial number : {self.serialNumber}\n"
        res += f"  primary mask : {utils.printableFlags(common.HS_SITE_PM, self.primaryMask)}\n"
        res += f"  hash option : {self.hashOption}\n"
        res += f"  hash filter : {self.hashFilter.decode()}\n"
        res += f"attribute list:\n"
        for attribute in self.attributeList:
            res += f"  {attribute[0].decode()} : {attribute[1].decode()}\n"
        res += "servers:"
        for server in self.servers:
            res += str(server)+'\n'
        return res


class HS_ADMIN(HandleValue):
    def __init__(self):
        super().__init__()
        self.adminPermission = 0
        self.adminID = b''
        self.adminIndex = b''
    
    def setDataVals(self,):
        pass
    
    def setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def parseData(self, data):
        assert isinstance(data, bytes)
        offset = 0
        self.adminPermission = utils.u16(data[offset:])
        offset += 2
        
        self.adminID = utils.uba(data[offset:])
        offset += 4 + len(self.adminID)

        self.adminIndex = utils.u32(data[offset:])
        offset += 4

        assert (offset == len(data) or offset+2 == len(data)) # todo legacyByteLength

    def packData(self):
        payload = b''
        logger.warning("HS_ADMIN packData unimplemented")
        return payload

    def __str__(self):
        res = super().__str__()+'\n'
        res += "data:\n"
        res += f"  adminPermission : {utils.printableFlags(common.HS_ADMIN_PERM, self.adminPermission)}\n"
        res += f"  admin ref : {self.adminID.decode()} ({self.adminIndex})"
        return res


class HS_STRING(HandleValue):
    """parser for URL, EMAIL, HS_ALIAS, HS_SERV, DESC, HS_SECKEY and types with these prefixes.
    """
    def __init__(self):
        super().__init__()
        self.info = b''

    def setDataVals(self, info):
        self.info = info
    
    def setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def parseData(self, data):
        assert isinstance(data, bytes)
        self.info = data.decode(common.TEXT_ENCODING)

    def packData(self):
        payload = b''
        payload = self.info.encode(common.TEXT_ENCODING)
        return payload


    def __str__(self):
        res = super().__str__()+'\n'
        res += f"data: {self.info}"
        return res


class HS_PUBKEY(HandleValue):
    def __init__(self):
        super().__init__()
    
    def setVals(self):
        logger.warning("unimplemented")

    def setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def parseData(self, data):
        assert isinstance(data, bytes)
        offset = 0

        self.keyType = utils.uba(data[offset:])
        offset += 4 + len(self.keyType)
        # unused currently
        self.flags = utils.u16(data[offset:])
        offset += 2

        if self.keyType == common.KEY_ENCODING_RSA_PUBLIC:
            e = utils.uba(data[offset:])
            offset += 4 + len(e)
            n = utils.uba(data[offset:])
            offset += len(n)
            self.e = int.from_bytes(e, byteorder='big')
            self.n = int.from_bytes(n, byteorder='big')
            logger.debug(f"e = {hex(self.e)}")
            logger.debug(f"n = {hex(self.n)}")
        elif self.keyType == common.KEY_ENCODING_DSA_PUBLIC:
            q = utils.uba(data[offset:])
            offset += 4 + len(q)
            p = utils.uba(data[offset:])
            offset += len(p)
            g = utils.uba(data[offset:])
            offset += len(g)
            y = utils.uba(data[offset:])
            offset += len(y)
            logger.error("unimplemented")
        elif self.keyType == common.KEY_ENCODING_DH_PUBLIC:
            y = utils.uba(data[offset:])
            offset += len(y)
            p = utils.uba(data[offset:])
            offset += len(p)
            g = utils.uba(data[offset:])
            offset += len(g)
            logger.error("unimplemented")
        else:
            logger.error(f"unsupport key type {self.keyType}")

    def packData(self):
        logger.warning("unimplemented")

    def __str__(self):
        res = super().__str__()+'\n'
        res += "data:\n"
        res += f"  public key type : {self.keyType}\n"
        if self.keyType == common.KEY_ENCODING_RSA_PUBLIC:
            res += f" n = {hex(self.n)}\n e = {hex(self.e)}"
        else:
            res += f"unsupport key type : {self.keyType}"
        return res


class HS_VLIST(HandleValue):
    def __init__(self):
        super().__init__()
    
    def setDataVals(self):
        logger.warning("unimplemented")
    
    def setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def parseData(self, data):
        assert isinstance(data, bytes)
        offset = 0

        refCnt = utils.u32(data[offset:])
        offset += 4
        
        refs = []

        for _i in range(refCnt):
            handle = utils.uba(data[offset:])
            offset += 4 + len(handle)
            index = utils.u32(data[offset:])
            offset += 4
            ref = Reference()
            ref.setVals(handle, index)
            refs.append(ref)
        
        self.refs = refs
        assert offset == len(data)

    def packData(self):
        logger.warning("unimplemented")

    def __str__(self):
        res = super().__str__()+'\n'
        res += "data:\n"
        for ref in self.refs:
            res += "  " + str(ref)
        return res


class HS_CERT(HandleValue):
    def __init__(self):
        super().__init__()
    
    def setDataVals(self,):
        logger.warning("unimplemented")
    
    def setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)
    
    def parseData(self, data):
        assert isinstance(data, bytes)
        # offset = 0
        logger.warning("unimplemented")
        return

    def packData(self):
        logger.warning("unimplemented")

    def __str__(self):
        res = super().__str__()+'\n'
        return res

# class HS_SIGNATURE(HandleValue):
#     def __init__(self):
#         super().__init__()
    
#     def setDataVals(self,):
#         pass
    
#     def setBasicVals(self, *args, **kwargs):
#         super().setVals(*args, **kwargs)
    
#     def parseData(self, data):
#         assert isinstance(data, bytes)
#         # offset = 0

#         return

#     def __str__(self):
#         res = super().__str__()

#         return res