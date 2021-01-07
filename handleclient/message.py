import logging
from struct import pack, unpack
from enum import Enum

from handleclient import common
from handleclient import utils

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

"""
Handle system client implemention.
Handle protocol (version 2.1)
rfc: https://tools.ietf.org/html/rfc3652
"""

class Message(object):
    def __init__(self):
        self.evp = Envelope()
        self.header = Header()
        self.bodyRaw = b''
        self.cred = Credential()
        self.body = RawBody()

    def setVals(self, evp, header, body, cred):
        assert isinstance(evp, Envelope)
        assert isinstance(header, Header)
        assert isinstance(body, Body)
        assert isinstance(cred, Credential) # todo
        self.evp = evp
        self.header = header
        self.body = body
        self.cred = cred

    def digest(self, hashType):
        return utils.doDigest(hashType, [self.header.pack(), self.body.pack()])
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        assert common.MIN_MESSAGE_SIZE <= len(payload)

        msg = Message()
        offset = 0
        msg.evp = Envelope.parse(payload[:common.ENVELOPE_LEN])
        offset += common.ENVELOPE_LEN
        
        msg.header = Header.parse(payload[offset:offset+common.HEADER_LEN])
        offset += common.HEADER_LEN

        bodyLength = msg.header.bodyLength
        msg.body = RawBody.parse(payload[offset:offset+bodyLength])
        offset += bodyLength

        credLength = utils.u32(payload[offset:])
        offset  += 4
        msg.cred = Credential.parse(payload[offset:offset+credLength])
        offset += credLength
        assert offset == len(payload)
        return msg
    
    def pack(self):
        payload = b''
        bodyRaw = self.body.pack()
        bodyLen = len(bodyRaw)
        self.header.setBodyLength(bodyLen)
        credRaw = self.cred.pack()
        credLen = len(credRaw)
        self.evp.setMessageLength(common.HEADER_LEN + bodyLen + credLen)

        payload += self.evp.pack()
        payload += self.header.pack()
        payload += bodyRaw
        payload += credRaw
        return payload


    def __str__(self):
        res = "Message:\n"
        res += str(self.evp)+"\n"
        res += str(self.header)+"\n"
        res += str(self.body)+"\n"
        res += str(self.cred)
        return res

"""Cautions
1. The order of transmission of data packets follows the network byte order (also called the Big-Endian [11]).

"""

"""
      .----------------------.
      |                      |  ; Message wrapper for proper message
      |   Message Envelope   |  ; delivery.  Not protected by the
      |                      |  ; digital signature in the Message
      |                      |  ; Credential.
      |----------------------|
      |                      |  ; Common data fields for all handle
      |   Message Header     |  ; operations.
      |                      |
      |----------------------|
      |                      |  ; Specific data fields for each
      |   Message Body       |  ; request/response.
      |                      |
      |----------------------|
      |                      |  ; Contains digital signature or
      |  Message Credential  |  ; message authentication code (MAC)
      |                      |  ; upon Message Header and Message
      '----------------------'  ; Body.

         Fig 2.2: Message format under the Handle protocol
"""

"""
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
.---------------------------------------------------------------.
| MajorVersion  | MinorVersion  |       MessageFlag             |
|---------------------------------------------------------------|
|               SessionID                                       |
|---------------------------------------------------------------|
|               RequestID                                       |
|---------------------------------------------------------------|
|               SequenceNumber                                  |
|---------------------------------------------------------------|
|               MessageLength                                   |
'---------------------------------------------------------------'

The <MessageFlag> consists of two octets defined as follows:
                                        1   1   1   1   1   1
0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
.---------------------------------------------------------------.
|CP |EC |TC |       Reserved                                    |
'---------------------------------------------------------------'
Bit 0 is the CP (ComPressed) flag that indicates whether the message
(excluding the Message Envelope) is compressed.  If the CP bit is set
(to 1), the message is compressed.  Otherwise, the message is not
compressed.  The Handle protocol uses the same compression method as
used by the FTP protocol[8].
Bit 1 is the EC (EnCrypted) flag that indicates whether the message
(excluding the Message Envelope) is encrypted.  The EC bit should
only be set under an established session where a session key is in
place.  If the EC bit is set (to 1), the message is encrypted using
the session key.  Otherwise the message is not encrypted.
Bit 2 is the TC (TrunCated) flag that indicates whether this is a
truncated message.  Message truncation happens most often when
transmitting a large message over the UDP protocol.  Details of
message truncation (or fragmentation) will be discussed in section
2.3.
Bits 3 to 15 are currently reserved and must be set to zero.


"""

class Envelope(object):
    
    def __init__(self):
        self.majorVersion   = common.COMPATIBILITY_MAJOR_VERSION
        self.minorVersion   = common.COMPATIBILITY_MINOR_VERSION
        self.suggestMajorVersion = common.MAJOR_VERSION
        self.suggestMinorVersion = common.MINOR_VERSION
        # The <MessageFlag> consists of two octets defined as follows:
        self.messageFlag    = 0
        # four-byte unsigned integer
        self.sessionID      = 0
        # four-byte unsigned integer
        self.requestID      = 0
        # four-byte unsigned integer
        self.sequenceNumber = 0
        # four-byte unsigned integer
        self.messageLength  = 0

    def setVals(self, messageFlag, sessionID, requestID, sequenceNumber, messageLength):
        self.messageFlag    = messageFlag
        self.sessionID      = sessionID
        self.requestID      = requestID
        self.sequenceNumber = sequenceNumber
        self.messageLength  = messageLength
    
    def setVersion(self, majorVersion, minorVersion, suggestMajorVersion, suggestMinorVersion):
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
        self.suggestMajorVersion = suggestMajorVersion
        self.suggestMinorVersion = suggestMinorVersion
    
    def setMessageFlag(self, messageFlag):
        assert isinstance(messageFlag, int)
        self.messageFlag = messageFlag
    
    def setSessionID(self, sessionID):
        assert isinstance(sessionID, int)
        self.sessionID = sessionID
    
    def setRequestID(self, requestID):
        assert isinstance(requestID, int)
        self.requestID = requestID
    
    def setSequenceNumber(self, sequenceNumber):
        assert isinstance(sequenceNumber, int)
        self.sequenceNumber = sequenceNumber
    
    def setMessageLength(self, messageLength):
        assert isinstance(messageLength, int)
        self.messageLength = messageLength
    # def set_vals()

    def pack(self):
        payload = b''
        payload += pack("!BBHIIII", 
            self.majorVersion,
            self.minorVersion,
            self.messageFlag | (((self.suggestMajorVersion)<<8) | self.suggestMinorVersion),
            self.sessionID,
            self.requestID,
            self.sequenceNumber,
            self.messageLength
        )
        return payload

    @classmethod
    def parse(cls, payload):
        assert type(payload)    == bytes
        assert len(payload)     == common.ENVELOPE_LEN
        
        evp = Envelope()

        vals = unpack("!BBHIIII", payload)

        index = 0
        evp.majorVersion   = vals[index]
        index += 1
        evp.minorVersion   = vals[index]
        index += 1
        tmp    = vals[index]
        index += 1
        evp.messageFlag = tmp & common.MESSAGE_FLAG_MASK
        tmp &= ~common.MESSAGE_FLAG_MASK
        evp.suggestMajorVersion = tmp >> 8
        evp.suggestMinorVersion = tmp & 0xff
        evp.sessionID      = vals[index]
        index += 1
        evp.requestID      = vals[index]
        index += 1
        evp.sequenceNumber = vals[index]
        index += 1
        evp.messageLength  = vals[index]
        index += 1

        return evp
    
    def toDict(self):
        return {
            "majorVersion"  : self.majorVersion,
            "minorVersion"  : self.minorVersion,
            "messageFlag "  : self.messageFlag ,
            "sessionID"     : self.sessionID,
            "requestID"     : self.requestID,
            "sequenceNumber": self.sequenceNumber,
            "messageLength" : self.messageLength,
        }

    def __str__(self):
        res = "Envelope:\n"
        res += f"  version(suggest)      : {self.majorVersion}.{self.minorVersion}({self.suggestMajorVersion}.{self.suggestMinorVersion})\n"
        res += f"  mesage flag  : {utils.printableFlags(common.MF, self.messageFlag)} ({self.messageFlag:#x})\n"
        res += f"  session id   : {self.sessionID:#x}\n"
        res += f"  request id   : {self.requestID:#x}\n"
        res += f"  sequence no  : {self.sequenceNumber:#x}\n"
        res += f"  message len  : {self.messageLength:#x}"
        return res

"""
The Message Header contains the common data elements among any
protocol operation.  It has a fixed size of 24 octets and consists of
eight fields.

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
.---------------------------------------------------------------.
|                     OpCode                                    |
|---------------------------------------------------------------|
|                     ResponseCode                              |
|---------------------------------------------------------------|
|                     OpFlag                                    |
|---------------------------------------------------------------|
|     SiteInfoSerialNumber      | RecursionCount|               |
|---------------------------------------------------------------|
|                     ExpirationTime                            |
|---------------------------------------------------------------|
|                     BodyLength                                |
'---------------------------------------------------------------'
"""

class Header(object):
    def __init__(self):
        """init each member with zero
        """
        # 4-byte unsigned integer
        self.opCode         = 0
        # 4-byte unsigned integer
        self.responseCode   = 0
        # 4-byte unsigned integer
        self.opFlag         = 0
        self.siteInfoSerialNumber = 0
        self.recursionCount = 0
        self.reserved1      = 0
        self.expirationTime = 0
        self.bodyLength     = 0

    def setVals(self, opCode, responseCode, opFlag, siteInfoSerialNumber, recursionCount, expirationTime, bodyLength):
        # 4-byte unsigned integer
        self.opCode         = opCode
        # 4-byte unsigned integer
        self.responseCode   = responseCode
        # 4-byte unsigned integer
        self.opFlag         = opFlag
        self.siteInfoSerialNumber = siteInfoSerialNumber
        self.recursionCount = recursionCount
        self.reserved1      = 0 # todo
        self.expirationTime = expirationTime
        self.bodyLength     = bodyLength
    
    def setOpCode(self, opCode):
        assert isinstance(opCode, int)
        self.opCode = opCode

    def setResponseCode(self, responseCode):
        assert isinstance(responseCode, int)
        self.responseCode = responseCode
    
    def setOpFlag(self, opFlag):
        assert isinstance(opFlag, int)
        self.opFlag = opFlag
    
    def setSiteInfoSerialNumber(self, siteInfoSerialNumber):
        assert isinstance(siteInfoSerialNumber, int)
        self.siteInfoSerialNumber = siteInfoSerialNumber
    
    def setRecursionCount(self, recursionCount):
        assert isinstance(recursionCount, int)
        self.recursionCount = recursionCount
    
    def setExpirationTime(self, expirationTime):
        assert isinstance(expirationTime, int)
        self.expirationTime = expirationTime
    
    def setBodyLength(self, bodyLength):
        assert isinstance(bodyLength, int)
        self.bodyLength = bodyLength

    def pack(self):
        payload = b''
        payload += pack("!IIIHBBII",
            self.opCode,
            self.responseCode,
            self.opFlag,
            self.siteInfoSerialNumber,
            self.recursionCount,
            self.reserved1,
            self.expirationTime,
            self.bodyLength
        )
        return payload
    
    @classmethod
    def parse(cls, payload):
        assert type(payload)    == bytes
        assert len(payload)     == common.HEADER_LEN

        hd = Header()
        vals = unpack("!IIIHBBII", payload)
        index = 0
        hd.opCode         = vals[index]
        index += 1
        hd.responseCode   = vals[index]
        index += 1
        hd.opFlag         = vals[index]
        index += 1
        hd.siteInfoSerialNumber   = vals[index]
        index += 1
        hd.recursionCount = vals[index]
        index += 1
        hd.reserved1      = vals[index]
        index += 1
        hd.expirationTime = vals[index]
        index += 1
        hd.bodyLength     = vals[index]
        index += 1

        return hd

    def __str__(self):
        res = "Header:\n"
        res += f"  opCode           : {utils.printableCode(common.OC, self.opCode)} ({self.opCode:#x})\n"
        res += f"  responseCode     : {utils.printableCode(common.RC, self.responseCode)} ({self.responseCode:#x})\n"
        res += f"  opFlag           : {utils.printableFlags(common.OPF, self.opFlag)} ({self.opFlag:#x})\n"
        res += f"  siteInfoSerialNumber   : {self.siteInfoSerialNumber:#x}\n"
        res += f"  recursionCount   : {self.recursionCount:#x}\n"
        # res += f"  reserved1      : {self.reserved1:#x}\n"
        res +=  (f"  expirationTime   : "
                + f"{utils.formatTimestamp(self.expirationTime)}"
                + f"({self.expirationTime:d})\n")
        res += f"  bodyLength       : {self.bodyLength:#x}"
        return res

class Body(object):
    def __init__(self):
        pass
    def __str__(self):
        return "Body :"

class RawBody(Body):
    def __init__(self):
        self.bodyRaw = b''
    
    def pack(self):
        return self.bodyRaw
    
    def __str__(self):
        return "raw body"
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        rb = RawBody()
        rb.bodyRaw = payload
        return rb

class Credential(object):
    def __init__(self, ):
        self.isEmpty = True
    
    def setVals(self, 
            version: int,
            reserved: int,
            options: int,
            signer: tuple,
            credType: bytes,
            signedInfo: tuple):
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        .---------------------------------------------------------------.
        |           CredentialLength                                    |
        |---------------------------------------------------------------|
        |   Version     |    Reserved   |       Options                 |
        |---------------------------------------------------------------|
        |                                                               |
        |   Signer: <Handle, Index>                                     |
        |                                                               |
        |---------------------------------------------------------------|
        |           Type      (UTF8-String)                             |
        |---------------------------------------------------------------|
        |                                                               |
        |   SignedInfo: <Length> : 4-byte unsigned integer              |
        |               DigestAlgorithm: <UTF8-String>                  |
        |               SignedData: <Length, Signature>                 |
        |                                                               |
        '---------------------------------------------------------------'
        """
        assert isinstance(version, int)
        assert isinstance(reserved, int)
        assert isinstance(options, int)
        assert isinstance(signer, tuple)
        assert len(signer) == 2
        assert isinstance(signer[0], bytes)
        assert isinstance(signer[1], int)
        assert isinstance(credType, bytes)
        assert isinstance(signedInfo, tuple)
        assert len(signedInfo) == 2
        assert issubclass(signedInfo[0], Enum)
        assert issubclass(signedInfo[1], bytes)

        self.isEmpty = False
        self.version = version
        self.reserved = reserved
        self.options = options
        self.signer = signer
        self.credType = credType
        self.signedInfo = signedInfo

    def pack(self):
        if self.isEmpty:
            return utils.p32(0)
        payload = b''
        payload += utils.p8(self.version)
        payload += utils.p8(self.reserved)
        payload += utils.p16(self.options)
        # signer.handle
        payload += utils.pba(self.signer[0])
        # signer.handle_index
        payload += utils.p32(self.signer[1])
        payload += utils.pba(self.credType)
        
        signedInfoPack = b''
        signedInfoPack += utils.pba(self.signedInfo[0])
        signedInfoPack += utils.pba(self.signedInfo[1])
        signedInfoPack = utils.p32(len(signedInfoPack)) + signedInfoPack
        payload += signedInfoPack

        payload = utils.p32(len(payload)) + payload
        return payload

    @classmethod
    def emptyCred(cls):
        cred = Credential()
        return cred

    @classmethod
    def parse(cls, payload):
        assert type(payload) == bytes
        cred = Credential()
        return cred
        # raise Exception("not impl")

    def __str__(self):
        res = "Cred :\n"
        if self.isEmpty:
            res += " empty"
        else:
            res += " todo"
        return res

class RequestDigest(object):

    def __init__(self):
        self.dai = 0
        self.data = b''

    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        rd = RequestDigest()
        offset = 0
        rd.dai = utils.u8(payload[offset:])
        offset += 1
        if rd.dai == common.HASH_CODE.MD5.value:
            rd.data = payload[offset:offset+common.MD5_DIGEST_SIZE]
            offset += common.MD5_DIGEST_SIZE
        elif rd.dai == common.HASH_CODE.SHA1.value:
            rd.data = payload[offset:offset+common.SHA1_DIGEST_SIZE]
            offset += common.SHA1_DIGEST_SIZE
        elif rd.dai == common.HASH_CODE.SHA256.value:
            rd.data = payload[offset:offset+common.SHA256_DIGEST_SIZE]
        elif rd.dai == common.HASH_CODE.OLD_FORMAT.value:
            offset -= 1
            rd.data = utils.uba(payload[offset:])
        else:
            logger.critical(f"unimplemented digest parse : {rd.dai:#x}")
        return rd
    
    def pack(self):
        if self.dai == common.HASH_CODE.OLD_FORMAT.value:
            return utils.pba(self.data)
        else:
            return utils.p8(self.dai) + self.data

    def __len__(self):
        l = len(self.data)
        if l == 0:
            return 0
        elif self.dai == common.HASH_CODE.OLD_FORMAT.value:
            return 4 + l
        else:
            return l + 1
    
    def __str__(self):
        return f"{utils.printableCode(common.HASH_CODE, self.dai)} : {self.data.hex()}"
