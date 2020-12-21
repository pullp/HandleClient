from enum import Enum
from struct import pack, unpack
import logging

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
    def __init__(self, evp, hd, body, cred):
        assert isinstance(evp, Envelope)
        assert isinstance(hd, Header)
        assert isinstance(body, body)
        # assert isinstance(cred, Credential) # todo
        self.evp = evp
        self.hd = hd
        self.body = body
        self.cred = cred
    
    def digest(self, hashType):
        pass


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
|               SessionId                                       |
|---------------------------------------------------------------|
|               RequestId                                       |
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
    class MF(Enum):
        MF_CP   = 1<<15 # MessageFlag:ComPressed
        MF_EC   = 1<<14 # MessageFlag:EnCrypted
        MF_TC   = 1<<13 # MessageFlag:TrunCated
        # MF_USED = MF_CP | MF_EC | MF_TC
    
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
        self.requestId      = 0
        # four-byte unsigned integer
        self.sequenceNumber = 0
        # four-byte unsigned integer
        self.messageLength  = 0

    def setVals(self, messageFlag, sessionID, requestId, sequenceNumber, messageLength):
        self.messageFlag    = messageFlag
        self.sessionID      = sessionID
        self.requestId      = requestId
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
    
    def setSessionId(self, sessionID):
        assert isinstance(sessionID, int)
        self.sessionID = sessionID
    
    def setRequestId(self, requestId):
        assert isinstance(requestId, int)
        self.requestId = requestId
    
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
            self.requestId,
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
        evp.requestId      = vals[index]
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
            "requestId"     : self.requestId,
            "sequenceNumber": self.sequenceNumber,
            "messageLength" : self.messageLength,
        }

    def __str__(self):
        res = "Envelope:\n"
        res += f"  version(suggest)      : {self.majorVersion}.{self.minorVersion}({self.suggestMajorVersion}.{self.suggestMinorVersion})\n"
        res += f"  mesage flag  : {utils.printableFlags(Envelope.MF, self.messageFlag)} ({self.messageFlag:#x})\n"
        res += f"  session id   : {self.sessionID:#x}\n"
        res += f"  request id   : {self.requestId:#x}\n"
        res += f"  sequence no  : {self.sequenceNumber:#x}\n"
        res += f"  message len  : {self.messageLength:#x}\n"
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

    # op code
    # from https://tools.ietf.org/html/rfc3652#section-2.2.2.1
    class OC(Enum):
        # 300
        #  :        { Reserved for handle server administration }
        # 399
        OC_RESERVED            =   0 # Reserved
        OC_RESOLUTION          =   1 # Handle query
        OC_GET_SITEINFO        =   2 # Get HS_SITE values
        OC_CREATE_HANDLE       = 100 # Create new handle
        OC_DELETE_HANDLE       = 101 # Delete existing handle
        OC_ADD_VALUE           = 102 # Add handle value(s)
        OC_REMOVE_VALUE        = 103 # Remove handle value(s)
        OC_MODIFY_VALUE        = 104 # Modify handle value(s)
        OC_LIST_HANDLE         = 105 # List handles
        OC_LIST_NA             = 106 # List sub-naming authorities
        OC_CHALLENGE_RESPONSE  = 200 # Response to challenge
        OC_VERIFY_RESPONSE     = 201 # Verify challenge response
        OC_SESSION_SETUP       = 400 # Session setup request
        OC_SESSION_TERMINATE   = 401 # Session termination request
        OC_SESSION_EXCHANGEKEY = 402 # Session key exchange

    # response code
    # https://tools.ietf.org/html/rfc3652#section-2.2.2.2
    class RC(Enum):
         RC_RESERVED                = 0   #  Reserved for request
         RC_SUCCESS                 = 1   #  Success response
         RC_ERROR                   = 2   #  General error
         RC_SERVER_BUSY             = 3   #  Server too busy to respond
         RC_PROTOCOL_ERROR          = 4   #  Corrupted or unrecognizable message
         RC_OPERATION_DENIED        = 5   #  Unsupported operation
         RC_RECUR_LIMIT_EXCEEDED    = 6   #  Too many recursions for the request
         RC_HANDLE_NOT_FOUND        = 100 #  Handle not found
         RC_HANDLE_ALREADY_EXIST    = 101 #  Handle already exists
         RC_INVALID_HANDLE          = 102 #  Encoding (or syntax) error
         RC_VALUE_NOT_FOUND         = 200 #  Value not found
         RC_VALUE_ALREADY_EXIST     = 201 #  Value already exists
         RC_VALUE_INVALID           = 202 #  Invalid handle value
         RC_EXPIRED_SITE_INFO       = 300 #  SITE_INFO out of date
         RC_SERVER_NOT_RESP         = 301 #  Server not responsible
         RC_SERVICE_REFERRAL        = 302 #  Server referral
         RC_PREFIX_REFERRAL             = 303 #  // formerly RC_NA_DELEGATE Naming authority delegation takes place.
         RC_NOT_AUTHORIZED          = 400 #  Not authorized/permitted
         RC_ACCESS_DENIED           = 401 #  No access to data
         RC_AUTHEN_NEEDED           = 402 #  Authentication required
         RC_AUTHEN_FAILED           = 403 #  Failed to authenticate
         RC_INVALID_CREDENTIAL      = 404 #  Invalid credential
         RC_AUTHEN_TIMEOUT          = 405 #  Authentication timed out
         RC_UNABLE_TO_AUTHEN        = 406 #  Unable to authenticate
         RC_SESSION_TIMEOUT         = 500 #  Session expired
         RC_SESSION_FAILED          = 501 #  Unable to establish session
         RC_NO_SESSION_KEY          = 502 #  No session yet available
         RC_SESSION_NO_SUPPORT      = 503 #  Session not supported
         RC_SESSION_KEY_INVALID     = 504 #  Invalid session key
         RC_TRYING                  = 900 #  Request under processing
         RC_FORWARDED               = 901 #  Request forwarded to another server
         RC_QUEUED                  = 902 #  Request queued for later processing
    
    # OpFlag
    # https://tools.ietf.org/html/rfc3652#section-2.2.2.3
    class OPF(Enum):
        OPF_AT  = 1 << 31 # AuThoritative bit.
        OPF_CT  = 1 << 30 # CerTified bit.
        OPF_ENC = 1 << 29 # ENCryption bit.
        OPF_REC = 1 << 28 # RECursive bit.
        OPF_CA  = 1 << 27 # Cache Authentication.
        OPF_CN  = 1 << 26 # ContiNuous bit.
        OPF_KC  = 1 << 25 # Keep Connection bit.
        OPF_PO  = 1 << 24 # Public Only bit.
        OPF_RD  = 1 << 23 # Request-Digest bit.
        # OPF_USED    = 0x1ff

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
        res += f"  opCode           : {utils.printableCode(Header.OC, self.opCode)} ({self.opCode:#x})\n"
        res += f"  responseCode     : {utils.printableCode(Header.RC, self.responseCode)} ({self.responseCode:#x})\n"
        res += f"  opFlag           : {utils.printableFlags(Header.OPF, self.opFlag)} ({self.opFlag:#x})\n"
        res += f"  siteInfoSerialNumber   : {self.siteInfoSerialNumber:#x}\n"
        res += f"  recursionCount   : {self.recursionCount:#x}\n"
        # res += f"  reserved1      : {self.reserved1:#x}\n"
        res +=  (f"  expirationTime   : "
                + f"{utils.formatTimestamp(self.expirationTime)}"
                + f"({self.expirationTime:d})\n")
        res += f"  bodyLength       : {self.bodyLength:#x}\n"
        return res

Body = bytes


class Credential(object):
    def __init__(self, ):
        pass
    
    def pack(self):
        pass

    @classmethod
    def parse(cls, payload):
        assert type(payload) == bytes
        cred = Credential()
        return cred
        # raise Exception("not impl")

    def __str__(self):
        return ""

class RequestDigest(object):

    def __init__(self):
        self.dai = 0
        self.digest = b''
    
    def pack(self):
        pass

    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        rd = RequestDigest()
        offset = 0
        rd.dai = utils.u8(payload[offset:])
        offset += 1
        if rd.dai == common.HASH_CODE.MD5.value:
            rd.digest = payload[offset:offset+common.MD5_DIGEST_SIZE]
            offset += common.MD5_DIGEST_SIZE
        elif rd.dai == common.HASH_CODE.SHA1.value:
            rd.digest = payload[offset:offset+common.SHA1_DIGEST_SIZE]
            offset += common.SHA1_DIGEST_SIZE
        elif rd.dai == common.HASH_CODE.SHA256.value:
            rd.digest = payload[offset:offset+common.SHA256_DIGEST_SIZE]
        else:
            logger.critical(f"unimplemented digest parse : {rd.dai:#x}")
        return rd
    
    def __len__(self):
        l = len(self.digest)
        if l == 0:
            return 0
        else:
            return l + 1
    
    def __str__(self):
        return f"{utils.printableCode(common.HASH_CODE, self.dai)} : {self.digest.hex()}"
