#coding:utf-8
from enum import Enum
from struct import pack, unpack
from datetime import datetime

import utils

"""
Handle system client implemention.
Handle protocol (version 2.1)
rfc: https://tools.ietf.org/html/rfc3652
"""

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

ENVELOPE_LEN    = 20
HEADER_LEN      = 24

class Envelope(object):
    class MF(Enum):
        MF_CP   = 1<<15 # MessageFlag:ComPressed
        MF_EC   = 1<<14 # MessageFlag:EnCrypted
        MF_TC   = 1<<13 # MessageFlag:TrunCated
        # MF_USED = MF_CP | MF_EC | MF_TC
    
    def __init__(self):
        # one-byte unsigned integer.
        self.majorVersion   = 0
        # one-byte unsigned integer.
        self.minorVersion   = 0
        # The <MessageFlag> consists of two octets defined as follows:
        self.messageFlag    = 0
        # four-byte unsigned integer
        self.sessionId      = 0
        # four-byte unsigned integer
        self.requestId      = 0
        # four-byte unsigned integer
        self.sequenceNumber = 0
        # four-byte unsigned integer
        self.messageLength  = 0

    def setVals(self, messageFlag, sessionId, requestId, sequenceNumber, messageLength):
        self.majorVersion   = 2
        self.minorVersion   = 1
        self.messageFlag    = messageFlag
        self.sessionId      = sessionId
        self.requestId      = requestId
        self.sequenceNumber = sequenceNumber
        self.messageLength  = messageLength
    
    def setVersion(self, majorVersion, minorVersion):
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
    
    def setMessageFlag(self, messageFlag):
        assert isinstance(messageFlag, int)
        self.messageFlag = messageFlag
    
    def setSessionId(self, sessionId):
        assert isinstance(sessionId, int)
        self.sessionId = sessionId
    
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
            self.messageFlag ,
            self.sessionId,
            self.requestId,
            self.sequenceNumber,
            self.messageLength
        )
        return payload

    # @staticmethod
    def parse(self, payload):
        assert type(payload)    == bytes
        assert len(payload)     == ENVELOPE_LEN

        vals = unpack("!BBHIIII", payload)

        idx = 0
        self.majorVersion   = vals[idx]
        idx += 1
        self.minorVersion   = vals[idx]
        idx += 1
        self.messageFlag    = vals[idx]
        idx += 1
        self.sessionId      = vals[idx]
        idx += 1
        self.requestId      = vals[idx]
        idx += 1
        self.sequenceNumber = vals[idx]
        idx += 1
        self.messageLength  = vals[idx]
        idx += 1
    
    def toDict(self):
        return {
            "majorVersion"  : self.majorVersion,
            "minorVersion"  : self.minorVersion,
            "messageFlag "  : self.messageFlag ,
            "sessionId"     : self.sessionId,
            "requestId"     : self.requestId,
            "sequenceNumber": self.sequenceNumber,
            "messageLength" : self.messageLength,
        }

    def __str__(self):
        res = "Envelope:\n"
        res += f"  version      : {self.majorVersion}.{self.minorVersion}\n"
        res += f"  mesage flag  : {utils.printableFlags(Envelope.MF, self.messageFlag)} ({self.messageFlag:#x})\n"
        res += f"  session id   : {self.sessionId:#x}\n"
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
         RC_NA_DELEGATE             = 303 #  Naming authority delegation takes place.
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
        OPF_AT  = 1 << 31
        OPF_CT  = 1 << 30
        OPF_ENC = 1 << 29
        OPF_REC = 1 << 28
        OPF_CA  = 1 << 27
        OPF_CN  = 1 << 26
        OPF_KC  = 1 << 25
        OPF_PO  = 1 << 24
        OPF_RD  = 1 << 23
        # OPF_USED    = 0x1ff

    # class OF(Enum):
    #     AT = 

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
    
    def parse(self, payload):
        assert type(payload)    == bytes
        assert len(payload)     == HEADER_LEN
        vals = unpack("!IIIHBBII", payload)
        idx = 0
        self.opCode         = vals[idx]
        idx += 1
        self.responseCode   = vals[idx]
        idx += 1
        self.opFlag         = vals[idx]
        idx += 1
        self.siteInfoSerialNumber   = vals[idx]
        idx += 1
        self.recursionCount = vals[idx]
        idx += 1
        self.reserved1      = vals[idx]
        idx += 1
        self.expirationTime = vals[idx]
        idx += 1
        self.bodyLength     = vals[idx]
        idx += 1

    def __str__(self):
        res = ""
        res += f"  opCode           : {self.opCode:#x}\n"
        res += f"  responseCode     : {self.responseCode:#x}\n"
        res += f"  opFlag           : {utils.printableFlags(Header.OPF, self.opFlag)} ({self.opFlag:#x})\n"
        res += f"  siteInfoSerialNumber   : {self.siteInfoSerialNumber:#x}\n"
        res += f"  recursionCount   : {self.recursionCount:#x}\n"
        # res += f"  reserved1      : {self.reserved1:#x}\n"
        res += f"  expirationTime   : { datetime.utcfromtimestamp(self.expirationTime).strftime('%Y-%m-%d %H:%M:%S')}({self.expirationTime:d})\n"
        res += f"  bodyLength       : {self.bodyLength:#x}\n"
        return res

class Body(object):
    def __init__(self, data):
        self.data = data
    
    def pack(self):
        payload = self.data
        return payload
    
    @staticmethod
    def parse(payload):
        assert type(payload) == bytes
        return payload

class Credential(object):
    def __init__(self, ):
        pass
    
    def pack(self):
        pass

    @staticmethod
    def parse(payload):
        assert type(payload) == bytes
        # assert len(payload) == 
        pass