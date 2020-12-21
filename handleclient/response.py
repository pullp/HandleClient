
from struct import pack, unpack 
import logging

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import handlevalue

from handleclient.handlevalue import HandleValue
from handleclient.message import Envelope, Header, Body, Credential

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

class Response(object):
    def __init__(self):
        self.evp = None
        self.header = None
        self.bodyRaw = None
        self.cred = None
        self.body = "unparsed"
        self.errMsg = ""

    def  setVals(self, evp, header, bodyRaw, cred):
        assert isinstance(evp, Envelope)
        assert isinstance(header, Header)
        assert isinstance(bodyRaw, bytes)
        assert isinstance(cred, Credential)

        self.evp = evp
        self.header = header
        self.bodyRaw = bodyRaw
        self.cred = cred

    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        assert common.MIN_MESSAGE_SIZE <= len(payload)

        resp = Response()
        offset = 0
        resp.evp = Envelope.parse(payload[:common.ENVELOPE_LEN])
        offset += common.ENVELOPE_LEN
        
        resp.header = Header.parse(payload[offset:offset+common.HEADER_LEN])
        offset += common.HEADER_LEN

        bodyLength = resp.header.bodyLength
        resp.bodyRaw = payload[offset:offset+bodyLength]
        offset += bodyLength

        credLength = utils.u32(payload[offset:])
        offset  += 4
        resp.cred = Credential.parse(payload[offset:offset+credLength])
        offset += credLength
        assert offset == len(payload)
        return resp
    
    def isSuccess(self):
        return self.header.responseCode == Header.RC.RC_SUCCESS.value

    def __str__(self):
        res = ""
        res += "Response:\n"
        res += str(self.evp)
        res += str(self.header)
        res += str(self.body)
        res += str(self.cred)
        return res


class ErrorResponseBody():
    def __init__(self):
        self.errMsg = ""

    @classmethod
    def parse(self, body):
        assert isinstance(body, bytes)
        self.errMsg = utils.unpackByteArray(body)
        assert 4 + len(self.errMsg) == len(body)

    def __str__(self):
        res = ""
        res += f"{self.errMsg}\n"
        return res

class ReferralResponseBody():
    """https://tools.ietf.org/html/rfc3652#section-3.4
    """
    def __init__(self):
        self.valueList = []

    @classmethod
    def parse(self, body):
        assert isinstance(body, bytes)
        logger.debug(body[:])
        
        offset = 0
        self.valueCnt = utils.u32(body[offset:])
        offset += 4
        for _i in range(self.valueCnt):
            pass

    def __str__(self):
        res = ""
        res += f"{self.errMsg}\n"
        return res


class SomeResponseBody():
    def __init__(self):
        pass
    
    @classmethod
    def parse(self, body):
        assert isinstance(body, bytes)
        logger.warning("todo")

    def __str__(self):
        res = ""
        res += "unimplemented\n"
        return res
