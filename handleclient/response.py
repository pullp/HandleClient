
from struct import pack, unpack 
import logging

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import handlevalue

from handleclient.handlevalue import HandleValue
from handleclient.message import Message, Envelope, Header, Body, Credential

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

class ErrorResponseBody(Body):
    def __init__(self):
        self.errMsg = ""

    @classmethod
    def parse(self, body):
        assert isinstance(body, bytes)
        self.errMsg = utils.uba(body)
        assert 4 + len(self.errMsg) == len(body)

    def __str__(self):
        res = ""
        res += f"{self.errMsg}"
        return res

class ReferralResponseBody(Body):
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

    # def __str__(self):
    #     res = ""
    #     res += f"{self.errMsg}\n"
    #     return res


class SomeResponseBody(Body):
    def __init__(self):
        pass
    
    @classmethod
    def parse(self, body):
        assert isinstance(body, bytes)
        logger.warning("todo")

    def __str__(self):
        res = ""
        res += "unimplemented"
        return res
