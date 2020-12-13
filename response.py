from struct import pack, unpack 
import logging

import common
import utils
import message
import handlevalue

from message import Envelope, Header, Body, Credential
from handlevalue import HandleValue

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

class Response(object):
    def __init__(self):
        self.evp = None
        self.header = None
        self.body = None
        self.cred = None

    def  setVals(self, evp, header, body, cred):
        assert isinstance(evp, Envelope)
        assert isinstance(header, Header)
        assert isinstance(body, bytes)
        assert isinstance(cred, Credential)

        self.evp = evp
        self.header = header
        self.body = body
        self.cred = cred

    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        assert common.MIN_MESSAGE_SIZE <= len(payload)

        offset = 0
        evp = Envelope.parse(payload[:common.ENVELOPE_LEN])
        offset += common.ENVELOPE_LEN
        header = Header.parse(payload[offset:offset+common.HEADER_LEN])
        offset += common.HEADER_LEN

        bodyLength = header.bodyLength
        body = payload[offset:offset+bodyLength]
        offset += bodyLength

        credLen = utils.u32(payload[offset:])
        offset  += 4
        cred = Credential.parse(payload[offset:offset+credLen])
        offset += credLen
        
        if header.opCode == Header.OC.OC_RESOLUTION.value \
            and header.responseCode == Header.RC.RC_SUCCESS.value :
            resp = ResolutionResponse()
        else:
            logger.info(str(evp))
            logger.info(str(header))
            raise Exception(f"unsupported response type")
        
        resp._setBasicVals(evp=evp, header=header, body=body, cred=cred)
        resp._parseBody(body)

        assert offset == len(payload)
        return resp
    
    def __str__(self):
        res = ""
        res += "Response:\n"
        res += str(self.evp)
        res += str(self.header)
        res += str(self.cred)
        return res

class ResolutionResponse(Response):
    def __init__(self):
        super().__init__()
        self.handle = None
        self.valueList = []
        self.requestDigest = None

    def _setBasicVals(self, *args, **kwargs):
        super().setVals(*args, **kwargs)

    def _parseBody(self, body):
        assert isinstance(body, bytes)

        offset = 0
        self.handle = utils.unpackString(body[offset:])
        offset += 4 + len(self.handle)
        # logger.debug(f"handle : {self.handle}({len(self.handle)})")
        # logger.debug(f"offset : {offset}/{len(body)}")
        if (valueCnt := utils.u32(body[offset:])) \
            > common.MAX_HANDLE_VALUES:
            raise Exception(f"invalid valueCnt : {valueCnt}")
        offset += 4
        logger.debug(f"valueCnt: {valueCnt}")
        for _i in range(valueCnt):
            valueLen = HandleValue.calcHandleValueSize(body, offset)
            hv = HandleValue.parse(body[offset:offset+valueLen])
            # logger.debug(str(hv))
            offset += valueLen
            self.valueList.append(hv)
        
        assert offset == len(body)

    def __str__(self):
        res = super().__str__()
        res += "values:\n"
        for value in self.valueList:
            res += "\n" + str(value)
        return res