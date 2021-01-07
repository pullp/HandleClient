import time
import socket
from struct import pack, unpack 
import logging

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import request
from handleclient import response
from handleclient import handlevalue
from handleclient import auth

from handleclient.handlevalue import HandleValue
from handleclient.message import Message, Envelope, Header, Body, Credential

from handleclient.auth import ChallengeBody

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)


class CreateHandleRequestBody(Body):
    def __init__(self):
        self.handle = b''
        self.valueList = []
    
    def setVals(self, handle, valueList):
        assert isinstance(handle, bytes)
        assert isinstance(valueList, list)
        assert all(isinstance(item, HandleValue) for item in valueList)
        self.handle = handle
        self.valueList = valueList
    
    def pack(self):
        payload = b''
        payload += utils.p32(len(self.handle)) + self.handle
        payload += utils.packValueList(self.valueList)
        return payload
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        body = CreateHandleRequestBody()
        offset = 0

        handle = utils.uba(payload[offset:])
        offset += 4 + len(handle)

        valueList, consumed = utils.unpackValueList(payload[offset:])
        offset += consumed
        
        body.setVals(handle, valueList)
        
        assert offset == len(payload)
        return body
    
    def __str__(self):
        res = ""
        res += f"handle : {self.handle}\n"
        res += f"value list:\n"
        for value in self.valueList:
            res += f"  {str(value)}\n"
        return res


def createHandle(serverAddr, handle, valueList,
        # auth args
        handleID=b'', 
        handleIndex=0, authType=0,
        secretKey=b'', privateKeyContent =b'',
        privateKeyPasswd=b'',
        # message fields
        requestID = 0, sessionID=0,
        messageFlag = 0,
        opFlag = common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value,
        siteInfoSerialNumber = 1,
        recursionCount = 0,
        expirationDelay = 3):
    """just care about add value things, if need auth, it will return.
    """

    resp = createHandleWithoutAuth(serverAddr, handle, valueList,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)

    if (rc := resp.header.responseCode) == common.RC.SUCCESS:
        logger.info(f"add value success")
    elif rc == common.RC.PREFIX_REFERRAL.value:
        resp.body = response.ReferralResponseBody.parse(resp.body.pack())
    elif rc == common.RC.AUTHEN_NEEDED.value:
        resp, sockTCP = auth.doAuth(serverAddr, resp, handleID, handleIndex,
            authType, secretKey, privateKeyContent, privateKeyPasswd)
        sockTCP.close()
    else:
        logger.warning(f"unimplemented response parser : {rc:#x}")
    return resp


def createHandleWithoutAuth(serverAddr, handle, valueList,
        # message fields
        requestID = 0, sessionID=0,
        messageFlag = 0,
        opFlag = common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value,
        siteInfoSerialNumber = 1,
        recursionCount = 0,
        expirationDelay = 3):
    """just care about add value things, if need auth, it will return.
    """
    body = CreateHandleRequestBody()
    body.setVals(handle, valueList)
    resp = request.doRequest(serverAddr, body,
        opCode=common.OC.CREATE_HANDLE.value,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)
    return resp