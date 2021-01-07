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


class RemoveValueRequestBody(Body):
    def __init__(self):
        self.handle = b''
        self.indexList = []
    
    def setVals(self, handle, indexList):
        assert isinstance(handle, bytes)
        assert isinstance(indexList, list)
        assert all(isinstance(item, int) for item in indexList)
        self.handle = handle
        self.indexList = indexList

    def pack(self):
        payload = b''
        payload += utils.p32(len(self.handle)) + self.handle
        payload += utils.p32List(self.indexList)
        return payload
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        body = RemoveValueRequestBody()
        offset = 0

        handle = utils.uba(payload[offset:])
        offset += 4 + len(handle)

        indexList, consumed = utils.u32List(payload[offset:])
        offset += consumed

        body.setVals(handle, indexList)
        
        assert offset == len(payload)
        return body

    def __str__(self):
        res = ""
        res += f"handle : {self.handle}\n"
        res += f"index list: {str(self.indexList)}"
        return res


def removeValue(serverAddr, handle, indexList,
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
    resp = removeValueWithoutAuth(serverAddr, handle, indexList,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)

    if (rc := resp.header.responseCode) == common.RC.SUCCESS:
        logger.info(f"remove value success")
    elif rc == common.RC.PREFIX_REFERRAL.value:
        resp.body = response.ReferralResponseBody.parse(resp.body.pack())
    elif rc == common.RC.AUTHEN_NEEDED.value:
        resp, sockTCP = auth.doAuth(serverAddr, resp, handleID, handleIndex,
            authType, secretKey, privateKeyContent, privateKeyPasswd)
        sockTCP.close()
    else:
        logger.warning(f"unimplemented response parser : {rc:#x}")
    return resp


def removeValueWithoutAuth(serverAddr, handle, indexList,
        # message fields
        requestID = 0, sessionID=0,
        messageFlag = 0,
        opFlag = common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value,
        siteInfoSerialNumber = 1,
        recursionCount = 0,
        expirationDelay = 3):
    """just care about remove value things, if need auth, it will return.
    """
    body = RemoveValueRequestBody()
    body.setVals(handle, indexList)
    resp = request.doRequest(serverAddr, body,
        opCode=common.OC.REMOVE_VALUE.value,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)
    
    return resp