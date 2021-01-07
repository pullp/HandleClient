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


class DeleteHandleRequestBody(Body):
    def __init__(self):
        self.handle = b''
    
    def setVals(self, handle):
        assert isinstance(handle, bytes)
        self.handle = handle

    def pack(self):
        return utils.pba(self.handle)
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        body = DeleteHandleRequestBody()
        offset = 0

        handle = utils.uba(payload[offset:])
        offset += 4 + len(handle)

        body.setVals(handle)
        
        assert offset == len(payload)
        return body

    def __str__(self):
        res = ""
        res += f"handle : {self.handle}\n"
        return res


def deleteHandle(serverAddr, handle,
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

    resp = deleteHandleWithoutAuth(serverAddr, handle,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)

    if (rc := resp.header.responseCode) == common.RC.SUCCESS:
        logger.info(f"delete handle success")
    elif rc == common.RC.PREFIX_REFERRAL.value:
        resp.body = response.ReferralResponseBody.parse(resp.body.pack())
    elif rc == common.RC.AUTHEN_NEEDED.value:
        resp, sockTCP = auth.doAuth(serverAddr, resp, handleID, handleIndex,
            authType, secretKey, privateKeyContent, privateKeyPasswd)
        sockTCP.close()
    else:
        logger.warning(f"unimplemented response parser : {rc:#x}")
    return resp


def deleteHandleWithoutAuth(serverAddr, handle,
        # message fields
        requestID = 0, sessionID=0,
        messageFlag = 0,
        opFlag = common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value,
        siteInfoSerialNumber = 1,
        recursionCount = 0,
        expirationDelay = 3):
    body = DeleteHandleRequestBody()
    body.setVals(handle)
    resp = request.doRequest(serverAddr, body,
        opCode=common.OC.DELETE_HANDLE.value,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)
    
    return resp