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


class AddValueRequestBody(Body):
    def __init__(self):
        self.handle = b''
        self.valueList = []
    
    def  setVals(self, handle, valueList):
        assert isinstance(handle, bytes)
        assert isinstance(valueList, list)
        assert all(isinstance(item, HandleValue) for item in valueList)
        self.handle = handle
        self.valueList = valueList

    def pack(self):
        payload = b''
        payload += utils.p32(len(self.handle)) + self.handle
        payload += utils.p32(len(self.valueList))
        for value in self.valueList:
            payload += value.pack()
        return payload

    def __str__(self):
        res = ""
        res += f"handle : {self.handle}\n"
        res += f"value list:\n"
        for value in self.valueList:
            res += f"  {str(value)}\n"
        return res

class AddValueResponseBody(Body):
    def __init__(self):
        pass

    @classmethod
    def parse(cls, body):
        assert isinstance(body, bytes)



def simpleAddValueTest(handle, valueList, serverAddr, handleID=b'', 
        handleIndex=0, authType=0,
        secretKey=b'', privateKeyContent =b'',
        privateKeyPasswd=b''):
    assert isinstance(handle, bytes)
    # construct payload
    msg = Message()

    msg.evp.setMessageFlag(0)
    msg.evp.setRequestId(0x1236)

    msg.header.setOpCode(Header.OC.OC_ADD_VALUE.value)
    msg.header.setOpFlag(Header.OPF.OPF_CT.value 
            | Header.OPF.OPF_REC.value 
            | Header.OPF.OPF_CA.value 
            | Header.OPF.OPF_PO.value)
    msg.header.setSiteInfoSerialNumber(6)
    msg.header.setRecursionCount(0)
    msg.header.setExpirationTime(int(time.time() + 3600 * 3))

    body = AddValueRequestBody()
    body.setVals(handle, valueList)
    msg.body = body

    logger.debug(f"add value request:\n{str(msg)}")
    payload = msg.pack()
    logger.debug(f"request hash : {msg.digest(common.HASH_CODE.SHA256.value).hex()}")
    # send payload
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_tcp.connect(serverAddr)
    sock_tcp.send(payload)

    res = b''
    while len(tmp := sock_tcp.recv(0x100)) != 0:
        res += tmp

    # open("./traffics/res.tmp", "wb").write(res)
    # res = open("./traffics/res.tmp", "rb").read()
    logger.debug(f"reslen : {len(res)}")
    resp = Message.parse(res)
    logger.debug(f"add value response:\n{str(resp)}")
    if (rc := resp.header.responseCode) == Header.RC.RC_SUCCESS:
        resp.body = AddValueResponseBody.parse(resp.body.pack())
    elif rc == Header.RC.RC_PREFIX_REFERRAL.value:
        resp.body = response.ReferralResponseBody.parse(resp.body.pack())
    elif rc == Header.RC.RC_AUTHEN_NEEDED.value:
        sessionID = resp.evp.sessionID
        logger.debug(f"session id : {sessionID}")
        resp.body = auth.ChallengeBody.parse(resp.body.pack())
        auth.doAuth(sock_tcp, resp, handleID, handleIndex,
            authType, secretKey, privateKeyContent, privateKeyPasswd)
        # resp.body = ChallengeBody.parse(resp.body.pack())
    else:
        logger.warning(f"unimplemented response parser : {rc:#x}")
    # logger.info(str(resp))

    return resp