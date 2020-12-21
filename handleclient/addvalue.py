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

from handleclient.handlevalue import HandleValue
from handleclient.message import Envelope, Header, Body, Credential

from handleclient.auth import ChallengeBody

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)


class AddValueRequestBody(object):
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

class AddValueResponseBody(object):
    def __init__(self):
        pass

    @classmethod
    def parse(cls, body):
        assert isinstance(body, bytes)



def simpleAddValueTest(handle, valueList, serverAddr):
    assert isinstance(handle, bytes)
    # construct payload
    evp = Envelope()
    evp.setMessageFlag(0x020b)
    evp.setRequestId(0x1236)

    hd = Header()
    hd.setOpCode(Header.OC.OC_ADD_VALUE.value)
    hd.setOpFlag(Header.OPF.OPF_CT.value 
            | Header.OPF.OPF_REC.value 
            | Header.OPF.OPF_CA.value 
            | Header.OPF.OPF_PO.value)
    hd.setSiteInfoSerialNumber(6)
    hd.setRecursionCount(0)
    hd.setExpirationTime(int(time.time() + 3600 * 3))

    body = AddValueRequestBody()
    body.setVals(handle, valueList)
    bodyPack = body.pack()
    bodyLen = len(bodyPack)

    hd.setBodyLength(bodyLen)
    cred = utils.p32(0)
    credLen = len(cred)

    evp.setMessageLength(common.HEADER_LEN + bodyLen + credLen)

    payload = b''
    payload += evp.pack()
    payload += hd.pack()
    payload += bodyPack
    payload += cred
    logger.debug(f"body hash : {utils.doDigest(common.HASH_CODE.SHA256.value, [hd.pack(), bodyPack]).hex()}")
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
    resp = response.Response.parse(res)
    if (rc := resp.header.responseCode) == Header.RC.RC_SUCCESS:
        resp.body = AddValueResponseBody.parse(resp.bodyRaw)
    elif rc == Header.RC.RC_PREFIX_REFERRAL.value:
        resp.body = response.ReferralResponseBody.parse(resp.bodyRaw)
    elif rc == Header.RC.RC_AUTHEN_NEEDED.value:
        sessionID = resp.evp.sessionID
        logger.debug(f"session id : {sessionID}")
        resp.body = ChallengeBody.parse(resp.bodyRaw)
    else:
        logger.warning(f"unimplemented response parser : {rc:#x}")
    # logger.info(str(resp))

    return resp