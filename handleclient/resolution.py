
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

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)


class ResolutionRequestBody(Body):
    def __init__(self):
        self.handle     = b''
        self.indexList  = []
        self.typeList   = []
        
    def setVals(self, handle, indexList, typeList):
        assert isinstance(handle, bytes)
        assert isinstance(indexList, list)
        assert all(isinstance(index, int) for index in indexList)
        assert isinstance(typeList, list)
        assert all(isinstance(tp, bytes) for tp in typeList)

        self.handle = handle
        self.indexList = indexList
        self.typeList = typeList

    def pack(self):
        """refer to method `encodeResolutionRequest` in official sourcecode of client written in java
        """
        payload = utils.pba(self.handle)
        payload += utils.p32List(self.indexList)
        payload += utils.pbaList(self.typeList)
        return payload
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)

        body = ResolutionRequestBody()
        offset  = 0
        
        body.handle = utils.uba(payload[offset:])
        offset += 4 + len(body.handle)

        indexList, used = utils.u32List(payload[offset:])
        offset += used
        body.indexList = indexList
        
        typeList, used = utils.ubaList(payload[offset:])
        offset += used
        body.typeList = typeList

        assert offset == len(payload)
        return body

    def __str__(self):
        res = "ResolutionRequestBody:\n"
        res += f"  handle       : {self.handle.decode(common.TEXT_ENCODING)}\n"
        res += f"  indexList    : {self.indexList}\n"
        res += f"  typeList     : {list(map(lambda x : x.decode(), self.typeList))}"
        return res


class ResolutionResponseBody(Body):
    def __init__(self):
        self.handle = None
        self.valueList = []
        self.requestDigest = None
        self.bodyRaw = b''

    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        body = ResolutionResponseBody()
        body.bodyRaw = payload
        offset = 0
        body.handle = utils.uba(payload[offset:])
        offset += 4 + len(body.handle)
        # logger.debug(f"handle : {body.handle}({len(body.handle)})")
        # logger.debug(f"offset : {offset}/{len(payload)}")
        if (valueCnt := utils.u32(payload[offset:])) \
            > common.MAX_HANDLE_VALUES:
            raise Exception(f"invalid valueCnt : {valueCnt}")
        offset += 4
        logger.debug(f"valueCnt: {valueCnt}")
        for _i in range(valueCnt):
            valueLen = HandleValue.calcHandleValueSize(payload, offset)
            hv = HandleValue.parse(payload[offset:offset+valueLen])
            # logger.debug(str(hv))
            offset += valueLen
            body.valueList.append(hv)
        assert offset == len(payload)
        return body

    def pack(self):
        return self.bodyRaw

    def __str__(self):
        res = super().__str__()+'\n'
        res += "values:\n"
        for value in self.valueList:
            res += f"{str(value)}\n\n"
        return res

def resolution(serverAddr, handle, indexList=[], typeList=[],
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
    resp = resolutionWithoutAuth(serverAddr, indexList, typeList,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)
    if (rc := resp.header.responseCode) == common.RC.SUCCESS:
        resp.body = ResolutionResponseBody.parse(resp.body.pack())
        logger.info("resolution success")
    elif rc == common.RC.AUTHEN_NEEDED.value:
        resp, sockTCP = auth.doAuth(serverAddr, resp, handleID, handleIndex,
            authType, secretKey, privateKeyContent, privateKeyPasswd)
        sockTCP.close()
    else:
        logger.warning(f"unimplemented response parser : {rc:#x}")
    return resp
    

def resolutionWithoutAuth(serverAddr, handle, indexList=[], typeList=[],
        # message fields
        requestID = 0, sessionID=0,
        messageFlag = 0,
        opFlag = common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value,
        siteInfoSerialNumber = 1,
        recursionCount = 0,
        expirationDelay = 3):
    body = ResolutionRequestBody()
    body.setVals(handle, indexList, typeList)
    resp = request.doRequest(
        serverAddr, body, opCode=common.OC.RESOLUTION.value,
        requestID = requestID,
        sessionID = sessionID,
        messageFlag = messageFlag,
        opFlag = opFlag,
        siteInfoSerialNumber = siteInfoSerialNumber,
        recursionCount = recursionCount,
        expirationDelay = expirationDelay)
    return resp

def simpleResolutionTest(handle, serverAddr=''):
    assert isinstance(handle, bytes)

    # construct payload
    msg = Message()
    msg.evp.setRequestID(0x1235)

    msg.header.setOpCode(common.OC.RESOLUTION.value)
    msg.header.setOpFlag(common.OPF.CT.value 
            | common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value)
    msg.header.setSiteInfoSerialNumber(6)
    msg.header.setRecursionCount(0)
    msg.header.setExpirationTime(int(time.time() + 3600*3))
    
    msg.body = ResolutionRequestBody()
    msg.body.setVals(handle, [], [])

    payload = msg.pack()
    logger.debug(f"resolution request:\n{str(msg)}")

    # logger.debug(evp)
    # logger.debug(hd)
    # logger.debug(body)
    # logger.debug(payload)

    # send payload
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_tcp.connect(serverAddr)
    sock_tcp.send(payload)

    res = b''
    while len(tmp := sock_tcp.recv(0x100)) != 0:
        res += tmp

    # open("./traffics/res.tmp", "wb").write(res)
    # res = open("./traffics/res.tmp", "rb").read()
    logger.debug(f"reslen : {len(res)}\n")
    resp = Message.parse(res)
    if (rc := resp.header.responseCode) == common.RC.SUCCESS.value:
        resp.body = ResolutionResponseBody.parse(resp.body.pack())
    elif rc == common.RC.HANDLE_NOT_FOUND.value \
        or rc == common.RC.SERVER_NOT_RESP.value \
        or rc == common.RC.SERVER_BUSY.value \
        or rc == common.RC.ACCESS_DENIED.value:
        resp.body = response.ErrorResponseBody().parse(resp.body.pack())
    elif rc == common.RC.SERVICE_REFERRAL.value:
        # parse referral
        logger.warning(f"parse referral type todo")
        pass
    elif rc == common.RC.AUTHEN_NEEDED.value \
        and (resp.header.opFlag & common.OPF.RD.value == 1):
        logger.warning(f"parse auth type todo")
    else:
        logger.warning(f"unsupport resolution response")
        logger.debug(resp.evp)
        logger.debug(resp.header)

    return resp
