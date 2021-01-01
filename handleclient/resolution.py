
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
from handleclient.message import Message, Envelope, Header, Body, Credential

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

"""
The Message Header of any query request must set its <OpCode> to
OC_RESOLUTION (defined in section 2.2.2.1) and <ResponseCode> to 0.

The Message Body for any query request is defined as follows:

    <Message Body of Query Request>  ::=  <Handle>
                                        <IndexList>
                                        <TypeList>

        where

        <Handle>
        A UTF8-String (as defined in section 2.1.4) that specifies
        the handle to be resolved.

        <IndexList>
        A 4-byte unsigned integer followed by an array of 4-byte
        unsigned integers.  The first integer indicates the number
        of integers in the integer array.  Each number in the
        integer array is a handle value index and refers to a handle
        value to be retrieved.  The client sets the first integer to
        zero (followed by an empty array) to ask for all the handle
        values regardless of their index.

        <TypeList>
        A 4-byte unsigned integer followed by a list of UTF8-
        Strings.  The first integer indicates the number of
        UTF8-Strings in the list that follows.  Each UTF8-String in
        the list specifies a data type.  This tells the server to
        return all handle values whose data type is listed in the
        list.  If a UTF8-String ends with the '.' (0x2E) character,
        the server must return all handle values whose data type is
        under the type hierarchy specified in the UTF8-String.  The
        <TypeList> may contain no UTF8-String if the first integer
        is 0.  In this case, the server must return all handle
        values regardless of their data type.
"""

class ResolutionRequestBody(Body):
    def __init__(self):
        self.handle     = b''
        self.indexList  = []
        self.typeList   = []
        
    def setVals(self, handle, indexList, typeList):
        """handle(unicode):
            A UTF8-String (as defined in section 2.1.4) that specifies
            the handle to be resolved.
        indexList(int list):
            A 4-byte unsigned integer followed by an array of 4-byte
            unsigned integers.  The first integer indicates the number
            of integers in the integer array.  Each number in the
            integer array is a handle value index and refers to a handle
            value to be retrieved.  The client sets the first integer to
            zero (followed by an empty array) to ask for all the handle
            values regardless of their index.
        indexList(unicode list): 
            A 4-byte unsigned integer followed by a list of UTF8-
            Strings.  The first integer indicates the number of
            UTF8-Strings in the list that follows.  Each UTF8-String in
            the list specifies a data type.  This tells the server to
            return all handle values whose data type is listed in the
            list.  If a UTF8-String ends with the '.' (0x2E) character,
            the server must return all handle values whose data type is
            under the type hierarchy specified in the UTF8-String.  The
            <TypeList> may contain no UTF8-String if the first integer
            is 0.  In this case, the server must return all handle
            values regardless of their data type.
        """
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
        payload = b''
        payload += (pack("!I", len(self.handle)) + self.handle)
        payload += pack("!I", len(self.indexList))
        for idx in self.indexList:
            payload += pack("!I", idx)
        payload += pack("!I", len(self.typeList))
        for tp in self.typeList:
            payload += (pack("!I", len(tp)) + tp)
        return payload
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)

        rrb = ResolutionRequestBody()
        offset  = 0
        handleLen   = utils.u32(payload[offset:])
        offset  += 4
        rrb.handle = payload[offset:offset+handleLen]
        offset  += handleLen

        indexListSize = utils.u32(payload[offset:])
        offset  += 4
        for _i in range(0, indexListSize):
            rrb.indexList.append(utils.u32(payload[offset:]))
            offset  += 4
        
        typeListSize = utils.u32(payload[offset:])
        offset  += 4
        for _i in range(0, typeListSize):
            typeLen = utils.u32(payload[offset:])
            offset  += 4
            rrb.typeList.append(payload[offset:offset+typeLen])
            offset += typeLen
        assert offset == len(payload)

        return rrb

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

    @classmethod
    def parse(cls, body):
        assert isinstance(body, bytes)
        rrb = ResolutionResponseBody()
        offset = 0
        rrb.handle = utils.unpackByteArray(body[offset:])
        offset += 4 + len(rrb.handle)
        # logger.debug(f"handle : {rrb.handle}({len(rrb.handle)})")
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
            rrb.valueList.append(hv)
        assert offset == len(body)
        return rrb

    def __str__(self):
        res = super().__str__()+'\n'
        res += "values:\n"
        for value in self.valueList:
            res += f"{str(value)}\n\n"
        return res

def simpleResolutionTest(handle, serverAddr=''):
    assert isinstance(handle, bytes)

    # construct payload
    msg = Message()
    msg.evp.setRequestId(0x1235)

    msg.header.setOpCode(Header.OC.OC_RESOLUTION.value)
    msg.header.setOpFlag(Header.OPF.OPF_CT.value 
            | Header.OPF.OPF_REC.value 
            | Header.OPF.OPF_CA.value 
            | Header.OPF.OPF_PO.value)
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
    if (rc := resp.header.responseCode) == Header.RC.RC_SUCCESS.value:
        resp.body = ResolutionResponseBody.parse(resp.body.pack())
    elif rc == Header.RC.RC_HANDLE_NOT_FOUND.value \
        or rc == Header.RC.RC_SERVER_NOT_RESP.value \
        or rc == Header.RC.RC_SERVER_BUSY.value \
        or rc == Header.RC.RC_ACCESS_DENIED.value:
        resp.body = response.ErrorResponseBody().parse(resp.body.pack())
    elif rc == Header.RC.RC_SERVICE_REFERRAL.value:
        # parse referral
        logger.warning(f"parse referral type todo")
        pass
    elif rc == Header.RC.RC_AUTHEN_NEEDED.value \
        and (resp.header.opFlag & Header.OPF.OPF_RD.value == 1):
        logger.warning(f"parse auth type todo")
    else:
        logger.warning(f"unsupport resolution response")
        logger.debug(resp.evp)
        logger.debug(resp.header)

    return resp
