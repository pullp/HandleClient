#coding:utf-8

from struct import pack, unpack 

# import message as msg
import message
from message import Envelope, Header, Body, Credential

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

class QueryRequestBody(object):
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
    
    def parse(self, payload):
        assert isinstance(payload, bytes)
        self.__init__()
        offset  = 0
        handleLen   = unpack("!I", payload[offset:offset+4])[0]
        offset  += 4
        self.handle = payload[offset:offset+handleLen]
        offset  += handleLen

        indexListSize = unpack("!I", payload[offset:offset+4])[0]
        offset  += 4
        for i in range(0, indexListSize):
            self.indexList.append(unpack("!I", payload[offset:offset+4])[0])
            offset  += 4
        
        typeListSize = unpack("!I", payload[offset:offset+4])[0]
        offset  += 4
        for i in range(0, typeListSize):
            typeLen = unpack("!I", payload[offset:offset+4])[0]
            offset  += 4
            self.typeList.append(payload[offset:offset+typeLen])
            offset += typeLen
    
    def __str__(self):
        res = "QueryRequestBody\n"
        res += f"  handle       : {self.handle.decode('utf8')}\n"
        res += f"  indexList    : {self.indexList}\n"
        res += f"  typeList     : {list(map(lambda x : x.decode(), self.typeList))}\n"
        return res


class QueryResponse(object):
    def __init__(self):
        pass

def test():
    body = QueryRequestBody()
    body.setVals(b"handle1234", [1, 2, 3], [u"关山难越".encode('utf8'), b"t2"])
    print(body)
    p1 = body.pack()

    body2 = QueryRequestBody()
    body2.parse(p1)
    print(body2)

def simpleResolutionRequest(handle):
    assert isinstance(handle, str)
    import time

    evp = Envelope()
    evp.setVersion(2, 10)
    evp.setRequestId(0x1234)

    hd  = Header()
    hd.setOpCode(Header.OC.OC_RESOLUTION.value)
    hd.setResponseCode(0)
    hd.setOpFlag(Header.OPF.OPF_CT.value | Header.OPF.OPF_REC.value | Header.OPF.OPF_CA.value | Header.OPF.OPF_PO.value)
    hd.setSiteInfoSerialNumber(6)
    hd.setRecursionCount(0)
    hd.setExpirationTime(int(time.time() + 3600*24))
    
    body = QueryRequestBody()
    body.setVals(handle.encode(), [], [])
    body = body.pack()
    bodyLen = len(body)
    # print()
    hd.setBodyLength(bodyLen)

    cred = pack("!I", 0) # todo
    credLen = len(cred)

    evp.setMessageLength(bodyLen + message.HEADER_LEN + credLen)

    payload = evp.pack()
    payload += hd.pack()
    payload += body

    return payload
