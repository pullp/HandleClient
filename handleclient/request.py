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

def doRequest(serverAddr, body,
        # message fields
        requestID = 0, sessionID=0,
        messageFlag = 0,
        opCode = 0,
        opFlag = common.OPF.REC.value 
            | common.OPF.CA.value 
            | common.OPF.PO.value,
        siteInfoSerialNumber = 1,
        recursionCount = 0,
        expirationDelay = 3):

    sockTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockTCP.connect(serverAddr)

    msg = Message()

    msg.evp.setMessageFlag(messageFlag)
    msg.evp.setRequestID(requestID)
    msg.evp.setSessionID(sessionID)

    msg.header.setOpCode(opCode)
    msg.header.setOpFlag(opFlag)
    msg.header.setSiteInfoSerialNumber(siteInfoSerialNumber)
    msg.header.setRecursionCount(recursionCount)
    msg.header.setExpirationTime(int(time.time() + 3600 * expirationDelay))

    msg.body = body
    
    payload = msg.pack()
    sendCnt = sockTCP.send(payload)
    logger.debug(f"remove value req : send {sendCnt} bytes")
    assert sendCnt == len(payload)

    res = b''
    while len(buf := sockTCP.recv(0x100)) != 0:
        res += buf
    sockTCP.close()
    resp = Message.parse(res)
    logger.debug(f"remove value response : ({len(res)} bytes) :\n")
    logger.debug(str(resp))
    return resp