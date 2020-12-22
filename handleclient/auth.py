"""https://tools.ietf.org/html/rfc3652#section-3.5
"""
import logging
import hashlib
import socket
import time
from struct import pack, unpack 
from enum import Enum
from Crypto.Cipher import AES

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import handlevalue

from handleclient.handlevalue import HandleValue
from handleclient.message import Message, Envelope, Header,Credential, RequestDigest

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)


class ChallengeBody(object):
    """from server to client
    """
    def __init__(self):
        self.digest = None
        self.nonce = b''
    
    @classmethod
    def parse(cls, body):
        assert isinstance(body, bytes)

        cb = ChallengeBody()

        offset = 0
        cb.digest = RequestDigest.parse(body[offset:])
        offset += len(cb.digest)
        logger.debug(f"digest len {len(cb.digest)}")

        cb.nonce = utils.unpackByteArray(body[offset:])
        offset += 4 + len(cb.nonce)
        # logger.debug(f"nonce len {len(cb.nonce)}")
        # logger.debug(f"{offset}/{len(body)}")
        # logger.debug(body.hex())
        assert len(cb.nonce) == common.CHALLENGE_NONCE_SIZE
        assert offset == len(body)
        return cb

    def __str__(self):
        res = ""
        res += "digest:\n"
        res += str(self.digest) + '\n'
        res += "nonce:\n"
        res += self.nonce.hex()
        return res

# auth type
class AT(Enum):
    PUB_KEY = 1
    SEC_KEY = 2

class ChallengeAnswerBody(object):
    """https://tools.ietf.org/html/rfc3652#section-3.5.2
    """
    def __init__(self):
        pass

    def setVals(self, challengeBody, handleID, handleIndex, 
            authType, secretKey=b'', 
            privateKeyContent=b'', privateKeyPasswd=b''):
        assert isinstance(challengeBody, ChallengeBody) 
        assert isinstance(authType, int)
        assert isinstance(handleID, bytes)
        assert isinstance(handleIndex, int)

        self.challengeBody = challengeBody
        self.authType = authType
        self.handleID = handleID
        self.handleIndex = handleIndex
        self.secretKey = secretKey
        self.privateKeyContent = privateKeyContent 
        self.privateKeyPasswd = privateKeyPasswd
    
    def _generateAnswer(self):
        if self.authType == AT.PUB_KEY.value:
            encryptionType = utils.u32(self.privateKeyContent)
            if encryptionType == common.ENCRYPT_NONE:
                data = self.privateKeyContent[4:] # todo
            elif encryptionType == common.ENCRYPT_PBKDF2_AES_CBC_PKCS5:
                offset = 4
                salt = utils.unpackByteArray(self.privateKeyContent[offset:])
                offset += 4 + len(salt)

                iterations = utils.u32(self.privateKeyContent[offset:])
                offset += 4

                keyLength = utils.u32(self.privateKeyContent[offset:]) # in bits
                offset += 4
                secKey = hashlib.pbkdf2_hmac("sha1", 
                    self.privateKeyPasswd, salt, iterations, keyLength/8)
                iv = utils.unpackByteArray(self.privateKeyContent[offset:])
                offset += 4 + len(iv)
                ciphertext = utils.unpackByteArray(self.privateKeyContent[offset:])
                offset += 4 + len(ciphertext)
                assert(offset == len(self.privateKeyContent))

                logger.debug(f"salt : {salt.hex()}")
                logger.debug(f"iterations : {iterations}")
                logger.debug(f"key len : {keyLength}")
                logger.debug(f"seckey : {secKey.hex()}({len(secKey)})")
                logger.debug(f"iv : {iv.hex()}({len(iv)})")
                logger.debug(f"cipher text : {ciphertext.hex()}")

                cipher = AES.new(secKey, AES.MODE_CBC, iv)
                data = cipher.decrypt(ciphertext)
                logger.debug(f"data : {data.hex()}")
            # elif encryptionType == common.ENCRYPT_DES_CBC_PKCS5:

            # elif encryptionType == common.ENCRYPT_AES_CBC_PKCS5:
            
            else:
                logger.error(f"unsupport encryption type {encryptionType:#x}")
            
            # get privkey from data
            offset = 0
            keyType = utils.unpackByteArray(data[offset:])
            offset += 4 + len(keyType)
            logger.debug(f"key type : {keyType.decode()}")
            if keyType == common.KEY_ENCODING_RSACRT_PRIVATE:
                n = utils.unpackByteArray(data[offset:])
                offset += 4 + len(n)
                d = utils.unpackByteArray(data[offset:])
                offset += 4 + len(d)

                logger.debug(f"n : {n.hex()}({len(n)})")
                logger.debug(f"d : {d.hex()}({len(d)})")

                n = int.from_bytes(n, byteorder='big')
                d = int.from_bytes(d, byteorder='big')

                # todo
            else:
                logger.error(f"unsupport key type : {keyType.decode()}")
            sigID = b"SHA256withRSA"
            sigHashType = b"SHA-256"
            
            challengeDigest = int.from_bytes(utils.doDigest(
                    common.HASH_CODE.SHA256.value, [
                        self.challengeBody.nonce, self.challengeBody.digest.pack()
                    ]
                ), byteorder='big'
            )
            logger.debug(f"challengeDigest : {hex(challengeDigest)}")
            signature = bytes.fromhex(hex(pow(challengeDigest, d, n))[2:])
            logger.debug(f"signature : {signature.hex()}({len(signature)})")
            answer = b''
            answer += utils.packByteArray(sigHashType)
            answer += utils.packByteArray(signature)
        elif self.authType == AT.SEC_KEY.value:
            logger.error(f"unsupport auth type {self.authType:#x}")
        else:
            logger.error(f"unsupport auth type {self.authType:#x}")
        return answer

    def pack(self):
        payload = b''
        if self.authType == AT.PUB_KEY.value:
            payload += utils.packByteArray(b"HS_PUBKEY")
        else:
            logger.critical(f"unsupport auth type {self.authType}")
        payload += utils.packByteArray(self.handleID)
        payload += utils.p32(self.handleIndex)
        answer = self._generateAnswer()
        payload += answer
        return payload


def doAuth(sockfd, challengeMessage, handleID,
            handleIndex, authType, secretKey=b'', privateKeyContent =b'',
            privateKeyPasswd=b''):
    """do auth, return session id
    """
    assert isinstance(sockfd, socket.socket)
    assert isinstance(challengeMessage, Message)

    sessionID = challengeMessage.evp.sessionID
    challengeBody = challengeMessage.body

    cab = ChallengeAnswerBody()
    cab.setVals(challengeMessage.body, handleID,
        handleIndex, authType, secretKey, privateKeyContent, privateKeyPasswd)
    bodyRaw = cab.pack()

    evp = Envelope()
    evp.setMessageFlag(0x020b)
    evp.setRequestId(0x1236)
    evp.setSessionId(sessionID)

    hd = Header()
    hd.setOpCode(Header.OC.OC_CHALLENGE_RESPONSE .value)
    hd.setOpFlag(Header.OPF.OPF_CT.value 
            | Header.OPF.OPF_REC.value 
            | Header.OPF.OPF_CA.value 
            | Header.OPF.OPF_PO.value)
    hd.setSiteInfoSerialNumber(6)
    hd.setRecursionCount(0)
    hd.setExpirationTime(int(time.time() + 3600 * 3))

    bodyLen = len(bodyRaw)
    hd.setBodyLength(bodyLen)
    
    cred = Credential.emptyCred()
    credRaw = cred.pack()
    credLen = len(credRaw)

    evp.setMessageLength(common.HEADER_LEN + bodyLen + credLen)

    payload = b''
    payload += evp.pack()
    payload += hd.pack()
    payload += bodyRaw
    payload += credRaw
    
    message = Message()
    message.setVals(evp, hd, bodyRaw, cred)
    logger.debug(str(message))

    sockfd.send(payload)

    res = b''
    while len(tmp := sockfd.recv(0x100)) != 0:
        res += tmp
    logger.debug(f"reslen : {len(res)}")
    resp = Message.parse(res)
    logger.debug(str(resp))

