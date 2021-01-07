"""https://tools.ietf.org/html/rfc3652#section-3.5
"""
import logging
import hashlib
import socket
import time
from struct import pack, unpack 
from Crypto.Cipher import AES

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import handlevalue

from handleclient.handlevalue import HandleValue
from handleclient.message import Message, Envelope, Header, Body, Credential, RequestDigest

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)

def rsaDigestSign(datas, hashType, rsaKeySize, n, d):
    """https://medium.com/@bn121rajesh/rsa-sign-and-verify-using-openssl-behind-the-scene-bf3cac0aade2"""
    assert isinstance(datas, list)
    assert all(isinstance(item, bytes) for item in datas)
    assert isinstance(hashType, int)
    assert isinstance(rsaKeySize, int)
    assert isinstance(n, int)
    assert isinstance(d, int)

    # calc hash digest
    digest = utils.doDigest(hashType, datas)
    logger.debug(f"len(digest) = {len(digest)}")
    # do padding
    if hashType == common.HASH_CODE.SHA256.value:
        paddingDigest = b"\x00\x01"
        paddingDigest += b'\xff'*(
                int(rsaKeySize/8)
                -len(common.SHA256_DIGEST_INFO)
                -common.SHA256_DIGEST_SIZE
                -3)
        paddingDigest += b'\x00'
        paddingDigest += common.SHA256_DIGEST_INFO
        paddingDigest += digest
        logger.debug(f"len(paddingDigest) = {len(paddingDigest)}")
        assert len(paddingDigest) == int(rsaKeySize/8)
    else:
        logging.error(f"unsupported hash type {hashType}")
    
    # sign with private key
    paddingDigestInt = int.from_bytes(paddingDigest, byteorder='big')
    signatureInt = pow(paddingDigestInt, d, n)
    signature = int.to_bytes(signatureInt, length=int(rsaKeySize/8), byteorder='big')
    return signature


class ChallengeBody(Body):
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

        cb.nonce = utils.uba(body[offset:])
        offset += 4 + len(cb.nonce)
        # logger.debug(f"nonce len {len(cb.nonce)}")
        # logger.debug(f"{offset}/{len(body)}")
        # logger.debug(body.hex())
        assert len(cb.nonce) == common.CHALLENGE_NONCE_SIZE
        assert offset == len(body)
        return cb
    
    def pack(self):
        payload = b''
        payload += self.digest.pack()
        payload += utils.pba(self.nonce)
        return payload

    def __str__(self):
        res = "challenge body:\n"
        res += f" digest : {str(self.digest)}\n"
        res += f" nonce : {self.nonce.hex()}"
        return res

class ChallengeAnswerBody(Body):
    """https://tools.ietf.org/html/rfc3652#section-3.5.2
    """
    def __init__(self):
        pass

    def setVals(self, handleID, handleIndex, 
            authType, answer=b''):
        assert isinstance(handleID, bytes)
        assert isinstance(handleIndex, int)
        assert isinstance(authType, int)
        assert isinstance(answer, bytes)

        self.handleID = handleID
        self.handleIndex = handleIndex
        self.authType = authType
        self.answer = answer
    
    @classmethod
    def generateAnswer(cls, challengeBody, authType, secretKey=b'', 
            privateKeyContent=b'', privateKeyPasswd=b''):
        """Util.decrypt
        Util.getPrivateKeyFromBytes
        """
        if authType == common.AT.HS_PUBKEY.value:
            encryptionType = utils.u32(privateKeyContent)
            if encryptionType == common.ENCRYPT_NONE:
                data = privateKeyContent[4:] # todo
            elif encryptionType == common.ENCRYPT_PBKDF2_AES_CBC_PKCS5:
                offset = 4
                salt = utils.uba(privateKeyContent[offset:])
                offset += 4 + len(salt)

                iterations = utils.u32(privateKeyContent[offset:])
                offset += 4

                keyLength = utils.u32(privateKeyContent[offset:]) # in bits
                offset += 4
                secKey = hashlib.pbkdf2_hmac("sha1", 
                    privateKeyPasswd, salt, iterations, keyLength/8)
                iv = utils.uba(privateKeyContent[offset:])
                offset += 4 + len(iv)
                ciphertext = utils.uba(privateKeyContent[offset:])
                offset += 4 + len(ciphertext)
                assert(offset == len(privateKeyContent))

                # logger.debug(f"salt : {salt.hex()}")
                # logger.debug(f"iterations : {iterations}")
                # logger.debug(f"key len : {keyLength}")
                # logger.debug(f"seckey : {secKey.hex()}({len(secKey)})")
                # logger.debug(f"iv : {iv.hex()}({len(iv)})")
                # logger.debug(f"cipher text : {ciphertext.hex()}")

                cipher = AES.new(secKey, AES.MODE_CBC, iv)
                data = cipher.decrypt(ciphertext)
                # logger.debug(f"data : {data.hex()}")
            # elif encryptionType == common.ENCRYPT_DES_CBC_PKCS5:

            # elif encryptionType == common.ENCRYPT_AES_CBC_PKCS5:
            
            else:
                logger.error(f"unsupport encryption type {encryptionType:#x}")
            
            # get privkey from data
            offset = 0
            keyType = utils.uba(data[offset:])
            offset += 4 + len(keyType)
            logger.debug(f"key type : {keyType.decode()}")
            if keyType == common.KEY_ENCODING_RSA_PRIVATE:
                n = utils.uba(data[offset:])
                offset += 4 + len(n)
                d = utils.uba(data[offset:])
                offset += 4 + len(d)

                logger.debug(f"n : {n.hex()}({len(n)})")
                logger.debug(f"d : {d.hex()}({len(d)})")

                n = int.from_bytes(n, byteorder='big')
                d = int.from_bytes(d, byteorder='big')
            elif keyType == common.KEY_ENCODING_RSACRT_PRIVATE:
                n = utils.uba(data[offset:])
                rsaKeySize = (len(n) & ~0xf)*8
                offset += 4 + len(n)
                pubEx = utils.uba(data[offset:])
                offset += 4 + len(pubEx)
                ex = utils.uba(data[offset:])
                offset += 4 + len(ex)
                p = utils.uba(data[offset:])
                offset += 4 + len(p)
                q = utils.uba(data[offset:])
                offset += 4 + len(q)
                exP = utils.uba(data[offset:])
                offset += 4 + len(exP)
                exQ = utils.uba(data[offset:])
                offset += 4 + len(exQ)
                coeff = utils.uba(data[offset:])
                offset += 4 + len(coeff)

                # logger.debug(f"n = 0x{n.hex()}")
                # logger.debug(f"pubEx = 0x{pubEx.hex()}")
                # logger.debug(f"ex = 0x{ex.hex()}")
                # logger.debug(f"p = 0x{p.hex()}")
                # logger.debug(f"q = 0x{q.hex()}")
                # logger.debug(f"exP = 0x{exP.hex()}")
                # logger.debug(f"exQ = 0x{exQ.hex()}")
                # logger.debug(f"coeff = 0x{coeff.hex()}")
                
                d = int.from_bytes(ex, byteorder='big')
                n = int.from_bytes(n, byteorder='big')
                # todo
            else:
                logger.error(f"unsupport key type : {keyType.decode()}")
            sigID = b"SHA256withRSA"
            sigHashType = b"SHA-256"
            
            logger.debug(f"nonce :\n{utils.hexdump(challengeBody.nonce)}")
            logger.debug(f"req digest : {utils.hexdump(challengeBody.digest.pack())}")

            datas = [challengeBody.nonce, challengeBody.digest.data]
            signature = rsaDigestSign(
                datas, common.HASH_CODE.SHA256.value,
                rsaKeySize, n, d)
            logger.debug(f"signature : {signature.hex()}({len(signature)})")
            answer = b''
            answer += utils.pba(sigHashType)
            answer += utils.pba(signature)
        elif authType == common.AT.SEC_KEY.value:
            logger.error(f"unsupport auth type {authType:#x}")
        else:
            logger.error(f"unsupport auth type {authType:#x}")
        return answer

    def _parseAnswer(self):
        offset = 0
        payload = self.answer

        sigHashType = utils.uba(payload[offset:])
        offset += 4 + len(sigHashType)
        logger.debug(f"sigHashType : {sigHashType}")

        signature = utils.uba(payload[offset:])
        offset += 4 + len(signature)
        logger.debug(f"signature : {signature.hex()}({len(signature)})")

    def pack(self):
        payload = b''
        if self.authType == common.AT.HS_PUBKEY.value:
            payload += utils.pba(b"HS_PUBKEY")
        else:
            logger.critical(f"unsupport auth type {self.authType}")
        payload += utils.pba(self.handleID)
        payload += utils.p32(self.handleIndex)
        payload += utils.pba(self.answer)
        return payload
    
    @classmethod
    def parse(cls, payload):
        assert isinstance(payload, bytes)
        offset = 0

        authTypeStr = utils.uba(payload[offset:])
        offset += 4 + len(authTypeStr)
        logger.debug(f"authTypeStr : {authTypeStr}")
        authType = common.AT.HS_PUBKEY.value

        handleID = utils.uba(payload[offset:])
        offset += 4 + len(handleID)
        handleIndex = utils.u32(payload[offset:])
        offset += 4

        answer = utils.uba(payload[offset:])
        offset += 4 + len(answer)

        cab = ChallengeAnswerBody()
        cab.setVals(handleID, handleIndex, authType, answer)

        return cab


    def __str__(self):
        res = "challenge answer body :\n"
        res += f" auth type : {utils.printableCode(common.AT, self.authType)}\n"
        res += f" handle : {self.handleID.decode()} ({self.handleIndex})"
        logger.debug(f"answer : {self.answer.hex()}")
        return res

r"""
src\main\java\net\handle\server\servletcontainer\auth\StandardHandleAuthenticator.java
constructSignedResponse
"""
def doAuth(serverAddr, challengeMessage, handleID,
            handleIndex, authType, secretKey=b'', privateKeyContent =b'',
            privateKeyPasswd=b''):
    """do auth, return session id
    """
    assert isinstance(challengeMessage, Message)
    challengeMessage.body = ChallengeBody.parse(challengeMessage.body.pack())
    sessionID = challengeMessage.evp.sessionID

    cab = ChallengeAnswerBody()
    cab.setVals(handleID, handleIndex, authType)
    cab.answer = cab.generateAnswer(
            challengeMessage.body, authType, secretKey, privateKeyContent, privateKeyPasswd)

    msg = Message()
    msg.evp.setMessageFlag(0)
    msg.evp.setRequestID(1234)
    msg.evp.setSessionID(sessionID)

    msg.header.setOpCode(common.OC.CHALLENGE_RESPONSE .value)
    msg.header.setOpFlag(common.OPF.CT.value 
            | common.OPF.REC.value 
            | common.OPF.CA.value )
    msg.header.setSiteInfoSerialNumber(6)
    msg.header.setRecursionCount(0)
    msg.header.setExpirationTime(int(time.time() + 3600 * 3))

    msg.body = cab

    logger.debug(str(msg))

    payload = msg.pack()
    logger.debug(f"do auth request")
    logger.debug(str(msg))
    sockTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockTCP.connect(serverAddr)
    _cnt = sockTCP.send(payload)
    logger.debug(f"send res : {_cnt}")

    res = b''
    while len(tmp := sockTCP.recv(0x100)) != 0:
        res += tmp
    resp = Message.parse(res)
    logger.debug(f"do auth response ({len(res)} bytes)")
    logger.debug(str(resp))
    return (resp, sockTCP)


