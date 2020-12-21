"""https://tools.ietf.org/html/rfc3652#section-3.5
"""
import logging
import hashlib
from struct import pack, unpack 
from enum import Enum
from Crypto.Cipher import AES

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import handlevalue

from handleclient.handlevalue import HandleValue
from handleclient.message import Envelope, Header, Body, Credential, RequestDigest

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


class ChallengeResponsesBody(object):
    """https://tools.ietf.org/html/rfc3652#section-3.5.2
    """
    # auth type
    class AT(Enum):
        PUB_KEY = 1
        SEC_KEY = 2

    def __init__(self):
        pass

    def setVals(self, challengeBody, authType, handleID, handleIndex, secretKey=b'', privateKeyContent =b'', privateKeyPasswd=b''):
        assert isinstance(challengeBody, ChallengeBody) 
        assert isinstance(authType, int)
        assert isinstance(handleID, bytes)
        assert isinstance(handleIndex, int)
        # 
        # 
        self.challengeBody = challengeBody
        self.authType = authType
        self.handleID = handleID
        self.handleIndex = handleIndex
        self.secretKey = secretKey
        self.privateKeyContent = privateKeyContent 
        self.privateKeyPasswd = privateKeyPasswd
    
    def _generateAnswer(self):
        if self.authType == ChallengeResponsesBody.AT.PUB_KEY.value:
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
                # raise Exception("todo")
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
                e = utils.unpackByteArray(data[offset:])
                offset += 4 + len(e)
                logger.debug(f"n : {n.hex()}")
                logger.debug(f"e : {e.hex()}")
                # todo
            else:
                logger.error(f"unsupport key type : {keyType.decode()}")


        elif self.authType == ChallengeResponsesBody.AT.SEC_KEY.value:
            logger.error(f"unsupport auth type {keyType:#x}")
        else:
            logger.error(f"unsupport auth type {keyType:#x}")
