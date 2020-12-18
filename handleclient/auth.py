"""https://tools.ietf.org/html/rfc3652#section-3.5
"""
from struct import pack, unpack 
import logging

from handleclient import common
from handleclient import utils
from handleclient import message
from handleclient import handlevalue

from handleclient.handlevalue import HandleValue
from handleclient.message import Envelope, Header, Body, Credential, RequestDigest

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)


class ChanllengeBody():
    """from server to client
    """
    def __init__(self):
        self.digest = None
        self.nonce = b''
    
    @classmethod
    def parse(cls, body):
        assert isinstance(body, bytes)

        cb = ChanllengeBody()

        offset = 0
        cb.digest = RequestDigest.parse(body[offset:])
        offset += len(cb.digest)
        logger.debug(f"digest len {len(cb.digest)}")

        cb.nonce = utils.unpackString(body[offset:])
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
