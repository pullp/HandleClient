import logging
from enum import Enum

COMPATIBILITY_MAJOR_VERSION = 2
COMPATIBILITY_MINOR_VERSION = 1
MAJOR_VERSION = 2
MINOR_VERSION = 11

MESSAGE_FLAG_MASK = 0b1110_0000_0000_0000

ENCRYPT_ALG_DES = 1
ENCRYPT_ALG_DESEDE = 2
ENCRYPT_ALG_AES = 3

# whether user passphrase to encrypt private key
ENCRYPT_NONE = 1
ENCRYPT_DES_CBC_PKCS5 = 2 # DES with CBC and PKCS5 padding
ENCRYPT_PBKDF2_DESEDE_CBC_PKCS5 = 3 # DESede with CBC and PKCS5 padding and PBKDF2 to derive encryption key
ENCRYPT_PBKDF2_AES_CBC_PKCS5 = 4 # AES with CBC and PKCS5 padding and PBKDF2 to derive encryption key

# identifier for the DSA private key encoding
KEY_ENCODING_DSA_PRIVATE = b"DSA_PRIV_KEY"
# identifier for the DSA key encoding
KEY_ENCODING_DSA_PUBLIC = b"DSA_PUB_KEY"
# identifier for the DH private key encoding
KEY_ENCODING_DH_PRIVATE = b"DH_PRIV_KEY"
# identifier for the DH key encoding
KEY_ENCODING_DH_PUBLIC = b"DH_PUB_KEY"
# identifier for the RSA private key and private crt key encoding
KEY_ENCODING_RSA_PRIVATE = b"RSA_PRIV_KEY"
KEY_ENCODING_RSACRT_PRIVATE = b"RSA_PRIVCRT_KEY"
# identifier for the RSA key encoding
KEY_ENCODING_RSA_PUBLIC = b"RSA_PUB_KEY"

ENVELOPE_LEN    = 20
HEADER_LEN      = 24
MAX_HANDLE_VALUES = 2048
MIN_MESSAGE_SIZE = ENVELOPE_LEN + HEADER_LEN + 4 # 4 is credential
MAX_ARRAY_SIZE = 1048576
TEXT_ENCODING = "utf8"

MD5_DIGEST_SIZE = 16
SHA1_DIGEST_SIZE = 20
SHA256_DIGEST_SIZE = 32

class HASH_CODE(Enum):
	OLD_FORMAT  = 0
	MD5         = 1
	SHA1        = 2
	SHA256 	    = 3
	HMAC_SHA1   = 0x12
	HMAC_SHA256 = 0x13
	PBKDF2_HMAC_SHA1 = 0x22
	
IPV6_SIZE_IN_BYTES = 16
IPV4_SIZE_IN_BYTES = 4

# MIN_NONCE_LENGTH = 20 # deprecated in source code, though in rfc, fuck it!
CHALLENGE_NONCE_SIZE = 16

#################################
# below codes are for logging
#################################
import colorlog

LOG_LEVEL = logging.DEBUG
LOG_LEVEL_CONSOLE = logging.DEBUG
LOG_LEVEL_FILE = logging.INFO

ch = logging.StreamHandler()
ch.setLevel(LOG_LEVEL_CONSOLE)

# formatter = colorlog.ColoredFormatter("[%(log_color)s%(name)s:%(lineno)s - %(funcName)20s()] %(message)s")
# ch.setFormatter(formatter)
ch.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s[%(levelname)-7s %(name)20s:%(lineno)s] %(message)s",
    log_colors = {
		'DEBUG':    'green',
		'INFO':     'white',
		'WARNING':  'yellow',
		'ERROR':    'red',
		'CRITICAL': 'red,bg_white',
    }
))

