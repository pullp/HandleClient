import logging
from enum import Enum

COMPATIBILITY_MAJOR_VERSION = 2
COMPATIBILITY_MINOR_VERSION = 11
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

# https://tools.ietf.org/html/rfc3447#page-43
MD2_DIGEST_INFO = b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10"
MD5_DIGEST_INFO = b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"
SHA1_DIGEST_INFO = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
SHA256_DIGEST_INFO = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
SHA384_DIGEST_INFO = b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"
SHA512_DIGEST_INFO = b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"


class HASH_CODE(Enum):
	OLD_FORMAT  = 0
	MD5         = 1
	SHA1        = 2
	SHA256 	    = 3
	HMAC_SHA1   = 0x12
	HMAC_SHA256 = 0x13
	PBKDF2_HMAC_SHA1 = 0x22

# auth type
class AT(Enum):
    HS_PUBKEY = 1
    SEC_KEY = 2

# handle value permission
class HV_PERM(Enum):
	PUBLIC_WRITE    = 1
	PUBLIC_READ     = 1 << 1
	ADMIN_WRITE     = 1 << 2
	ADMIN_READ      = 1 << 3
	# PUBLIC_EXECUTE  = 1 << 4
	# ADMIN_EXECUTE   = 1 << 5

# handle value TTL type
class HV_TTLTYPE(Enum):
	RELA = 0 # relative
	ABS = 1 # absolute

# service interface type
class SI_TYPE(Enum):
	ADMIN = 1 # handle administration
	QUERY = 2 # handle resolution
	BOTH = 3

# service interface protocol
class SI_PROTOCOL(Enum):
	UDP = 0
	TCP = 1
	HTTP = 2

# HS_SITE primary mask
class HS_SITE_PM(Enum):
	IS_PRIMARY = 0x80
	MULTI_PRIMARY = 0x40

# HS_ADMIN permission
class HS_ADMIN_PERM(Enum):
	ADD_HANDLE      = 0x0001
	DELETE_HANDLE   = 0x0002
	ADD_NA          = 0x0004
	DELETE_NA       = 0x0008
	MODIFY_VALUD    = 0x0010
	DELETE_VALU     = 0x0020
	ADD_VALUE       = 0x0040
	MODIFY_ADMIN    = 0x0080
	REMOVE_ADMIN    = 0x0100
	ADD_ADMIN       = 0x0200
	AUTHORIZED_READ = 0x0400
	LIST_HANDLE     = 0x0800
	LIST_NA         = 0x1000

# message flag
class MF(Enum):
	MF_CP   = 1<<15 # MessageFlag:ComPressed
	MF_EC   = 1<<14 # MessageFlag:EnCrypted
	MF_TC   = 1<<13 # MessageFlag:TrunCated
	# MF_USED = MF_CP | MF_EC | MF_TC

# op code
# from https://tools.ietf.org/html/rfc3652#section-2.2.2.1
class OC(Enum):
	# 300
	#  :        { Reserved for handle server administration }
	# 399
	RESERVED            =   0 # Reserved
	RESOLUTION          =   1 # Handle query
	GET_SITEINFO        =   2 # Get HS_SITE values
	CREATE_HANDLE       = 100 # Create new handle
	DELETE_HANDLE       = 101 # Delete existing handle
	ADD_VALUE           = 102 # Add handle value(s)
	REMOVE_VALUE        = 103 # Remove handle value(s)
	MODIFY_VALUE        = 104 # Modify handle value(s)
	LIST_HANDLE         = 105 # List handles
	LIST_NA             = 106 # List sub-naming authorities
	CHALLENGE_RESPONSE  = 200 # Response to challenge
	VERIFY_RESPONSE     = 201 # Verify challenge response
	SESSION_SETUP       = 400 # Session setup request
	SESSION_TERMINATE   = 401 # Session termination request
	SESSION_EXCHANGEKEY = 402 # Session key exchange

# response code
# https://tools.ietf.org/html/rfc3652#section-2.2.2.2
class RC(Enum):
	RESERVED                = 0   #  Reserved for request
	SUCCESS                 = 1   #  Success response
	ERROR                   = 2   #  General error
	SERVER_BUSY             = 3   #  Server too busy to respond
	PROTOCOL_ERROR          = 4   #  Corrupted or unrecognizable message
	OPERATION_DENIED        = 5   #  Unsupported operation
	RECUR_LIMIT_EXCEEDED    = 6   #  Too many recursions for the request
	HANDLE_NOT_FOUND        = 100 #  Handle not found
	HANDLE_ALREADY_EXIST    = 101 #  Handle already exists
	INVALID_HANDLE          = 102 #  Encoding (or syntax) error
	VALUE_NOT_FOUND         = 200 #  Value not found
	VALUE_ALREADY_EXIST     = 201 #  Value already exists
	VALUE_INVALID           = 202 #  Invalid handle value
	EXPIRED_SITE_INFO       = 300 #  SITE_INFO out of date
	SERVER_NOT_RESP         = 301 #  Server not responsible
	SERVICE_REFERRAL        = 302 #  Server referral
	PREFIX_REFERRAL        = 303 #  // formerly RC_NA_DELEGATE Naming authority delegation takes place.
	NOT_AUTHORIZED          = 400 #  Not authorized/permitted
	ACCESS_DENIED           = 401 #  No access to data
	AUTHEN_NEEDED           = 402 #  Authentication required
	AUTHEN_FAILED           = 403 #  Failed to authenticate
	INVALID_CREDENTIAL      = 404 #  Invalid credential
	AUTHEN_TIMEOUT          = 405 #  Authentication timed out
	UNABLE_TO_AUTHEN        = 406 #  Unable to authenticate
	SESSION_TIMEOUT         = 500 #  Session expired
	SESSION_FAILED          = 501 #  Unable to establish session
	NO_SESSION_KEY          = 502 #  No session yet available
	SESSION_NO_SUPPORT      = 503 #  Session not supported
	SESSION_KEY_INVALID     = 504 #  Invalid session key
	TRYING                  = 900 #  Request under processing
	FORWARDED               = 901 #  Request forwarded to another server
	QUEUED                  = 902 #  Request queued for later processing

# OpFlag
# https://tools.ietf.org/html/rfc3652#section-2.2.2.3
class OPF(Enum):
    AT  = 1 << 31 # AuThoritative bit.
    CT  = 1 << 30 # CerTified bit.
    ENC = 1 << 29 # ENCryption bit.
    REC = 1 << 28 # RECursive bit.
    CA  = 1 << 27 # Cache Authentication.
    CN  = 1 << 26 # ContiNuous bit.
    KC  = 1 << 25 # Keep Connection bit.
    PO  = 1 << 24 # Public Only bit.
    RD  = 1 << 23 # Request-Digest bit.
    OVRW = 1 << 22 # ask server to overwrite existing values
    MINT = 1 << 21 # used in create request. Asks server to mint a new suffix
    DNRF = 1 << 21 # requests server to not send a referral response
    # OPF_USED    = 0x1ff

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

