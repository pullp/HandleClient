import logging

ENVELOPE_LEN    = 20
HEADER_LEN      = 24
MAX_HANDLE_VALUES = 2048
MIN_MESSAGE_SIZE = ENVELOPE_LEN + HEADER_LEN + 4 # 4 is credential
MAX_ARRAY_SIZE = 1048576
TEXT_ENCODING = "utf8"

MD5_DIGEST_SIZE = 16
SHA1_DIGEST_SIZE = 20
SHA256_DIGEST_SIZE = 32

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

