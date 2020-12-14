import logging

ENVELOPE_LEN    = 20
HEADER_LEN      = 24
MAX_HANDLE_VALUES = 2048
MIN_MESSAGE_SIZE = ENVELOPE_LEN + HEADER_LEN + 4 # 4 is credential
MAX_ARRAY_SIZE = 1048576
IP_ADDRESS_LENGTH = 16
TEXT_ENCODING = "utf8"

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
    "%(log_color)s[%(levelname)-8s][ %(name)s:%(lineno)s - %(funcName)20s()] %(message)s",
    log_colors = {
		'DEBUG':    'green',
		'INFO':     'white',
		'WARNING':  'yellow',
		'ERROR':    'red',
		'CRITICAL': 'red,bg_white',
    }
))

