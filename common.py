import logging

ENVELOPE_LEN    = 20
HEADER_LEN      = 24
MAX_HANDLE_VALUES = 2048
MIN_MESSAGE_SIZE = ENVELOPE_LEN + HEADER_LEN + 4 # 4 is credential
MAX_ARRAY_SIZE = 1048576
IP_ADDRESS_LENGTH = 16
TEXT_ENCODING = "utf8"

LOG_LEVEL = logging.DEBUG

ch = logging.StreamHandler()
ch.setLevel(LOG_LEVEL)
# formatter = logging.Formatter(
    # '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
formatter = logging.Formatter("[%(name)s:%(lineno)s - %(funcName)20s()] %(message)s")
ch.setFormatter(formatter)