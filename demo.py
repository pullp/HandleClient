from handleclient import resolution

rootAddr = ("132.151.1.179", 2641) # ghr
resp = resolution.simpleResolutionTest("0.NA/10", rootAddr)

import logging
from handleclient import common

logger = logging.getLogger(__name__)
logger.setLevel(common.LOG_LEVEL)
logger.addHandler(common.ch)
logger.debug("test debug")
logger.info("test info")
logger.warning("test warning")
logger.error("test error")
logger.critical("test critical")