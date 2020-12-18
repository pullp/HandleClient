import time
import handleclient.handlevalue as handlevalue
from handleclient import resolution
from handleclient import addvalue

def testResolution():
    rootAddr = ("132.151.1.179", 2641) # ghr
    # resp = resolution.simpleResolutionTest("0.0/0.0", rootAddr)
    doiAddr = ("38.100.138.134", 2641) # ghr
    resp = resolution.simpleResolutionTest(b"10.1038/nature18948", doiAddr)
    print(resp)

def testAddValue():
    doiAddr = ("38.100.138.134", 2641) # ghr
    valueList = []
    hv1 = handlevalue.HS_STRING()
    hv1.setBasicVals(b"URL", 123, b'', 0, 86400,
        handlevalue.HandleValue.PERM.PUBLIC_READ.value, int(time.time()),[])
    hv1.setDataVals("https://www.example.com")
    valueList.append(hv1)

    resp = addvalue.simpleAddValueTest(b"10.1038/12324", valueList, doiAddr)
    print(resp)


# testResolution()
testAddValue()

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