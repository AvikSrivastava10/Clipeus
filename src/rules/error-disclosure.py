import traceback
import logging

logger = logging.getLogger(__name__)


def handler_bad():
    try:
        do_work()
    except Exception:
        # ruleid: clipeus-traceback-to-client-python
        return traceback.format_exc()


def handler_bad_tuple():
    try:
        do_work()
    except Exception:
        # ruleid: clipeus-traceback-to-client-python
        return traceback.format_exc(), 500


def handler_good():
    try:
        do_work()
    except Exception:
        logger.exception("request failed")
        # ok: clipeus-traceback-to-client-python
        return "Internal Server Error", 500
