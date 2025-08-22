import logging

_LOGGER = logging.getLogger(__name__)
_LOGGER.warning("TEST_INTEGRATION: Module imported!")

async def async_setup(hass, config):
    _LOGGER.warning("TEST_INTEGRATION: async_setup called!")
    return True