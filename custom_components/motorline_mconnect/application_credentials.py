from __future__ import annotations

import logging
from homeassistant.components.application_credentials import AuthorizationServer # type: ignore
from homeassistant.core import HomeAssistant # type: ignore

_LOGGER = logging.getLogger(__name__)

async def async_get_authorization_server(hass: HomeAssistant) -> AuthorizationServer:
    """Return Google OAuth2 authorization server for Motorline MConnect."""
    _LOGGER.debug("application_credentials: registering Google AuthorizationServer for motorline_mconnect")
    return AuthorizationServer(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
    )
