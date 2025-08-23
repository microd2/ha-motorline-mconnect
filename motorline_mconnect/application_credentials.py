# Gmail OAuth2 implementation for MConnect integration

from __future__ import annotations

from custom_components.motorline_mconnect.const import DOMAIN
from homeassistant.components.application_credentials import (
    AuthorizationServer,
    ClientCredential,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.config_entry_oauth2_flow import (
    LocalOAuth2ImplementationWithPkce,
)

# Use main domain for OAuth
AUTH_DOMAIN = DOMAIN


async def async_get_authorization_server(hass: HomeAssistant) -> AuthorizationServer:
    """Return Gmail OAuth2 authorization server."""
    return AuthorizationServer(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
    )


class _GmailImpl(LocalOAuth2ImplementationWithPkce):
    """Gmail OAuth2 implementation."""
    pass


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, cred: ClientCredential
):
    """Return Gmail OAuth2 implementation."""
    from .const import LOGGER
    LOGGER.info(f"async_get_auth_implementation called for Gmail OAuth with domain: {auth_domain}")
    
    return _GmailImpl(
        hass,
        AUTH_DOMAIN,
        cred.client_id,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        client_secret=cred.client_secret or "",
    )
