# Fixed OAuth endpoints for Gmail and Microsoft Graph

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

# Use single OAuth domain
AUTH_DOMAIN = DOMAIN


async def async_get_authorization_server(hass: HomeAssistant) -> AuthorizationServer:
    # Required by HA; not used when we return custom implementations
    return AuthorizationServer(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
    )


class _GmailImpl(LocalOAuth2ImplementationWithPkce):
    pass


class _MsftImpl(LocalOAuth2ImplementationWithPkce):
    pass


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, cred: ClientCredential
):
    from .const import LOGGER
    LOGGER.info(f"async_get_auth_implementation called with domain: {auth_domain}")
    # For now, default to Gmail OAuth (we'll handle provider selection in config flow)
    return _GmailImpl(
        hass,
        AUTH_DOMAIN,
        cred.client_id,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        client_secret=cred.client_secret or "",
    )
