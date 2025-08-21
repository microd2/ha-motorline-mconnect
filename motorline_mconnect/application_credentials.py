# Fixed OAuth endpoints for Gmail and Microsoft Graph

from __future__ import annotations
from homeassistant.core import HomeAssistant
from homeassistant.components.application_credentials import (
    AuthorizationServer,
    ClientCredential,
)
from homeassistant.helpers.config_entry_oauth2_flow import LocalOAuth2ImplementationWithPkce

from custom_components.motorline_mconnect.const import DOMAIN

AUTH_DOMAIN_GMAIL = f"{DOMAIN}_gmail"
AUTH_DOMAIN_MSFT  = f"{DOMAIN}_microsoft"

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

async def async_get_auth_implementation(hass: HomeAssistant, auth_domain: str, cred: ClientCredential):
    if auth_domain == AUTH_DOMAIN_GMAIL:
        return _GmailImpl(
            hass, AUTH_DOMAIN_GMAIL, cred.client_id,
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            client_secret=cred.client_secret or "",
        )
    if auth_domain == AUTH_DOMAIN_MSFT:
        return _MsftImpl(
            hass, AUTH_DOMAIN_MSFT, cred.client_id,
            authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
            client_secret=cred.client_secret or "",
        )
    # Fallback to Gmail
    return _GmailImpl(
        hass, AUTH_DOMAIN_GMAIL, cred.client_id,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        client_secret=cred.client_secret or "",
    )
