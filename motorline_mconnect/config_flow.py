# UI flow: username/password -> choose provider -> OAuth -> auto-read OTP -> create entry
from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers import selector
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN, CONF_EMAIL_PROVIDER, CONF_EMAIL_OAUTH, CONF_MCONNECT_TOKENS,
    AUTH_DOMAIN_GMAIL, AUTH_DOMAIN_MSFT, GMAIL_SCOPES, MSFT_SCOPES,
)
from .api import (
    MConnectClient, MConnectAuthError, MConnectCommError,
)

class MConnectConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._username = None
        self._password = None
        self._provider = None
        self._oauth_tokens = None
        self._reauth_entry = None

    async def async_step_user(self, user_input: dict | None = None) -> ConfigFlowResult:
        if user_input is not None:
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            return await self.async_step_provider()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_USERNAME): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)),
                vol.Required(CONF_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)),
            }),
        )

    async def async_step_provider(self, user_input: dict | None = None) -> ConfigFlowResult:
        if user_input is not None:
            choice = user_input["provider"]
            match choice:
                case "gmail":
                    self._provider = AUTH_DOMAIN_GMAIL
                case "microsoft":
                    self._provider = AUTH_DOMAIN_MSFT
                case _:
                    raise ValueError(f"Unsupported choice: {choice}")
            return await self.async_step_oauth()

        return self.async_show_form(
            step_id="provider",
            data_schema=vol.Schema({
                vol.Required("provider"): vol.In({"gmail": "Gmail", "microsoft": "Outlook"})
            }),
        )

    async def async_step_oauth(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Show instructions for OAuth2 setup."""
        provider_name = "Gmail" if self._provider == AUTH_DOMAIN_GMAIL else "Microsoft 365"
        
        return self.async_show_form(
            step_id="oauth_setup", 
            data_schema=vol.Schema({
                vol.Required("setup_complete", default=False): bool,
            }),
            description_placeholders={
                "provider": provider_name,
                "auth_domain": str(self._provider),
                "docs_url": "https://www.home-assistant.io/integrations/application_credentials/"
            }
        )
    
    async def async_step_oauth_setup(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Handle OAuth setup completion."""
        if user_input is not None and user_input.get("setup_complete"):
            # For now, create test tokens to allow the flow to continue
            self._oauth_tokens = {
                "access_token": f"test_token_{self._provider}",
                "token_type": "Bearer", 
                "expires_in": 3600,
            }
            return await self._finish_login()
        
        return self.async_abort(reason="oauth_setup_incomplete")
                
    async def async_oauth_create_entry(self, data: dict) -> ConfigFlowResult:
        """Create entry from OAuth2 flow completion."""
        # OAuth2 flow completed successfully, store tokens
        self._oauth_tokens = data
        return await self._finish_login()
    

    async def async_step_reauth(self, entry_data: dict | None = None) -> ConfigFlowResult:
        """Handle reauth when tokens expire."""
        if "entry_id" in self.context:
            self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if self._reauth_entry:
            self._username = self._reauth_entry.data.get(CONF_USERNAME)
            self._password = self._reauth_entry.data.get(CONF_PASSWORD)
            self._provider = self._reauth_entry.data.get(CONF_EMAIL_PROVIDER)
            stored_oauth = self._reauth_entry.data.get(CONF_EMAIL_OAUTH)
            stored_mconnect = self._reauth_entry.data.get(CONF_MCONNECT_TOKENS)

            # Try refreshing existing tokens first (like C# RefreshTokenAsync)
            if stored_mconnect and stored_mconnect.get("refresh_token"):
                session = async_get_clientsession(self.hass)
                timezone = str(self.hass.config.time_zone)
                client = MConnectClient(session, "HomeAssistant", timezone)

                try:
                    # Attempt to refresh home tokens
                    home_id = stored_mconnect.get("home_id")
                    refresh_token = stored_mconnect.get("refresh_token")

                    if home_id and refresh_token:
                        refreshed_tokens = await client.async_refresh_home_tokens(
                            home_id, refresh_token
                        )

                        # Update entry with refreshed tokens
                        entry_data = dict(self._reauth_entry.data)
                        entry_data[CONF_MCONNECT_TOKENS] = refreshed_tokens

                        return self.async_update_reload_and_abort(
                            self._reauth_entry, data=entry_data
                        )

                except MConnectAuthError:
                    # Token refresh failed, fall through to full re-authentication
                    pass
                except Exception:
                    # Any other error, fall through to full re-authentication
                    pass

            # If token refresh fails or no tokens, use existing OAuth tokens if valid
            if stored_oauth:
                self._oauth_tokens = stored_oauth
                return await self._finish_login()

        # Re-run OAuth to refresh mailbox tokens, then finish login
        match self._provider:
            case p if p in (AUTH_DOMAIN_GMAIL, AUTH_DOMAIN_MSFT):
                return await self.async_step_oauth()
            case _:
                return await self.async_step_provider()

    async def _finish_login(self) -> ConfigFlowResult:
        assert self._username and self._password and self._provider and self._oauth_tokens

        session = async_get_clientsession(self.hass)
        timezone = str(self.hass.config.time_zone)
        client = MConnectClient(session, "HomeAssistant", timezone)

        try:
            # Step 1: Initial login (triggers MFA email)
            await client.async_begin_login(self._username, self._password)

            # Step 2: Complete login with mailbox MFA + get home tokens
            tokens = await client.async_complete_login_with_mailbox(
                provider=self._provider,
                oauth_tokens=self._oauth_tokens
            )

            # Step 3: Get account info for unique_id
            account_info = await client.async_get_account_info(tokens)

        except MConnectAuthError as e:
            return self.async_show_form(
                step_id="user",
                errors={"base": "invalid_auth"},
                description_placeholders={"error": str(e)}
            )
        except MConnectCommError as e:
            return self.async_show_form(
                step_id="user",
                errors={"base": "cannot_connect"},
                description_placeholders={"error": str(e)}
            )
        except Exception as e:
            return self.async_show_form(
                step_id="user",
                errors={"base": "unknown"},
                description_placeholders={"error": str(e)}
            )

        unique_id = account_info.get("account_id", self._username.lower())
        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_configured()

        entry_data = {
            CONF_USERNAME: self._username,
            CONF_PASSWORD: self._password,          # stored to enable always-on auto-login
            CONF_EMAIL_PROVIDER: self._provider,
            CONF_EMAIL_OAUTH: self._oauth_tokens,
            CONF_MCONNECT_TOKENS: tokens,
        }

        if self._reauth_entry:
            return self.async_update_reload_and_abort(
                self._reauth_entry, data=entry_data
            )
        return self.async_create_entry(
            title=f"MConnect ({self._username})", data=entry_data
        )


class GmailOAuth2FlowHandler(
    config_entry_oauth2_flow.AbstractOAuth2FlowHandler, domain=AUTH_DOMAIN_GMAIL
):
    """Handle Gmail OAuth2 authentication."""

    DOMAIN = AUTH_DOMAIN_GMAIL
    VERSION = 1

    @property
    def logger(self):
        """Return logger."""
        from .const import LOGGER
        return LOGGER

    @property
    def name(self) -> str:
        """Name of the integration."""
        return "Gmail (for MConnect)"

    @property
    def config_flow(self):
        """Return config flow."""
        return MConnectConfigFlow

    async def async_step_creation(self, user_input=None):
        """Handle creation."""
        await self.async_set_unique_id(f"{DOMAIN}_gmail")
        self._abort_if_unique_id_configured()
        
        return await self.async_oauth_create_entry(self.external_data)


class MicrosoftOAuth2FlowHandler(
    config_entry_oauth2_flow.AbstractOAuth2FlowHandler, domain=AUTH_DOMAIN_MSFT
):
    """Handle Microsoft OAuth2 authentication."""

    DOMAIN = AUTH_DOMAIN_MSFT
    VERSION = 1

    @property
    def logger(self):
        """Return logger."""
        from .const import LOGGER
        return LOGGER

    @property
    def name(self) -> str:
        """Name of the integration."""
        return "Microsoft 365 (for MConnect)"

    @property
    def config_flow(self):
        """Return config flow."""
        return MConnectConfigFlow

    async def async_step_creation(self, user_input=None):
        """Handle creation."""
        await self.async_set_unique_id(f"{DOMAIN}_microsoft")
        self._abort_if_unique_id_configured()
        
        return await self.async_oauth_create_entry(self.external_data)
