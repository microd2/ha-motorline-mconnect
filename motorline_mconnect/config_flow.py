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
    MConnectClient, MConnectAuthError, MConnectCommError, MConnectError,
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
            self._provider = AUTH_DOMAIN_GMAIL if choice == "gmail" else AUTH_DOMAIN_MSFT
            return await self.async_step_oauth()

        return self.async_show_form(
            step_id="provider",
            data_schema=vol.Schema({
                vol.Required("provider"): vol.In({"gmail": "Gmail", "microsoft": "Microsoft 365"})
            }),
        )

    async def async_step_oauth(self, user_input: dict | None = None) -> ConfigFlowResult:
        """OAuth step - placeholder until proper OAuth2 is implemented."""
        if user_input is not None:
            # Simulate successful OAuth - replace with real OAuth tokens later
            self._oauth_tokens = {
                "access_token": "fake_access_token", 
                "refresh_token": "fake_refresh_token",
                "token_type": "Bearer"
            }
            return await self._finish_login()

        return self.async_show_form(
            step_id="oauth",
            data_schema=vol.Schema({
                vol.Required("confirm", default=True): bool,
            }),
            description_placeholders={
                "provider": "Gmail" if self._provider == AUTH_DOMAIN_GMAIL else "Microsoft 365"
            }
        )

    async def async_oauth_create_entry(self, data: dict) -> ConfigFlowResult:
        self._oauth_tokens = data
        return await self._finish_login()

    async def async_step_reauth(self, _entry_data: dict | None = None) -> ConfigFlowResult:
        if "entry_id" in self.context:
            self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if self._reauth_entry:
            self._username = self._reauth_entry.data.get(CONF_USERNAME)
            self._password = self._reauth_entry.data.get(CONF_PASSWORD)
            self._provider = self._reauth_entry.data.get(CONF_EMAIL_PROVIDER)
        # Re-run OAuth to refresh mailbox tokens, then finish login
        if self._provider in (AUTH_DOMAIN_GMAIL, AUTH_DOMAIN_MSFT):
            return await self.async_step_oauth()
        return await self.async_step_provider()

    async def _finish_login(self) -> ConfigFlowResult:
        assert self._username and self._password and self._provider and self._oauth_tokens
        
        # TODO: Temporarily bypass API calls for testing - re-enable for production
        # For now, just create fake tokens and account info
        tokens = {"access_token": "fake_mconnect_token", "refresh_token": "fake_refresh"}
        account_info = {"account_id": f"test_{self._username.lower()}"}

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
            return self.async_update_reload_and_abort(self._reauth_entry, data=entry_data)
        return self.async_create_entry(title=f"MConnect ({self._username})", data=entry_data)
