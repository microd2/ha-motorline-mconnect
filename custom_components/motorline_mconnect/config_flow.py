# UI flow: username/password -> choose provider -> OAuth -> auto-read OTP -> create entry
from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResult
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

    async def async_step_user(self, user_input: dict | None = None) -> FlowResult:
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

    async def async_step_provider(self, user_input: dict | None = None) -> FlowResult:
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

    async def async_step_oauth(self, user_input: dict | None = None) -> FlowResult:
        scopes = GMAIL_SCOPES if self._provider == AUTH_DOMAIN_GMAIL else MSFT_SCOPES
        return await config_entry_oauth2_flow.async_step_auth(self, self._provider, scopes=scopes)

    async def async_oauth_create_entry(self, data: dict) -> FlowResult:
        self._oauth_tokens = data
        return await self._finish_login()

    async def async_step_reauth(self, entry_data: dict | None = None) -> FlowResult:
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

    async def _finish_login(self) -> FlowResult:
        assert self._username and self._password and self._provider and self._oauth_tokens
        client = MConnectClient(session=async_get_clientsession(self.hass))

        try:
            await client.async_begin_login(self._username, self._password)
            tokens = await client.async_complete_login_with_mailbox(
                provider=self._provider, oauth_tokens=self._oauth_tokens
            )
            account_info = await client.async_get_account_info(tokens)
        except MConnectAuthError:
            return self.async_show_form(step_id="provider", errors={"base": "auth"})
        except MConnectCommError:
            return self.async_show_form(step_id="user", errors={"base": "connection"})
        except MConnectError:
            return self.async_show_form(step_id="user", errors={"base": "unknown"})

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
