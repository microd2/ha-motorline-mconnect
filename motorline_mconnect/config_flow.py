from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_entry_oauth2_flow, selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    MConnectAuthError,
    MConnectClient,
    MConnectCommError,
    MConnectError,
)
from .const import (
    AUTH_DOMAIN_GMAIL,
    AUTH_DOMAIN_MSFT,
    CONF_EMAIL_OAUTH,
    CONF_EMAIL_PROVIDER,
    CONF_MCONNECT_TOKENS,
    DOMAIN,
    GMAIL_SCOPES,
    MSFT_SCOPES,
)


class MConnectConfigFlow(config_entry_oauth2_flow.AbstractOAuth2FlowHandler):
    """Handle a config flow for Motorline MConnect."""

    DOMAIN = DOMAIN
    VERSION = 1

    def __init__(self) -> None:
        super().__init__()
        self._username: str | None = None
        self._password: str | None = None
        self._provider: str | None = None
        self._oauth_tokens: dict[str, Any] | None = None
        self._reauth_entry: ConfigEntry | None = None

    @staticmethod
    def is_matching(domain: str) -> bool:
        """Return True if the domain matches."""
        return domain == DOMAIN

    # --- OAuth2 helper hooks ---

    @property
    def logger(self):
        """Return logger."""
        return logging.getLogger(__name__)

    @property
    def extra_authorize_data(self) -> dict[str, str] | None:
        # Provide provider-specific scopes to the helper
        if self._provider == AUTH_DOMAIN_GMAIL:
            return {"scope": " ".join(GMAIL_SCOPES)}
        if self._provider == AUTH_DOMAIN_MSFT:
            return {"scope": " ".join(MSFT_SCOPES)}
        return None

    async def async_oauth_create_entry(self, data: dict[str, Any]) -> ConfigFlowResult:
        # Called by the helper after the OAuth dance
        self._oauth_tokens = data
        return await self._finish_login()

    # --- Your steps ---

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            return await self.async_step_provider()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): selector.TextSelector(
                        selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        )
                    ),
                }
            ),
        )

    async def async_step_provider(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            choice = user_input["provider"]
            self._provider = (
                AUTH_DOMAIN_GMAIL if choice == "gmail" else AUTH_DOMAIN_MSFT
            )
            # Hand control to the OAuth2 helper to pick implementation and authorize
            return await self.async_step_pick_implementation()

        return self.async_show_form(
            step_id="provider",
            data_schema=vol.Schema(
                {
                    vol.Required("provider"): vol.In(
                        {"gmail": "Gmail", "microsoft": "Microsoft 365"}
                    )
                }
            ),
        )

    async def async_step_reauth(
        self, _entry_data: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if "entry_id" in self.context:
            self._reauth_entry = self.hass.config_entries.async_get_entry(
                self.context["entry_id"]
            )
        if self._reauth_entry:
            self._username = self._reauth_entry.data.get(CONF_USERNAME)
            self._password = self._reauth_entry.data.get(CONF_PASSWORD)
            self._provider = self._reauth_entry.data.get(CONF_EMAIL_PROVIDER)
        if self._provider in (AUTH_DOMAIN_GMAIL, AUTH_DOMAIN_MSFT):
            return await self.async_step_pick_implementation()
        return await self.async_step_provider()

    async def _finish_login(self) -> ConfigFlowResult:
        assert (
            self._username and self._password and self._provider and self._oauth_tokens
        )

        # (2) Fix for missing required args in your client constructor (see next section)
        client = MConnectClient(
            session=async_get_clientsession(self.hass),
            user_agent="HomeAssistant",  # string as required by your client
            timezone=str(self.hass.config.time_zone or "UTC"),
        )

        try:
            # (3) Ensure these API methods exist on your client, or rename to the actual ones
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
            CONF_PASSWORD: self._password,  # stored for your auto-login use-case
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
