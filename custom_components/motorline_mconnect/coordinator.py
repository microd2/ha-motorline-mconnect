# Coordinator with ±15% jitter, exponential backoff, and always-on auto-relogin
from __future__ import annotations

from datetime import timedelta
import random
import logging

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.const import CONF_USERNAME, CONF_PASSWORD

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN, CONF_EMAIL_PROVIDER, CONF_EMAIL_OAUTH, CONF_MCONNECT_TOKENS,
)
from .api import (
    MConnectClient,
    MConnectAuthError,
    MConnectRateLimitError,
    MConnectServerError,
    MConnectCommError,
    MConnectError,
)

_LOGGER = logging.getLogger(__name__)

class MConnectCoordinator(DataUpdateCoordinator[dict]):
    """Fetches snapshots; handles jitter, backoff, and forced auto-relogin."""

    def __init__(self, hass: HomeAssistant, entry) -> None:
        self.entry = entry
        self.client = MConnectClient(async_get_clientsession(hass))

        # Base polling config
        self._base_interval_seconds = 90
        self._jitter = 0.15  # ±15%

        # Backoff state
        self._current_interval_seconds = self._base_interval_seconds
        self._max_backoff_seconds = 15 * 60  # 15 minutes
        self._backoff_multiplier = 2.0

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=self._jittered_interval(),
        )

    # ----- interval helpers -----
    def _jittered_interval(self) -> timedelta:
        factor = 1.0 + random.uniform(-self._jitter, self._jitter)
        secs = int(self._base_interval_seconds * factor)
        return timedelta(seconds=max(1, secs))

    def _apply_success_interval(self) -> None:
        self._current_interval_seconds = self._base_interval_seconds
        self.update_interval = self._jittered_interval()
        _LOGGER.debug("Polling interval reset to base with jitter: %s", self.update_interval)

    def _apply_backoff_interval(self, reason: str) -> None:
        self._current_interval_seconds = min(
            int(self._current_interval_seconds * self._backoff_multiplier),
            self._max_backoff_seconds,
        )
        factor = 1.0 + random.uniform(-self._jitter, self._jitter)
        secs = int(self._current_interval_seconds * factor)
        self.update_interval = timedelta(seconds=max(5, secs))
        _LOGGER.warning(
            "Backoff due to %s; next update in ~%s seconds (cap %s).",
            reason, secs, self._max_backoff_seconds,
        )

    # ----- main update -----
    async def _async_update_data(self) -> dict:
        tokens = self.entry.data[CONF_MCONNECT_TOKENS]
        try:
            data = await self.client.async_fetch_all(tokens)
            self._apply_success_interval()
            return data

        except MConnectAuthError:
            # Always attempt auto-relogin with stored credentials + mailbox OAuth
            _LOGGER.info("Auth failed; attempting automatic re-login.")
            if await self._try_auto_relogin_and_retry():
                return self.data or {}
            # If auto-relogin fails, trigger HA reauth UI
            _LOGGER.error("Automatic re-login failed; triggering reauth.")
            raise ConfigEntryAuthFailed

        except MConnectRateLimitError:
            self._apply_backoff_interval("rate limiting (429)")
            return self.data or {}

        except (MConnectServerError, MConnectCommError):
            self._apply_backoff_interval("server/communication error")
            return self.data or {}

    # ----- helper used by fetch and commands -----
    async def _try_auto_relogin_and_retry(self) -> bool:
        username = self.entry.data.get(CONF_USERNAME)
        password = self.entry.data.get(CONF_PASSWORD)
        provider = self.entry.data.get(CONF_EMAIL_PROVIDER)
        email_oauth = self.entry.data.get(CONF_EMAIL_OAUTH)
        if not (username and password and provider and email_oauth):
            return False

        try:
            new_tokens = await self.client.async_full_login_via_mailbox(
                username=username,
                password=password,
                provider=provider,
                email_oauth=email_oauth,
            )
            # Persist and immediately try to fetch again
            new_data = dict(self.entry.data)
            new_data[CONF_MCONNECT_TOKENS] = new_tokens
            self.hass.config_entries.async_update_entry(self.entry, data=new_data)
            _LOGGER.info("Automatic re-login succeeded; tokens updated.")
            # Try a fetch now so entities refresh quickly
            await self.client.async_fetch_all(new_tokens)
            self._apply_success_interval()
            return True
        except MConnectError:
            return False

    async def async_execute_with_auth(self, func, *args, **kwargs):
        """Run a client call; if 401 occurs, auto-relogin once and retry."""
        tokens = self.entry.data[CONF_MCONNECT_TOKENS]
        try:
            return await func(tokens, *args, **kwargs)
        except MConnectAuthError:
            if not await self._try_auto_relogin_and_retry():
                raise
            # After successful re-login, retry once with new tokens
            new_tokens = self.entry.data[CONF_MCONNECT_TOKENS]
            return await func(new_tokens, *args, **kwargs)
