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

import time
from homeassistant.exceptions import ConfigEntryAuthFailed
from .const import CONF_MCONNECT_TOKENS


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
REFRESH_SKEW_SECONDS = 300  # refresh 5 minutes early


class MConnectCoordinator(DataUpdateCoordinator[dict]):
    """Fetches snapshots; handles jitter, backoff, and forced auto-relogin."""

    def __init__(self, hass: HomeAssistant, entry, user_agent: str, timezone: str) -> None:
        self.entry = entry
        
        self.client = MConnectClient(
            async_get_clientsession(hass),
            user_agent=user_agent,          # 👈 pass through
            timezone=timezone,              # 👈 pass through
        )
        

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
        tokens = await self.async_ensure_fresh_tokens()
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


def _tokens_need_refresh(self, tokens: dict) -> bool:
    """Return True if tokens are close to expiring (or have no expiry)."""
    exp = tokens.get("expires_at")
    if not exp:
        return True
    return (int(exp) - int(time.time())) <= REFRESH_SKEW_SECONDS

async def _save_tokens(self, new_tokens: dict) -> None:
    """Persist updated tokens back to the config entry."""
    new_data = dict(self.entry.data)
    new_data[CONF_MCONNECT_TOKENS] = new_tokens
    # Persist to HA's storage
    self.hass.config_entries.async_update_entry(self.entry, data=new_data)

async def async_ensure_fresh_tokens(self) -> dict:
    """
    Ensure we have a valid home access token.
    Strategy:
      1) If not expiring → reuse.
      2) Else try HOME refresh first.
      3) If that fails, do USER refresh + home exchange.
    """
    tokens = dict(self.entry.data.get(CONF_MCONNECT_TOKENS) or {})
    if not tokens:
        raise ConfigEntryAuthFailed("Missing tokens")

    if not self._tokens_need_refresh(tokens):
        return tokens

    home_id = tokens.get("home_id")
    home_refresh = tokens.get("refresh")
    user_refresh = tokens.get("user_refresh")

    # Prefer home refresh
    try:
        if home_id and home_refresh:
            new_home = await self.client.async_refresh_home_tokens(home_id, home_refresh)
            # carry forward user refresh for fallback later
            new_home["user_refresh"] = user_refresh
            await self._save_tokens(new_home)
            return new_home
    except Exception:
        # fall through to user refresh path
        pass

    # Fallback: refresh user token then re-exchange for a home token
    if not user_refresh:
        raise ConfigEntryAuthFailed("No valid refresh tokens available")

    new_user = await self.client.async_refresh_user_tokens(user_refresh)
    homes = await self.client.async_get_homes(new_user["access"])
    if not homes:
        raise ConfigEntryAuthFailed("No homes available after user refresh")
    home_id = homes[0].get("id")

    new_home = await self.client.async_exchange_home_token(new_user["access"], home_id)
    new_home["home_id"] = home_id
    new_home["user_refresh"] = new_user.get("refresh", user_refresh)
    await self._save_tokens(new_home)
    return new_home