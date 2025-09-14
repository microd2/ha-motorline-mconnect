# custom_components/motorline_mconnect/coordinator.py
# Coordinator with ±15% jitter, exponential backoff, and always-on auto-relogin
from __future__ import annotations

import logging
import random
import time
from datetime import timedelta

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME  # type: ignore
from homeassistant.core import HomeAssistant  # type: ignore
from homeassistant.exceptions import ConfigEntryAuthFailed  # type: ignore
from homeassistant.helpers.aiohttp_client import async_get_clientsession  # type: ignore
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator  # type: ignore
from homeassistant.helpers import config_entry_oauth2_flow as oauth2  # type: ignore

from .api import (
    MConnectAuthError,
    MConnectClient,
    MConnectCommError,
    MConnectError,
    MConnectRateLimitError,
    MConnectServerError,
)
from .const import (
    CONF_EMAIL_OAUTH,
    CONF_EMAIL_PROVIDER,
    CONF_MCONNECT_TOKENS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)
REFRESH_SKEW_SECONDS = 300  # refresh 5 minutes early


class MConnectCoordinator(DataUpdateCoordinator[dict]):
    """Fetches snapshots; handles jitter, backoff, and forced auto-relogin."""

    def __init__(
        self, hass: HomeAssistant, entry, user_agent: str, timezone: str
    ) -> None:
        self.hass = hass
        self.entry = entry

        self.client = MConnectClient(
            async_get_clientsession(hass),
            user_agent=user_agent,
            timezone=timezone,
        )

        # polling policy
        self._base_interval_seconds = 180  # idle
        self._active_interval_seconds = 45  # shortly after user actions
        self._recent_activity_window = 120  # seconds
        self._recent_activity_until = 0.0
        self._jitter = 0.15

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

    def note_recent_activity(self) -> None:
        self._recent_activity_until = time.time() + self._recent_activity_window

    def _compute_target_base_interval(self) -> float:
        return (
            self._active_interval_seconds
            if time.time() < self._recent_activity_until
            else self._base_interval_seconds
        )

    # ----- interval helpers -----
    def _jittered_interval(self) -> timedelta:
        factor = 1.0 + random.uniform(-self._jitter, self._jitter)
        secs = int(self._base_interval_seconds * factor)
        return timedelta(seconds=max(1, secs))

    def _apply_success_interval(self) -> None:
        """Normal cadence: adaptive base (active vs idle) + jitter."""
        # Decide active vs idle base interval
        base = (
            self._active_interval_seconds
            if time.time() < self._recent_activity_until
            else self._base_interval_seconds
        )

        # Jitter
        factor = 1.0 + random.uniform(-self._jitter, self._jitter)
        secs = int(max(5, base * factor))  # keep the 5s floor

        # Store + inform HA
        self._current_interval_seconds = base
        self.update_interval = timedelta(seconds=secs)

    def _apply_backoff_interval(
        self, reason: str, retry_after: float | None = None
    ) -> None:
        """
        Increase the polling interval after an error.

        If the server provided a Retry-After (seconds), respect it; otherwise
        use exponential backoff. Always apply jitter and enforce a sane floor.
        """
        # 1) Choose the next wait
        if retry_after and retry_after > 0:
            next_wait = max(self._current_interval_seconds, float(retry_after))
            used = f"retry_after={retry_after:g}s"
        else:
            next_wait = min(
                self._current_interval_seconds * self._backoff_multiplier,
                self._max_backoff_seconds,
            )
            used = f"backoff*x{self._backoff_multiplier:g}"

        # 2) Add jitter
        factor = 1.0 + random.uniform(-self._jitter, self._jitter)
        secs = int(max(5, next_wait * factor))  # keep your 5s floor

        # 3) Store + inform HA
        self._current_interval_seconds = next_wait
        self.update_interval = timedelta(seconds=secs)

        _LOGGER.warning(
            "Backoff due to %s (%s); next update in ~%s seconds (cap %s).",
            reason,
            used,
            secs,
            self._max_backoff_seconds,
        )

    # ----- token helpers (now INSIDE the class) -----
    def _tokens_need_refresh(self, tokens: dict) -> bool:
        """Return True if tokens are close to expiring (or have no expiry)."""
        exp = tokens.get("expires_at")
        if not exp:
            return True
        return (int(exp) - int(time.time())) <= REFRESH_SKEW_SECONDS

    async def _save_tokens(self, new_tokens: dict) -> None:
        """Persist updated tokens, preserving existing fields and normalizing expiry."""
        # 1) Start from what's already stored so we don't lose fields like user_refresh/home_id
        existing = dict(self.entry.data.get(CONF_MCONNECT_TOKENS) or {})
        merged = {
            **existing,
            **(new_tokens or {}),
        }  # new values override; missing keys are preserved

        # normalize legacy key once: 'refresh_token' -> 'refresh'
        if "refresh" not in merged and "refresh_token" in merged:
            merged["refresh"] = merged.pop("refresh_token")

        # 2) Normalize expiry: compute expires_at once if only expires_in is present
        try:
            if merged.get("expires_in") is not None:
                merged["expires_in"] = int(merged["expires_in"])
        except (TypeError, ValueError):
            merged.pop("expires_in", None)

        if not merged.get("expires_at") and merged.get("expires_in"):
            try:
                merged["expires_at"] = int(time.time()) + int(merged["expires_in"])
            except Exception:
                # Leave unset; the coordinator will refresh next cycle
                pass

        # 3) Avoid unnecessary writes if nothing changed
        if merged == existing:
            return

        # 4) Save back to the entry
        new_data = dict(self.entry.data)
        new_data[CONF_MCONNECT_TOKENS] = merged
        self.hass.config_entries.async_update_entry(self.entry, data=new_data)

        # Optional: debug log without leaking secrets
        try:
            _LOGGER.debug(
                "Tokens saved (home_id=%s, exp_at=%s)",
                merged.get("home_id"),
                merged.get("expires_at"),
            )
        except Exception:
            pass

    async def async_ensure_fresh_tokens(self) -> dict:
        """
        Ensure we have a valid *home* access token.
        - If only expires_in is present, compute expires_at once.
        - If near expiry, try HOME refresh.
        - If that fails (or keys are missing), perform full mailbox login.
        """
        tokens = dict(self.entry.data.get(CONF_MCONNECT_TOKENS) or {})
        if not tokens:
            raise ConfigEntryAuthFailed("Missing tokens")

        # normalize legacy key once: 'refresh_token' -> 'refresh'
        if "refresh" not in tokens and "refresh_token" in tokens:
            tokens["refresh"] = tokens.pop("refresh_token")

        # Compute expires_at once so we don't refresh every poll
        if tokens.get("expires_in") and not tokens.get("expires_at"):
            try:
                tokens["expires_at"] = int(time.time()) + int(tokens["expires_in"])
            finally:
                await self._save_tokens(tokens)

        # Not near expiry? keep using current tokens
        if not self._tokens_need_refresh(tokens):
            return tokens

        home_id = tokens.get("home_id")
        home_refresh = tokens.get("refresh")
        user_refresh = tokens.get(
            "user_refresh"
        )  # we will carry this forward unchanged

        # Prefer HOME refresh; we do not use user tokens here
        if home_id and home_refresh:
            try:
                new_home = await self.client.async_refresh_home_tokens(
                    home_id, home_refresh
                )
                # Ensure expected fields are present & preserved
                new_home["home_id"] = home_id
                if user_refresh:
                    new_home["user_refresh"] = user_refresh  # preserve for future flows
                # Ensure expires_at is set going forward
                if new_home.get("expires_in") and not new_home.get("expires_at"):
                    new_home["expires_at"] = int(time.time()) + int(
                        new_home["expires_in"]
                    )
                await self._save_tokens(new_home)
                return new_home
            except MConnectError as e:
                _LOGGER.warning("Home token refresh failed: %s", e)

        # Final fallback — full mailbox login (handles MFA & exchanges home token)
        if await self._try_auto_relogin_and_retry():
            return dict(self.entry.data.get(CONF_MCONNECT_TOKENS) or {})

        raise ConfigEntryAuthFailed(
            "Home refresh failed and auto re-login unsuccessful"
        )

    async def _async_update_data(self) -> dict:
        tokens = await self.async_ensure_fresh_tokens()
        try:
            data = await self.client.async_fetch_all(tokens)
            self._apply_success_interval()
            return data

        except MConnectAuthError as e:
            _LOGGER.info("Auth failed; attempting automatic re-login: %s", e)
            if await self._try_auto_relogin_and_retry():
                new_tokens = self.entry.data.get(CONF_MCONNECT_TOKENS) or {}
                data = await self.client.async_fetch_all(new_tokens)
                self._apply_success_interval()
                return data
            _LOGGER.error("Automatic re-login failed; triggering reauth.")
            raise ConfigEntryAuthFailed("gmail_oauth") from e

        except MConnectRateLimitError as e:
            # NEW: respect server-provided Retry-After when present
            self._apply_backoff_interval(
                "rate limiting (429)", retry_after=getattr(e, "retry_after", None)
            )
            return self.data or {}

        except (MConnectServerError, MConnectCommError):
            self._apply_backoff_interval("server/communication error")
            return self.data or {}

    # ----- helper used by fetch and commands -----
    async def _try_auto_relogin_and_retry(self) -> bool:
        username = self.entry.data.get(CONF_USERNAME)
        password = self.entry.data.get(CONF_PASSWORD)
        provider = self.entry.data.get(CONF_EMAIL_PROVIDER)

        if not (username and password and provider):
            return False

        try:
            email_oauth = await self._ensure_fresh_gmail_oauth()  # <-- new
        except Exception as e:
            _LOGGER.warning("Unable to refresh Gmail OAuth tokens: %s", e)
            return False

        try:
            new_tokens = await self.client.async_full_login_via_mailbox(
                username=username,
                password=password,
                provider=provider,
                email_oauth=email_oauth,
            )
            await self._save_tokens(new_tokens)
            _LOGGER.info("Automatic re-login succeeded; tokens updated.")
            await self.client.async_fetch_all(new_tokens)
            self._apply_success_interval()
            return True
        except MConnectError:
            return False

    async def async_execute_with_auth(self, func, *args, **kwargs):
        """Run a client call; ensure fresh tokens, on 401 auto-relogin once and retry."""
        tokens = await self.async_ensure_fresh_tokens()
        try:
            return await func(tokens, *args, **kwargs)
        except MConnectAuthError:
            if not await self._try_auto_relogin_and_retry():
                raise
            # After successful re-login, retry once with new tokens
            tokens = self.entry.data.get(CONF_MCONNECT_TOKENS) or {}
            return await func(tokens, *args, **kwargs)
        

    async def async_execute_with_retry(self, func, *args, **kwargs):
        """
        Like async_execute_with_auth, but also retries transient gateway/server/network
        errors a few times with short backoff. Use for device commands where a 502 may
        be transient.
        """
        import asyncio

        attempts = 3
        for i in range(attempts):
            try:
                return await self.async_execute_with_auth(func, *args, **kwargs)
            except MConnectRateLimitError as e:
                # Respect Retry-After if present, else short sleep
                wait = getattr(e, "retry_after", None) or (1.5 * (i + 1))
                self._apply_backoff_interval("rate limiting (command)", retry_after=wait)
                await asyncio.sleep(min(wait, 10))
            except (MConnectServerError, MConnectCommError):
                # Transient gateway/network error → short linear backoff
                await asyncio.sleep(1.5 * (i + 1))
                if i == attempts - 1:
                    raise
    

    async def _ensure_fresh_gmail_oauth(self) -> dict:
        """Ensure Gmail OAuth token is valid; migrate shapes; persist updates."""
        data = dict(self.entry.data)

        # 1) Find the token (prefer modern location "token", else legacy CONF_EMAIL_OAUTH)
        token = data.get("token") or data.get(CONF_EMAIL_OAUTH) or {}
        # Unwrap legacy shape: {"token": {...}} -> {...}
        if (
            isinstance(token, dict)
            and "token" in token
            and isinstance(token["token"], dict)
        ):
            token = token["token"]

        # 2) Make sure the entry actually stores the token at data["token"]
        if data.get("token") != token:
            data["token"] = token
            self.hass.config_entries.async_update_entry(self.entry, data=data)

        # 3) Get an implementation; persist id if missing (handles old entries)
        try:
            impl = await oauth2.async_get_config_entry_implementation(
                self.hass, self.entry
            )
        except Exception:
            impls = await oauth2.async_get_implementations(self.hass, DOMAIN)
            if not impls:
                raise KeyError("auth_implementation")
            impl_id, impl = next(iter(impls.items()))
            data = dict(self.entry.data)
            data["auth_implementation"] = impl_id
            self.hass.config_entries.async_update_entry(self.entry, data=data)

        # 4) Refresh using the HA session (NOTE: no 'token=' kwarg here)
        sess = oauth2.OAuth2Session(self.hass, self.entry, impl)
        await sess.async_ensure_token_valid()
        fresh = sess.token  # latest token dict

        # 5) Persist normalized token (and mirror to CONF_EMAIL_OAUTH for backwards reads)
        if fresh != token:
            data = dict(self.entry.data)
            data["token"] = fresh
            data[CONF_EMAIL_OAUTH] = (
                fresh  # optional: keep both until you remove legacy reads
            )
            self.hass.config_entries.async_update_entry(self.entry, data=data)

        return fresh
