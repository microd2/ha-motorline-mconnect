# UI flow: username/password -> OAuth (Gmail) -> auto-read OTP -> create entry
from __future__ import annotations

from typing import Any, Self
from urllib.parse import urlparse, parse_qs
import logging
import voluptuous as vol
from homeassistant import config_entries # type: ignore
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME # type: ignore
from homeassistant.config_entries import ConfigFlowResult # type: ignore
from homeassistant.helpers import selector # type: ignore
from homeassistant.helpers import config_entry_oauth2_flow # type: ignore
from homeassistant.helpers.aiohttp_client import async_get_clientsession # type: ignore
from homeassistant.helpers import config_entry_oauth2_flow as oauth2 # type: ignore
from .const import (
    DOMAIN, CONF_EMAIL_PROVIDER, CONF_EMAIL_OAUTH, CONF_MCONNECT_TOKENS,
    AUTH_DOMAIN_GMAIL, GMAIL_SCOPES,
)
from .api import (
    MConnectClient, MConnectAuthError, MConnectCommError,
)

_LOGGER = logging.getLogger(__name__)

class ConfigFlow(config_entry_oauth2_flow.AbstractOAuth2FlowHandler, domain=DOMAIN): # pyright: ignore[reportGeneralTypeIssues, reportCallIssue]

    DOMAIN = DOMAIN
    domain: str = DOMAIN
    VERSION = 1

    @property
    def logger(self):
        return _LOGGER

    # 👇 NEW: tell HA which OAuth scopes to request
    @property
    def scopes(self) -> list[str]:
        """OAuth scopes required for Gmail access."""
        self.logger.warning("OAuth scopes property called. scopes=%s", GMAIL_SCOPES)
        _LOGGER.warning("OAuth scopes requested: %s", GMAIL_SCOPES)
        return GMAIL_SCOPES

    # 👇 NEW: Google-specific authorize params
    @property
    def extra_authorize_data(self) -> dict[str, Any]:
        # Ensure scope is included in the authorize URL
        scope = " ".join(GMAIL_SCOPES)
        self.logger.warning("extra_authorize_data: adding scope=%s", scope)
        return {
            "access_type": "offline",
            "prompt": "consent",
            "scope": scope,          # 👈 add this line
        }


    def is_matching(self, other_flow) -> bool:
        """No discovery de-dupe needed for this integration."""
        return False

    def __init__(self) -> None:
        super().__init__()  # ✅ call base init
        self._username: str | None = None
        self._password: str | None = None
        self._oauth_tokens: dict | None = None
        self._reauth_entry: config_entries.ConfigEntry | None = None
        self._oauth_started = False   # Guard against multiple callbacks
        self._oauth_done = False      # Guard against multiple callbacks
        self._oauth_impl: str | None = None


    async def async_step_user(self, user_input: dict | None = None) -> ConfigFlowResult:
        self.logger.warning("async_step_user: domain=%r, handler_class_domain=%r", getattr(self, "domain", None), getattr(self.__class__, "domain", None))
        if user_input is not None:
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            return await self.async_step_oauth()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_USERNAME): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)),
                vol.Required(CONF_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)),
            }),
        )

    async def async_step_oauth(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Show instructions for OAuth2 setup."""
        return self.async_show_form(
            step_id="oauth_setup",
            data_schema=vol.Schema({
                vol.Required("setup_complete", default=False): bool,
            }),
            description_placeholders={
                "provider": "Gmail",
                "auth_domain": str(DOMAIN),
                "docs_url": "https://www.home-assistant.io/integrations/application_credentials/",
            },
        )

    async def async_step_oauth_setup(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Confirm and kick off the OAuth helper."""
        if user_input and user_input.get("setup_complete"):

            if self._oauth_started:                     # debounce
                return self.async_abort(reason="already_in_progress")

            self._oauth_started = True

            # First call (no args): returns an EXTERNAL_STEP dict that includes the URL.
            result = await super().async_step_pick_implementation()

            # Log the exact authorize URL HA is about to open.
            url = result.get("url")
            if url:
                self.logger.warning("AUTH URL = %s", url)
                self.logger.warning("AUTH URL QUERY = %s", parse_qs(urlparse(url).query))
            else:
                self.logger.warning("No auth URL present in pick_implementation result: %s", result)

            # Return the normal result so the UI continues to the external step
            return result

        return self.async_abort(reason="oauth_setup_incomplete")



    async def async_step_pick_implementation(self, user_input=None) -> ConfigFlowResult:
        return await super().async_step_pick_implementation(user_input)

    async def async_step_auth(self, user_input=None) -> ConfigFlowResult:
        return await super().async_step_auth(user_input)

    async def async_oauth_create_entry(self, data: dict) -> ConfigFlowResult:
        """Handle OAuth2 callback from Gmail authorization."""
        if self._oauth_done:  # ignore duplicate callback
            return self.async_abort(reason="already_configured")
        self._oauth_done = True

        # data usually contains {"auth_implementation": "...", "token": {...}, ...}
        token = data.get("token") or data            # <-- store *only* the token dict
        auth_impl = data.get("auth_implementation")  # <-- keep the impl id for lookups

        _LOGGER.info("Gmail OAuth2 callback keys: %s", list(data.keys()))
        self._oauth_tokens = token
        self._oauth_impl = auth_impl
        _LOGGER.info("Gmail OAuth2 tokens stored, proceeding with MConnect login")

        return await self._finish_login()




    async def async_step_reauth(self, entry_data: dict | None = None) -> ConfigFlowResult:
        """Handle reauth when tokens expire."""
        if "entry_id" in self.context:
            self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if self._reauth_entry:
            self._username = self._reauth_entry.data.get(CONF_USERNAME)
            self._password = self._reauth_entry.data.get(CONF_PASSWORD)
            stored_oauth = self._reauth_entry.data.get(CONF_EMAIL_OAUTH)
            stored_mconnect = self._reauth_entry.data.get(CONF_MCONNECT_TOKENS)

            # Try refreshing existing tokens first (fast path)
            stored_mconnect = (self._reauth_entry.data or {}).get(CONF_MCONNECT_TOKENS)

            refresh = None
            home_id = None
            if stored_mconnect:
                # prefer canonical 'refresh', accept legacy 'refresh_token'
                refresh = stored_mconnect.get("refresh") or stored_mconnect.get("refresh_token")
                home_id = stored_mconnect.get("home_id")

            if refresh and home_id:
                session = async_get_clientsession(self.hass)
                timezone = str(self.hass.config.time_zone)
                client = MConnectClient(session, "HomeAssistant", timezone)
                try:
                    refreshed_tokens = await client.async_refresh_home_tokens(home_id, refresh)
                    entry_data = dict(self._reauth_entry.data)
                    entry_data[CONF_MCONNECT_TOKENS] = refreshed_tokens
                    return self.async_update_reload_and_abort(self._reauth_entry, data=entry_data)
                except MConnectAuthError:
                    # Token refresh failed, fall through to full re-authentication
                    pass
                except Exception:
                    # Any other error, fall through to full re-authentication
                    pass

            if stored_oauth:
                # Normalize token shape and ensure it's at entry.data["token"]
                token = stored_oauth.get("token") if isinstance(stored_oauth, dict) else stored_oauth
                entry = self._reauth_entry
                if entry:
                    data = dict(entry.data)
                    data["token"] = token
                    self.hass.config_entries.async_update_entry(entry, data=data)

                    # Refresh Gmail access token via HA session
                    impl = await oauth2.async_get_config_entry_implementation(self.hass, entry)
                    sess = oauth2.OAuth2Session(self.hass, entry, impl)
                    await sess.async_ensure_token_valid()
                    self._oauth_tokens = sess.token
                else:
                    self._oauth_tokens = token

                return await self._finish_login()

        # Re-run OAuth to refresh mailbox tokens, then finish login
        return await self.async_step_oauth()

    async def _finish_login(self) -> ConfigFlowResult:
        assert self._username and self._password and self._oauth_tokens

        _LOGGER.info("Starting MConnect login with Gmail OAuth2 tokens available")

        session = async_get_clientsession(self.hass)
        timezone = str(self.hass.config.time_zone)
        client = MConnectClient(session, "HomeAssistant", timezone)

        try:
            # Step 1: Initial login (triggers MFA email)
            await client.async_begin_login(self._username, self._password)

            # Step 2: Complete login with mailbox MFA + get home tokens
            tokens = await client.async_complete_login_with_mailbox(
                provider="motorline_mconnect_gmail",
                oauth_tokens=self._oauth_tokens,
            )

            # Step 3: Get account info for unique_id
            account_info = await client.async_get_account_info(tokens)

        except MConnectAuthError as e:
            _LOGGER.error(f"Failed completing MConnect Config Flow: {str(e)}")
            return self.async_show_form(
                step_id="user",
                errors={"base": "invalid_auth"},
                description_placeholders={"error": str(e)},
            )
        except MConnectCommError as e:
            _LOGGER.error(f"MConnect communication failure: {str(e)}")
            return self.async_show_form(
                step_id="user",
                errors={"base": "cannot_connect"},
                description_placeholders={"error": str(e)},
            )
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Unexpected error in _finish_login: %s", e, exc_info=True)
            return self.async_show_form(
                step_id="user",
                errors={"base": "unknown"},
                description_placeholders={"error": str(e)},
            )

        unique_id = account_info.get("account_id", self._username.lower())
        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_configured()

        entry_data = {
            CONF_USERNAME: self._username,
            CONF_PASSWORD: self._password,  # stored to enable always-on auto-login
            CONF_EMAIL_PROVIDER: "motorline_mconnect_gmail",
            CONF_EMAIL_OAUTH: self._oauth_tokens,
            "auth_implementation": self._oauth_impl,  # <-- helps OAuth2Session find impl
            CONF_MCONNECT_TOKENS: tokens,
            "token": self._oauth_tokens              # where OAuth2Session expects it
        }

        if self._reauth_entry:
            return self.async_update_reload_and_abort(self._reauth_entry, data=entry_data)

        return self.async_create_entry(title=f"MConnect ({self._username})", data=entry_data)

try:
    _LOGGER.debug(
        "motorline_mconnect.config_flow: class discovered: %s, domain=%r",
        issubclass(ConfigFlow, config_entry_oauth2_flow.AbstractOAuth2FlowHandler),
        getattr(ConfigFlow, "domain", None),
    )
except Exception as e:
    _LOGGER.exception("motorline_mconnect.config_flow: sanity-check failed: %s", e)