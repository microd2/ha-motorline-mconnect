# UI flow: username/password -> OAuth (Gmail) -> auto-read OTP -> create entry
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
    AUTH_DOMAIN_GMAIL, GMAIL_SCOPES,
)
from .api import (
    MConnectClient, MConnectAuthError, MConnectCommError,
)

class MConnectConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1


    def __init__(self) -> None:
        self._username = None
        self._password = None
        self._oauth_tokens = None
        self._reauth_entry = None

    async def async_step_user(self, user_input: dict | None = None) -> ConfigFlowResult:
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
                "docs_url": "https://www.home-assistant.io/integrations/application_credentials/"
            }
        )
    
    async def async_step_oauth_setup(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Handle OAuth setup completion."""
        if user_input is not None and user_input.get("setup_complete"):
            # Check if OAuth2 implementations are available
            try:
                # Use the main domain for OAuth2 lookups
                implementations = await config_entry_oauth2_flow.async_get_implementations(
                    self.hass, DOMAIN
                )
                # Add debug logging
                from .const import LOGGER
                LOGGER.info(f"OAuth2 implementations for {DOMAIN}: {list(implementations.keys()) if implementations else 'None'}")
                
                if implementations:
                    # Start the actual OAuth2 flow
                    return await self.async_step_pick_implementation()
                else:
                    # No implementations configured - show error
                    LOGGER.warning(f"No OAuth2 implementations found for domain: {DOMAIN}")
                    return self.async_show_form(
                        step_id="oauth_setup",
                        errors={"base": "no_implementations"},
                        data_schema=vol.Schema({
                            vol.Required("setup_complete", default=False): bool,
                        }),
                        description_placeholders={
                            "provider": "Gmail",
                            "auth_domain": str(DOMAIN),
                            "docs_url": "https://www.home-assistant.io/integrations/application_credentials/"
                        }
                    )
            except Exception as e:
                # Log the exception for debugging
                from .const import LOGGER
                LOGGER.error(f"Exception checking OAuth2 implementations: {e}")
                return self.async_abort(reason="oauth_error")
        
        return self.async_abort(reason="oauth_setup_incomplete")

    async def async_step_pick_implementation(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Pick OAuth2 implementation to use and start OAuth flow."""
        # Get available implementations for the main domain
        implementations = await config_entry_oauth2_flow.async_get_implementations(
            self.hass, DOMAIN
        )
        
        if not implementations:
            # No OAuth implementations configured - show error
            from .const import LOGGER
            LOGGER.error("No OAuth2 implementations found - user needs to configure Application Credentials")
            return self.async_abort(reason="no_oauth_config")
        
        # If only one implementation, use it directly
        if len(implementations) == 1:
            implementation_key = list(implementations.keys())[0]
            implementation = implementations[implementation_key]
            # Start OAuth2 flow with the implementation
            return await self.async_step_auth(implementation=implementation)
        
        # Multiple implementations - show selection (shouldn't happen with Gmail-only)
        if user_input is not None:
            implementation_key = user_input["implementation"]
            implementation = implementations[implementation_key]
            return await self.async_step_auth(implementation=implementation)
        
        implementation_options = {
            key: impl.name for key, impl in implementations.items()
        }
        
        return self.async_show_form(
            step_id="pick_implementation", 
            data_schema=vol.Schema({
                vol.Required("implementation"): vol.In(implementation_options)
            }),
        )
        
    async def async_step_auth(self, user_input: dict | None = None, implementation=None) -> ConfigFlowResult:
        """Initiate OAuth2 flow to get Gmail access tokens before MConnect login.""" 
        if implementation is None:
            return self.async_abort(reason="missing_implementation")
            
        from .const import LOGGER
        LOGGER.info(f"Need to get Gmail OAuth2 tokens before MConnect login: {implementation}")
        
        # Store implementation for later use
        self._implementation = implementation
        
        # Create a manual OAuth2 session to get access tokens
        import secrets
        from urllib.parse import urlencode
        
        # Generate state for OAuth2 security
        state = secrets.token_urlsafe(32)
        self._oauth_state = state
        
        # Build authorization URL with My Home Assistant redirect URI
        params = {
            "response_type": "code",
            "client_id": implementation.client_id,
            "redirect_uri": "https://my.home-assistant.io/redirect/oauth",
            "scope": " ".join(GMAIL_SCOPES),
            "state": state,
            "access_type": "offline",
            "prompt": "consent"
        }
        
        auth_url = f"{implementation.authorize_url}?{urlencode(params)}"
        LOGGER.info(f"OAuth2 redirect_uri: https://my.home-assistant.io/redirect/oauth")
        LOGGER.info(f"Generated Gmail OAuth2 authorization URL: {auth_url[:100]}...")
        
        # Open browser to authorization URL, then show form for manual code entry
        self._auth_url = auth_url  # Store for later reference
        return self.async_external_step(
            step_id="gmail_auth_browser",
            url=auth_url
        )
    
    async def async_step_gmail_auth_browser(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Handle return from external browser step - show form for manual code entry."""
        # After user clicks through external authorization, show form for code entry
        import voluptuous as vol
        return self.async_show_form(
            step_id="gmail_code_entry",
            data_schema=vol.Schema({
                vol.Required("authorization_code"): str
            }),
            description_placeholders={}
        )
    
    async def async_step_gmail_code_entry(self, user_input: dict | None = None) -> ConfigFlowResult:
        """Handle manual entry of OAuth2 authorization code."""
        from .const import LOGGER
        
        if user_input is None:
            return self.async_abort(reason="no_user_input")
            
        authorization_code = user_input.get("authorization_code")
        if not authorization_code:
            return self.async_abort(reason="oauth_failed")
            
        LOGGER.info(f"Received Gmail OAuth2 authorization code: {authorization_code[:10]}...")
        
        # Exchange authorization code for access tokens
        try:
            
            token_data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "client_id": self._implementation.client_id,
                "client_secret": self._implementation.client_secret,
                "redirect_uri": "https://my.home-assistant.io/redirect/oauth",
            }
            
            session = async_get_clientsession(self.hass)
            async with session.post(
                self._implementation.token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    LOGGER.error(f"OAuth2 token exchange failed: {error_text}")
                    return self.async_abort(reason="oauth_token_failed")
                    
                token_response = await resp.json()
                LOGGER.info("Gmail OAuth2 tokens obtained successfully")
                
            # Store tokens and proceed with MConnect login
            self._oauth_tokens = token_response
            return await self._finish_login()
            
        except Exception as e:
            LOGGER.error(f"OAuth2 token exchange error: {e}")
            return self.async_abort(reason="oauth_error")
        
    async def async_oauth_create_entry(self, data: dict) -> ConfigFlowResult:
        """Handle OAuth2 callback from Gmail authorization."""
        from .const import LOGGER
        LOGGER.info(f"Gmail OAuth2 callback received: {list(data.keys())}")
        
        # Store the OAuth2 tokens for Gmail access
        self._oauth_tokens = data
        LOGGER.info("Gmail OAuth2 tokens stored, proceeding with MConnect login")
        
        # Now we have Gmail access - proceed with MConnect login
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
        return await self.async_step_oauth()

    async def _finish_login(self) -> ConfigFlowResult:
        assert self._username and self._password and self._oauth_tokens
        
        from .const import LOGGER
        LOGGER.info("Starting MConnect login with Gmail OAuth2 tokens available")

        session = async_get_clientsession(self.hass)
        timezone = str(self.hass.config.time_zone)
        client = MConnectClient(session, "HomeAssistant", timezone)

        try:
            # Step 1: Initial login (triggers MFA email)
            await client.async_begin_login(self._username, self._password)

            # Step 2: Complete login with mailbox MFA + get home tokens
            tokens = await client.async_complete_login_with_mailbox(
                provider="motorline_mconnect_gmail",
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
            from .const import LOGGER
            LOGGER.error(f"Unexpected error in _finish_login: {e}", exc_info=True)
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
            CONF_EMAIL_PROVIDER: "motorline_mconnect_gmail",
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

