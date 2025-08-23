"""Constants for motorline_mconnect."""

from logging import Logger, getLogger

LOGGER: Logger = getLogger(__package__)

DOMAIN = "motorline_mconnect"
ATTRIBUTION = "Data provided by http://jsonplaceholder.typicode.com/"
# Config entry keys used across the integration
CONF_EMAIL_PROVIDER = "email_provider"
CONF_EMAIL_OAUTH = "email_oauth"
CONF_MCONNECT_TOKENS = "mconnect_tokens"  # <-- required by config_flow/coordinator

# OAuth provider (Gmail only)
AUTH_DOMAIN_GMAIL = DOMAIN  # Use main domain for OAuth2

# Scopes for Gmail inbox polling
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
