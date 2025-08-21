from __future__ import annotations
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.loader import async_get_integration          
from homeassistant.util import dt as dt_util    
from .const import DOMAIN
from .coordinator import MConnectCoordinator

PLATFORMS = [Platform.COVER, Platform.SWITCH, Platform.LIGHT]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:

      # Build UA from the manifest version (HACS requires this field in manifest.json)
    integration = await async_get_integration(hass, DOMAIN)     # gets manifest + version
    user_agent = f"HomeAssistant-MCONNECT/{integration.version}"
    timezone = str(dt_util.DEFAULT_TIME_ZONE)

    coordinator = MConnectCoordinator(
        hass,
        entry,
        user_agent=user_agent,                                   #pass UA
        timezone=timezone,                                       #pass HA timezone
    )

    
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok

async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
