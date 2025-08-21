from __future__ import annotations
from homeassistant.components.switch import SwitchEntity
from .const import DOMAIN
from .entity import MConnectEntity
from .models import SwitchDevice

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    items: list[SwitchDevice] = coordinator.data.get("switches", [])
    async_add_entities([MConnectSwitch(coordinator, entry, it) for it in items])

class MConnectSwitch(MConnectEntity, SwitchEntity):
    def __init__(self, coordinator, entry, obj: SwitchDevice):
        super().__init__(coordinator, entry, obj, kind="switches")

    @property
    def is_on(self) -> bool:
        return self._obj.state

    async def async_turn_on(self, **kwargs):
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "on"
        )
        self._obj.state = True  # optimistic
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs):
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "off"
        )
        self._obj.state = False
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
