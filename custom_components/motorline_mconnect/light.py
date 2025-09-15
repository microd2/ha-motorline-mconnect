from __future__ import annotations

from homeassistant.components.light import LightEntity  # type: ignore

from .const import DOMAIN
from .entity import MConnectEntity
from .models import LightDevice
import time

OPTIMISTIC_WINDOW_SECONDS = 2

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    items: list[LightDevice] = coordinator.data.get("lights", [])
    async_add_entities([MConnectLight(coordinator, entry, it) for it in items])


class MConnectLight(MConnectEntity, LightEntity):
    _attr_supported_color_modes = {"onoff"}
    _attr_color_mode = "onoff"

    def __init__(self, coordinator, entry, obj: LightDevice):
        super().__init__(coordinator, entry, obj, kind="lights")
        self._optimistic_until = 0.0
        self._pending_is_on: bool | None = None #Track whether we turned the light On (True) or Off (False)



    @property
    def is_on(self) -> bool:
        if self._pending_is_on is not None and time.time() < self._optimistic_until:
           return bool(self._pending_is_on)
        # window expired → trust coordinator snapshot
        self._pending_is_on = None
        return bool(self._obj.state)

    async def async_turn_on(self, **kwargs):
        vid = getattr(self._obj, "command_value_id", None)
        await self.coordinator.async_execute_with_retry(
            self.client.async_command, self._obj.device_id, "on", value_id=vid
        )
        self._obj.state = True                    # instant UI feedback
        self._pending_is_on = True
        self._optimistic_until = time.time() + OPTIMISTIC_WINDOW_SECONDS
        if hasattr(self.coordinator, "note_recent_activity"):
           self.coordinator.note_recent_activity()

        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()




    async def async_turn_off(self, **kwargs):
        vid = getattr(self._obj, "command_value_id", None)
        await self.coordinator.async_execute_with_retry(
            self.client.async_command, self._obj.device_id, "off", value_id=vid
        )
        self._obj.state = False
        self._pending_is_on = False
        self._optimistic_until = time.time() + OPTIMISTIC_WINDOW_SECONDS
        if hasattr(self.coordinator, "note_recent_activity"):
            self.coordinator.note_recent_activity()

        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
