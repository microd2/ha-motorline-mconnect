from homeassistant.components.cover import CoverEntity, CoverEntityFeature

from .entity import MConnectEntity
from .models import CoverDevice


class MConnectCover(MConnectEntity, CoverEntity):
    def __init__(self, coordinator, entry, obj: CoverDevice):
        super().__init__(coordinator, entry, obj, kind="covers")
        feats = (
            CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE | CoverEntityFeature.STOP
        )
        if obj.supports_position:
            feats |= CoverEntityFeature.SET_POSITION
        self._attr_supported_features = feats

    @property
    def is_closed(self) -> bool | None:
        if self._obj.position is not None:
            return self._obj.position == 0
        return self._obj.is_closed

    @property
    def current_cover_position(self) -> int | None:
        return self._obj.position  # shows 0-100 in HA UI

    async def async_open_cover(self, **kwargs):
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "open"
        )
        if self._obj.supports_position:
            self._obj.position = 100
        self._obj.is_closed = False
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_close_cover(self, **kwargs):
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "close"
        )
        if self._obj.supports_position:
            self._obj.position = 0
        self._obj.is_closed = True
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_stop_cover(self, **kwargs):
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "stop"
        )
        await self.coordinator.async_request_refresh()

    async def async_set_cover_position(self, **kwargs):
        pos = int(kwargs.get("position"))
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "set_position", position=pos
        )
        # optimistic
        self._obj.position = pos
        self._obj.is_closed = pos == 0
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
