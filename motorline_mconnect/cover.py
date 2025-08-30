# custom_components/motorline_mconnect/cover.py

from __future__ import annotations

from typing import Any

from homeassistant.components.cover import (  # type: ignore
    CoverEntity,
    CoverEntityFeature,
    ATTR_POSITION,
)
from homeassistant.core import HomeAssistant  # type: ignore
from homeassistant.helpers.entity_platform import AddEntitiesCallback  # type: ignore
from homeassistant.config_entries import ConfigEntry  # type: ignore

from .const import DOMAIN
from .entity import MConnectEntity
from .models import CoverDevice


def _schedule_poke_refresh(hass, coordinator, delays=(2.0, 4.0, 4.0, 8.0, 4.0, 15.0, 30.0)):

    total = 0.0
    abs_delays = []
    for d in delays:
        total += float(d)
        abs_delays.append(total)


    for t in abs_delays:
        hass.loop.call_later(
            t,
            lambda: hass.async_create_task(
                coordinator.async_request_refresh()
            ),
        )

class MConnectCover(MConnectEntity, CoverEntity):
    """Motorline MConnect cover entity."""

    def __init__(self, coordinator, entry: ConfigEntry, obj: CoverDevice):
        super().__init__(coordinator, entry, obj, kind="covers")
        feats = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE | CoverEntityFeature.STOP
        if getattr(obj, "supports_position", False):
            feats |= CoverEntityFeature.SET_POSITION
        self._attr_supported_features = feats

    # ---------- State ----------
    @property
    def is_closed(self) -> bool | None:
        if getattr(self._obj, "position", None) is not None:
            return self._obj.position == 0
        return getattr(self._obj, "is_closed", None)

    @property
    def current_cover_position(self) -> int | None:
        return getattr(self._obj, "position", None)

    # ---------- Commands ----------
    async def async_open_cover(self, **kwargs: Any) -> None:
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "open"
        )
        # optimistic local state
        if getattr(self._obj, "supports_position", False):
            self._obj.position = 100
        self._obj.is_closed = False
        self.async_write_ha_state()

        # hint the coordinator to use the “active” cadence and poke-refresh
        self.coordinator.note_recent_activity()
        _schedule_poke_refresh(self.hass, self.coordinator)

    async def async_close_cover(self, **kwargs: Any) -> None:
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "close"
        )
        if getattr(self._obj, "supports_position", False):
            self._obj.position = 0
        self._obj.is_closed = True
        self.async_write_ha_state()

        self.coordinator.note_recent_activity()
        _schedule_poke_refresh(self.hass, self.coordinator)

    async def async_stop_cover(self, **kwargs: Any) -> None:
        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "stop"
        )
        # no position change assumed; just refresh to collapse drift
        self.coordinator.note_recent_activity()
        _schedule_poke_refresh(self.hass, self.coordinator, delays=(2.0,))

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        pos_raw = kwargs.get(ATTR_POSITION)
        if pos_raw is None:
            return  # or: raise ValueError("Missing required ATTR_POSITION")
        pos = int(pos_raw)

        await self.coordinator.async_execute_with_auth(
            self.client.async_command, self._obj.device_id, "set_position", position=pos
        )
        # optimistic local state update
        self._obj.position = pos
        self._obj.is_closed = pos == 0
        self.async_write_ha_state()

        self.coordinator.note_recent_activity()
        _schedule_poke_refresh(self.hass, self.coordinator)

# --------- REQUIRED: platform setup for config entries ---------
async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Motorline MConnect covers from a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]  # it's already the coordinator
    data = getattr(coordinator, "data", None) or {}

    covers_raw = []
    if isinstance(data, dict) and isinstance(data.get("covers"), list):
        covers_raw = data["covers"]
    elif isinstance(data, list):
        from .models import CoverDevice  # if not already imported at top
        covers_raw = [obj for obj in data if isinstance(obj, CoverDevice)]

    entities = [MConnectCover(coordinator, entry, obj) for obj in covers_raw]
    if entities:
        async_add_entities(entities, update_before_add=False)
