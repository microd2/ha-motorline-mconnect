# custom_components/motorline_mconnect/cover.py

from __future__ import annotations
import asyncio

from homeassistant.components.cover import (  # type: ignore
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.core import HomeAssistant  # type: ignore
from homeassistant.helpers.entity_platform import AddEntitiesCallback  # type: ignore
from homeassistant.config_entries import ConfigEntry  # type: ignore

from .const import DOMAIN
from .entity import MConnectEntity
from .models import CoverDevice


class MConnectCover(MConnectEntity, CoverEntity):
    """Motorline MConnect cover entity."""

    def __init__(self, coordinator, entry: ConfigEntry, obj: CoverDevice):
        super().__init__(coordinator, entry, obj, kind="covers")
        feats = (
            CoverEntityFeature.OPEN
            | CoverEntityFeature.CLOSE
        )
        # Add STOP only if the device supports it
        if getattr(obj, "supports_stop", True):
            feats |= CoverEntityFeature.STOP
        # Add SET_POSITION only if the device supports it (not for gates)
        if getattr(obj, "supports_position", True):
            feats |= CoverEntityFeature.SET_POSITION
        self._attr_supported_features = feats
        self._last_target: int | None = None
        self._poke_handles: list[asyncio.TimerHandle] = []

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
    async def async_open_cover(self, **kwargs) -> None:
        vid = self._obj.command_value_id
        if not vid:
            return
        self._last_target = 100  # remember last target
        await self.coordinator.async_execute_with_retry(
            self.client.async_command,
            self._obj.device_id,
            "set_position",
            value_id=vid,
            position=100,
        )
        await self.coordinator.async_refresh()  # immediate post-command truth
        self._schedule_poke_refresh(
            _motion_delays(getattr(self._obj, "travel_time_s", None))
        )

    async def async_close_cover(self, **kwargs) -> None:
        vid = self._obj.command_value_id
        if not vid:
            return
        self._last_target = 0
        await self.coordinator.async_execute_with_retry(
            self.client.async_command,
            self._obj.device_id,
            "set_position",
            value_id=vid,
            position=0,
        )
        await self.coordinator.async_refresh()
        self._schedule_poke_refresh(
            _motion_delays(getattr(self._obj, "travel_time_s", None))
        )

    async def async_set_cover_position(self, **kwargs) -> None:
        # Only allow position setting if the device supports it
        if not getattr(self._obj, "supports_position", True):
            return

        vid = self._obj.command_value_id
        if not vid:
            return
        pos = int(kwargs["position"])
        self._last_target = pos
        await self.coordinator.async_execute_with_retry(
            self.client.async_command,
            self._obj.device_id,
            "set_position",
            value_id=vid,
            position=pos,
        )
        await self.coordinator.async_refresh()
        self._schedule_poke_refresh(
            _motion_delays(getattr(self._obj, "travel_time_s", None))
        )

    async def async_stop_cover(self, **kwargs) -> None:
        # Only allow stop if the device supports it
        if not getattr(self._obj, "supports_stop", True):
            return

        vid = self._obj.command_value_id
        if not vid:
            return

        if not getattr(self._obj, "supports_position", True):
            # For gates: send inverse position to stop movement
            # If gate was opening (target=100), send close (0) to stop
            # If gate was closing (target=0), send open (100) to stop
            stop_position = 0 if self._last_target == 100 else 100
        else:
            # For blinds/shutters: send same position (original behavior)
            stop_position = self._last_target if self._last_target is not None else 0

        await self.coordinator.async_execute_with_retry(
            self.client.async_command,
            self._obj.device_id,
            "set_position",
            value_id=vid,
            position=stop_position,
        )
        # Make the UI snap to the stopped percent
        await self.coordinator.async_refresh()
        self._schedule_poke_refresh((0.5, 1.0, 2.0))

    def _schedule_poke_refresh(self, delays: tuple[float, ...]) -> None:
        """Schedule forced refreshes at absolute offsets (seconds), cancelling any previous schedule."""
        # cancel old timers
        for h in self._poke_handles:
            try:
                h.cancel()
            except Exception:
                pass
        self._poke_handles.clear()

        # schedule new ones (absolute offsets)
        for t in delays:
            handle = self.hass.loop.call_later(
                float(t),
                lambda: self.hass.async_create_task(self.coordinator.async_refresh()),
            )
            self._poke_handles.append(handle)


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


def _motion_delays(travel_time_s: int | None) -> tuple[float, ...]:
    tt = max(int(travel_time_s or 0), 6)
    # denser at start, then every ~1–2s until end
    seq = [1.0, 2.0, 3.0, 4.0, 5.0]
    t = 6.0
    while t < tt:
        seq.append(t)
        t += 1.5 if tt <= 20 else 2.0
    # a couple of tail checks after expected end
    seq += [tt + 2.0, tt + 6.0]
    return tuple(seq)
