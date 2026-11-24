from __future__ import annotations

from homeassistant.components.button import ButtonEntity  # type: ignore
from homeassistant.config_entries import ConfigEntry  # type: ignore
from homeassistant.core import HomeAssistant  # type: ignore
from homeassistant.helpers.entity_platform import AddEntitiesCallback  # type: ignore

from .const import DOMAIN
from .entity import MConnectEntity
from .models import CoverDevice

PEDESTRIAN_VALUE = 3


class MConnectPedestrianButton(MConnectEntity, ButtonEntity):
    _attr_icon = "mdi:walk"

    def __init__(self, coordinator, entry: ConfigEntry, obj: CoverDevice):
        super().__init__(coordinator, entry, obj, kind="covers")
        self._attr_unique_id = f"{obj.id}_pedestrian"
        self._attr_name = f"{self._attr_name} Pedestrian"

    async def async_press(self) -> None:
        await self.coordinator.async_execute_with_retry(
            self.client.async_command,
            self._obj.device_id,
            "set_position",
            value_id=self._obj.pedestrian_value_id,
            position=PEDESTRIAN_VALUE,
        )
        await self.coordinator.async_refresh()


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    data = getattr(coordinator, "data", None) or {}
    covers = data.get("covers", []) if isinstance(data, dict) else []

    entities = [
        MConnectPedestrianButton(coordinator, entry, obj)
        for obj in covers
        if getattr(obj, "pedestrian_value_id", None)
    ]
    if entities:
        async_add_entities(entities, update_before_add=False)
