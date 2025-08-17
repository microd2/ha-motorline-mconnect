# custom_components/motorline_mconnect/entity.py
from __future__ import annotations
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo
from .const import DOMAIN

class MConnectEntity(CoordinatorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry, obj, *, kind: str):
        super().__init__(coordinator)
        self._entry = entry
        self._kind = kind
        self._obj = obj
        self._attr_unique_id = obj.id
        self._attr_name = obj.name

    @property
    def client(self):
        return self.coordinator.client

    @property
    def device_info(self) -> DeviceInfo:
        meta = self._obj.device
        return DeviceInfo(
            identifiers={(DOMAIN, meta.id)},
            manufacturer=meta.manufacturer,
            model=meta.model,
            name=meta.name,
        )

    def _handle_coordinator_update(self) -> None:
        for item in self.coordinator.data.get(self._kind, []):
            if item.id == self._obj.id:
                self._obj = item
                break
        self.async_write_ha_state()
