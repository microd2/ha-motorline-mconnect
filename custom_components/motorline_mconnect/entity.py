# custom_components/motorline_mconnect/entity.py
from __future__ import annotations

from homeassistant.helpers.entity import DeviceInfo  # type: ignore
from homeassistant.helpers.update_coordinator import CoordinatorEntity  # type: ignore
from .const import DOMAIN


class MConnectEntity(CoordinatorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry, obj, *, kind: str):
        super().__init__(coordinator)
        self._entry = entry
        self._kind = kind
        self._obj = obj
        self._attr_unique_id = obj.id
        self._attr_name = f"{obj.device.room_name} {obj.name}"
        # self._attr_name = f"{obj.name}"
        self._attr_has_entity_name = False

    @property
    def client(self):
        return self.coordinator.client

    @property
    def device_info(self) -> DeviceInfo:
        return self._normalize_device_info(self._obj.device)

    def _normalize_device_info(self, meta) -> DeviceInfo:
        raw_model = (getattr(meta, "model", "") or "").lower()

        # LEFT COLUMN (short)
        if "shutter" in raw_model or "blind" in raw_model:
            model = "Shutter"
        elif "switch" in raw_model:
            model = (
                "Dual Switch" if "dual" in raw_model or "2" in raw_model else "Switch"
            )
        elif "light" in raw_model or "bulb" in raw_model or "lamp" in raw_model:
            model = "Light"
        else:
            model = "Device"

        # RIGHT COLUMN
        manufacturer = "Motorline"

        # Device label (no vendor text)
        label = (getattr(meta, "name", "") or "").strip()
        for trash in ("motorline", "mconnect"):
            if label.lower().startswith(trash):
                label = label[len(trash) :].strip(" -_")
        if not label:
            label = f"{getattr(meta, 'room_name', '')} {model}".strip()

        return DeviceInfo(
            identifiers={(DOMAIN, getattr(meta, "id", ""))},
            manufacturer=manufacturer,  # right column
            model=model,  # short left column
            name=label,
            suggested_area=getattr(meta, "room_name", None),
        )

    def _handle_coordinator_update(self) -> None:
        for item in self.coordinator.data.get(self._kind, []):
            if item.id == self._obj.id:
                # Preserve a recent optimistic state so a stale poll can't clobber it.
                if hasattr(self._obj, "state") and item.state != self._obj.state:
                    item.state = self._obj.state
                self._obj = item
                break
        self.async_write_ha_state()
