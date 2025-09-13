# custom_components/motorline_mconnect/models.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from typing import Literal


@dataclass(slots=True)
class DeviceMeta:
    id: str
    name: str
    manufacturer: str = "Motorline"
    model: str = "MConnect"
    room_name: Optional[str] = None   # <-- add this


@dataclass(slots=True)
class BaseDeviceEntity:
    id: str  # unique_id for HA (use vendor device id)
    name: str
    device: DeviceMeta  # for HA device registry
    device_id: str  # vendor id (same as id)


@dataclass(slots=True)
class SwitchDevice(BaseDeviceEntity):
    state: bool
    status: Literal["0", "1"]  # vendor binary as string
    command_value_id: str | None = None


@dataclass(slots=True)
class LightDevice(BaseDeviceEntity):
    state: bool
    status: Literal["0", "1"]
    command_value_id: str | None = None


@dataclass(slots=True)
class CoverDevice(BaseDeviceEntity):
    is_closed: bool | None = None
    # No percentage in your dump, so position is None
    position: int | None = None
    command_value_id: str | None = None
    travel_time_s: int | None = None   # <— add
    supports_position: bool = True   # always true for MConnect shutters

