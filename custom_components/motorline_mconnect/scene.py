# custom_components/motorline_mconnect/scene.py
from __future__ import annotations

from typing import Any
import hashlib

from homeassistant.core import HomeAssistant  # type: ignore
from homeassistant.config_entries import ConfigEntry  # type: ignore
from homeassistant.helpers.entity_platform import AddEntitiesCallback  # type: ignore
from homeassistant.components.scene import Scene  # type: ignore
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator  # type: ignore
from asyncio import sleep

from .const import DOMAIN, LOGGER


def _derive_scene_id(entry: ConfigEntry, scene: dict) -> str:
    """Pick a stable ID for a scene from payload fields; fallback to hashed name+home."""
    raw_id = (
        scene.get("_id")
        or scene.get("id")
        or scene.get("uuid")
        or scene.get("code")
        or scene.get("scene_id")
    )
    if raw_id:
        return str(raw_id)

    # Fallback: stable hash from entry + name + home_id
    name = scene.get("name") or "Scene"
    home_id = scene.get("home_id") or ""
    raw = f"{entry.entry_id}:{home_id}:{name}".encode()
    return hashlib.md5(raw).hexdigest()[:12]


class MConnectScene(Scene):
    _attr_icon = "mdi:play-circle"

    def __init__(self, coordinator: DataUpdateCoordinator, entry: ConfigEntry, scene: dict):
        """Scene dict should have at least 'name' and '_id' per API; we hedge with fallbacks."""
        self.coordinator = coordinator
        self.entry = entry
        self._scene = scene

        name = scene.get("name") or "Scene"
        stable_id = _derive_scene_id(entry, scene)

        self._attr_name = name
        self._attr_unique_id = f"{entry.entry_id}_scene_{stable_id}"

    @property
    def available(self) -> bool:
        # Tie availability to your coordinator/data source
        return not self.coordinator.last_update_success is False

    async def async_activate(self, **kwargs: Any) -> None:
        """Trigger the vendor scene via API."""
        client = getattr(self.coordinator, "client", None)
        scene_id = _derive_scene_id(self.entry, self._scene)
        if not client or not scene_id:
            LOGGER.error("MConnectScene: missing client or scene_id")
            return

        await self.coordinator.async_execute_with_auth(client.async_run_scene, scene_id)
        # Scenes are momentary; no state to update. Optionally refresh devices:
        await sleep(1)   # 0.5–1.0s works well in practice
        await self.coordinator.async_request_refresh()


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Motorline MConnect scenes from a config entry."""
    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    client = getattr(coordinator, "client", None)
    if not client:
        LOGGER.error("MConnect scene setup: no API client on coordinator")
        return

    # Fetch scenes via the coordinator wrapper so tokens are fresh
    scenes = await coordinator.async_execute_with_auth(client.async_list_scenes)
    scenes = scenes or []

    # Order-preserving dedupe by stable scene id
    seen: set[str] = set()
    deduped: list[dict] = []
    for s in scenes:
        sid = _derive_scene_id(entry, s)
        if sid in seen:
            continue
        seen.add(sid)
        deduped.append(s)

    prefix = ""
    entities = [
        MConnectScene(coordinator, entry, {**s, "name": f"{prefix}{s.get('name', 'Scene')}"})
        for s in deduped
    ]

    if entities:
        async_add_entities(entities, update_before_add=False)
