# All network I/O + exception mapping. Replace the TODO parts with real endpoints/logic.

from __future__ import annotations

import asyncio
from typing import Any, Dict

from aiohttp import ClientSession, ClientError

# ----- Exceptions used by coordinator/backoff -----
class MConnectError(Exception):
    pass

class MConnectAuthError(MConnectError):
    pass  # 401 / invalid or expired tokens

class MConnectRateLimitError(MConnectError):
    pass  # 429

class MConnectServerError(MConnectError):
    pass  # 5xx

class MConnectCommError(MConnectError):
    pass  # timeouts, connection issues

from .models import DeviceMeta, SwitchDevice, LightDevice, CoverDevice


# ----- Endpoints (replace with your actual ones) -----
LOGIN_URL       = "https://api.mconnect.motorline.pt/auth/login"       # TODO: confirm
MFA_SUBMIT_URL  = "https://api.mconnect.motorline.pt/auth/verify"      # TODO: confirm
REFRESH_URL     = "https://api.mconnect.motorline.pt/auth/refresh"     # TODO: confirm
ALL_DEVICES_URL = "https://api.mconnect.motorline.pt/rooms"            # TODO: confirm
COMMAND_URL     = "https://api.mconnect.motorline.pt/device/{id}/cmd"  # TODO: confirm


class MConnectClient:
    def __init__(self, session: ClientSession) -> None:
        self._session = session

    # ---------- Login / MFA ----------
    async def async_begin_login(self, username: str, password: str) -> None:
        payload = {"username": username, "password": password}
        try:
            async with self._session.post(LOGIN_URL, json=payload, timeout=15) as resp:
                if resp.status == 401:
                    raise MConnectAuthError("Invalid credentials")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during login")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during login")
                await resp.read()
        except asyncio.TimeoutError as e:
            raise MConnectCommError("Login timeout") from e
        except ClientError as e:
            raise MConnectCommError("Login connection error") from e

    async def async_complete_login_with_mailbox(self, provider: str, oauth_tokens: dict) -> dict:
        # TODO: Implement Gmail/Graph inbox polling and OTP extraction.
        # For now this stub will fail auth to force you to wire it.
        otp = await self._async_fetch_latest_otp(provider, oauth_tokens)
        if not otp:
            raise MConnectAuthError("OTP not found")

        try:
            async with self._session.post(MFA_SUBMIT_URL, json={"otp": otp}, timeout=15) as resp:
                if resp.status == 401:
                    raise MConnectAuthError("MFA rejected")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during MFA")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during MFA")
                data = await resp.json()
        except asyncio.TimeoutError as e:
            raise MConnectCommError("MFA submit timeout") from e
        except ClientError as e:
            raise MConnectCommError("MFA submit connection error") from e

        return {
            "access": data.get("access_token"),
            "refresh": data.get("refresh_token"),
            "expires_at": data.get("expires_at"),
        }

    async def async_get_account_info(self, tokens: dict) -> dict:
        # TODO: If you have an endpoint that returns a stable account/user id, call it.
        # If not, you can return {'account_id': username} from config_flow instead.
        return {"account_id": "mconnect-account"}

    async def async_full_login_via_mailbox(self, username: str, password: str, provider: str, email_oauth: dict) -> dict:
        await self.async_begin_login(username, password)  # triggers OTP email
        return await self.async_complete_login_with_mailbox(provider=provider, oauth_tokens=email_oauth)

    # ---------- Token refresh (optional) ----------
    async def async_refresh_tokens(self, tokens: dict) -> dict:
        if not tokens or not tokens.get("refresh"):
            return tokens
        try:
            async with self._session.post(REFRESH_URL, json={"refresh_token": tokens["refresh"]}, timeout=15) as resp:
                if resp.status == 401:
                    raise MConnectAuthError("Refresh token invalid")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during refresh")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during refresh")
                data = await resp.json()
        except asyncio.TimeoutError as e:
            raise MConnectCommError("Refresh timeout") from e
        except ClientError as e:
            raise MConnectCommError("Refresh connection error") from e

        tokens.update(
            access=data.get("access_token"),
            refresh=data.get("refresh_token", tokens.get("refresh")),
            expires_at=data.get("expires_at", tokens.get("expires_at")),
        )
        return tokens

    # ---------- Snapshot fetch ----------
    async def async_fetch_all(self, tokens: dict) -> dict:
        headers = {"Authorization": f"Bearer {tokens.get('access')}", "Accept": "application/json"}
        try:
            async with self._session.get(ALL_DEVICES_URL, headers=headers, timeout=20) as resp:
                if resp.status == 401:
                    raise MConnectAuthError("Access token expired/invalid")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited (429)")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during fetch")
                data = await resp.json()
        except asyncio.TimeoutError as e:
            raise MConnectCommError("Fetch timeout") from e
        except ClientError as e:
            raise MConnectCommError("Fetch connection error") from e

        return self._map_snapshot(data)

def _iter_devices(self, vendor_json: dict):
    """
    Iterate top-level device dicts from a /rooms response.
    Supports:
      - {"rooms":[{"devices":[...]}]}
      - {"devices":[...]}
      - flat list: [ ... ]
    """
    # Flat list
    if isinstance(vendor_json, list):
        for item in vendor_json:
            if isinstance(item, dict):
                # device dict directly
                if any(k in item for k in ("id", "type", "status")):
                    yield item
                # room wrapper
                if "devices" in item and isinstance(item["devices"], list):
                    for d in item["devices"]:
                        if isinstance(d, dict):
                            yield d
        return

    # Dict root
    if not isinstance(vendor_json, dict):
        return

    rooms = vendor_json.get("rooms")
    if isinstance(rooms, list):
        for room in rooms:
            for d in (room or {}).get("devices", []):
                if isinstance(d, dict):
                    yield d

    for d in vendor_json.get("devices", []) or []:
        if isinstance(d, dict):
            yield d


def _map_snapshot(self, vendor_json: dict) -> dict:
    """
    Convert /rooms JSON into HA-friendly lists, one entity per device.

    Mapping from your dumps:
      - Switch/Light: 'status' "0"/"1"  -> off/on
        (lights are SWITCH type but icon contains 'bulb'/'lamp'/'light' in some cases)
      - Cover/Shutter: 'status' in {"0","1","2","3"} and/or values.types.OpenClose
          * If an OpenClose value with min=0 & max=100 exists, use its 0..100 'value' as position.
          * Else, use discrete status: "0"=closed, "2"=open; "1"/"3" moving (position unknown).
    """
    switches: list[SwitchDevice] = []
    lights: list[LightDevice] = []
    covers: list[CoverDevice] = []

    for dev in self._iter_devices(vendor_json):
        dev_id = str(dev.get("id") or dev.get("device_id") or dev.get("_id") or "")
        if not dev_id:
            continue

        dev_name = dev.get("name") or f"Device {dev_id}"
        dev_type = (dev.get("type") or "").lower()              # e.g. "devices.types.switch", "devices.types.shutter"
        icon = (dev.get("icon") or "").lower()                  # e.g. "bulb" for lights
        status = dev.get("status")                              # often int-like, but we normalize to str below
        values = dev.get("values") or []

        meta = DeviceMeta(
            id=dev_id,
            name=dev_name,
            manufacturer=(dev.get("product") or {}).get("manufacturer") or "Motorline",
            model=(dev.get("product") or {}).get("name") or "MConnect",
        )

        # --- helpers ---
        def resolve_onoff() -> tuple[bool, str]:
            """
            Returns (is_on, status_str) using top-level 'status' ("1"/"0").
            If a binary value exists in values[], you could read it here instead; your dumps
            show top-level 'status' is already authoritative for switch/light.
            """
            s = "1" if str(status) == "1" else "0"
            return (s == "1", s)

        def resolve_cover_position() -> int | None:
            """
            Search values[] for an OpenClose with 0..100 range and return its 'value' clamped 0..100.
            """
            for v in values:
                vtype = (v.get("type") or "").lower()
                if "values.types.openclose" in vtype or "openclose" in vtype:
                    try:
                        vmin = int(v.get("min", 0))
                        vmax = int(v.get("max", 0))
                        vval = int(v.get("value"))
                        if vmin == 0 and vmax == 100:
                            return max(0, min(100, vval))
                    except (TypeError, ValueError):
                        continue
            return None

        # --- classify device type ---
        is_cover = (
            "devices.types.shutter" in dev_type or
            "shutter" in icon or "blind" in icon
        )
        # Some lights arrive as SWITCH type but have a bulb/lamp icon
        is_light = (
            "devices.types.light" in dev_type or
            "bulb" in icon or "lamp" in icon or "light" in icon
        )

        if is_cover:
            pos = resolve_cover_position()
            st = None if status is None else str(status)
            is_closed = None

            if pos is not None:
                is_closed = (pos == 0)
            elif st is not None:
                if st == "0":  # closed
                    is_closed, pos = True, 0
                elif st == "2":  # open
                    is_closed, pos = False, 100

            covers.append(
                CoverDevice(
                    id=dev_id,
                    name=dev_name,
                    device=meta,
                    device_id=dev_id,
                    is_closed=is_closed,
                    position=pos,                # None if unknown
                    status=st,                   # "0"/"1"/"2"/"3" or None
                    supports_position=(pos is not None),
                    supports_stop=True,
                )
            )
            continue

        if is_light:
            on, st = resolve_onoff()
            lights.append(
                LightDevice(
                    id=dev_id,
                    name=dev_name,
                    device=meta,
                    device_id=dev_id,
                    state=on,
                    status=st,
                )
            )
            continue

        # Default to switch (plain on/off)
        on, st = resolve_onoff()
        switches.append(
            SwitchDevice(
                id=dev_id,
                name=dev_name,
                device=meta,
                device_id=dev_id,
                state=on,
                status=st,
            )
        )

    return {"switches": switches, "lights": lights, "covers": covers}

    # ---------- Commands ----------
async def async_command(self, tokens: dict, device_id: str, action: str, **kw) -> None:
    """
    Send a command to a device.
    action: "on", "off", "open", "close", "stop", "set_position"
    kw: extra fields (e.g. position=30)
    """
    url = f"https://api.mconnect.motorline.pt/devices/{device_id}/action"

    # This is just a skeleton — adjust to the real MConnect API body
    if action in ("on", "off"):
        body = {"action": action}
    elif action in ("open", "close", "stop"):
        body = {"action": action}
    elif action == "set_position":
        body = {"action": "set_position", "position": kw.get("position")}
    else:
        raise ValueError(f"Unknown action {action}")

    try:
        async with self._session.post(
            url, json=body, headers={"Authorization": f"Bearer {tokens['access']}"}
        ) as resp:
            if resp.status == 401:
                raise MConnectAuthError("Unauthorized")
            if resp.status != 200:
                raise MConnectCommError(f"Command {action} failed with {resp.status}")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        raise MConnectCommError(f"Command {action} failed: {e}") from e


# ---------- Mailbox OTP (stub to fill) ----------
async def _async_fetch_latest_otp(self, provider: str, oauth_tokens: dict) -> str | None:
    # TODO:
    # - If provider endswith "_gmail": call Gmail API (messages.list + messages.get),
    #   filter by sender/subject and extract OTP via regex.
    # - If endswith "_microsoft": call Graph (GET /me/messages?$top=5&$select=...),
    #   filter and extract OTP.
    # Return the OTP string, or None if not found within a short window.
    return None
