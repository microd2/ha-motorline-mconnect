# All network I/O + exception mapping. Replace the TODO parts with real endpoints/logic.

from __future__ import annotations

import asyncio
import json
import time
from typing import Literal

from aiohttp import ClientError, ClientSession, ClientTimeout

from .const import LOGGER

from .models import CoverDevice, DeviceMeta, LightDevice, SwitchDevice
from .mfa import wait_for_mfa_code


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


# ----- Endpoints (replace with your actual ones) -----
BASE_URL = "https://api.mconnect.motorline.pt"
LOGIN_URL = f"{BASE_URL}/auth/login"  # TODO: confirm
VERIFY_URL = f"{BASE_URL}/user/mfa/verify"
RESET_URL = f"{BASE_URL}/user/trusted_devices/reset"
RESET_CODE_URL = f"{BASE_URL}/user/trusted_devices/reset/{{code}}"
REMOVE_THIS_DEVICE_URL = f"{BASE_URL}/user/trusted_device"
HOMES_URL = f"{BASE_URL}/homes"
HOMES_TOKEN_URL = f"{BASE_URL}/homes/auth/token"
USER_REFRESH_URL = f"{BASE_URL}/auth/token/refresh"
HOME_REFRESH_URL = f"{BASE_URL}/homes/auth/token/refresh"
ALL_DEVICES_URL = f"{BASE_URL}/rooms"


class MConnectClient:
    # def __init__(self, session: ClientSession) -> None:
    #     self._session = session

    def __init__(self, session: ClientSession, user_agent: str, timezone: str) -> None:
        self._session = session
        self._user_agent = user_agent
        self._timezone = timezone

    def _log_api_call(self, method: str, url: str, payload: dict | None = None, headers: dict | None = None, response_status: int | None = None, response_text: str | None = None) -> None:
        """Log API calls to MConnect endpoints."""
        # Mask sensitive data
        safe_payload = payload.copy() if payload else {}
        if "password" in safe_payload:
            safe_payload["password"] = "***MASKED***"
        if "client_secret" in safe_payload:
            safe_payload["client_secret"] = "***MASKED***"
            
        safe_headers = headers.copy() if headers else {}
        if "Authorization" in safe_headers:
            safe_headers["Authorization"] = f"Bearer ***MASKED***"
            
        LOGGER.info(f"MConnect API Call: {method} {url}")
        LOGGER.info(f"  Request Headers: {json.dumps(safe_headers, indent=2)}")
        LOGGER.info(f"  Request Payload: {json.dumps(safe_payload, indent=2)}")
        
        if response_status is not None:
            LOGGER.info(f"  Response Status: {response_status}")
        if response_text is not None:
            # Truncate very long responses
            truncated_response = response_text[:1000] + "..." if len(response_text) > 1000 else response_text
            LOGGER.info(f"  Response Body: {truncated_response}")

    async def async_begin_login(self, username: str, password: str) -> None:
        # ---------- Login / MFA ----------
        """
        Step 1: Initial login (triggers OTP email).
        POST /auth/token with { grant_type: "authorization", email, password, mfa: true }.
        """
        self._last_username = username  # store for re-login
        self._last_password = password  # store for re-loginneeded

        url = f"{BASE_URL}/auth/token"
        payload = {
            "grant_type": "authorization",
            "email": username,
            "password": password,
            "mfa": True,
        }
        headers = _build_headers(self._user_agent, self._timezone)
        
        # Log the request
        self._log_api_call("POST", url, payload, headers)
        
        try:
            async with self._session.post(
                url, json=payload, headers=headers, timeout=ClientTimeout(total=15)
            ) as resp:
                text = await resp.text()
                
                # Log the response
                self._log_api_call("POST", url, response_status=resp.status, response_text=text)
                
                if resp.status == 401:
                    raise MConnectAuthError("Invalid credentials")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during login")
                if 500 <= resp.status < 600:
                    raise MConnectServerError(f"Server error during login: {text}")
                if resp.status != 200:
                    raise MConnectCommError(
                        f"Unexpected login status {resp.status}: {text}"
                    )
                await resp.read()
        except TimeoutError as e:
            raise MConnectCommError("Login timeout") from e
        except ClientError as e:
            raise MConnectCommError(f"Login connection error: {e}") from e

    async def async_complete_login_with_mailbox(
        self, provider: str, oauth_tokens: dict
    ) -> dict:
        """
        End-to-end mailbox flow:

          1) Wait (≤5 min) for 'Verification code' email → extract code
          2) POST /user/mfa/verify
             - if 200 → success
             - if 403 MaxTrustedDevicesError → run "End all sessions" reset flow
          3) GET /homes, then POST /homes/auth/token → exchange to home-scoped token
          4) Return home tokens { access, refresh, expires_in, expires_at, home_id, user_refresh }
        """
        headers_api = _build_headers(self._user_agent, self._timezone)

        async def _poll_for_code(kind: str) -> str:
            """
            kind: "verification" or "end_all"  
            Use the new MFA module for robust email polling.
            """
            try:
                return await wait_for_mfa_code(
                    session=self._session,
                    provider=provider,
                    oauth_tokens=oauth_tokens,
                    code_type=kind,
                    timeout=300  # 5 minutes
                )
            except TimeoutError as e:
                raise MConnectAuthError(str(e)) from e

        # ---- 1) normal verification ----
        verif_code = await _poll_for_code("verification")
        payload = {"code": verif_code, "platform": "Win32", "model": "edge"}

        # Log the MFA verification request
        self._log_api_call("POST", VERIFY_URL, payload, headers_api)

        try:
            async with self._session.post(
                VERIFY_URL,
                json=payload,
                headers=headers_api,
                timeout=ClientTimeout(total=15),
            ) as resp:
                text = await resp.text()
                
                # Log the MFA verification response
                self._log_api_call("POST", VERIFY_URL, response_status=resp.status, response_text=text)

                if resp.status == 200:
                    data = await resp.json()
                    user_access = data.get("access_token")
                    user_refresh = data.get("refresh_token")

                    # use class-level helpers (no duplication!)
                    homes = await self.async_get_homes(user_access)
                    if not homes:
                        raise MConnectAuthError("No homes available for this account")
                    home_id = homes[0].get("id")
                    if not home_id:
                        raise MConnectAuthError("No valid home ID found")

                    home_tokens = await self.async_exchange_home_token(
                        user_access, home_id
                    )
                    home_tokens["home_id"] = home_id
                    home_tokens["user_refresh"] = user_refresh
                    return home_tokens

                # ---- 2) Kickoff-all-sessions flow ----
                if resp.status == 403 and "MaxTrustedDevicesError" in (text or ""):
                    # Log reset trigger request
                    self._log_api_call("GET", RESET_URL, headers=headers_api)
                    
                    async with self._session.get(
                        RESET_URL, headers=headers_api, timeout=ClientTimeout(total=15)
                    ) as r2:
                        r2_text = await r2.text()
                        
                        # Log reset trigger response
                        self._log_api_call("GET", RESET_URL, response_status=r2.status, response_text=r2_text)
                        
                        if r2.status != 200:
                            raise MConnectAuthError(
                                f"Reset trigger failed: {r2.status} {r2_text}"
                            )

                    reset_code = await _poll_for_code("end_all")

                    url_del = RESET_CODE_URL.format(code=reset_code)
                    async with self._session.delete(
                        url_del, headers=headers_api, timeout=ClientTimeout(total=15)
                    ) as r3:
                        if r3.status != 200:
                            raise MConnectAuthError(
                                f"Reset confirm failed: {r3.status} {await r3.text()}"
                            )

                    async with self._session.delete(
                        REMOVE_THIS_DEVICE_URL,
                        headers=headers_api,
                        timeout=ClientTimeout(total=15),
                    ) as r4:
                        if r4.status != 200:
                            raise MConnectAuthError(
                                f"Trusted device delete failed: {r4.status} {await r4.text()}"
                            )

                    if not getattr(self, "_last_username", None) or not getattr(
                        self, "_last_password", None
                    ):
                        raise MConnectAuthError(
                            "Cannot re-login: missing stored credentials."
                        )
                    await self.async_begin_login(
                        self._last_username, self._last_password
                    )

                    verif_code = await _poll_for_code("verification")
                    payload = {"code": verif_code, "platform": "Win32", "model": "edge"}
                    async with self._session.post(
                        VERIFY_URL,
                        json=payload,
                        headers=headers_api,
                        timeout=ClientTimeout(total=15),
                    ) as r5:
                        t5 = await r5.text()
                        if r5.status != 200:
                            raise MConnectAuthError(
                                f"MFA after reset failed: {r5.status} {t5}"
                            )
                        data = await r5.json()
                        user_access = data.get("access_token")
                        user_refresh = data.get("refresh_token")

                        homes = await self.async_get_homes(user_access)
                        if not homes:
                            raise MConnectAuthError(
                                "No homes available for this account"
                            )
                        home_id = homes[0].get("id")
                        if not home_id:
                            raise MConnectAuthError("No valid home ID found")

                        home_tokens = await self.async_exchange_home_token(
                            user_access, home_id
                        )
                        home_tokens["home_id"] = home_id
                        home_tokens["user_refresh"] = user_refresh
                        return home_tokens

                if resp.status == 401:
                    raise MConnectAuthError("MFA rejected")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during MFA")
                if 500 <= resp.status < 600:
                    raise MConnectServerError(f"Server error during MFA: {text}")
                raise MConnectCommError(f"Unexpected MFA status {resp.status}: {text}")

        except TimeoutError as e:
            raise MConnectCommError("MFA submit timeout") from e
        except ClientError as e:
            raise MConnectCommError(f"MFA submit connection error: {e}") from e


    async def async_get_account_info(self, tokens: dict) -> dict:
        # TODO: If you have an endpoint that returns a stable account/user id, call it.
        # If not, you can return {'account_id': username} from config_flow instead.
        return {"account_id": "mconnect-account"}

    async def async_full_login_via_mailbox(
        self, username: str, password: str, provider: str, email_oauth: dict
    ) -> dict:
        await self.async_begin_login(username, password)  # triggers OTP email
        return await self.async_complete_login_with_mailbox(
            provider=provider, oauth_tokens=email_oauth
        )

    # ---------- Token refresh (optional) ----------
    async def async_refresh_tokens(self, tokens: dict) -> dict:
        if not tokens or not tokens.get("refresh"):
            return tokens
        try:
            async with self._session.post(
                USER_REFRESH_URL,
                json={"refresh_token": tokens["refresh"]},
                timeout=ClientTimeout(total=15),
            ) as resp:
                if resp.status == 401:
                    raise MConnectAuthError("Refresh token invalid")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during refresh")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during refresh")
                data = await resp.json()
        except TimeoutError as e:
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
        access = tokens.get("access")
        if not access:
            raise MConnectAuthError("Missing access token")

        # Reuse the exact headers we send everywhere else + add Authorization
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access}"
        headers["Accept"] = "application/json"

        # Log devices fetch request
        self._log_api_call("GET", ALL_DEVICES_URL, headers=headers)

        try:
            async with self._session.get(
                ALL_DEVICES_URL, headers=headers, timeout=ClientTimeout(total=20)
            ) as resp:
                response_text = await resp.text()
                
                # Log devices fetch response
                self._log_api_call("GET", ALL_DEVICES_URL, response_status=resp.status, response_text=response_text)
                
                if resp.status == 401:
                    raise MConnectAuthError("Access token expired/invalid")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited (429)")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during fetch")
                if resp.status != 200:
                    raise MConnectCommError(
                        f"Unexpected fetch status {resp.status}: {response_text}"
                    )

                try:
                    data = await resp.json()
                except Exception as e:
                    # Server said 200 but body isn't JSON
                    raise MConnectCommError(
                        f"Invalid JSON from fetch: {response_text[:200]}"
                    ) from e

        except TimeoutError as e:
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
            dev_type = (
                dev.get("type") or ""
            ).lower()  # e.g. "devices.types.switch", "devices.types.shutter"
            icon = (dev.get("icon") or "").lower()  # e.g. "bulb" for lights
            status = dev.get("status")  # often int-like, but we normalize to str below
            values = dev.get("values") or []

            meta = DeviceMeta(
                id=dev_id,
                name=dev_name,
                manufacturer=(dev.get("product") or {}).get("manufacturer")
                or "Motorline",
                model=(dev.get("product") or {}).get("name") or "MConnect",
            )

            # --- classify device type ---
            is_cover = (
                "devices.types.shutter" in dev_type
                or "shutter" in icon
                or "blind" in icon
            )
            # Some lights arrive as SWITCH type but have a bulb/lamp icon
            is_light = (
                "devices.types.light" in dev_type
                or "bulb" in icon
                or "lamp" in icon
                or "light" in icon
            )

            if is_cover:
                pos = resolve_cover_position(values)
                st = None if status is None else str(status)
                is_closed = None

                if pos is not None:
                    is_closed = pos == 0
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
                        position=pos,  # None if unknown
                    )
                )
                continue

            if is_light:
                on, st = resolve_onoff(status)
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
            on, st = resolve_onoff(status)
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
    async def async_command(
        self, tokens: dict, device_id: str, action: str, **kw
    ) -> None:
        """
        Send a command to a device.
        action: "on", "off", "open", "close", "stop", "set_position"
        kw: extra fields (e.g. position=30)
        """
        url = f"https://api.mconnect.motorline.pt/devices/{device_id}/action"

        # This is just a skeleton — adjust to the real MConnect API body
        if action in ("on", "off") or action in ("open", "close", "stop"):
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
                    raise MConnectCommError(
                        f"Command {action} failed with {resp.status}"
                    )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            raise MConnectCommError(f"Command {action} failed: {e}") from e


    async def async_get_homes(self, access_token: str) -> list[dict]:
        """
        Get list of homes available to this user.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"
        
        # Log homes request
        self._log_api_call("GET", HOMES_URL, headers=headers)
        
        async with self._session.get(
            HOMES_URL, headers=headers, timeout=ClientTimeout(total=15)
        ) as resp:
            response_text = await resp.text()
            
            # Log homes response
            self._log_api_call("GET", HOMES_URL, response_status=resp.status, response_text=response_text)
            
            if resp.status != 200:
                raise MConnectCommError(
                    f"Failed to fetch homes: {resp.status} {response_text}"
                )
            return await resp.json()

    async def async_exchange_home_token(self, access_token: str, home_id: str) -> dict:
        """
        Exchange a user access token for a home-scoped token.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"
        payload = {"home_id": home_id}
        
        # Log home token exchange request
        self._log_api_call("POST", HOMES_TOKEN_URL, payload, headers)
        
        async with self._session.post(
            HOMES_TOKEN_URL,
            json=payload,
            headers=headers,
            timeout=ClientTimeout(total=15),
        ) as resp:
            response_text = await resp.text()
            
            # Log home token exchange response
            self._log_api_call("POST", HOMES_TOKEN_URL, response_status=resp.status, response_text=response_text)
            
            if resp.status != 200:
                raise MConnectCommError(
                    f"Failed to exchange home token: {resp.status} {response_text}"
                )
            data = await resp.json()
            return {
                "access": data.get("access_token"),
                "refresh": data.get("refresh_token"),
                "expires_in": data.get("expires_in"),
                "expires_at": None,
            }

    async def async_refresh_user_tokens(self, refresh_token: str) -> dict:
        """
        Refresh the user-level access token.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        payload = {"refresh_token": refresh_token}
        async with self._session.post(
            USER_REFRESH_URL,
            json=payload,
            headers=headers,
            timeout=ClientTimeout(total=15),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise MConnectAuthError(
                    f"User token refresh failed: {resp.status} {text}"
                )
            data = await resp.json()
            return {
                "access": data.get("access_token"),
                "refresh": data.get("refresh_token", refresh_token),
                "expires_in": data.get("expires_in"),
                "expires_at": None,
            }

    async def async_refresh_home_tokens(self, home_id: str, refresh_token: str) -> dict:
        """
        Refresh the home-scoped access token.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        payload = {"home_id": home_id, "refresh_token": refresh_token}
        async with self._session.post(
            HOME_REFRESH_URL,
            json=payload,
            headers=headers,
            timeout=ClientTimeout(total=15),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise MConnectAuthError(
                    f"Home token refresh failed: {resp.status} {text}"
                )
            data = await resp.json()
            return {
                "access": data.get("access_token"),
                "refresh": data.get("refresh_token", refresh_token),
                "expires_in": data.get("expires_in"),
                "expires_at": None,
                "home_id": home_id,
            }


# --- Helper functions ---




def _build_headers(user_agent: str, timezone: str) -> dict[str, str]:
    """Match your C# headers, plus an explicit, honest User-Agent."""
    return {
        "Accept": "*/*",
        "Origin": "https://mconnect.pt",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "sec-ch-ua": f'"{user_agent}"',
        "sec-ch-ua-platform": '"HomeAssistant"',
        "sec-ch-ua-mobile": "?0",
        "accept-language": "en",
        "timezone": timezone,
        "User-Agent": user_agent,  # Your explicit UA: HomeAssistant-MCONNECT/<version>
    }


Status = Literal["0", "1"]


def resolve_onoff(status) -> tuple[bool, Status]:
    """
    Returns (is_on, status_str) where status_str is "1" or "0".
    """
    s: Status = "1" if str(status) == "1" else "0"
    return (s == "1", s)


def resolve_cover_position(values) -> int | None:
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
