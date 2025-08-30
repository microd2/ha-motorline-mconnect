# All network I/O + exception mapping. Replace the TODO parts with real endpoints/logic.

from __future__ import annotations

import asyncio
import json
import time
from typing import Literal

from aiohttp import ClientError, ClientSession, ClientTimeout

from .const import LOGGER

from .models import CoverDevice, DeviceMeta, LightDevice, SwitchDevice
from .mfa import wait_for_mfa_code, MailboxAuthError  # <-- import the new error

# ----- Exceptions used by coordinator/backoff -----
class MConnectError(Exception):
    pass


class MConnectAuthError(MConnectError):
    pass

class MConnectRateLimitError(MConnectError):
    def __init__(self, *args, retry_after: float | None = None):
        super().__init__(*args)
        self.retry_after = retry_after


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
HOMES_TOKEN_URL = f"{BASE_URL}/homes/auth/token"



class MConnectClient:
    # def __init__(self, session: ClientSession) -> None:
    #     self._session = session

    def __init__(self, session: ClientSession, user_agent: str, timezone: str) -> None:
        self._session = session
        self._user_agent = user_agent
        self._timezone = timezone

    def _log_api_call(self, method: str, url: str, payload: dict | None = None, headers: dict | None = None, response_status: int | None = None, response_text: str | None = None) -> None:
        return
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

    async def async_begin_login(self, username: str, password: str) -> dict:
        """
        Step 1: Initial login (triggers OTP email).
        POST /auth/token with { grant_type: "authorization", email, password, mfa: true }.
        Returns the token response {access_token, refresh_token, ...}.
        """
        self._last_username = username  # store for re-login
        self._last_password = password  # store for re-login

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
                self._log_api_call("POST", url, response_status=resp.status, response_text=text)

                if resp.status == 401:
                    raise MConnectAuthError("Invalid credentials")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during login")
                if 500 <= resp.status < 600:
                    raise MConnectServerError(f"Server error during login: {text}")
                if resp.status != 200:
                    raise MConnectCommError(f"Unexpected login status {resp.status}: {text}")

                data = await resp.json()

                # --- store tokens for later MFA verification ---
                self._user_access_token = data.get("access_token")
                self._user_refresh_token = data.get("refresh_token")
                return data

        except asyncio.TimeoutError as e:
            raise MConnectCommError("Login timeout") from e
        except ClientError as e:
            raise MConnectCommError(f"Login connection error: {e}") from e


    async def async_complete_login_with_mailbox(
        self, provider: str, oauth_tokens: dict
    ) -> dict:
        """
        End-to-end mailbox flow:

          1) Wait (≤5 min) for 'Verification code' email → extract code
          2) POST /user/mfa/verify with stored Bearer token
          3) If OK → fetch homes and exchange to home token
        """
        headers_api = _build_headers(self._user_agent, self._timezone)
        # --- include the access token from async_begin_login ---
        if getattr(self, "_user_access_token", None):
            headers_api["Authorization"] = f"Bearer {self._user_access_token}"
        headers_api["Content-Type"] = "application/json"

        async def _poll_for_code(kind: str) -> str:
            try:
                return await wait_for_mfa_code(
                    session=self._session,
                    provider=provider,
                    oauth_tokens=oauth_tokens,
                    code_type=kind,
                    timeout=300  # 5 minutes
                )
            except asyncio.TimeoutError as e:
                raise MConnectAuthError(str(e)) from e
            except MailboxAuthError as e:
                raise MConnectAuthError(f"Mailbox auth failed: {e}") from e

        # ---- 1) normal verification ----
        verif_code = await _poll_for_code("verification")
        payload = {"code": verif_code, "platform": self._user_agent, "model": "edge"}

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
                self._log_api_call("POST", VERIFY_URL, response_status=resp.status, response_text=text)

                if resp.status == 200:

                    data = await resp.json()
                    user_access = data.get("access_token") or self._user_access_token
                    user_refresh = data.get("refresh_token") or self._user_refresh_token

                    return await self.async_logIntoHome(user_access,user_refresh)

                if resp.status == 401:
                    raise MConnectAuthError("MFA rejected")

                if resp.status == 403:
                    # TOO MANY DEVICES
                     response_text = await resp.text()
                     if "MaxTrustedDevicesError" in response_text:
                        LOGGER.info(f"Max devices reached")
                        await self.async_endAllSessions(self._user_access_token)
                        LOGGER.info(f" Waiting for end all code")
                        endAllMFACode = await _poll_for_code("end_all")
                        await self.async_endAllSessionsConfirm(self._user_access_token,endAllMFACode)
                        return await self.async_logIntoHome(self._user_access_token, self._user_refresh_token)

                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited during MFA")
                if 500 <= resp.status < 600:
                    raise MConnectServerError(f"Server error during MFA: {text}")
                raise MConnectCommError(f"Unexpected MFA status {resp.status}: {text}")

        except asyncio.TimeoutError as e:
            raise MConnectCommError("MFA submit timeout") from e
        except ClientError as e:
            raise MConnectCommError(f"MFA submit connection error: {e}") from e

    async def async_get_account_info(self, tokens: dict) -> dict:
        # TODO: If you have an endpoint that returns a stable account/user id, call it.
        # If not, you can return {'account_id': username} from config_flow instead.
        return {"account_id": "mconnect-account"}

    async def async_logIntoHome(self, userLoginBearerToken : str, userLoginRefreshToken : str ) -> dict:
        LOGGER.info(f" Logging in to home")

        homes = await self.async_get_homes(userLoginBearerToken)
        guesthomes = await self.async_get_guesthomes(userLoginBearerToken)
        homes = homes + guesthomes
        if not homes:
            raise MConnectAuthError("No homes available for this account")

        LOGGER.info(f"Found {len(homes)} homes")

        home_id = homes[0].get("_id")

        if not home_id:
            raise MConnectAuthError("No valid home ID found")

        home_tokens = await self.async_exchange_home_token(
            userLoginBearerToken, home_id
        )
        home_tokens["home_id"] = home_id
        home_tokens["user_refresh"] = userLoginRefreshToken

        LOGGER.info(f" Logged in to Home")
        return home_tokens


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
                LOGIN_URL,
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
        url = f"{BASE_URL}/rooms"

        access = tokens.get("access")
        if not access:
            raise MConnectAuthError("Missing access token")

        # Reuse the exact headers we send everywhere else + add Authorization
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access}"
        headers["Accept"] = "application/json"

        # Log devices fetch request
        self._log_api_call("GET", url, headers=headers)

        try:
            async with self._session.get(url, headers=headers, timeout=ClientTimeout(total=20)) as resp:
                response_text = await resp.text()

                # Log devices fetch response
                self._log_api_call("GET", url, response_status=resp.status, response_text=response_text)

                if resp.status == 401:
                    raise MConnectAuthError("Access token expired/invalid")
                if resp.status == 429:
                    ra = resp.headers.get("Retry-After")
                    retry_after = None
                    if ra:
                        try:
                            retry_after = int(ra)
                        except ValueError:
                            retry_after = None
                    raise MConnectRateLimitError("rate limited", retry_after=retry_after)
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
                        room_name = item.get("name")  # <-- may exist here
                        for d in item["devices"]:
                            if isinstance(d, dict):
                                if room_name and "_room_name" not in d:
                                    d["_room_name"] = room_name
                                yield d
            return

        # Dict root
        if not isinstance(vendor_json, dict):
            return

        rooms = vendor_json.get("rooms")
        if isinstance(rooms, list):
            for room in rooms:
                room_name = (room or {}).get("name")   # <-- pull room name
                for d in (room or {}).get("devices", []):
                    if isinstance(d, dict):
                        if room_name and "_room_name" not in d:
                            d["_room_name"] = room_name
                        yield d

        for d in (vendor_json.get("devices", []) or []):
            if isinstance(d, dict):
                yield d

    def _map_snapshot(self, vendor_json: dict) -> dict:
            """
            Convert /rooms JSON into HA-friendly lists, one entity per device.

            Mapping from your dumps:
            - Switch/Light: On/Off is values.types.OnOff with value_id like "switch_01"/"switch_02" and 0/1 values.
            - Cover/Shutter: Open/Close is values.types.OpenClose with value_id "shutter" and 0..100.
            """

            def _first_value_id(values: list[dict], want_type: str) -> str | None:
                # Return first non-config, non-query value_id matching the given type
                want = want_type.lower()
                for v in values or []:
                    if (v.get("type") or "").lower() == want:
                        if v.get("configuration") or v.get("query_only"):
                            continue
                        vid = v.get("value_id")
                        if vid:
                            return str(vid)
                return None

            switches: list[SwitchDevice] = []
            lights: list[LightDevice] = []
            covers: list[CoverDevice] = []

            for dev in self._iter_devices(vendor_json):
                # Prefer the logical device "_id" you command against (present in your dump)
                dev_id = str(dev.get("_id") or dev.get("id") or dev.get("device_id") or "")
                if not dev_id:
                    continue

                dev_name = dev.get("name") or f"Device {dev_id}"
                dev_type = (dev.get("type") or "").lower()      # e.g. "devices.types.switch", "devices.types.shutter"
                icon = (dev.get("icon") or "").lower()          # e.g. "bulb" for lights
                status = dev.get("status")
                values = dev.get("values") or []

                meta = DeviceMeta(
                    id=dev_id,
                    name=dev_name,
                    manufacturer=(dev.get("product") or {}).get("manufacturer") or "Motorline",
                    model=(dev.get("product") or {}).get("name") or "MConnect",
                    room_name=dev.get("_room_name"),
                )

                # --- classify device type ---
                is_cover = ("devices.types.shutter" in dev_type) or ("shutter" in icon) or ("blind" in icon)
                # Some lights arrive as SWITCH type but have a bulb/lamp icon
                is_light = ("devices.types.light" in dev_type) or ("bulb" in icon) or ("lamp" in icon) or ("light" in icon)

                if is_cover:
                    pos = resolve_cover_position(values)  # your existing helper
                    st = None if status is None else str(status)
                    is_closed = None
                    if pos is not None:
                        is_closed = pos == 0
                    elif st is not None:
                        if st == "0":      # closed
                            is_closed, pos = True, 0
                        elif st == "2":    # open
                            is_closed, pos = False, 100

                    # derive the command value_id for covers from the values list (e.g., "shutter")
                    oc_id = _first_value_id(values, "values.types.openclose")

                    cover = CoverDevice(
                        id=dev_id,
                        name=dev_name,
                        device=meta,
                        device_id=dev_id,
                        is_closed=is_closed,
                        position=pos,                  # None if unknown
                        command_value_id=oc_id,        # <-- used by async_command
                    )
                    covers.append(cover)
                    continue

                if is_light:
                    on, st = resolve_onoff(status)  # your existing helper
                    # derive the command value_id for lights (e.g., "switch_01")
                    onoff_id = _first_value_id(values, "values.types.onoff")

                    light = LightDevice(
                        id=dev_id,
                        name=dev_name,
                        device=meta,
                        device_id=dev_id,
                        state=on,
                        status=st,
                        command_value_id=onoff_id,     # <-- used by async_command
                    )
                    lights.append(light)
                    continue

                # Default to switch
                on, st = resolve_onoff(status)
                onoff_id = _first_value_id(values, "values.types.onoff")

                switch = SwitchDevice(
                    id=dev_id,
                    name=dev_name,
                    device=meta,
                    device_id=dev_id,
                    state=on,
                    status=st,
                    command_value_id=onoff_id,         # <-- used by async_command
                )
                switches.append(switch)

            return {"switches": switches, "lights": lights, "covers": covers}
    # ---------- Commands ----------
    async def async_command(self, tokens: dict, device_id: str, action: str, **kw) -> None:
        """
        Send a command to a device.

        Supported actions:
        - "on", "off"        → switches/lights (values.types.OnOff, e.g. "switch_01")
        - "open", "close"    → covers/shutters (values.types.OpenClose, e.g. "shutter")
        - "set_position"     → covers with position (0..100)
        - "stop"             → send the same edge command again (see below)

        kw:
        - value_id: str      (entity passes this from .command_value_id)
        - position: int      (0..100, required for set_position)
        - direction: str     ("up" or "down", optional for stop; if absent we auto-detect)
        """
        url = f"{BASE_URL}/devices/value/{device_id}"
        value_id = kw.get("value_id")
        access = tokens.get("access")
        if not access:
            raise MConnectAuthError("Missing access token")

        # --- helpers (local) ---
        async def _post_command(body: dict) -> None:
            headers = {"Authorization": f"Bearer {access}"}
            try:
                async with self._session.post(url, json=body, headers=headers) as resp:
                    if resp.status == 401:
                        raise MConnectAuthError("Unauthorized")
                    if resp.status != 200:
                        raise MConnectCommError(f"Command {action} failed with {resp.status}")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                raise MConnectCommError(f"Command {action} failed: {e}") from e

        async def _fetch_position() -> int | None:
            """
            Read current OpenClose 'value' (0..100) for this logical device
            by scanning /rooms for this device_id and its OpenClose value_id.
            """
            rooms_url = f"{BASE_URL}/rooms"
            headers = {
                "Authorization": f"Bearer {access}",
                "Accept": "application/json",
            }
            try:
                async with self._session.get(rooms_url, headers=headers) as resp:
                    if resp.status == 401:
                        raise MConnectAuthError("Unauthorized")
                    if resp.status != 200:
                        txt = await resp.text()
                        raise MConnectCommError(f"Read state failed: {resp.status} {txt}")
                    data = await resp.json()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                raise MConnectCommError(f"Read state failed: {e}") from e

            # locate this logical device and its OpenClose value
            for room in data or []:
                for dev in room.get("devices", []):
                    dev_id_match = str(dev.get("_id") or dev.get("id") or dev.get("device_id") or "")
                    if dev_id_match != device_id:
                        continue
                    for v in dev.get("values") or []:
                        if (v.get("type") or "").lower() == "values.types.openclose":
                            # value is 0..100 according to your dump
                            return int(v.get("value")) if v.get("value") is not None else None
            return None

        # --- Switch/Light on/off ---
        if action in ("on", "off"):
            if not value_id:
                raise MConnectCommError("Missing value_id for on/off")
            body = {"value_id": value_id, "value": 1 if action == "on" else 0}
            return await _post_command(body)

        # --- Cover open/close ---
        if action == "open":
            if not value_id:
                raise MConnectCommError("Missing value_id for open")
            body = {"value_id": value_id, "value": 100}
            return await _post_command(body)

        if action == "close":
            if not value_id:
                raise MConnectCommError("Missing value_id for close")
            body = {"value_id": value_id, "value": 0}
            return await _post_command(body)

        # --- Cover set position (0..100) ---
        if action == "set_position":
            if not value_id:
                raise MConnectCommError("Missing value_id for set_position")
            pos = kw.get("position")
            if not isinstance(pos, int) or not (0 <= pos <= 100):
                raise MConnectCommError("set_position requires integer 'position' 0..100")
            body = {"value_id": value_id, "value": pos}
            return await _post_command(body)

        # --- Stop (repeat the edge command based on current movement direction) ---
        if action == "stop":
            if not value_id:
                raise MConnectCommError("Missing value_id for stop")

            # 1) If caller tells direction, trust it
            direction = kw.get("direction")
            if direction in ("up", "down"):
                edge_value = 100 if direction == "up" else 0
                body = {"value_id": value_id, "value": edge_value}
                return await _post_command(body)

            # 2) Otherwise auto-detect: sample position twice and compare
            p1 = await _fetch_position()
            if p1 is None:
                raise MConnectCommError("stop: unable to read current position (p1)")

            # short delay to let position advance a bit; tune as needed
            await asyncio.sleep(0.6)

            p2 = await _fetch_position()
            if p2 is None:
                raise MConnectCommError("stop: unable to read current position (p2)")

            if p2 > p1:
                # moving up → repeat open
                body = {"value_id": value_id, "value": 100}
                return await _post_command(body)
            elif p2 < p1:
                # moving down → repeat close
                body = {"value_id": value_id, "value": 0}
                return await _post_command(body)
            else:
                # no movement detected between samples
                raise MConnectCommError(
                    "stop: direction not detectable (position unchanged); "
                    "pass kw['direction']='up' or 'down'"
                )

        raise ValueError(f"Unknown action {action}")


    async def async_get_homes(self, access_token: str) -> list[dict]:
        """
        Get list of homes available to this user.
        """
        url = f"{BASE_URL}/homes"

        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"

        # Log homes request
        self._log_api_call("GET", url, headers=headers)

        async with self._session.get(
            url, headers=headers, timeout=ClientTimeout(total=15)
        ) as resp:
            response_text = await resp.text()

            # Log homes response
            self._log_api_call("GET", url, response_status=resp.status, response_text=response_text)

            if resp.status != 200:
                raise MConnectCommError(
                    f"Failed to fetch homes: {resp.status} {response_text}"
                )
            return await resp.json()

    async def async_get_guesthomes(self, access_token: str) -> list[dict]:
        """
        Get list of guest homes available to this user.
        """
        url = f"{BASE_URL}/guests/homes"
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"

        # Log homes request
        self._log_api_call("GET", url, headers=headers)

        async with self._session.get(
            url, headers=headers, timeout=ClientTimeout(total=15)
        ) as resp:
            response_text = await resp.text()

            # Log homes response
            self._log_api_call("GET", url, response_status=resp.status, response_text=response_text)

            if resp.status != 200:
                raise MConnectCommError(
                    f"Failed to fetch homes: {resp.status} {response_text}"
                )
            return await resp.json()



    async def async_endAllSessions(self, access_token: str) -> None:
        """
        Ask MConnect to end all logged in sessions.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"

        async with self._session.get(RESET_URL, headers=headers, timeout=ClientTimeout(total=15)) as resp:
            response_text = await resp.text()

            if resp.status != 200:
                raise MConnectCommError(f"Failed to end all sessions: {resp.status} {response_text}")


    async def async_endAllSessionsConfirm(self, access_token: str, mfaCode: str) -> None:
        """
        Complete End All Sessions MFA
        """
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"

        async with self._session.delete(RESET_CODE_URL.format(code=mfaCode), headers=headers, timeout=ClientTimeout(total=15)) as resp:
            response_text = await resp.text()

            if resp.status != 200:
                raise MConnectCommError(f"Failed to verify End All Sessions: {resp.status} {response_text}")




    async def async_exchange_home_token(self, access_token: str, home_id: str) -> dict:
        """
        Exchange a user access token for a home-scoped token.
        """
        LOGGER.info(f"Logging in to home {home_id}")

        headers = _build_headers(self._user_agent, self._timezone)
        #headers["Authorization"] = f"Bearer {access_token}"
        payload = {"grant_type":"authorization","code":access_token,"home_id": home_id}

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
            LOGIN_URL,
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
            HOMES_TOKEN_URL,
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


    async def async_list_scenes(self, tokens: dict) -> list[dict]:
        """Return list of scenes; each should include at least 'id' and 'name'."""
        access = tokens.get("access")
        if not access:
            raise MConnectAuthError("Missing access token")

        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access}"
        url = f"{BASE_URL}/scenes"

        self._log_api_call("GET", url, headers=headers)
        async with self._session.get(url, headers=headers, timeout=ClientTimeout(total=15)) as resp:
            text = await resp.text()
            self._log_api_call("GET", url, response_status=resp.status, response_text=text)

            if resp.status == 401:
                raise MConnectAuthError("Unauthorized (list scenes)")
            if resp.status == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    retry_after = float(ra) if ra is not None else None
                except ValueError:
                    retry_after = None
                raise MConnectRateLimitError("Rate limited (list scenes)", retry_after=retry_after)
            if 500 <= resp.status < 600:
                raise MConnectServerError(f"Server error during list scenes: {text}")
            if resp.status != 200:
                raise MConnectCommError(f"Failed to fetch scenes: {resp.status} {text}")

            try:
                data = await resp.json()
            except Exception as e:
                raise MConnectCommError(f"Invalid JSON from scenes: {text[:200]}") from e

            # Normalize {"scenes":[...]} → [...]
            if isinstance(data, dict) and isinstance(data.get("scenes"), list):
                return data["scenes"]
            if isinstance(data, list):
                return data
            return []

    async def async_run_scene(self, tokens: dict, scene_id: str) -> None:
        """Activate a scene by its id."""
        access = tokens.get("access")
        if not access:
            raise MConnectAuthError("Missing access token")

        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access}"
        url = f"{BASE_URL}/scenes/{scene_id}"

        self._log_api_call("POST", url, headers=headers)
        async with self._session.post(url, headers=headers, timeout=ClientTimeout(total=15)) as resp:
            text = await resp.text()
            self._log_api_call("POST", url, response_status=resp.status, response_text=text)

            if resp.status == 401:
                raise MConnectAuthError("Unauthorized (run scene)")
            if resp.status == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    retry_after = float(ra) if ra is not None else None
                except ValueError:
                    retry_after = None
                raise MConnectRateLimitError("Rate limited (run scene)", retry_after=retry_after)
            if 500 <= resp.status < 600:
                raise MConnectServerError(f"Server error during run scene: {text}")
            if resp.status not in (200, 204):
                raise MConnectCommError(f"Failed to run scene {scene_id}: {resp.status} {text}")



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

def _first_value_id(values: list[dict], want_type: str) -> str | None:
    for v in values or []:
        if (v.get("type") or "").lower() == want_type.lower():
            # Skip config/query-only entries
            if v.get("configuration") or v.get("query_only"):
                continue
            vid = v.get("value_id")
            if vid:
                return str(vid)
    return None