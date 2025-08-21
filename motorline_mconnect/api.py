# All network I/O + exception mapping. Replace the TODO parts with real endpoints/logic.

from __future__ import annotations

import asyncio
import base64
import time
from datetime import UTC, datetime
from re import compile as re_compile
from typing import Literal

from aiohttp import ClientError, ClientSession, ClientTimeout

from .models import CoverDevice, DeviceMeta, LightDevice, SwitchDevice


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
_OTP_RE = re_compile(r"\b(\d{6})\b")
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
        try:
            async with self._session.post(
                url, json=payload, headers=headers, timeout=ClientTimeout(total=15)
            ) as resp:
                text = await resp.text()
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

        started_at = time.time()  # when this login attempt started

        async def _poll_for_code(kind: str) -> str:
            """
            kind: "verification" or "end_all"
            Accept only OTP emails that arrived after we started this login attempt (with small skew),
            and not older than 5 minutes.
            """
            deadline = time.monotonic() + 300  # 5 minutes
            min_ts = started_at - 30  # allow 30s skew before we pressed 'login'
            while time.monotonic() < deadline:
                # now returns (body, subject, sender, received_ts)
                body, subject, sender, received_ts = await self._fetch_latest_otp_email(
                    provider, oauth_tokens
                )
                if body:
                    subj = (subject or "").lower()
                    sndr = (sender or "").lower()
                    fresh_enough = (received_ts or 0) >= min_ts and (
                        time.time() - (received_ts or 0)
                    ) <= 5 * 60

                    if sndr == "noreply@mconnect.pt" and fresh_enough:
                        if kind == "verification" and "verification code" in subj:
                            m = _OTP_RE.search(body or "")
                            if m:
                                return m.group(1)
                        if kind == "end_all" and "end all sessions" in subj:
                            m = _OTP_RE.search(body or "")
                            if m:
                                return m.group(1)

                await asyncio.sleep(5)

            raise MConnectAuthError(
                f"Timed out waiting for {kind.replace('_', ' ')} email (5 minutes)."
            )

        # ---- 1) normal verification ----
        verif_code = await _poll_for_code("verification")
        payload = {"code": verif_code, "platform": "Win32", "model": "edge"}

        try:
            async with self._session.post(
                VERIFY_URL,
                json=payload,
                headers=headers_api,
                timeout=ClientTimeout(total=15),
            ) as resp:
                text = await resp.text()

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
                    async with self._session.get(
                        RESET_URL, headers=headers_api, timeout=ClientTimeout(total=15)
                    ) as r2:
                        if r2.status != 200:
                            raise MConnectAuthError(
                                f"Reset trigger failed: {r2.status} {await r2.text()}"
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

    async def _mail_list_messages(
        self, provider: str, oauth_tokens: dict
    ) -> list[dict]:
        """
        Return a small list of recent message stubs with consistent keys:
          [{ "id": str, "subject": str, "from": str, "body_preview": str, "received_ts": int, "has_full": bool }]
        """
        access_token = oauth_tokens.get("token", {}).get(
            "access_token"
        ) or oauth_tokens.get("access_token")
        if not access_token:
            return []
        auth = {"Authorization": f"Bearer {access_token}"}

        if provider.endswith("_gmail"):
            # Recent messages from sender + subjects of interest (last ~2 days)
            q = 'from:noreply@mconnect.pt subject:(verification OR "end all sessions") newer_than:2d'
            url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
            params = {"q": q, "maxResults": 10}
            async with self._session.get(
                url, headers=auth, params=params, timeout=ClientTimeout(total=15)
            ) as resp:
                data = await resp.json()
            msgs = []
            for m in data.get("messages") or []:
                mid = m.get("id")
                if mid:
                    # Gmail received_ts will be filled in _mail_get_message (from internalDate)
                    msgs.append(
                        {
                            "id": mid,
                            "subject": "",
                            "from": "",
                            "body_preview": "",
                            "received_ts": 0,
                            "has_full": False,
                        }
                    )
            return msgs

        if provider.endswith("_microsoft"):
            # Newest first; include receivedDateTime so we can filter by time
            url = "https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages?$top=20&$orderby=receivedDateTime desc"
            async with self._session.get(
                url, headers=auth, timeout=ClientTimeout(total=15)
            ) as resp:
                data = await resp.json()
            msgs = []
            for item in data.get("value") or []:
                subj = item.get("subject") or ""
                sender = (item.get("from", {}) or {}).get("emailAddress", {}).get(
                    "address"
                ) or ""
                preview = item.get("bodyPreview") or ""
                rts = _parse_iso_to_epoch(item.get("receivedDateTime"))
                body = preview or (item.get("body", {}) or {}).get("content") or ""
                msgs.append(
                    {
                        "id": item.get("id"),
                        "subject": subj,
                        "from": sender,
                        "body_preview": body,
                        "received_ts": rts,
                        "has_full": True,  # Graph already gave us usable content
                    }
                )
            return msgs

        return []

    async def _mail_get_message(
        self, provider: str, oauth_tokens: dict, msg_stub: dict
    ) -> tuple[str, str, str, int]:
        """
        Given one stub from _mail_list_messages, return:
            (body_text_or_html, subject, sender_email, received_ts)
        """
        access_token = oauth_tokens.get("token", {}).get(
            "access_token"
        ) or oauth_tokens.get("access_token")
        if not access_token:
            return "", "", "", 0
        auth = {"Authorization": f"Bearer {access_token}"}

        if provider.endswith("_microsoft"):
            return (
                (msg_stub.get("body_preview") or "").strip(),
                msg_stub.get("subject") or "",
                (msg_stub.get("from") or "").strip(),
                msg_stub.get("received_ts") or 0,
            )

        if provider.endswith("_gmail"):
            mid = msg_stub.get("id")
            if not mid:
                return "", "", "", 0
            url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}"
            params = {"format": "full"}
            async with self._session.get(
                url, headers=auth, params=params, timeout=ClientTimeout(total=15)
            ) as resp:
                data = await resp.json()

            # Subject + sender
            subject = ""
            sender = ""
            for h in (data.get("payload", {}) or {}).get("headers", []):
                n = (h.get("name") or "").lower()
                v = h.get("value") or ""
                if n == "subject":
                    subject = v
                elif n == "from":
                    sender = (
                        v.split("<")[-1].split(">")[0].strip()
                        if "<" in v
                        else v.strip()
                    )

            # Received timestamp from internalDate (ms since epoch)
            internal_ms = int(data.get("internalDate") or 0)
            received_ts = internal_ms // 1000 if internal_ms else 0

            # Snippet first; else walk MIME parts
            snippet = (data.get("snippet") or "").strip()
            if snippet:
                return snippet, subject, sender, received_ts

            payload = data.get("payload") or {}
            stack = [payload]
            while stack:
                p = stack.pop()
                mime = (p.get("mimeType") or "").lower()
                body = p.get("body") or {}
                data_b64 = body.get("data")
                if data_b64 and ("text/plain" in mime or "text/html" in mime):
                    decoded = base64.urlsafe_b64decode(data_b64.encode("utf-8")).decode(
                        "utf-8", errors="ignore"
                    )
                    if decoded.strip():
                        return decoded, subject, sender, received_ts
                for part in p.get("parts") or []:
                    stack.append(part)
            return "", subject, sender, received_ts

        return "", "", "", 0

    async def async_get_account_info(self, _tokens: dict) -> dict:
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

        try:
            async with self._session.get(
                ALL_DEVICES_URL, headers=headers, timeout=ClientTimeout(total=20)
            ) as resp:
                if resp.status == 401:
                    raise MConnectAuthError("Access token expired/invalid")
                if resp.status == 429:
                    raise MConnectRateLimitError("Rate limited (429)")
                if 500 <= resp.status < 600:
                    raise MConnectServerError("Server error during fetch")
                if resp.status != 200:
                    raise MConnectCommError(
                        f"Unexpected fetch status {resp.status}: {await resp.text()}"
                    )

                try:
                    data = await resp.json()
                except Exception as e:
                    # Server said 200 but body isn't JSON
                    text = await resp.text()
                    raise MConnectCommError(
                        f"Invalid JSON from fetch: {text[:200]}"
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

    # ---------- Mailbox OTP (stub to fill) ----------
    async def _fetch_latest_otp_email(
        self, provider: str, oauth_tokens: dict
    ) -> tuple[str, str, str, int]:
        """
        Returns (body, subject, sender, received_ts) of the newest relevant email.
        """
        stubs = await self._mail_list_messages(provider, oauth_tokens)
        if not stubs:
            return "", "", "", 0

        for stub in stubs:
            body, subject, sender, received_ts = await self._mail_get_message(
                provider, oauth_tokens, stub
            )
            subj_l = (subject or "").lower()
            sndr_l = (sender or "").lower()
            if sndr_l == "noreply@mconnect.pt" and (
                "verification code" in subj_l or "end all sessions" in subj_l
            ):
                return body, subject, sender, received_ts

        return "", "", "", 0

    async def async_get_homes(self, access_token: str) -> list[dict]:
        """
        Get list of homes available to this user.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"
        async with self._session.get(
            HOMES_URL, headers=headers, timeout=ClientTimeout(total=15)
        ) as resp:
            if resp.status != 200:
                raise MConnectCommError(
                    f"Failed to fetch homes: {resp.status} {await resp.text()}"
                )
            return await resp.json()

    async def async_exchange_home_token(self, access_token: str, home_id: str) -> dict:
        """
        Exchange a user access token for a home-scoped token.
        """
        headers = _build_headers(self._user_agent, self._timezone)
        headers["Authorization"] = f"Bearer {access_token}"
        payload = {"home_id": home_id}
        async with self._session.post(
            HOMES_TOKEN_URL,
            json=payload,
            headers=headers,
            timeout=ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                raise MConnectCommError(
                    f"Failed to exchange home token: {resp.status} {await resp.text()}"
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


def _parse_iso_to_epoch(iso_str: str | None) -> int:
    if not iso_str:
        return 0
    try:
        return int(
            datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            .replace(tzinfo=UTC)
            .timestamp()
        )
    except Exception:
        return 0


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
