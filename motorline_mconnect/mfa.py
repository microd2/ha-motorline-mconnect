"""MFA email verification for MConnect integration.

This module handles automatic extraction of MFA codes from Gmail and Outlook emails
sent by noreply@mconnect.pt during the authentication process.
"""
from __future__ import annotations

import asyncio
import base64
import re
import time
from datetime import UTC, datetime
from typing import Callable

from aiohttp import ClientError, ClientSession, ClientTimeout

# Regex to extract 6-digit codes from email content
_OTP_RE = re.compile(r"\b(\d{6})\b")
_SUBJECT_RE = re.compile(r"(Verification code|End all sessions) - (?P<code>\d{6})")


class MFAManager:
    """Manages MFA code retrieval from email providers."""
    
    def __init__(self, session: ClientSession) -> None:
        self._session = session
        self._polling = False
        self._start_time = 0.0
        
    async def wait_for_mfa_code(
        self,
        provider: str,
        oauth_tokens: dict,
        code_type: str = "verification",
        timeout: int = 300,
        poll_interval: int = 5
    ) -> str:
        """
        Wait for MFA code email and extract the 6-digit code.
        
        Args:
            provider: Email provider ("_gmail" or "_microsoft")
            oauth_tokens: OAuth tokens for email access
            code_type: "verification" or "end_all" 
            timeout: Maximum wait time in seconds (default: 5 minutes)
            poll_interval: Seconds between email checks (default: 5)
            
        Returns:
            6-digit MFA code as string
            
        Raises:
            TimeoutError: If no valid code found within timeout
            ValueError: If invalid provider or no access token
        """
        if not provider.endswith(("_gmail", "_microsoft")):
            raise ValueError(f"Unsupported provider: {provider}")
            
        access_token = self._extract_access_token(oauth_tokens)
        if not access_token:
            raise ValueError("No access token available from OAuth2 flow")
            
        self._start_time = time.time()
        deadline = time.monotonic() + timeout
        min_timestamp = self._start_time - 30  # Allow 30s skew
        
        self._polling = True
        try:
            while time.monotonic() < deadline and self._polling:
                messages = await self._list_recent_messages(provider, access_token)
                
                for msg in messages:
                    body, subject, sender, received_ts = await self._get_message_content(
                        provider, access_token, msg
                    )
                    
                    # Check if message is from MConnect and recent enough
                    if (sender.lower() == "noreply@mconnect.pt" and 
                        received_ts >= min_timestamp and
                        (time.time() - received_ts) <= 5 * 60):  # Within 5 minutes
                        
                        code = self._extract_code_from_email(body, subject, code_type)
                        if code:
                            return code
                            
                await asyncio.sleep(poll_interval)
                
        finally:
            self._polling = False
            
        raise TimeoutError(
            f"Timed out waiting for {code_type.replace('_', ' ')} email ({timeout} seconds)"
        )
    
    def stop_polling(self) -> None:
        """Stop the current MFA polling operation."""
        self._polling = False
    
    def _extract_access_token(self, oauth_tokens: dict) -> str | None:
        """Extract access token from OAuth2 token formats."""
        # OAuth2 flow format: access token directly available
        access_token = oauth_tokens.get("access_token")
        if access_token:
            return access_token
            
        # Check if token is nested in 'token' key (some OAuth implementations)
        token_data = oauth_tokens.get("token", {})
        if isinstance(token_data, dict):
            return token_data.get("access_token")
        
        return None
    
    def _extract_code_from_email(self, body: str, subject: str, code_type: str) -> str | None:
        """
        Extract MFA code from email content.
        
        Supports both subject line format: "Verification code - 123456"
        and body content extraction.
        """
        # Try subject line first (more reliable)
        subject_match = _SUBJECT_RE.search(subject or "")
        if subject_match:
            if code_type == "verification" and "verification code" in subject.lower():
                return subject_match.group("code")
            elif code_type == "end_all" and "end all sessions" in subject.lower():
                return subject_match.group("code")
        
        # Fallback to body content
        if body:
            subject_lower = (subject or "").lower()
            if code_type == "verification" and "verification code" in subject_lower:
                match = _OTP_RE.search(body)
                if match:
                    return match.group(1)
            elif code_type == "end_all" and "end all sessions" in subject_lower:
                match = _OTP_RE.search(body)
                if match:
                    return match.group(1)
        
        return None
    
    async def _list_recent_messages(self, provider: str, access_token: str) -> list[dict]:
        """List recent messages from MConnect."""
        auth_header = {"Authorization": f"Bearer {access_token}"}
        
        match provider:
            case p if p.endswith("_gmail"):
                return await self._list_gmail_messages(auth_header)
            case p if p.endswith("_microsoft"):
                return await self._list_microsoft_messages(auth_header)
            case _:
                return []
    
    async def _list_gmail_messages(self, auth_header: dict) -> list[dict]:
        """List recent Gmail messages from noreply@mconnect.pt."""
        query = 'from:noreply@mconnect.pt subject:(verification OR "end all sessions") newer_than:2d'
        url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        params = {"q": query, "maxResults": 10}
        
        try:
            async with self._session.get(
                url, headers=auth_header, params=params, timeout=ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                
            messages = []
            for msg in data.get("messages", []):
                msg_id = msg.get("id")
                if msg_id:
                    messages.append({
                        "id": msg_id,
                        "subject": "",
                        "from": "",
                        "body_preview": "",
                        "received_ts": 0,
                        "provider": "gmail"
                    })
            return messages
            
        except (ClientError, TimeoutError, asyncio.TimeoutError):
            return []
    
    async def _list_microsoft_messages(self, auth_header: dict) -> list[dict]:
        """List recent Microsoft Graph messages from noreply@mconnect.pt."""
        # Filter by sender and date, ordered by most recent first
        filter_date = datetime.fromtimestamp(self._start_time - 3600, tz=UTC).isoformat()  # 1 hour ago
        url = (
            "https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages"
            f"?$filter=receivedDateTime ge {filter_date} and "
            "from/emailAddress/address eq 'noreply@mconnect.pt'"
            "&$orderby=receivedDateTime desc&$top=10"
            "&$select=id,subject,from,bodyPreview,receivedDateTime,body"
        )
        
        try:
            async with self._session.get(
                url, headers=auth_header, timeout=ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                
            messages = []
            for item in data.get("value", []):
                subject = item.get("subject", "")
                sender = (
                    item.get("from", {})
                    .get("emailAddress", {})
                    .get("address", "")
                )
                preview = item.get("bodyPreview", "")
                received_dt = item.get("receivedDateTime", "")
                received_ts = self._parse_iso_timestamp(received_dt)
                body = preview or item.get("body", {}).get("content", "")
                
                messages.append({
                    "id": item.get("id"),
                    "subject": subject,
                    "from": sender,
                    "body_preview": body,
                    "received_ts": received_ts,
                    "provider": "microsoft"
                })
            return messages
            
        except (ClientError, TimeoutError, asyncio.TimeoutError):
            return []
    
    async def _get_message_content(
        self, provider: str, access_token: str, msg: dict
    ) -> tuple[str, str, str, int]:
        """Get full message content."""
        match provider:
            case p if p.endswith("_microsoft"):
                # Microsoft Graph already provides content in the list
                return (
                    msg.get("body_preview", ""),
                    msg.get("subject", ""),
                    msg.get("from", ""),
                    msg.get("received_ts", 0)
                )
            case p if p.endswith("_gmail"):
                return await self._get_gmail_message_content(access_token, msg)
            case _:
                return "", "", "", 0
    
    async def _get_gmail_message_content(
        self, access_token: str, msg: dict
    ) -> tuple[str, str, str, int]:
        """Get Gmail message content via Gmail API."""
        msg_id = msg.get("id")
        if not msg_id:
            return "", "", "", 0
            
        url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
        params = {"format": "full"}
        auth_header = {"Authorization": f"Bearer {access_token}"}
        
        try:
            async with self._session.get(
                url, headers=auth_header, params=params, timeout=ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    return "", "", "", 0
                data = await resp.json()
                
        except (ClientError, TimeoutError, asyncio.TimeoutError):
            return "", "", "", 0
        
        # Extract headers
        subject = ""
        sender = ""
        headers = data.get("payload", {}).get("headers", [])
        for header in headers:
            name = (header.get("name") or "").lower()
            value = header.get("value", "")
            if name == "subject":
                subject = value
            elif name == "from":
                # Extract email from "Name <email@domain.com>" format
                if "<" in value and ">" in value:
                    sender = value.split("<")[-1].split(">")[0].strip()
                else:
                    sender = value.strip()
        
        # Extract timestamp (Gmail uses milliseconds)
        internal_date_ms = int(data.get("internalDate", 0))
        received_ts = internal_date_ms // 1000 if internal_date_ms else 0
        
        # Extract body content
        body = self._extract_gmail_body(data.get("payload", {}))
        
        return body, subject, sender, received_ts
    
    def _extract_gmail_body(self, payload: dict) -> str:
        """Extract text content from Gmail message payload."""
        # Try snippet first
        snippet = payload.get("snippet", "").strip()
        if snippet:
            return snippet
            
        # Walk through MIME parts to find text content
        parts_to_check = [payload]
        
        while parts_to_check:
            part = parts_to_check.pop(0)
            mime_type = (part.get("mimeType") or "").lower()
            body = part.get("body", {})
            
            # Check if this part has text content
            if body.get("data") and ("text/plain" in mime_type or "text/html" in mime_type):
                try:
                    decoded = base64.urlsafe_b64decode(
                        body["data"].encode("utf-8")
                    ).decode("utf-8", errors="ignore")
                    if decoded.strip():
                        return decoded
                except Exception:
                    continue
            
            # Add sub-parts to check
            parts_to_check.extend(part.get("parts", []))
        
        return ""
    
    def _parse_iso_timestamp(self, iso_string: str) -> int:
        """Parse ISO timestamp to Unix epoch."""
        if not iso_string:
            return 0
        try:
            return int(
                datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
                .replace(tzinfo=UTC)
                .timestamp()
            )
        except Exception:
            return 0


async def wait_for_mfa_code(
    session: ClientSession,
    provider: str,
    oauth_tokens: dict,
    code_type: str = "verification",
    timeout: int = 300
) -> str:
    """
    Convenience function to wait for MFA code.
    
    Args:
        session: aiohttp ClientSession
        provider: Email provider ("_gmail" or "_microsoft") 
        oauth_tokens: OAuth tokens for email access
        code_type: "verification" or "end_all"
        timeout: Timeout in seconds
        
    Returns:
        6-digit MFA code
    """
    manager = MFAManager(session)
    return await manager.wait_for_mfa_code(provider, oauth_tokens, code_type, timeout)