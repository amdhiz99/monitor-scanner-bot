"""Klien Telegram Bot API minimal (stdlib only, tanpa python-telegram-bot)."""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from core.settings import load_config

API_BASE = "https://api.telegram.org/bot{token}/{method}"


class TelegramError(RuntimeError):
    pass


class TelegramClient:
    def __init__(self, token: str, chat_id: str, timeout: int = 20, logger: logging.Logger | None = None):
        if not token:
            raise TelegramError("bot_token kosong")
        self.token = token
        self.chat_id = str(chat_id)
        self.timeout = timeout
        self.log = logger or logging.getLogger("telegram")

    # ------------------------------------------------------------------ core
    def call(self, method: str, payload: dict[str, Any] | None = None, http_timeout: int | None = None):
        url = API_BASE.format(token=self.token, method=method)
        data = json.dumps(payload or {}).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=http_timeout or self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            self.log.error("Telegram %s HTTP %s: %s", method, exc.code, detail)
            raise TelegramError(f"{method} gagal: HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.log.error("Telegram %s network error: %s", method, exc)
            raise TelegramError(f"{method} gagal: network {exc}") from exc
        if not body.get("ok"):
            self.log.error("Telegram %s error: %s", method, body.get("description"))
            raise TelegramError(f"{method} gagal: {body.get('description')}")
        return body.get("result")

    # --------------------------------------------------------------- helpers
    @staticmethod
    def chunk(text: str, limit: int = 3800) -> list[str]:
        """Pecah pesan panjang tanpa memotong tag HTML di tengah jalan."""
        if len(text) <= limit:
            return [text]
        chunks: list[str] = []
        current = ""
        for line in text.split("\n"):
            candidate = f"{current}\n{line}" if current else line
            if len(candidate) <= limit:
                current = candidate
                continue
            if current:
                chunks.append(current)
            if len(line) <= limit:
                current = line
            else:
                # baris tunggal super panjang: potong paksa per limit
                for i in range(0, len(line), limit):
                    chunks.append(line[i : i + limit])
                current = ""
        if current:
            chunks.append(current)
        # tutup tag <b>/<i> yang mungkin menggantung per potongan
        return [c for c in chunks if c.strip()]

    def send(self, text: str, reply_markup: dict | None = None, chunk: bool = True) -> list[int]:
        cfg = load_config()["telegram"]
        parts = self.chunk(text, int(cfg.get("chunk_size", 3800))) if chunk else [text]
        ids: list[int] = []
        for idx, part in enumerate(parts):
            payload: dict[str, Any] = {
                "chat_id": self.chat_id,
                "text": part,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
            if reply_markup and idx == len(parts) - 1:
                payload["reply_markup"] = reply_markup
            ids.append(self._send_with_retry(payload))
            if idx < len(parts) - 1:
                time.sleep(0.4)
        return ids

    def _send_with_retry(self, payload: dict, attempts: int = 3) -> int:
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                res = self.call("sendMessage", payload)
                msg_id = res.get("message_id", 0)
                self.log.info("Pesan terkirim chat=%s msg_id=%s", payload["chat_id"], msg_id)
                return msg_id
            except TelegramError as exc:
                last = exc
                # fallback: kirim tanpa parse_mode kalau HTML ditolak
                if "can't parse entities" in str(exc) and payload.get("parse_mode"):
                    payload.pop("parse_mode", None)
                    continue
                time.sleep(min(2 * attempt, 5))
        raise TelegramError(f"sendMessage gagal setelah {attempts} percobaan: {last}")

    def edit(self, message_id: int, text: str, reply_markup: dict | None = None):
        payload = {
            "chat_id": self.chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        try:
            return self.call("editMessageText", payload)
        except TelegramError as exc:
            self.log.warning("editMessageText gagal (diabaikan): %s", exc)
            return None

    def send_file(self, path: str, caption: str = "") -> None:
        """Upload dokumen pakai multipart/form-data (stdlib)."""
        boundary = "----HermesBoundary7MA4YWxkTrZu0gW"
        import pathlib

        file_bytes = pathlib.Path(path).read_bytes()
        filename = pathlib.Path(path).name
        parts: list[bytes] = []
        for key, value in (("chat_id", self.chat_id), ("caption", caption[:1000])):
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode()
            )
        parts.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
                f"filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n"
            ).encode()
        )
        parts.append(file_bytes)
        parts.append(f"\r\n--{boundary}--\r\n".encode())
        body = b"".join(parts)
        url = API_BASE.format(token=self.token, method="sendDocument")
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            self.log.error("sendDocument gagal: %s", exc)
            raise TelegramError(f"sendDocument gagal: {exc}") from exc

    # ------------------------------------------------------------ long poll
    def get_updates(self, offset: int | None = None, timeout: int = 30):
        payload: dict[str, Any] = {"timeout": timeout, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            payload["offset"] = offset
        return self.call("getUpdates", payload, http_timeout=timeout + 15)

    def answer_callback(self, callback_id: str, text: str = "") -> None:
        try:
            self.call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:200]})
        except TelegramError:
            pass
