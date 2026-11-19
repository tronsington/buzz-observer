"""Kind-24200 agent observer frames from real Hermes turns.

What this is for: Buzz's per-agent *Activity* panel, the "working in #channel" badge and
(phase 1) Stop all read **agent observer frames** — ephemeral kind ``24200``, signed by the
agent key, content = NIP-44 v2 ciphertext of an ``ObserverEvent``. Hermes publishes none, so
every Hermes seat's panel is empty by construction.

Frame contract (``crates/buzz-core/src/observer.rs``, ``crates/buzz-sdk/src/builders.rs``):

    content = NIP-44 v2 to the owner of
      { "seq": 1, "timestamp": "<RFC3339>", "kind": "<kind>", "agentIndex": null,
        "channelId": "<uuid>", "sessionId": "...", "turnId": "...", "startedAt": "...",
        "payload": {...} }                      # camelCase, serde rename_all
    tags = [["p", <owner>], ["agent", <self>], ["frame", "telemetry"]]
    kind = 24200, published on a NIP-42-authenticated socket

Channel attribution — the hard part, and the reason this file exists in this shape:

  * ``post_gateway_admission`` is the ONLY hook that carries the inbound message's source
    (``source["chat_id"]``). It fires once per admitted inbound message, under the routed
    profile scope, *before* the session row exists — so its ``session_key`` usually has no
    session id yet. The pending turn is therefore parked under the session key and adopted
    by the first tool hook once ``sessions.session_key`` exists.
  * ``pre_tool_call`` / ``post_tool_call`` carry ``session_id`` and no chat id, so they
    resolve the channel from the profile's own ``state.db`` ``sessions`` row
    (``chat_id`` where ``source='buzz'``).
  * A **cron** turn has no channel at all: its session row is ``source='cron'`` with
    ``chat_id NULL`` (verified 2026-11-05 on the 07:00 UTC run). For those the channel is
    the job's delivery origin from ``cron/jobs.json`` — cron work then shows in the same
    pane, which is why the arm exists.

Rollback: ``display.platforms.buzz.observer_activity`` (default **false**) is re-read every
60 s, so flipping it to false stops all publishing within a minute without unloading the
plugin. Every publish path is wrapped: this plugin can never raise into a Hermes hook.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import nip44

logger = logging.getLogger(__name__)

FRAME_KIND = 24200
MIN_FRAME_INTERVAL = 1.0          # <= 1 frame/s (desktop archives every frame locally)
LIVENESS_INTERVAL = 10.0          # badge prunes at 25 s (LIVENESS_INTERVAL_MS * 2.5)
MAX_QUEUE = 64                    # bounded, drop-oldest
TURN_TTL = 300.0                  # forget a turn that stopped talking
CONFIG_TTL = 60.0                 # kill-switch re-read cadence

# Tool name -> ACP ``kind`` (drives the render class the desktop already has).
_TOOL_KINDS = {
    "read_file": "read", "read": "read", "search_files": "read", "web_search": "read",
    "web_extract": "read", "skill_view": "read", "skills_list": "read", "vision_analyze": "read",
    "write_file": "edit", "patch": "edit", "edit_file": "edit", "apply_patch": "edit",
    "terminal": "execute", "execute_code": "execute", "process": "execute",
    "todo_list": "plan", "delegate_task": "other",
}

_state_lock = threading.RLock()
_TURNS: Dict[str, dict] = {}          # session_id -> turn ctx (tool/lifecycle hooks)
_PENDING: Dict[str, dict] = {}        # session_key -> turn ctx awaiting its session id (admission)
_service: Optional["_Service"] = None
_config_cache: Dict[str, Any] = {"at": 0.0, "value": False}
_evidence_path: Optional[Path] = None


# ────────────────────────────── profile-scoped plumbing ──────────────────────────────


def _home() -> Path:
    from hermes_constants import get_hermes_home
    return Path(get_hermes_home())


def _secret(name: str) -> str:
    """Profile-scoped secret read.

    Never ``os.environ`` under multiplex: there it is another profile's environment. The
    process-env fallback is only taken in a single-profile process (a bare CLI run, where
    ``os.environ`` is definitionally this profile's own env).
    """
    try:
        from agent.secret_scope import get_secret
        value = get_secret(name, "")
        if isinstance(value, str) and value.strip():
            return value.strip()
    except Exception:
        pass
    try:
        from gateway.platforms._shared import get_scoped_secret
        value = get_scoped_secret(name, "")
        if isinstance(value, str) and value.strip():
            return value.strip()
    except Exception:
        pass
    try:
        from agent.secret_scope import is_multiplex_active
        if is_multiplex_active():
            return ""
    except Exception:
        return ""
    import os
    return (os.environ.get(name) or "").strip()


def _buzz_extra() -> dict:
    try:
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly() or {}
        platforms = (cfg.get("platforms") or {}).get("buzz") or {}
        extra = platforms.get("extra") or {}
        return extra if isinstance(extra, dict) else {}
    except Exception:
        return {}


def _enabled() -> bool:
    """``display.platforms.buzz.observer_activity`` — default off, re-read every 60 s."""
    now = time.monotonic()
    with _state_lock:
        if now - float(_config_cache["at"]) < CONFIG_TTL:
            return bool(_config_cache["value"])
    value = False
    raw: Any = None
    try:
        from hermes_yaml import safe_load
        cfg = safe_load((_home() / "config.yaml").read_text(encoding="utf-8")) or {}
        node = ((cfg.get("display") or {}).get("platforms") or {}).get("buzz") or {}
        raw = node.get("observer_activity", False)
        value = str(raw).strip().lower() in ("true", "1", "yes", "on")
    except Exception:
        if not _config_cache.get("warned"):
            logger.warning("buzz-observer: could not read observer_activity; staying off", exc_info=True)
            _config_cache["warned"] = True
        value = False
    with _state_lock:
        _config_cache["at"] = now
        _config_cache["value"] = value
    return value


def _evidence(message: dict) -> None:
    """Append one line to ``logs/buzz-observer-frames.jsonl`` (best effort, never raises)."""
    global _evidence_path
    try:
        if _evidence_path is None:
            _evidence_path = _home() / "logs" / "buzz-observer-frames.jsonl"
            _evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with _evidence_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(message, separators=(",", ":")) + "\n")
    except Exception:
        pass


def _rfc3339(ts: Optional[float] = None) -> str:
    when = datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc)
    return when.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _db_rows(sql: str, params: tuple) -> List[tuple]:
    try:
        db = _home() / "state.db"
        if not db.is_file():
            return []
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2.0)
        try:
            return list(con.execute(sql, params))
        finally:
            con.close()
    except Exception:
        return []


def _session_id_for_key(session_key: str) -> Optional[str]:
    if not session_key:
        return None
    rows = _db_rows("select id from sessions where session_key=? order by started_at desc limit 1",
                    (session_key,))
    return str(rows[0][0]) if rows and rows[0][0] else None


_key_cache: Dict[str, tuple] = {}   # session_id -> (monotonic, session_key)


def _session_key_for_id(session_id: str) -> Optional[str]:
    if not session_id:
        return None
    cached = _key_cache.get(session_id)
    if cached and time.monotonic() - cached[0] < 300.0:
        return cached[1]
    rows = _db_rows("select session_key from sessions where id=? limit 1", (session_id,))
    key = str(rows[0][0]) if rows and rows[0][0] else None
    if key:
        _key_cache[session_id] = (time.monotonic(), key)
        if len(_key_cache) > 256:
            _key_cache.pop(next(iter(_key_cache)))
    return key


def _buzz_channel_for_session(session_id: str) -> Optional[str]:
    rows = _db_rows("select chat_id from sessions where id=? and source='buzz' limit 1", (session_id,))
    if rows and rows[0][0]:
        return str(rows[0][0])
    return None


def _cron_channel_for_session(session_id: str) -> Optional[str]:
    """Cron turns have no channel; use the job's delivery origin (buzz only)."""
    match = re.match(r"^cron_([0-9a-f]+)_", session_id or "")
    if not match:
        return None
    try:
        raw = json.loads((_home() / "cron" / "jobs.json").read_text(encoding="utf-8"))
        jobs = raw if isinstance(raw, list) else (raw.get("jobs") or [])
        if isinstance(jobs, dict):
            jobs = list(jobs.values())
        for job in jobs:
            if str(job.get("id")) != match.group(1):
                continue
            origin = job.get("origin") or {}
            if str(origin.get("platform") or "").lower() == "buzz" and origin.get("chat_id"):
                return str(origin["chat_id"])
    except Exception:
        pass
    return None


# ────────────────────────────── turn bookkeeping ──────────────────────────────


def _new_ctx(session_id: str, channel: str, *, event_id: Optional[str] = None) -> dict:
    return {
        "sessionId": session_id,
        "channelId": channel,
        "turnId": f"hermes-{uuid.uuid4().hex[:12]}",
        "startedAt": _rfc3339(),
        "last": time.time(),
        "eventIds": [event_id] if event_id else [],
        "announced": False,
    }


def _ctx_for(session_id: str, channel: str = "") -> dict:
    """Existing ctx for a session, else adopt a pending admission, else start a new turn."""
    pending_key = _session_key_for_id(session_id)
    with _state_lock:
        ctx = _TURNS.get(session_id)
        if ctx is not None:
            if channel and not ctx.get("channelId"):
                ctx["channelId"] = channel
            ctx["last"] = time.time()
            return ctx
        if pending_key and pending_key in _PENDING:
            ctx = _PENDING.pop(pending_key)
        elif len(_PENDING) == 1:
            only_key, only_ctx = next(iter(_PENDING.items()))
            if time.time() - float(only_ctx.get("last", 0)) < 120.0:
                ctx = _PENDING.pop(only_key)
        if ctx is None:
            resolved = channel or _buzz_channel_for_session(session_id) or _cron_channel_for_session(session_id)
            if not resolved:
                return {}
            ctx = _new_ctx(session_id, resolved)
        ctx["sessionId"] = session_id
        ctx["last"] = time.time()
        _TURNS[session_id] = ctx
        return ctx


def _live_turns() -> List[dict]:
    now = time.time()
    out: List[dict] = []
    with _state_lock:
        for session_id, ctx in list(_TURNS.items()):
            if now - float(ctx.get("last", 0)) > TURN_TTL:
                _TURNS.pop(session_id, None)
                continue
            out.append(dict(ctx))
        for key, ctx in list(_PENDING.items()):
            if now - float(ctx.get("last", 0)) > TURN_TTL:
                _PENDING.pop(key, None)
    return out


def _frame(kind: str, ctx: dict, payload: dict) -> Callable[[int], dict]:
    """Return a builder so ``seq`` is assigned on the publisher loop in send order."""

    def build(seq: int) -> dict:
        return {
            "seq": seq,
            "timestamp": _rfc3339(),
            "kind": kind,
            "agentIndex": None,
            "channelId": ctx.get("channelId") or None,
            "sessionId": ctx.get("sessionId") or None,
            "turnId": ctx.get("turnId"),
            "startedAt": ctx.get("startedAt"),
            "payload": payload,
        }

    return build


def _emit(kind: str, ctx: dict, payload: dict) -> None:
    if not ctx or not ctx.get("channelId"):
        return
    svc = _service_instance()
    if svc is None:
        return
    svc.submit(_frame(kind, ctx, payload))


def _announce(ctx: dict) -> None:
    """Emit ``turn_started`` once per turn — the badge needs it, and it must precede the rows.

    Admission announces a channel turn at the top of the turn. Turns with no admission (cron,
    or an admission that arrived before the session row existed) announce on first use, which
    is why this is idempotent and lives here rather than in one hook.
    """
    if not ctx or ctx.get("announced"):
        return
    ctx["announced"] = True
    _emit("turn_started", ctx,
          {"source": "channel", "triggeringEventIds": list(ctx.get("eventIds") or [])})


def _acp_update(update: dict, session_id: str) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "session/update",
            "params": {"sessionId": session_id, "update": update}}


def _tool_title(tool_name: str, args: Any) -> str:
    """``Read: mem/agents.md`` — a title the renderer expands, without raw secret-bearing args."""
    safe_keys = ("path", "file_path", "pattern", "query", "command", "url", "goal", "skill", "name")
    detail = ""
    if isinstance(args, dict):
        for key in safe_keys:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                detail = value.strip().replace("\n", " ")[:80]
                break
    return f"{tool_name}: {detail}" if detail else tool_name


# ────────────────────────────── publisher (own loop + socket) ──────────────────────────────


class _Service:
    """One publisher per profile: dedicated thread + asyncio loop + NIP-42 socket."""

    def __init__(self, *, relay_url: str, private_key: str, auth_tag: str,
                 self_pubkey: str, owner_pubkey: str) -> None:
        self._relay = relay_url
        self._key = private_key
        self._tag = auth_tag
        self._self = self_pubkey
        self._owner = owner_pubkey
        self._conv = nip44.conversation_key(private_key, owner_pubkey)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._q: "asyncio.Queue[Callable[[int], dict]]" = asyncio.Queue()
        self._seq = 0
        self._last_send = 0.0
        self._pump_task: Optional[asyncio.Task] = None
        self._liveness_task: Optional[asyncio.Task] = None
        self._ws = None
        self._reader_task: Optional[asyncio.Task] = None
        self._connect_lock: Optional[asyncio.Lock] = None
        self._pending: Dict[str, dict] = {}
        self._sent = 0
        self._ok = 0
        self._failed = 0

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="buzz-observer", daemon=True)
        self._thread.start()
        self._ready.wait(2.0)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._connect_lock = asyncio.Lock()
        self._q = asyncio.Queue()
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                loop.close()
            except Exception:
                pass

    def submit(self, builder: Callable[[int], dict]) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(self._enqueue, builder)
        except RuntimeError:
            pass

    def _enqueue(self, builder: Callable[[int], dict]) -> None:
        while self._q.qsize() >= MAX_QUEUE:
            try:
                self._q.get_nowait()
            except asyncio.QueueEmpty:
                break
        self._q.put_nowait(builder)
        if self._pump_task is None or self._pump_task.done():
            self._pump_task = self._loop.create_task(self._pump())

    # -- pump --------------------------------------------------------------
    async def _pump(self) -> None:
        while True:
            try:
                builder = self._q.get_nowait()
            except asyncio.QueueEmpty:
                return
            delay = self._last_send + MIN_FRAME_INTERVAL - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            frame = builder(self._next_seq())
            self._last_send = time.monotonic()
            try:
                await self._send(frame)
            except Exception as exc:
                self._failed += 1
                logger.debug("buzz-observer: frame send failed: %s", exc)
                _evidence({"ts": _rfc3339(), "kind": frame.get("kind"), "seq": frame.get("seq"),
                           "channelId": frame.get("channelId"), "verdict": "send_failed",
                           "error": str(exc)[:200]})

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # -- connection --------------------------------------------------------
    async def _ensure_ws(self):
        if self._ws is not None and not getattr(self._ws, "closed", False):
            return self._ws
        import websockets

        async with self._connect_lock:
            if self._ws is not None and not getattr(self._ws, "closed", False):
                return self._ws
            ws = await websockets.connect(self._relay, max_size=None, open_timeout=15,
                                          close_timeout=5, ping_interval=20, ping_timeout=20)
            challenge = json.loads(await asyncio.wait_for(ws.recv(), 15))
            import nostr_auth
            auth_event = nostr_auth.build_auth_event(
                private_key=self._key, challenge=str(challenge[1]), relay_url=self._relay,
                auth_tag_json=self._tag,
            )
            await ws.send(json.dumps(["AUTH", auth_event], separators=(",", ":")))
            while True:
                reply = json.loads(await asyncio.wait_for(ws.recv(), 15))
                if reply[0] == "OK" and reply[1] == auth_event["id"]:
                    if reply[2] is not True:
                        raise ConnectionError(f"relay rejected AUTH: {reply[3] if len(reply) > 3 else ''}")
                    break
                if reply[0] in ("NOTICE", "CLOSED"):
                    raise ConnectionError(f"relay refused AUTH: {reply[-1]}")
            self._ws = ws
            self._reader_task = self._loop.create_task(self._reader(ws))
            logger.info("buzz-observer: publisher connected as %s…", self._self[:12])
            return ws

    async def _reader(self, ws) -> None:
        """Record the relay's per-frame verdict — the only acceptance signal that exists."""
        try:
            async for raw in ws:
                try:
                    message = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                if not isinstance(message, list) or not message:
                    continue
                if message[0] == "OK" and len(message) >= 3 and message[1] in self._pending:
                    info = self._pending.pop(message[1])
                    accepted = message[2] is True
                    self._ok += accepted
                    self._failed += (not accepted)
                    _evidence({
                        "ts": _rfc3339(), "eventId": message[1], "kind": info["kind"],
                        "seq": info["seq"], "channelId": info["channelId"],
                        "sessionId": info["sessionId"], "turnId": info["turnId"],
                        "verdict": "OK true" if accepted else "OK false",
                        "relay": str(message[3] if len(message) > 3 else "")[:200],
                    })
                elif message[0] in ("NOTICE", "CLOSED"):
                    logger.info("buzz-observer: relay %s: %s", message[0], message[-1])
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("buzz-observer: reader stopped: %s", exc)
        finally:
            if self._ws is ws:
                self._ws = None

    async def _send(self, frame: dict) -> None:
        payload = json.dumps(frame, separators=(",", ":"))
        if len(payload.encode()) > 65535:
            frame = dict(frame, payload={"truncated": True})
            payload = json.dumps(frame, separators=(",", ":"))
        ws = await self._ensure_ws()
        content = nip44.encrypt(payload, self._conv)
        import nostr_auth
        tags = [["p", self._owner], ["agent", self._self], ["frame", "telemetry"]]
        created = int(time.time())
        serialized = json.dumps([0, self._self, created, FRAME_KIND, tags, content],
                                separators=(",", ":")).encode()
        event_id = hashlib.sha256(serialized).digest()
        event = {"id": event_id.hex(), "pubkey": self._self, "created_at": created,
                 "kind": FRAME_KIND, "tags": tags, "content": content,
                 "sig": nostr_auth.schnorr_sign(event_id, self._key).hex()}
        self._pending[event["id"]] = {"kind": frame.get("kind"), "seq": frame.get("seq"),
                                      "channelId": frame.get("channelId"),
                                      "sessionId": frame.get("sessionId"),
                                      "turnId": frame.get("turnId")}
        if len(self._pending) > 256:  # a relay that never answers must not grow this
            for stale in list(self._pending)[:64]:
                self._pending.pop(stale, None)
        self._sent += 1
        await ws.send(json.dumps(["EVENT", event], separators=(",", ":")))

    # -- liveness ----------------------------------------------------------
    async def _liveness(self) -> None:
        while True:
            await asyncio.sleep(LIVENESS_INTERVAL)
            try:
                for ctx in _live_turns():
                    if ctx.get("channelId"):
                        self.submit(_frame("turn_liveness", ctx, {"status": "working"}))
            except Exception:
                logger.debug("buzz-observer: liveness tick failed", exc_info=True)

    def ensure_liveness(self) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._start_liveness)

    def _start_liveness(self) -> None:
        if self._liveness_task is None or self._liveness_task.done():
            self._liveness_task = self._loop.create_task(self._liveness())

    def stats(self) -> dict:
        return {"sent": self._sent, "ok": self._ok, "failed": self._failed,
                "seq": self._seq, "queued": self._q.qsize() if self._loop else 0}


def _service_instance() -> Optional[_Service]:
    """Lazily build the publisher for THIS profile; None when the feature is off/unconfigured."""
    global _service
    if _service is not None:
        return _service
    with _state_lock:
        if _service is not None:
            return _service
        if not _enabled():
            return None
        relay = (_secret("BUZZ_RELAY_URL") or str(_buzz_extra().get("relay_url") or "")).strip()
        key = _secret("BUZZ_PRIVATE_KEY")
        tag = _secret("BUZZ_AUTH_TAG")
        if not relay or not key or not tag:
            logger.warning("buzz-observer: observer_activity is on but relay/key/auth-tag is "
                           "incomplete; frames stay off (relay=%s key=%s tag=%s)",
                           bool(relay), bool(key), bool(tag))
            return None
        try:
            import sys
            if "/opt/hermes/plugins/platforms/buzz" not in sys.path:
                sys.path.insert(0, "/opt/hermes/plugins/platforms/buzz")
            import nostr_auth
            self_pubkey = nostr_auth.public_key_hex(key)
            owner = nostr_auth.parse_auth_tag(tag, "BUZZ_AUTH_TAG")[1]
            if not re.fullmatch(r"[0-9a-f]{64}", owner or ""):
                logger.warning("buzz-observer: unresolvable owner pubkey; frames stay off")
                return None
            relay_url = relay.replace("https://", "wss://").replace("http://", "ws://")
            service = _Service(relay_url=relay_url, private_key=key, auth_tag=tag,
                               self_pubkey=self_pubkey, owner_pubkey=owner)
            service.start()
            _service = service
            logger.info("buzz-observer: publisher up (self=%s… owner=%s… relay=%s)",
                        self_pubkey[:12], owner[:12], relay_url)
            return _service
        except Exception:
            logger.warning("buzz-observer: publisher could not start", exc_info=True)
            return None


# ────────────────────────────── hooks ──────────────────────────────


def on_post_gateway_admission(*, session_key: str = "", platform: str = "", source: Any = None,
                              message_id: str = "", text: str = "", **_kw) -> None:
    """Admitted inbound Buzz message: the only per-turn hook that carries the channel."""
    try:
        if str(platform or "").lower() != "buzz" or not _enabled():
            return
        src = source if isinstance(source, dict) else {}
        channel = str(src.get("chat_id") or "")
        if not channel:
            return
        session_id = _session_id_for_key(session_key) or session_key
        ctx = _new_ctx(session_id, channel, event_id=message_id or None)
        with _state_lock:
            # Parked under the session key until the session row exists; the first tool hook
            # adopts it once sessions.session_key is readable.
            _PENDING[session_key] = ctx
            if session_id != session_key:
                _TURNS[session_id] = ctx
        svc = _service_instance()
        if svc is None:
            return
        svc.ensure_liveness()
        ctx["announced"] = True
        payload = {"source": "channel", "triggeringEventIds": ctx["eventIds"]}
        svc.submit(_frame("turn_started", ctx, payload))
    except Exception:
        logger.debug("buzz-observer: admission hook failed", exc_info=True)


def on_pre_tool_call(*, tool_name: str = "", args: Any = None, session_id: str = "",
                     tool_call_id: str = "", turn_id: str = "", **_kw) -> None:
    try:
        if not _enabled() or not session_id:
            return
        ctx = _ctx_for(session_id)
        if not ctx:
            return
        frame = {
            "sessionUpdate": "tool_call",
            "toolCallId": str(tool_call_id or f"tc-{uuid.uuid4().hex[:8]}"),
            "title": _tool_title(tool_name, args),
            "kind": _TOOL_KINDS.get(tool_name, "other"),
            "status": "pending",
        }
        svc = _service_instance()
        if svc is None:
            return
        svc.ensure_liveness()
        _announce(ctx)
        svc.submit(_frame("acp_read", ctx, _acp_update(frame, session_id)))
    except Exception:
        logger.debug("buzz-observer: pre_tool_call hook failed", exc_info=True)


def on_post_tool_call(*, tool_name: str = "", session_id: str = "", tool_call_id: str = "",
                      result: Any = None, error: Any = None, **_kw) -> None:
    try:
        if not _enabled() or not session_id:
            return
        ctx = _ctx_for(session_id)
        if not ctx:
            return
        frame = {
            "sessionUpdate": "tool_call_update",
            "toolCallId": str(tool_call_id or ""),
            "status": "failed" if error else "completed",
        }
        svc = _service_instance()
        if svc is None:
            return
        _announce(ctx)
        svc.submit(_frame("acp_read", ctx, _acp_update(frame, session_id)))
    except Exception:
        logger.debug("buzz-observer: post_tool_call hook failed", exc_info=True)


def on_session_end(*, session_id: str = "", completed: bool = True, failed: bool = False,
                   interrupted: bool = False, **_kw) -> None:
    try:
        if not _enabled() or not session_id:
            return
        with _state_lock:
            ctx = _TURNS.pop(session_id, None)
        if not ctx:
            return
        status = "failed" if (failed or interrupted) else "completed"
        svc = _service_instance()
        if svc is None:
            return
        svc.submit(_frame("turn_completed", ctx, {"status": status}))
    except Exception:
        logger.debug("buzz-observer: on_session_end hook failed", exc_info=True)


HOOKS = (("post_gateway_admission", on_post_gateway_admission),
         ("pre_tool_call", on_pre_tool_call),
         ("post_tool_call", on_post_tool_call),
         ("on_session_end", on_session_end))


def register_hooks(ctx) -> int:
    registered = 0
    register = getattr(ctx, "register_hook", None)
    if not callable(register):
        logger.warning("buzz-observer: context has no register_hook; nothing wired")
        return 0
    for name, callback in HOOKS:
        try:
            register(name, callback)
            registered += 1
        except Exception:
            logger.warning("buzz-observer: could not register %s hook", name, exc_info=True)
    logger.info("buzz-observer: %d hook(s) registered (observer_activity=%s)",
                registered, _enabled())
    return registered
