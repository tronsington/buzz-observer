"""Offline proofs for buzz-observer: NIP-44 vectors, frame shape, rate limit, channel arms.

    /opt/hermes/.venv/bin/python selftest.py [--vectors PATH]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, "/opt/hermes")
sys.path.insert(0, "/opt/hermes/plugins/platforms/buzz")

import nip44  # noqa: E402


def _load_observer():
    spec = importlib.util.spec_from_file_location("obs_under_test", HERE / "observer.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["obs_under_test"] = module
    spec.loader.exec_module(module)
    return module


def test_vectors(path: Path) -> None:
    data = json.loads(path.read_text())["v2"]["valid"]
    bad = []

    for case in data["get_conversation_key"]:
        got = nip44.conversation_key(case["sec1"], case["pub2"]).hex()
        if got != case["conversation_key"]:
            bad.append(("get_conversation_key", case["pub2"][:16], got[:16]))

    for unpadded, padded in data["calc_padded_len"]:
        if nip44.calc_padded_len(unpadded) != padded:
            bad.append(("calc_padded_len", unpadded, nip44.calc_padded_len(unpadded)))

    for case in data["encrypt_decrypt"]:
        conv = bytes.fromhex(case["conversation_key"])
        nonce = bytes.fromhex(case["nonce"])
        got = nip44.encrypt(case["plaintext"], conv, nonce)
        if got != case["payload"]:
            bad.append(("encrypt", case["plaintext"][:12], "mismatch"))
        if nip44.decrypt(case["payload"], conv) != case["plaintext"]:
            bad.append(("decrypt", case["plaintext"][:12], "mismatch"))

    for case in data["encrypt_decrypt_long_msg"]:
        conv = bytes.fromhex(case["conversation_key"])
        nonce = bytes.fromhex(case["nonce"])
        plaintext = case["pattern"] * case["repeat"]
        import hashlib
        if hashlib.sha256(plaintext.encode()).hexdigest() != case["plaintext_sha256"]:
            bad.append(("long_plaintext", case["repeat"], "sha mismatch"))
            continue
        payload = nip44.encrypt(plaintext, conv, nonce)
        if hashlib.sha256(payload.encode()).hexdigest() != case["payload_sha256"]:
            bad.append(("long_payload", case["repeat"], "sha mismatch"))
        if nip44.decrypt(payload, conv) != plaintext:
            bad.append(("long_decrypt", case["repeat"], "mismatch"))

    counts = (len(data["get_conversation_key"]), len(data["calc_padded_len"]),
              len(data["encrypt_decrypt"]), len(data["encrypt_decrypt_long_msg"]))
    print(f"nip44: {counts[0]} conv keys, {counts[1]} padding buckets, "
          f"{counts[2]} encrypt/decrypt, {counts[3]} long — failures={len(bad)}")
    for item in bad[:10]:
        print("  FAIL", item)
    assert not bad, f"{len(bad)} NIP-44 vector failures"


class FakeService:
    def __init__(self):
        self.frames = []
        self.seq = 0
        self.submits = 0

    def submit(self, builder):
        self.submits += 1
        self.seq += 1
        self.frames.append(builder(self.seq))

    def ensure_liveness(self):
        pass

    def stats(self):
        return {"sent": len(self.frames)}


FRAME_KEYS = {"seq", "timestamp", "kind", "agentIndex", "channelId", "sessionId",
              "turnId", "startedAt", "payload"}


def test_frame_shape(obs) -> None:
    ctx = obs._new_ctx("sess-1", "afa12fb0-2876-4f18-8026-ca23ad1d8cd6", event_id="e" * 64)
    built = obs._frame("turn_started", ctx, {"source": "channel", "triggeringEventIds": ["e"]})(7)
    assert set(built) == FRAME_KEYS, set(built) ^ FRAME_KEYS
    assert built["seq"] == 7 and built["agentIndex"] is None
    text = json.dumps(built)
    assert "channel_id" not in text and "started_at" not in text and "turn_id" not in text
    assert built["channelId"] == "afa12fb0-2876-4f18-8026-ca23ad1d8cd6"
    tool = obs._acp_update({"sessionUpdate": "tool_call", "toolCallId": "tc-1",
                            "title": "read_file: mem/agents.md", "kind": "read",
                            "status": "pending"}, "sess-1")
    assert tool["params"]["update"]["sessionUpdate"] == "tool_call"
    print("frame: camelCase contract + ACP update shape OK")


def test_hooks(obs, channel: str, session_id: str) -> None:
    fake = FakeService()
    obs._service_instance = lambda: fake
    obs._enabled = lambda: True
    obs.on_post_gateway_admission(
        session_key="agent:goose:buzz:group:%s:%s" % (channel, "u" * 64),
        platform="buzz",
        source={"platform": "buzz", "chat_id": channel, "chat_type": "group",
                "user_id": "u" * 64, "thread_id": None},
        message_id="m" * 64, text="@Goose hi")
    obs.on_pre_tool_call(tool_name="read_file", args={"path": "mem/agents.md"},
                         session_id=session_id, tool_call_id="tc-1", turn_id="t-hermes")
    obs.on_post_tool_call(tool_name="read_file", session_id=session_id,
                          tool_call_id="tc-1", result="ok", error=None)
    obs.on_session_end(session_id=session_id, completed=True, failed=False, interrupted=False)
    kinds = [f["kind"] for f in fake.frames]
    assert kinds[0] == "turn_started", kinds
    assert "acp_read" in kinds and kinds[-1] == "turn_completed", kinds
    assert all(f["channelId"] == channel for f in fake.frames), [f["channelId"] for f in fake.frames]
    assert len({f["turnId"] for f in fake.frames}) == 1, "turn id must stay coherent"
    assert [f["seq"] for f in fake.frames] == list(range(1, len(fake.frames) + 1))
    assert obs._TURNS == {}, "turn must be cleared after on_session_end"
    print(f"hooks: {kinds} on channel {channel[:8]}… OK")


def test_channel_arms(obs, expect_cron: str) -> None:
    channel = obs._cron_channel_for_session("cron_102ab65ea456_20261105_070025")
    print("cron arm:", channel)
    assert channel == expect_cron, (channel, expect_cron)
    print("session arm:", obs._buzz_channel_for_session.__name__, "available")


def test_two_profiles(obs) -> None:
    """One process, two seats: each must get its own publisher, key and evidence file."""
    import tempfile
    import nostr_auth
    root = Path(tempfile.mkdtemp(prefix="obs-two-"))
    homes = {"a": root / "a", "b": root / "b"}
    keys = {"a": "11" * 32, "b": "33" * 32}
    owner = nostr_auth.public_key_hex("22" * 32)
    current = {"p": "a"}
    started = {}

    class Stub:
        def __init__(self, **kw):
            self.kw = kw
            started[kw["home"]] = kw["self_pubkey"]
        def start(self):
            pass

    obs._home = lambda: homes[current["p"]]
    obs._enabled = lambda: True
    obs._secret = lambda name: {"BUZZ_RELAY_URL": "wss://x.invalid", "BUZZ_PRIVATE_KEY": keys[current["p"]],
                                "BUZZ_AUTH_TAG": "unused"}[name]
    real_parse = nostr_auth.parse_auth_tag
    nostr_auth.parse_auth_tag = lambda tag, name: ("x", owner)
    obs._Service = Stub
    try:
        svcs = {}
        for p in ("a", "b"):
            current["p"] = p
            svcs[p] = obs._service_instance()
        assert svcs["a"] is not svcs["b"], "profiles share one publisher"
        assert svcs["a"].kw["self_pubkey"] != svcs["b"].kw["self_pubkey"], "profiles share one signing key"
        assert svcs["a"].kw["self_pubkey"] == nostr_auth.public_key_hex(keys["a"])
        current["p"] = "a"
        assert obs._service_instance() is svcs["a"], "same profile must reuse its publisher"
        for p in ("a", "b"):
            current["p"] = p
            obs._evidence({"p": p})
        for p in ("a", "b"):
            lines = (homes[p] / "logs" / "buzz-observer-frames.jsonl").read_text().splitlines()
            assert lines == [json.dumps({"p": p}, separators=(",", ":"))], (p, lines)
        # admission pending ctx of seat A must not be adopted by seat B
        current["p"] = "a"
        ctx_a = obs._new_ctx("sa", "chan-a")
        obs._PENDING["ka"] = ctx_a
        current["p"] = "b"
        assert ctx_a["home"] == str(homes["a"])
        assert all(c.get("home") != str(homes["b"]) for c in obs._live_turns(str(homes["b"])))
        obs._PENDING.clear()
        print("two-profiles: separate publishers, keys, evidence files, pending ctx — ok")
    finally:
        nostr_auth.parse_auth_tag = real_parse


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", default="/opt/data/profiles/goose/cache/scratch/nip44.vectors.json")
    ap.add_argument("--channel", default="afa12fb0-2876-4f18-8026-ca23ad1d8cd6")
    args = ap.parse_args()

    obs = _load_observer()
    test_vectors(Path(args.vectors))
    test_frame_shape(obs)
    test_channel_arms(obs, args.channel)
    test_hooks(obs, args.channel, "20261104_234002_298685f2")
    obs2 = _load_observer()
    test_rate_limit_via(obs2)
    test_two_profiles(_load_observer())
    print("ALL OFFLINE CHECKS PASSED")
    return 0


def test_rate_limit_via(obs) -> None:
    class Svc(obs._Service):
        def __init__(self):
            import nostr_auth
            key = "11" * 32
            owner_key = "22" * 32
            super().__init__(relay_url="wss://example.invalid", private_key=key,
                             auth_tag="", self_pubkey=nostr_auth.public_key_hex(key),
                             owner_pubkey=nostr_auth.public_key_hex(owner_key))
            self.sent = []

        async def _send(self, frame):
            self.sent.append((frame["seq"], time.monotonic()))

    svc = Svc()
    svc.start()
    ctx = {"channelId": "c", "sessionId": "s", "turnId": "t", "startedAt": obs._rfc3339()}
    start = time.monotonic()
    for kind in ("turn_started", "turn_liveness", "acp_read", "turn_completed"):
        svc.submit(obs._frame(kind, ctx, {"x": 1}))
    while len(svc.sent) < 4 and time.monotonic() - start < 15:
        time.sleep(0.05)
    seqs = [s for s, _ in svc.sent]
    gaps = [round(b[1] - a[1], 2) for a, b in zip(svc.sent, svc.sent[1:])]
    print(f"rate: seq={seqs} gaps={gaps} total={time.monotonic() - start:.1f}s")
    assert seqs == [1, 2, 3, 4], seqs
    assert all(g >= 0.9 for g in gaps), gaps


if __name__ == "__main__":
    raise SystemExit(main())
