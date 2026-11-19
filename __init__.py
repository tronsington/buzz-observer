"""buzz-observer — kind-24200 agent observer frames from real Hermes turns.

See ``observer.py`` for the frame contract, the channel-attribution arms and the rollback
switch. This module only wires the hooks into the plugin context; it never raises into
plugin loading.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
_MODULE_NAME = "hermes_buzz_observer"


def _load() -> object:
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    existing = sys.modules.get(_MODULE_NAME)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _HERE / "observer.py")
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError("observer.py is missing from the plugin directory")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def register(ctx):
    try:
        module = _load()
        return module.register_hooks(ctx)
    except Exception:
        logger.warning("buzz-observer: could not register hooks", exc_info=True)
        return 0
