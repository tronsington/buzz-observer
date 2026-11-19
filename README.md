#!/bin/sh
python3 selftest.py

## Rollout

Copy this directory into a profile's `plugins/` (`/opt/data/profiles/<seat>/plugins/buzz-observer/`), add `buzz-observer` to `plugins.enabled`, then set:

```yaml
display:
  platforms:
    buzz:
      observer_activity: true
```

Kill switch: flip `observer_activity` false (re-read every 60 s). Evidence: `logs/buzz-observer-frames.jsonl`.
