# Idle probe API confirmation

macOS: 26.5.1   Date: 2026-08-17   Context: root LaunchDaemon, system domain
(launchctl bootstrap system), uid=0 confirmed in the output header.

## ioreg -c IOHIDSystem -d 4 -r  →  HIDIdleTime

Idle samples (ns), rising while the machine was untouched:
  313984333, 6708413750, 15008950416, 22622657208, 32415708250,
  39704082208, 48440220166, 57596525333, 65867149166, 73521443291, 79640845291

Active samples (ns), while typing:
  31273500, 28992791, 613656208, 232369166, 98067875

Probe cost: min 0.46s, mean 1.39s, max 2.92s (16 runs).
The identical command interactively: 0.05s. A 30x slowdown in daemon context.

VERDICT: USABLE — tracks input from a root daemon context.
