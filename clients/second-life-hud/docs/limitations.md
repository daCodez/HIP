# Limitations

Second Life LSL has platform limits.

- The HUD cannot reliably block all link opening behavior like a browser extension.
- Safety behavior is warning and routing guidance, not true browser-level blocking.
- A normal LSL HUD can listen to nearby/local chat on channels it registers with `llListen`.
- A normal LSL HUD cannot reliably inspect every group chat or private IM without explicit user, viewer, relay, or platform support.
- Private IM scanning must be opt-in and must never upload full IM logs by default.
- HTTP requests are subject to LSL limits, throttling, and script memory constraints.
- Link parsing is best effort.
- Broken-up and obfuscated links may not always reconstruct correctly.
- LSL cannot intercept or cancel every URL click. It can warn and route users to HIP safety pages, but it cannot enforce true blocking.
- Popup alerts use `llDialog`, which is optional and can be intrusive.
- The MVP activation endpoint is not a production licensing system.

Future work should add better setup-code lifecycle, production licensing integration, configurable channels, and durable HUD device registration.
