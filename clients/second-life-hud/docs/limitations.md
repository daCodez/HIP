# Limitations

Second Life LSL has platform limits.

- The HUD cannot reliably block all link opening behavior like a browser extension.
- Safety behavior is warning and routing guidance, not true browser-level blocking.
- HTTP requests are subject to LSL limits, throttling, and script memory constraints.
- Link parsing is best effort.
- Broken-up and obfuscated links may not always reconstruct correctly.
- Private IM scanning requires user consent and must not send full IM logs to HIP.
- Popup alerts use `llDialog`, which is optional and can be intrusive.
- The MVP activation endpoint is not a production licensing system.

Future work should add better setup-code lifecycle, production licensing integration, configurable channels, and durable HUD device registration.
