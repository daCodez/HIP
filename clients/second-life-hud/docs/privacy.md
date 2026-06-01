# Privacy

The HIP Second Life HUD is privacy-first.

It must not send:

- full public chat logs
- full private IM logs
- raw private conversations
- avatar names by default
- unrelated message text
- personal information

It may send:

- risky URL or domain
- URL hash
- sender hash
- platform: `SecondLife`
- source client: `SecondLifeHud`
- risk reason
- timestamp
- HUD device/license placeholder
- HIP signature placeholder

The current MVP script sends a short suspicious snippet only after local detection has already found a risky link signal. That snippet is for context in HIP scoring and should stay short, sanitized, and limited to the suspicious message fragment.

Private owner warnings should be clear and limited:

`HIP Warning: A message from this sender looks suspicious.`

The HUD should warn only on suspicious links, not every unknown link.

Future private IM support must preserve the same rule: report the risky URL/domain signal and sender hash when needed, not the full private conversation.
