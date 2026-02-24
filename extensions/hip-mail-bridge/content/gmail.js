(() => {
  const BTN_CLASS = 'hip-sign-btn-gmail';
  const API_BTN_CLASS = 'hip-send-api-btn-gmail';
  const BADGE_CLASS = 'hip-trust-pill-gmail';

  function injectStyles() {
    if (document.getElementById('hip-mail-bridge-styles')) return;
    const style = document.createElement('style');
    style.id = 'hip-mail-bridge-styles';
    style.textContent = `
      .${BADGE_CLASS} {
        display:inline-flex; align-items:center; gap:6px;
        padding:4px 10px; border-radius:999px; font-size:11px; font-weight:600;
        color:#fff; cursor:default; margin-top:8px;
      }
      .${BADGE_CLASS}.ok { background:linear-gradient(90deg,#0d8a4d,#13b36a); }
      .${BADGE_CLASS}.warn { background:linear-gradient(90deg,#9b6a00,#d99b00); }
      .${BADGE_CLASS}.bad { background:linear-gradient(90deg,#8e1e1e,#cc2f2f); }
      .hip-tooltip {
        margin-top:6px; padding:8px 10px; border-radius:10px;
        background:#111827; color:#d1d5db; font-size:11px; line-height:1.4;
        border:1px solid #374151; max-width:540px;
      }
      .hip-row-chip {
        display:inline-block; margin-left:8px; padding:2px 8px;
        border-radius:999px; font-size:10px; font-weight:700;
        background:#334155; color:#e2e8f0;
      }
      .hip-row-chip.signal { background:#065f46; color:#d1fae5; }
    `;
    document.head.appendChild(style);
  }

  function findComposeBodies() {
    return Array.from(document.querySelectorAll('div[aria-label="Message Body"], div[role="textbox"][g_editable="true"]'));
  }

  function findReadableBodies() {
    const nodes = Array.from(document.querySelectorAll('div.a3s.aiL'));
    return nodes.filter(n => {
      if (!n.isConnected) return false;
      if (n.closest('[aria-hidden="true"]')) return false;
      const style = window.getComputedStyle(n);
      if (style.display === 'none' || style.visibility === 'hidden') return false;
      return true;
    });
  }

  function findInboxRows() {
    return Array.from(document.querySelectorAll('tr.zA'));
  }

  const verifyCache = new Map();

  function parseSignedMessage(text) {
    const marker = 'HIP-Signature:';
    const idx = text.indexOf(marker);
    if (idx < 0) return null;

    const after = text.slice(idx + marker.length).trim();
    const start = after.indexOf('{');
    const end = after.lastIndexOf('}');
    if (start < 0 || end < start) return null;

    try {
      return JSON.parse(after.slice(start, end + 1));
    } catch {
      return null;
    }
  }

  function getComposeTo(dialog) {
    const toInput = dialog?.querySelector('input[aria-label^="To"], textarea[name="to"]');
    return toInput?.value?.trim() || '';
  }

  function getComposeSubject(dialog) {
    const subject = dialog?.querySelector('input[name="subjectbox"]');
    return subject?.value?.trim() || '';
  }

  function makeTrustPill(state, text) {
    const pill = document.createElement('div');
    pill.className = `${BADGE_CLASS} ${state}`;
    pill.textContent = `🛡 ${text}`;
    return pill;
  }

  function makeTooltip(lines) {
    const tip = document.createElement('div');
    tip.className = 'hip-tooltip';
    for (const line of lines) {
      const row = document.createElement('div');
      row.textContent = String(line);
      tip.appendChild(row);
    }
    return tip;
  }

  async function verifyIfSigned(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipVerifyChecked === '1') return;
    if (bodyEl.querySelector(`.${BADGE_CLASS}`)) {
      bodyEl.dataset.hipVerifyChecked = '1';
      return;
    }

    const signed = parseSignedMessage(bodyEl.innerText || '');
    if (!signed || !signed.id) {
      bodyEl.dataset.hipVerifyChecked = '1';
      return;
    }

    let verdict = verifyCache.get(signed.id);
    if (!verdict) {
      const res = await chrome.runtime.sendMessage({ type: 'hip:verify', signedMessage: signed });
      verdict = {
        ok: !!(res?.ok && res?.payload?.isValid),
        reason: res?.payload?.reason || res?.error || 'unknown'
      };
      verifyCache.set(signed.id, verdict);
    }

    let pill;
    let details;
    if (verdict.ok) {
      pill = makeTrustPill('ok', 'HIP VERIFIED');
      details = makeTooltip([
        `Status: verified`,
        `Identity: ${signed.from || '-'}`,
        `Key: ${signed.keyId || '-'}`,
        `Issued: ${signed.createdAtUtc || '-'}`,
        `MessageId: ${signed.id || '-'}`
      ]);
    } else {
      const reason = verdict.reason;
      const badReason = ['replay_detected', 'message_expired', 'invalid_signature'].includes(reason);
      pill = makeTrustPill(badReason ? 'bad' : 'warn', badReason ? 'HIP RISK' : 'HIP REVIEW');
      details = makeTooltip([
        `Status: verification failed`,
        `Reason: ${reason}`,
        `Identity: ${signed.from || '-'}`,
        `Key: ${signed.keyId || '-'}`,
        `MessageId: ${signed.id || '-'}`
      ]);
    }

    bodyEl.querySelectorAll(`.${BADGE_CLASS}, .hip-tooltip`).forEach(n => n.remove());
    bodyEl.appendChild(pill);
    bodyEl.appendChild(details);
    bodyEl.dataset.hipVerifyChecked = '1';
  }

  function annotateInboxRows() {
    for (const row of findInboxRows()) {
      if (row.dataset.hipRowChecked === '1') continue;
      const snippetEl = row.querySelector('.y2');
      if (!snippetEl) {
        row.dataset.hipRowChecked = '1';
        continue;
      }

      const snippet = snippetEl.textContent || '';
      if (snippet.includes('HIP-Signature')) {
        const chip = document.createElement('span');
        chip.className = 'hip-row-chip signal';
        chip.textContent = 'HIP SIGNAL';
        snippetEl.appendChild(chip);
      }

      row.dataset.hipRowChecked = '1';
    }
  }

  function injectButtons(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipButtonAttached === '1') return;

    const dialog = bodyEl.closest('div[role="dialog"]');
    const toolbar = dialog?.querySelector('div[aria-label="More send options"]')?.parentElement;
    if (!toolbar) return;

    const signBtn = document.createElement('button');
    signBtn.textContent = 'Attach HIP Signature';
    signBtn.className = BTN_CLASS;
    Object.assign(signBtn.style, {
      marginLeft: '8px', padding: '6px 10px', borderRadius: '6px', border: '1px solid #ccc', background: '#fff', cursor: 'pointer'
    });

    signBtn.addEventListener('click', async () => {
      const plainText = bodyEl.innerText || '';
      if (!plainText.trim()) return alert('Body is empty. Add message text first.');

      const response = await chrome.runtime.sendMessage({ type: 'hip:sign', body: plainText, to: getComposeTo(dialog) });
      if (!response?.ok || !response?.payload?.success || !response?.payload?.message) {
        return alert(`HIP sign failed: ${response?.payload?.reason || response?.error || 'unknown'}`);
      }

      const signed = response.payload.message;
      bodyEl.innerText = `${plainText}\n\n---\nHIP-Signature:\n${JSON.stringify(signed, null, 2)}\n`;
      alert('HIP signature inserted in body.');
    });

    const apiBtn = document.createElement('button');
    apiBtn.textContent = 'Send via Gmail API (HIP headers)';
    apiBtn.className = API_BTN_CLASS;
    Object.assign(apiBtn.style, {
      marginLeft: '8px', padding: '6px 10px', borderRadius: '6px', border: '1px solid #0a7b32', background: '#e9f7ee', cursor: 'pointer'
    });

    apiBtn.addEventListener('click', async () => {
      const to = getComposeTo(dialog);
      const subject = getComposeSubject(dialog);
      const body = bodyEl.innerText || '';
      if (!to || !body.trim()) return alert('To and Body are required for Gmail API send.');

      const auth = await chrome.runtime.sendMessage({ type: 'hip:googleAuth' });
      if (!auth?.ok) return alert(`Google auth failed: ${auth?.error || 'unknown'}`);

      const sent = await chrome.runtime.sendMessage({ type: 'hip:gmailSendHeaderSigned', to, subject, body });
      if (!sent?.ok) return alert(`Gmail send failed: ${sent?.error || sent?.payload?.error?.message || 'unknown'}`);

      alert('Email sent via Gmail API with X-HIP-* headers.');
    });

    toolbar.appendChild(signBtn);
    toolbar.appendChild(apiBtn);
    bodyEl.dataset.hipButtonAttached = '1';
  }

  injectStyles();

  let scanScheduled = false;
  const observer = new MutationObserver(() => {
    if (scanScheduled) return;
    scanScheduled = true;
    setTimeout(() => {
      scanScheduled = false;
      findComposeBodies().forEach(injectButtons);
      findReadableBodies().forEach(verifyIfSigned);
      annotateInboxRows();
    }, 150);
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
