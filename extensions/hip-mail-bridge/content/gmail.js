(() => {
  const BTN_CLASS = 'hip-sign-btn-gmail';
  const API_BTN_CLASS = 'hip-send-api-btn-gmail';
  const BADGE_CLASS = 'hip-verify-badge-gmail';

  function findComposeBodies() {
    return Array.from(document.querySelectorAll('div[aria-label="Message Body"], div[role="textbox"][g_editable="true"]'));
  }

  function findReadableBodies() {
    return Array.from(document.querySelectorAll('div.a3s.aiL, div[role="listitem"] div[dir="ltr"]'));
  }

  function parseSignedMessage(text) {
    const marker = 'HIP-Signature:';
    const idx = text.indexOf(marker);
    if (idx < 0) return null;

    const after = text.slice(idx + marker.length).trim();
    const start = after.indexOf('{');
    const end = after.lastIndexOf('}');
    if (start < 0 || end < start) return null;

    const jsonText = after.slice(start, end + 1);
    try {
      return JSON.parse(jsonText);
    } catch {
      return null;
    }
  }

  function makeBadge(text, color) {
    const badge = document.createElement('div');
    badge.className = BADGE_CLASS;
    badge.textContent = text;
    badge.style.marginTop = '8px';
    badge.style.padding = '6px 10px';
    badge.style.borderRadius = '6px';
    badge.style.background = color;
    badge.style.color = '#fff';
    badge.style.fontSize = '12px';
    badge.style.display = 'inline-block';
    return badge;
  }

  function getComposeTo(dialog) {
    const toInput = dialog?.querySelector('input[aria-label^="To"], textarea[name="to"]');
    return toInput?.value?.trim() || '';
  }

  function getComposeSubject(dialog) {
    const subject = dialog?.querySelector('input[name="subjectbox"]');
    return subject?.value?.trim() || '';
  }

  async function verifyIfSigned(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipVerifyChecked === '1') return;
    const text = bodyEl.innerText || '';
    const signed = parseSignedMessage(text);
    if (!signed) {
      bodyEl.dataset.hipVerifyChecked = '1';
      return;
    }

    const res = await chrome.runtime.sendMessage({ type: 'hip:verify', signedMessage: signed });
    let badge;
    if (res?.ok && res?.payload?.isValid) {
      badge = makeBadge('✅ Verified by HIP', '#0a7b32');
    } else {
      const reason = res?.payload?.reason || res?.error || 'unknown';
      badge = makeBadge(`❌ HIP verify failed (${reason})`, '#b32727');
    }

    bodyEl.appendChild(badge);
    bodyEl.dataset.hipVerifyChecked = '1';
  }

  function injectButtons(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipButtonAttached === '1') return;

    const dialog = bodyEl.closest('div[role="dialog"]');
    const toolbar = dialog?.querySelector('div[aria-label="More send options"]')?.parentElement;
    if (!toolbar) return;

    const signBtn = document.createElement('button');
    signBtn.textContent = 'Attach HIP Signature';
    signBtn.className = BTN_CLASS;
    signBtn.style.marginLeft = '8px';
    signBtn.style.padding = '6px 10px';
    signBtn.style.borderRadius = '6px';
    signBtn.style.border = '1px solid #ccc';
    signBtn.style.background = '#fff';
    signBtn.style.cursor = 'pointer';

    signBtn.addEventListener('click', async () => {
      const plainText = bodyEl.innerText || '';
      if (!plainText.trim()) {
        alert('Body is empty. Add message text first.');
        return;
      }

      const response = await chrome.runtime.sendMessage({ type: 'hip:sign', body: plainText, to: getComposeTo(dialog) });
      if (!response?.ok || !response?.payload?.success || !response?.payload?.message) {
        alert(`HIP sign failed: ${response?.payload?.reason || response?.error || 'unknown'}`);
        return;
      }

      const signed = response.payload.message;
      const stamp = `\n\n---\nHIP-Signature:\n${JSON.stringify(signed, null, 2)}\n`;
      bodyEl.innerText = plainText + stamp;
      alert('HIP signature inserted in body.');
    });

    const apiBtn = document.createElement('button');
    apiBtn.textContent = 'Send via Gmail API (HIP headers)';
    apiBtn.className = API_BTN_CLASS;
    apiBtn.style.marginLeft = '8px';
    apiBtn.style.padding = '6px 10px';
    apiBtn.style.borderRadius = '6px';
    apiBtn.style.border = '1px solid #0a7b32';
    apiBtn.style.background = '#e9f7ee';
    apiBtn.style.cursor = 'pointer';

    apiBtn.addEventListener('click', async () => {
      const to = getComposeTo(dialog);
      const subject = getComposeSubject(dialog);
      const body = bodyEl.innerText || '';

      if (!to || !body.trim()) {
        alert('To and Body are required for Gmail API send.');
        return;
      }

      const auth = await chrome.runtime.sendMessage({ type: 'hip:googleAuth' });
      if (!auth?.ok) {
        alert(`Google auth failed: ${auth?.error || 'unknown'}`);
        return;
      }

      const sent = await chrome.runtime.sendMessage({ type: 'hip:gmailSendHeaderSigned', to, subject, body });
      if (!sent?.ok) {
        alert(`Gmail send failed: ${sent?.error || sent?.payload?.error?.message || 'unknown'}`);
        return;
      }

      alert('Email sent via Gmail API with X-HIP-* headers.');
    });

    toolbar.appendChild(signBtn);
    toolbar.appendChild(apiBtn);
    bodyEl.dataset.hipButtonAttached = '1';
  }

  const observer = new MutationObserver(() => {
    findComposeBodies().forEach(injectButtons);
    findReadableBodies().forEach(verifyIfSigned);
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
