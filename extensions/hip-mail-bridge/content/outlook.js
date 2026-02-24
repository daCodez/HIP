(() => {
  const BTN_CLASS = 'hip-sign-btn-outlook';

  function findComposeBodies() {
    return Array.from(document.querySelectorAll('div[aria-label="Message body"], div[role="textbox"]'));
  }

  function injectButton(bodyEl) {
    if (!bodyEl || bodyEl.dataset.hipButtonAttached === '1') return;

    const commandBar = bodyEl.closest('[role="dialog"]')?.querySelector('[role="toolbar"]');
    if (!commandBar) return;

    const btn = document.createElement('button');
    btn.textContent = 'Sign with HIP';
    btn.className = BTN_CLASS;
    btn.style.marginLeft = '8px';
    btn.style.padding = '6px 10px';
    btn.style.borderRadius = '6px';
    btn.style.border = '1px solid #ccc';
    btn.style.background = '#fff';
    btn.style.cursor = 'pointer';

    btn.addEventListener('click', async () => {
      const plainText = bodyEl.innerText || '';
      const response = await chrome.runtime.sendMessage({ type: 'hip:sign', body: plainText });
      if (!response?.ok || !response?.payload?.success || !response?.payload?.message) {
        alert(`HIP sign failed: ${response?.payload?.reason || response?.error || 'unknown'}`);
        return;
      }

      const signed = response.payload.message;
      const stamp = `\n\n---\nHIP-Signature:\n${JSON.stringify(signed, null, 2)}\n`;
      bodyEl.innerText = plainText + stamp;
      alert('HIP signature inserted.');
    });

    commandBar.appendChild(btn);
    bodyEl.dataset.hipButtonAttached = '1';
  }

  const observer = new MutationObserver(() => {
    findComposeBodies().forEach(injectButton);
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
