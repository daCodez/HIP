const ids = ['baseUrl', 'identityId', 'keyId'];

async function load() {
  const cfg = await chrome.storage.sync.get(ids);
  for (const id of ids) {
    document.getElementById(id).value = cfg[id] || '';
  }
}

function show(text, ok = true) {
  const msg = document.getElementById('msg');
  msg.className = ok ? 'ok' : 'err';
  msg.textContent = text;
}

async function save() {
  const data = {};
  for (const id of ids) {
    data[id] = document.getElementById(id).value.trim();
  }
  await chrome.storage.sync.set(data);
  show('Saved.', true);
}

async function authGoogle() {
  const result = await chrome.runtime.sendMessage({ type: 'hip:googleAuth' });
  if (result?.ok) show('Google authorization successful.', true);
  else show(`Google auth failed: ${result?.error || 'unknown'}`, false);
}

document.getElementById('saveBtn').addEventListener('click', save);
document.getElementById('authBtn').addEventListener('click', authGoogle);
load();
