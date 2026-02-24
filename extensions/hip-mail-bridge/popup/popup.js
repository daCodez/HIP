const ids = ['baseUrl', 'identityId', 'keyId'];

async function load() {
  const cfg = await chrome.storage.sync.get(ids);
  for (const id of ids) {
    document.getElementById(id).value = cfg[id] || '';
  }
}

async function save() {
  const data = {};
  for (const id of ids) {
    data[id] = document.getElementById(id).value.trim();
  }
  await chrome.storage.sync.set(data);

  const msg = document.getElementById('msg');
  msg.className = 'ok';
  msg.textContent = 'Saved.';
}

document.getElementById('saveBtn').addEventListener('click', save);
load();
