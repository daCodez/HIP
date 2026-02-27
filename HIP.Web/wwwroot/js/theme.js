(function () {
  const key = 'hip-theme';

  function systemPref() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function apply(mode) {
    const resolved = mode === 'system' ? systemPref() : mode;
    document.documentElement.setAttribute('data-theme', resolved);
    document.documentElement.setAttribute('data-theme-mode', mode);
  }

  function load() {
    const stored = localStorage.getItem(key) || 'system';
    apply(stored);
  }

  window.hipTheme = {
    set(mode) {
      localStorage.setItem(key, mode);
      apply(mode);
    }
  };

  load();
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const mode = localStorage.getItem(key) || 'system';
    if (mode === 'system') apply('system');
  });
})();
