window.hipTheme = {
  get: (key) => window.localStorage.getItem(key),
  set: (key, value) => window.localStorage.setItem(key, value),
  apply: (preset, darkMode, brightMode) => {
    const root = document.documentElement;
    root.style.setProperty('--hip-primary', preset.primary);
    root.style.setProperty('--hip-accent', preset.accent);
    root.style.setProperty('--hip-sidebar', preset.sidebar);
    root.style.setProperty('--hip-surface', preset.surface);

    document.body.classList.toggle('hip-dark', !!darkMode);
    document.body.classList.toggle('hip-bright', !!brightMode);
  },
  downloadCsv: (filename, content) => {
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  }
};
