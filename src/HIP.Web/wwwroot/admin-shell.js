(() => {
  const storageKey = "hip-admin-theme";
  const root = document.documentElement;
  const preferredTheme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";

  function readSavedTheme() {
    try {
      return window.localStorage.getItem(storageKey);
    } catch {
      return null;
    }
  }

  function saveTheme(theme) {
    try {
      window.localStorage.setItem(storageKey, theme);
    } catch {
      // Theme switching remains available when browser storage is disabled.
    }
  }

  function updateThemeControls(theme) {
    const nextTheme = theme === "dark" ? "light" : "dark";
    document.querySelectorAll("[data-hip-theme-toggle]").forEach((control) => {
      control.setAttribute("aria-label", `Switch to ${nextTheme} mode`);
      control.setAttribute("title", `Switch to ${nextTheme} mode`);
    });
  }

  function applyTheme(theme, persist = false) {
    const safeTheme = theme === "light" ? "light" : "dark";
    root.dataset.theme = safeTheme;
    root.style.colorScheme = safeTheme;
    updateThemeControls(safeTheme);
    if (persist) {
      saveTheme(safeTheme);
    }
  }

  function applySavedTheme() {
    applyTheme(readSavedTheme() ?? preferredTheme);
  }

  applySavedTheme();

  document.addEventListener("click", (event) => {
    if (event.target.closest("[data-hip-theme-toggle]")) {
      applyTheme(root.dataset.theme === "dark" ? "light" : "dark", true);
    }
  });

  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      document.querySelector(".hip-search input")?.focus();
    }
  });

  function initializeThemeControls() {
    updateThemeControls(root.dataset.theme);

    // Blazor enhanced navigation replaces server-rendered document attributes.
    // Restore the user's saved theme after each internal page transition.
    window.Blazor?.addEventListener("enhancedload", applySavedTheme);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeThemeControls, { once: true });
  } else {
    initializeThemeControls();
  }
})();
