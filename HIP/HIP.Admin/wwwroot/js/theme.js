const hipFocusTrapHandlers = new WeakMap();
const hipModalInertTargets = new WeakMap();
const hipModalInertElementState = new WeakMap();
const hipFocusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]'
].join(',');

const getFocusableElements = (container) => Array.from(container.querySelectorAll(hipFocusableSelector))
  .filter((el) => el instanceof HTMLElement)
  .filter((el) => {
    if (el.hidden || el.getAttribute('aria-hidden') === 'true' || el.inert) {
      return false;
    }

    if (el.tabIndex < 0) {
      return false;
    }

    const style = window.getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden';
  });

const applyInertToElement = (element) => {
  const existing = hipModalInertElementState.get(element);
  if (existing) {
    existing.count += 1;
    hipModalInertElementState.set(element, existing);
    return;
  }

  hipModalInertElementState.set(element, {
    count: 1,
    inert: element.inert,
    hasAriaHidden: element.hasAttribute('aria-hidden'),
    ariaHidden: element.getAttribute('aria-hidden')
  });

  element.inert = true;
  element.setAttribute('aria-hidden', 'true');
};

const restoreInertOnElement = (element) => {
  const existing = hipModalInertElementState.get(element);
  if (!existing) {
    return;
  }

  if (existing.count > 1) {
    existing.count -= 1;
    hipModalInertElementState.set(element, existing);
    return;
  }

  element.inert = !!existing.inert;
  if (existing.hasAriaHidden) {
    element.setAttribute('aria-hidden', existing.ariaHidden ?? '');
  } else {
    element.removeAttribute('aria-hidden');
  }

  hipModalInertElementState.delete(element);
};

const isIgnorableTag = (element) => ['SCRIPT', 'STYLE', 'LINK'].includes(element.tagName);

const getBodyLevelTargetsToInert = (backdrop) => {
  if (!document.body) {
    return [];
  }

  return Array.from(document.body.children)
    .filter((child) => child instanceof HTMLElement)
    .filter((child) => !isIgnorableTag(child))
    .filter((child) => !child.contains(backdrop));
};

const getParentSiblingTargetsToInert = (backdrop) => {
  if (!backdrop.parentElement) {
    return [];
  }

  return Array.from(backdrop.parentElement.children)
    .filter((child) => child instanceof HTMLElement)
    .filter((child) => child !== backdrop)
    .filter((child) => !isIgnorableTag(child));
};

const getModalBackgroundTargetsToInert = (backdrop) => {
  if (!backdrop || !(backdrop instanceof HTMLElement)) {
    return [];
  }

  const bodyLevelTargets = getBodyLevelTargetsToInert(backdrop);
  if (bodyLevelTargets.length > 0) {
    return bodyLevelTargets;
  }

  return getParentSiblingTargetsToInert(backdrop);
};

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
  },
  focusPageHeading: () => {
    const heading = document.getElementById('page-title');
    if (heading && typeof heading.focus === 'function') {
      heading.focus();
      return;
    }

    const main = document.getElementById('admin-main');
    if (main && typeof main.focus === 'function') {
      main.focus();
    }
  },
  captureFocus: () => {
    const active = document.activeElement;
    if (!active || !(active instanceof HTMLElement)) {
      return null;
    }

    if (!active.id) {
      active.id = `hip-focus-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    }

    return active.id;
  },
  focusById: (id) => {
    if (!id) {
      return;
    }

    const target = document.getElementById(id);
    if (target && typeof target.focus === 'function') {
      target.focus();
    }
  },
  focusFirstInElement: (element) => {
    if (!element || !(element instanceof HTMLElement)) {
      return;
    }

    const firstFocusable = getFocusableElements(element)[0];
    if (firstFocusable && typeof firstFocusable.focus === 'function') {
      firstFocusable.focus();
      return;
    }

    if (typeof element.focus === 'function') {
      element.focus();
    }
  },
  setModalBackgroundInert: (backdrop, isActive) => {
    if (!backdrop || !(backdrop instanceof HTMLElement)) {
      return;
    }

    if (isActive) {
      if (hipModalInertTargets.has(backdrop)) {
        return;
      }

      const targets = getModalBackgroundTargetsToInert(backdrop);
      targets.forEach((target) => applyInertToElement(target));
      hipModalInertTargets.set(backdrop, targets);
      return;
    }

    const targets = hipModalInertTargets.get(backdrop);
    if (!targets) {
      return;
    }

    targets.forEach((target) => restoreInertOnElement(target));
    hipModalInertTargets.delete(backdrop);
  },
  enableFocusTrap: (element) => {
    if (!element || !(element instanceof HTMLElement) || hipFocusTrapHandlers.has(element)) {
      return;
    }

    const handler = (event) => {
      if (event.key !== 'Tab' || !element.isConnected) {
        return;
      }

      const topMostDialog = Array.from(document.querySelectorAll('[role="dialog"][aria-modal="true"]'))
        .filter((dialog) => dialog instanceof HTMLElement && dialog.isConnected)
        .at(-1);
      if (topMostDialog && topMostDialog !== element) {
        return;
      }

      const eventPath = typeof event.composedPath === 'function' ? event.composedPath() : [];
      if (eventPath.length > 0 && !eventPath.includes(element)) {
        return;
      }

      const focusable = getFocusableElements(element);
      if (focusable.length === 0) {
        event.preventDefault();
        if (typeof element.focus === 'function') {
          element.focus();
        }
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;

      if (event.shiftKey) {
        if (!active || active === first || !element.contains(active)) {
          event.preventDefault();
          last.focus();
        }
        return;
      }

      if (!active || active === last || !element.contains(active)) {
        event.preventDefault();
        first.focus();
      }
    };

    element.addEventListener('keydown', handler);
    hipFocusTrapHandlers.set(element, handler);
  },
  disableFocusTrap: (element) => {
    if (!element || !(element instanceof HTMLElement)) {
      return;
    }

    const handler = hipFocusTrapHandlers.get(element);
    if (!handler) {
      return;
    }

    element.removeEventListener('keydown', handler);
    hipFocusTrapHandlers.delete(element);
  }
};
