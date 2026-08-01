document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("kc-form-login");
  const submitButton = document.getElementById("kc-login");

  if (!form || !submitButton) {
    return;
  }

  // The inherited Keycloak template disables the submit control from its
  // inline submit handler. Some embedded Chromium hosts then cancel the
  // native form action. Defer the double-submit guard until navigation starts.
  form.removeAttribute("onsubmit");
  form.addEventListener(
    "submit",
    () => window.setTimeout(() => {
      submitButton.disabled = true;
    }, 0),
    { once: true },
  );
});
