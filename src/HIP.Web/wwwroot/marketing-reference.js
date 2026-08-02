(() => {
    const routes = new Map([
        ["Platform", "/platform"],
        ["How it works", "/how-it-works"],
        ["Verification", "/verification"],
        ["Developers", "/developers"],
        ["Check a website →", "/lookup"],
        ["How verification works →", "/verification"],
        ["How verification works", "/verification"],
        ["Developer docs →", "/developers"],
        ["See the platform →", "/platform"],
        ["Contributing guide", "https://github.com/daCodez/HIP/blob/master/CONTRIBUTING.md"]
    ]);

    const compactRoutes = new Map([
        ["home", "/"],
        ["platform", "/platform"],
        ["how", "/how-it-works"],
        ["verify", "/verification"],
        ["dev", "/developers"]
    ]);

    /** Navigates to a first-party HIP route or the repository. */
    function navigate(target) {
        if (target.startsWith("https://")) {
            window.location.assign(target);
            return;
        }

        window.location.assign(new URL(target, window.location.origin));
    }

    /** Opens lookup with a normalized domain when the reference form has a value. */
    function openLookup(root) {
        const input = root.querySelector('input[placeholder="yourdomain.com"]');
        const domain = input?.value.trim().replace(/^https?:\/\//i, "").replace(/\/$/, "");
        navigate(domain ? `/lookup/${encodeURIComponent(domain)}` : "/lookup");
    }

    /** Binds the interactions from the supplied reference without changing its DOM geometry. */
    function bindReferencePage() {
        const root = document.querySelector(".hip-reference-page");
        if (!root || root.dataset.hipReferenceBound === "true") {
            return;
        }

        root.dataset.hipReferenceBound = "true";

        root.querySelector('[role="button"]')?.addEventListener("click", () => navigate("/"));

        root.querySelectorAll("select[data-nav-compact]").forEach(select => {
            select.addEventListener("change", event => {
                const route = compactRoutes.get(event.currentTarget.value);
                if (route) navigate(route);
            });
        });

        root.querySelectorAll("button").forEach(button => {
            const label = button.textContent.replace(/\s+/g, " ").trim();

            if (button.title === "Toggle theme") {
                button.addEventListener("click", () => {
                    const themed = root.querySelector("[data-theme]");
                    if (!themed) return;
                    const next = themed.dataset.theme === "dark" ? "light" : "dark";
                    themed.dataset.theme = next;
                    button.setAttribute("aria-label", next === "dark" ? "Use light theme" : "Use dark theme");
                });
                return;
            }

            if (button.title === "Switch hero direction") {
                button.addEventListener("click", () => {
                    const heroGrid = root.querySelector("main section > div[style*='grid-template-columns']");
                    if (!heroGrid) return;
                    const reversed = heroGrid.dataset.reversed === "true";
                    heroGrid.dataset.reversed = String(!reversed);
                    heroGrid.style.direction = reversed ? "ltr" : "rtl";
                    heroGrid.querySelectorAll(":scope > *").forEach(child => child.style.direction = "ltr");
                });
                return;
            }

            if (label === "Check my domain") {
                button.addEventListener("click", () => openLookup(root));
                return;
            }

            const route = routes.get(label);
            if (route) {
                button.addEventListener("click", () => navigate(route));
                return;
            }

            if (label.endsWith("+")) {
                button.addEventListener("click", () => {
                    const answer = button.parentElement?.nextElementSibling ?? button.nextElementSibling;
                    if (!answer) return;
                    const expanded = button.getAttribute("aria-expanded") === "true";
                    button.setAttribute("aria-expanded", String(!expanded));
                    answer.hidden = expanded;
                });
            }
        });

        const domainInput = root.querySelector('input[placeholder="yourdomain.com"]');
        domainInput?.addEventListener("keydown", event => {
            if (event.key === "Enter") {
                event.preventDefault();
                openLookup(root);
            }
        });

        const progress = root.querySelector("[data-progress]");
        if (progress) {
            const updateProgress = () => {
                const maximum = document.documentElement.scrollHeight - window.innerHeight;
                const percentage = maximum > 0 ? Math.min(100, Math.max(0, window.scrollY / maximum * 100)) : 0;
                progress.style.width = `${percentage}%`;
            };
            updateProgress();
            window.addEventListener("scroll", updateProgress, { passive: true });
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bindReferencePage, { once: true });
    } else {
        bindReferencePage();
    }
})();
