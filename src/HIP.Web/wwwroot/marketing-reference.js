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

    /** Restores the supplied design's scroll reveals and pointer-driven motion. */
    function bindMotion(root) {
        const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        root.classList.add("hip-motion-ready");

        const reveal = element => {
            element.style.opacity = "1";
            element.style.transform = "none";
            element.style.clipPath = "none";
        };

        const rises = [...root.querySelectorAll("[data-rise]")];
        const words = [...root.querySelectorAll("[data-words]")];
        const cardGroups = [...root.querySelectorAll("[data-cards]")];
        const revealCards = group => {
            [...group.children].forEach((card, index) => {
                card.style.transition = `opacity 560ms ${index * 70}ms cubic-bezier(.22,1,.36,1), transform 560ms ${index * 70}ms cubic-bezier(.22,1,.36,1), border-color 180ms ease`;
                requestAnimationFrame(() => {
                    card.style.opacity = "1";
                    card.style.transform = "none";
                });
            });
        };

        if (reducedMotion || !("IntersectionObserver" in window)) {
            [...rises, ...words].forEach(reveal);
        } else {
            const revealObserver = new IntersectionObserver(entries => {
                entries.forEach(entry => {
                    if (!entry.isIntersecting) return;
                    const element = entry.target;
                    element.style.transition = "opacity 700ms cubic-bezier(.22,1,.36,1), transform 700ms cubic-bezier(.22,1,.36,1), clip-path 800ms cubic-bezier(.22,1,.36,1)";
                    requestAnimationFrame(() => {
                        reveal(element);
                        element.querySelectorAll("[data-words]").forEach(reveal);
                        element.querySelectorAll("[data-cards]").forEach(revealCards);
                    });
                    revealObserver.unobserve(element);
                });
            }, { threshold: 0.08, rootMargin: "0px 0px -8%" });

            rises.forEach(element => revealObserver.observe(element));
            words.forEach(element => {
                const startsHidden = Number.parseFloat(getComputedStyle(element).opacity) < 0.1;
                if (!startsHidden) {
                    element.style.opacity = "0.001";
                    element.style.transform = "translateY(14px)";
                    element.style.clipPath = "inset(0 -0.14em 105%)";
                }
                if (element.closest("[data-rise]")) return;
                element.style.transition = "opacity 700ms cubic-bezier(.22,1,.36,1), transform 700ms cubic-bezier(.22,1,.36,1), clip-path 800ms cubic-bezier(.22,1,.36,1)";
                requestAnimationFrame(() => requestAnimationFrame(() => reveal(element)));
            });

            const cardObserver = new IntersectionObserver(entries => {
                entries.forEach(entry => {
                    if (!entry.isIntersecting) return;
                    revealCards(entry.target);
                    cardObserver.unobserve(entry.target);
                });
            }, { threshold: 0.08, rootMargin: "0px 0px -6%" });

            cardGroups.forEach(group => {
                [...group.children].forEach(card => {
                    card.style.opacity = "0";
                    card.style.transform = "translateY(14px)";
                });
                cardObserver.observe(group);
            });
        }

        root.querySelectorAll("[data-count]").forEach(counter => {
            const match = counter.dataset.count.match(/^(\d+)(.*)$/);
            if (!match) return;
            const target = Number.parseInt(match[1], 10);
            const suffix = match[2];
            counter.textContent = `0${suffix}`;
            delete counter.dataset.counted;

            const countUp = () => {
                if (counter.dataset.counted === "1") return;
                counter.dataset.counted = "1";
                if (reducedMotion) {
                    counter.textContent = `${target}${suffix}`;
                    return;
                }
                const started = performance.now();
                const tick = now => {
                    const progress = Math.min(1, (now - started) / 900);
                    const eased = 1 - Math.pow(1 - progress, 3);
                    counter.textContent = `${Math.round(target * eased)}${suffix}`;
                    if (progress < 1) requestAnimationFrame(tick);
                };
                requestAnimationFrame(tick);
            };

            if (!("IntersectionObserver" in window)) {
                countUp();
            } else {
                const counterObserver = new IntersectionObserver(entries => {
                    if (entries.some(entry => entry.isIntersecting)) {
                        countUp();
                        counterObserver.disconnect();
                    }
                }, { threshold: 0.35 });
                counterObserver.observe(counter);
            }
        });

        root.querySelectorAll("[data-spot]").forEach(card => {
            const layer = card.querySelector("[data-spot-layer]");
            if (!layer || reducedMotion) return;
            card.addEventListener("pointermove", event => {
                const bounds = card.getBoundingClientRect();
                layer.style.opacity = "1";
                layer.style.background = `radial-gradient(240px circle at ${event.clientX - bounds.left}px ${event.clientY - bounds.top}px,var(--tint),transparent 70%)`;
                card.style.borderColor = "color-mix(in srgb,var(--action) 45%,var(--border))";
                card.style.transform = "translateY(-4px)";
            });
            card.addEventListener("pointerleave", () => {
                layer.style.opacity = "0";
                card.style.borderColor = "var(--border)";
                card.style.transform = "none";
            });
        });

        root.querySelectorAll("[data-tilt]").forEach(panel => {
            if (reducedMotion) return;
            panel.style.transition = "transform 180ms ease-out";
            panel.addEventListener("pointermove", event => {
                const bounds = panel.getBoundingClientRect();
                const x = (event.clientX - bounds.left) / bounds.width - 0.5;
                const y = (event.clientY - bounds.top) / bounds.height - 0.5;
                panel.style.transform = `perspective(1100px) rotateX(${-y * 5}deg) rotateY(${x * 6}deg)`;
            });
            panel.addEventListener("pointerleave", () => panel.style.transform = "none");
        });

        root.querySelectorAll("[data-magnet]").forEach(button => {
            if (reducedMotion) return;
            button.style.transition = "transform 160ms ease-out, filter 160ms ease";
            button.addEventListener("pointermove", event => {
                const bounds = button.getBoundingClientRect();
                const x = event.clientX - bounds.left - bounds.width / 2;
                const y = event.clientY - bounds.top - bounds.height / 2;
                button.style.transform = `translate(${x * 0.16}px,${y * 0.16}px)`;
            });
            button.addEventListener("pointerleave", () => button.style.transform = "none");
        });

        const parallax = [...root.querySelectorAll("[data-px]")];
        if (!reducedMotion && parallax.length) {
            let pending = false;
            const updateParallax = () => {
                pending = false;
                parallax.forEach(element => {
                    const bounds = element.getBoundingClientRect();
                    const factor = Number.parseFloat(element.dataset.px) || 0;
                    const offset = (window.innerHeight / 2 - (bounds.top + bounds.height / 2)) * factor;
                    element.style.transform = `translate3d(0,${Math.max(-140, Math.min(140, offset)).toFixed(1)}px,0)`;
                });
            };
            const requestParallax = () => {
                if (pending) return;
                pending = true;
                requestAnimationFrame(updateParallax);
            };
            updateParallax();
            window.addEventListener("scroll", requestParallax, { passive: true });
            window.addEventListener("resize", requestParallax, { passive: true });
        }
    }

    /** Binds the interactions from the supplied reference without changing its DOM geometry. */
    function bindReferencePage() {
        const root = document.querySelector(".hip-reference-page");
        if (!root || root.dataset.hipReferenceBound === "true") {
            return;
        }

        root.dataset.hipReferenceBound = "true";
        bindMotion(root);

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
