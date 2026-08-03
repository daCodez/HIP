/*  HIP — motion engine
 *  Parallax, scroll reveals, count-ups, card spotlight, magnetic buttons,
 *  the hero trust-network globe, and the "X-ray this page" scanner.
 *  Boots itself for the static marketing shell; interactive page components can also call hip.xray().
 */
(function () {
  "use strict";

  var booted = false;
  var teardown = [];

  function initChrome() {
    document.querySelectorAll(".hip-marketing-site").forEach(function (root) {
      if (root.dataset.hipChromeBound === "true") return;
      root.dataset.hipChromeBound = "true";

      var themeToggle = root.querySelector("[data-theme-toggle]");
      if (themeToggle) themeToggle.addEventListener("click", function () {
        root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
      });

      var registerToggle = root.querySelector("[data-register-toggle]");
      if (registerToggle) registerToggle.addEventListener("click", function () {
        var technical = root.dataset.register !== "technical";
        root.dataset.register = technical ? "technical" : "plain";
        var label = registerToggle.querySelector("[data-register-label]");
        if (label) label.textContent = technical ? "Technical" : "Plain language";
        root.querySelectorAll("[data-register-copy]").forEach(function (copy) {
          copy.textContent = copy.getAttribute(technical ? "data-technical" : "data-plain") || "";
        });
      });

      var nav = root.querySelector("[data-nav-compact]");
      if (nav) nav.addEventListener("change", function () {
        if (nav.value && nav.value.charAt(0) === "/") window.location.assign(nav.value);
      });
    });
  }

  function css(name, fallback) {
    var themeRoot = document.querySelector(".hip-marketing-site") || document.documentElement;
    var v = getComputedStyle(themeRoot).getPropertyValue(name);
    return (v || fallback).trim();
  }

  function rgba(hex, a) {
    var c = hex.replace("#", "");
    if (c.length === 3) c = c.split("").map(function (x) { return x + x; }).join("");
    var n = parseInt(c, 16);
    return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
  }

  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /** Returns whether the marketing shell explicitly opts into its full motion design. */
  function motionEnabled() {
    var root = document.querySelector(".hip-marketing-site");
    return !!root && (root.dataset.motion === "full" || !reduced);
  }

  /* ---------------- scroll: parallax, progress, reveals ---------------- */

  function initScroll() {
    var frame = null;

    function paint() {
      frame = null;
      var view = window.innerHeight;
      var y = window.scrollY || document.documentElement.scrollTop || 0;
      var max = Math.max(1, document.documentElement.scrollHeight - view);

      var bar = document.querySelector("[data-progress]");
      if (bar) bar.style.width = Math.min(100, (y / max) * 100).toFixed(2) + "%";

      if (motionEnabled()) {
        document.querySelectorAll("[data-px]").forEach(function (el) {
          var speed = parseFloat(el.getAttribute("data-px")) || 0;
          var r = el.getBoundingClientRect();
          if (r.bottom < -400 || r.top > view + 400) return;
          var mid = r.top + r.height / 2 - view / 2;
          el.style.transform = "translate3d(0," + (-mid * speed).toFixed(1) + "px,0)";
        });
      }

      revealPass(view);
    }

    function onScroll() {
      if (frame === null) frame = requestAnimationFrame(paint);
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    teardown.push(function () {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    });

    // Content is visible by default; entrances are an enhancement only.
    if (motionEnabled()) armEntrances();
    paint();

    var pump = setInterval(paint, 250);
    teardown.push(function () { clearInterval(pump); });
  }

  function armEntrances() {
    var fold = window.innerHeight * 0.92;
    document.querySelectorAll("[data-rise]").forEach(function (el) {
      if (el.hasAttribute("data-reveal") || el.getBoundingClientRect().top <= fold) return;
      el.style.transition = "none";
      el.style.opacity = "0";
      el.style.transform = "translateY(16px)";
      el.setAttribute("data-reveal", "rise");
    });
    document.querySelectorAll("[data-words]").forEach(function (h) {
      if (h.hasAttribute("data-reveal") || h.getBoundingClientRect().top <= fold) return;
      h.style.transition = "none";
      h.style.clipPath = "inset(0 -0.14em 105% -0.14em)";
      h.style.transform = "translateY(14px)";
      h.style.opacity = "0.001";
      h.setAttribute("data-reveal", "words");
    });
  }

  function revealPass(view) {
    var line = view * 0.92;
    document.querySelectorAll("[data-reveal]:not([data-revealed])").forEach(function (el) {
      if (el.getBoundingClientRect().top > line) return;
      el.setAttribute("data-revealed", "1");
      tween(el, el.getAttribute("data-reveal"));
    });
    document.querySelectorAll("[data-count]:not([data-counted])").forEach(function (el) {
      if (el.getBoundingClientRect().top > line) return;
      el.setAttribute("data-counted", "1");
      if (motionEnabled()) countUp(el);
    });
  }

  function tween(el, kind) {
    var dur = kind === "words" ? 900 : 700;
    var start = performance.now();
    (function step(now) {
      var p = Math.min(1, (now - start) / dur);
      var e = 1 - Math.pow(1 - p, 3);
      if (kind === "words") {
        el.style.clipPath = "inset(0 -0.14em " + ((1 - e) * 105).toFixed(2) + "% -0.14em)";
        el.style.transform = "translateY(" + ((1 - e) * 14).toFixed(2) + "px)";
        el.style.opacity = Math.max(0.001, e).toFixed(3);
      } else {
        el.style.opacity = e.toFixed(3);
        el.style.transform = "translateY(" + ((1 - e) * 16).toFixed(2) + "px)";
      }
      if (p < 1) requestAnimationFrame(step);
      else {
        if (kind === "words") el.style.clipPath = "none";
        el.style.transform = "none";
        el.style.opacity = "1";
      }
    })(performance.now());
  }

  function countUp(el) {
    var m = String(el.getAttribute("data-count") || el.textContent).match(/^(\d+(?:\.\d+)?)(.*)$/);
    if (!m) return;
    var target = parseFloat(m[1]), suffix = m[2] || "", start = performance.now(), dur = 1100;
    (function step(now) {
      var p = Math.min(1, (now - start) / dur);
      el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))) + suffix;
      if (p < 1) requestAnimationFrame(step);
    })(performance.now());
  }

  /* ---------------- pointer: tilt, spotlight, magnetic ---------------- */

  function initPointer() {
    if (!motionEnabled()) return;

    function onMove(e) {
      document.querySelectorAll("[data-tilt]").forEach(function (el) {
        var r = el.getBoundingClientRect();
        if (r.bottom < 0 || r.top > window.innerHeight) return;
        var dx = (e.clientX - (r.left + r.width / 2)) / r.width;
        var dy = (e.clientY - (r.top + r.height / 2)) / r.height;
        el.style.transform = "perspective(1400px) rotateY(" + (dx * 4.5).toFixed(2) + "deg) rotateX(" + (-dy * 3.5).toFixed(2) + "deg)";
      });

      document.querySelectorAll("[data-spot]").forEach(function (el) {
        var layer = el.firstElementChild;
        if (!layer || !layer.hasAttribute("data-spot-layer")) return;
        var r = el.getBoundingClientRect();
        var inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
        if (!inside) { layer.style.opacity = "0"; return; }
        layer.style.opacity = "1";
        layer.style.background = "radial-gradient(240px circle at " + (e.clientX - r.left) + "px " + (e.clientY - r.top) + "px, var(--tint), transparent 70%)";
      });

      document.querySelectorAll("[data-magnet]").forEach(function (el) {
        var r = el.getBoundingClientRect();
        var dx = e.clientX - (r.left + r.width / 2);
        var dy = e.clientY - (r.top + r.height / 2);
        var dist = Math.hypot(dx, dy);
        var range = Math.max(r.width, 120) * 1.1;
        if (dist > range) { el.style.transform = "translate(0,0)"; return; }
        var f = (1 - dist / range) * 0.34;
        el.style.transform = "translate(" + (dx * f).toFixed(1) + "px," + (dy * f).toFixed(1) + "px)";
      });
    }

    window.addEventListener("pointermove", onMove, { passive: true });
    teardown.push(function () { window.removeEventListener("pointermove", onMove); });
  }

  // Re-runnable: Blazor replaces nodes on navigation.
  function wireCards() {
    document.querySelectorAll("[data-cards] > div").forEach(function (card) {
      if (card.hasAttribute("data-spot")) return;
      card.setAttribute("data-spot", "");
      card.style.position = "relative";
      card.style.overflow = "hidden";
      var layer = document.createElement("div");
      layer.setAttribute("data-spot-layer", "");
      layer.style.cssText = "position:absolute;inset:0;opacity:0;pointer-events:none";
      card.insertBefore(layer, card.firstChild);
      Array.prototype.forEach.call(card.children, function (c) {
        if (c !== layer) c.style.position = c.style.position || "relative";
      });
      card.addEventListener("pointerenter", function () {
        card.style.transform = "translateY(-4px)";
        card.style.borderColor = "color-mix(in srgb, var(--action) 45%, var(--border))";
      });
      card.addEventListener("pointerleave", function () {
        card.style.transform = "none";
        card.style.borderColor = "var(--border)";
      });
    });
  }

  /* ---------------- hero globe ---------------- */

  function initGlobe() {
    var N = 520;
    var pts = [];
    for (var i = 0; i < N; i++) {
      var y = 1 - (i / (N - 1)) * 2;
      var r = Math.sqrt(Math.max(0, 1 - y * y));
      var th = i * Math.PI * (3 - Math.sqrt(5));
      pts.push({ x: Math.cos(th) * r, y: y, z: Math.sin(th) * r, seed: Math.random() });
    }
    var arcs = [];
    for (var k = 0; k < 16; k++) {
      arcs.push({
        a: pts[(Math.random() * N) | 0],
        b: pts[(Math.random() * N) | 0],
        t: Math.random(),
        spd: 0.0022 + Math.random() * 0.0026
      });
    }

    var teal = css("--action", "#14B8A6");
    var blue = css("--blue", "#1F6FEB");
    var rot = 0, last = performance.now(), raf = null;

    function draw(now) {
      var dt = Math.min(48, now - last);
      last = now;
      if (motionEnabled()) rot += dt * 0.00016;

      document.querySelectorAll("canvas[data-globe]").forEach(function (cv) {
        var dpr = Math.min(2, window.devicePixelRatio || 1);
        var w = cv.clientWidth, h = cv.clientHeight;
        if (!w || !h) return;
        if (cv.width !== w * dpr || cv.height !== h * dpr) { cv.width = w * dpr; cv.height = h * dpr; }
        var ctx = cv.getContext("2d");
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, w, h);

        var wide = w / Math.max(1, h) > 1.4;
        var cx = wide ? w * 0.62 : w / 2, cy = h / 2;
        var R = wide ? h * 0.62 : Math.min(w, h) * 0.42;
        var tilt = -0.42, ct = Math.cos(tilt), st = Math.sin(tilt);
        var cr = Math.cos(rot), sr = Math.sin(rot);

        function proj(p) {
          var x1 = p.x * cr - p.z * sr, z1 = p.x * sr + p.z * cr;
          var y2 = p.y * ct - z1 * st, z2 = p.y * st + z1 * ct;
          return { X: cx + x1 * R, Y: cy + y2 * R, Z: z2 };
        }

        var g = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R * 1.5);
        g.addColorStop(0, rgba(teal, 0.10));
        g.addColorStop(1, rgba(teal, 0));
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, R * 1.5, 0, Math.PI * 2); ctx.fill();

        ctx.lineWidth = 1;
        for (var kk = -2; kk <= 2; kk++) {
          var lat = (kk / 3) * Math.PI / 2;
          ctx.beginPath();
          for (var aa = 0; aa <= 64; aa++) {
            var ang = (aa / 64) * Math.PI * 2;
            var p = proj({ x: Math.cos(ang) * Math.cos(lat), y: Math.sin(lat), z: Math.sin(ang) * Math.cos(lat) });
            if (aa === 0) ctx.moveTo(p.X, p.Y); else ctx.lineTo(p.X, p.Y);
          }
          ctx.strokeStyle = rgba(blue, 0.13);
          ctx.stroke();
        }

        pts.forEach(function (pt) {
          var p = proj(pt);
          var depth = (p.Z + 1) / 2;
          var s = 0.6 + depth * 1.7;
          ctx.beginPath(); ctx.arc(p.X, p.Y, s, 0, Math.PI * 2);
          ctx.fillStyle = rgba(teal, 0.10 + depth * 0.55);
          ctx.fill();
          var pulse = motionEnabled() ? Math.max(0, Math.sin(now * 0.0011 + pt.seed * 9)) : 0;
          if (pulse > 0.985 && depth > 0.55) {
            ctx.beginPath(); ctx.arc(p.X, p.Y, s * 5, 0, Math.PI * 2);
            ctx.strokeStyle = rgba(teal, 0.35 * depth);
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        });

        arcs.forEach(function (arc) {
          if (motionEnabled()) { arc.t += arc.spd * (dt / 16); if (arc.t > 1.35) arc.t = -0.15; }
          var A = proj(arc.a), B = proj(arc.b);
          if (A.Z < -0.1 && B.Z < -0.1) return;
          var mx = (A.X + B.X) / 2, my = (A.Y + B.Y) / 2;
          var bx = cx + (mx - cx) * 1.42, by = cy + (my - cy) * 1.42;
          ctx.beginPath(); ctx.moveTo(A.X, A.Y); ctx.quadraticCurveTo(bx, by, B.X, B.Y);
          ctx.strokeStyle = rgba(teal, 0.16); ctx.lineWidth = 1; ctx.stroke();
          var tt = Math.max(0, Math.min(1, arc.t));
          var q = (1 - tt) * (1 - tt), m = 2 * (1 - tt) * tt, e = tt * tt;
          var px = q * A.X + m * bx + e * B.X, py = q * A.Y + m * by + e * B.Y;
          ctx.beginPath(); ctx.arc(px, py, 2.4, 0, Math.PI * 2); ctx.fillStyle = rgba(teal, 0.95); ctx.fill();
          ctx.beginPath(); ctx.arc(px, py, 7, 0, Math.PI * 2); ctx.fillStyle = rgba(teal, 0.12); ctx.fill();
        });

        if (motionEnabled()) {
          var sy = cy + Math.sin(now * 0.00045) * R;
          var lg = ctx.createLinearGradient(cx - R, sy, cx + R, sy);
          lg.addColorStop(0, rgba(teal, 0));
          lg.addColorStop(0.5, rgba(teal, 0.4));
          lg.addColorStop(1, rgba(teal, 0));
          ctx.strokeStyle = lg; ctx.lineWidth = 1.4;
          ctx.beginPath(); ctx.moveTo(cx - R * 1.05, sy); ctx.lineTo(cx + R * 1.05, sy); ctx.stroke();
        }
      });

      raf = requestAnimationFrame(draw);
    }

    raf = requestAnimationFrame(draw);
    teardown.push(function () { cancelAnimationFrame(raf); });
  }

  /* ---------------- X-ray: scan the real page ---------------- */

  var xrayRoot = null;
  var onXrayKey = null;

  function probePage() {
    var origin = location.origin;
    var links = Array.prototype.slice.call(document.querySelectorAll("a[href]"));
    var external = links.filter(function (a) {
      try { return new URL(a.href, location.href).origin !== origin; } catch (e) { return false; }
    });
    var thirdParty = Array.prototype.slice.call(document.querySelectorAll("script[src]")).filter(function (s) {
      try { return new URL(s.src, location.href).origin !== origin; } catch (e) { return false; }
    });
    var pw = document.querySelectorAll('input[type="password"]').length;
    var imgs = Array.prototype.slice.call(document.querySelectorAll("img"));
    var noAlt = imgs.filter(function (i) { return !i.getAttribute("alt"); });
    var https = location.protocol === "https:";
    var desc = document.head.querySelector('meta[name="description"]');

    var f = [];
    f.push(https
      ? { t: "ok", d: 12, label: "Connection is encrypted", plain: "Served over HTTPS" }
      : { t: "warn", d: -12, label: "Connection is not encrypted", plain: "This page is served over " + location.protocol.replace(":", "") });
    f.push(pw === 0
      ? { t: "ok", d: 8, label: "No password is requested", plain: "No password field anywhere on this page" }
      : { t: "risk", d: -20, label: pw + " password field" + (pw > 1 ? "s" : "") + " found", plain: "Where they submit to would be checked next" });
    f.push(thirdParty.length === 0
      ? { t: "ok", d: 6, label: "No third-party scripts", plain: "Every script on this page is first-party" }
      : { t: "warn", d: -4, label: thirdParty.length + " third-party script" + (thirdParty.length > 1 ? "s" : ""), plain: "Loaded from another origin" });
    f.push({ t: "ok", d: 4, label: links.length + " links, " + external.length + " leaving this site",
      plain: external.length ? "Outbound destinations are recorded" : "Nothing here navigates away" });
    f.push(noAlt.length === 0
      ? { t: "ok", d: 2, label: imgs.length + " image" + (imgs.length === 1 ? "" : "s") + ", all described", plain: "Alt text present on every image" }
      : { t: "warn", d: -2, label: noAlt.length + " image" + (noAlt.length > 1 ? "s" : "") + " without a description", plain: "A small quality signal, not a risk" });
    f.push(desc && desc.getAttribute("content")
      ? { t: "ok", d: 3, label: "Page describes itself", plain: "Title and description are present" }
      : { t: "warn", d: -3, label: "No page description", plain: "Harder for anyone to verify what this page claims to be" });

    var score = 70;
    f.forEach(function (x) { score += x.d; });
    return { findings: f, score: Math.max(0, Math.min(100, score)), nodes: document.getElementsByTagName("*").length };
  }

  function xray() {
    if (xrayRoot) return;

    var probe = probePage();
    var teal = css("--action", "#14B8A6"), ink = css("--text", "#F8FAFB");
    var bg = css("--bg", "#0B1220"), surface = css("--surface", "#111827");
    var border = css("--border", "#1F2937"), muted = css("--muted", "#9CA3AF");
    var TONE = { ok: css("--ok", "#22C55E"), warn: css("--warn", "#F59E0B"), risk: css("--danger", "#EF4444") };
    var vh = window.innerHeight, vw = window.innerWidth;

    var root = document.createElement("div");
    root.style.cssText = "position:fixed;inset:0;z-index:9000;pointer-events:none;font-family:Satoshi,system-ui,sans-serif";

    var scrim = document.createElement("div");
    scrim.style.cssText = "position:absolute;inset:0;background:" + bg + ";opacity:0;backdrop-filter:saturate(.45) blur(1px);pointer-events:auto";
    scrim.addEventListener("click", closeXray);
    root.appendChild(scrim);

    var prevOverflow = document.documentElement.style.overflow;
    var prevBody = document.body.style.overflow;
    document.documentElement.style.overflow = "hidden";
    document.body.style.overflow = "hidden";

    var boxes = [];
    document.querySelectorAll("h1,h2,h3,p,a,button,input,img,svg,[data-cards] > div,[data-tilt],section").forEach(function (el) {
      if (root.contains(el)) return;
      var r = el.getBoundingClientRect();
      if (r.width < 24 || r.height < 12 || r.bottom < 0 || r.top > vh) return;
      if (r.width > vw * 0.98 && r.height > vh * 0.9) return;
      var b = document.createElement("div");
      b.style.cssText = "position:absolute;left:" + (r.left - 2) + "px;top:" + (r.top - 2) + "px;width:" + (r.width + 4) +
        "px;height:" + (r.height + 4) + "px;border:1px solid " + teal + ";border-radius:4px;opacity:0;box-shadow:inset 0 0 22px rgba(20,184,166,.10)";
      var lab = document.createElement("span");
      lab.textContent = el.tagName.toLowerCase();
      lab.style.cssText = "position:absolute;left:0;top:-15px;font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.06em;color:" + teal + ";opacity:.85";
      b.appendChild(lab);
      root.appendChild(b);
      boxes.push({ node: b, top: r.top, lit: false });
    });

    var line = document.createElement("div");
    line.style.cssText = "position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,transparent," + teal +
      ",transparent);box-shadow:0 0 26px 5px rgba(20,184,166,.45);transform:translateY(-4px)";
    root.appendChild(line);

    var hud = document.createElement("div");
    hud.style.cssText = "position:absolute;right:24px;top:24px;width:330px;max-width:calc(100vw - 48px);max-height:calc(100vh - 48px);overflow-y:auto;background:" +
      surface + ";border:1px solid " + border + ";border-radius:16px;padding:22px;box-shadow:0 26px 70px rgba(0,0,0,.5);pointer-events:auto;opacity:0";
    hud.innerHTML =
      '<div style="position:sticky;top:-22px;z-index:2;margin:-22px -22px 14px;padding:16px 22px 12px;background:' + surface +
        ';display:flex;align-items:center;justify-content:space-between;gap:12px">' +
        '<span style="font-size:10.5px;font-weight:800;letter-spacing:.18em;color:' + muted + '">HIP \u00b7 SCANNING THIS PAGE</span>' +
        '<button data-xq aria-label="Close X-ray" style="width:26px;height:26px;flex-shrink:0;display:grid;place-items:center;border:1px solid ' +
          border + ';background:transparent;color:' + ink + ';border-radius:7px;font-size:15px;line-height:1;cursor:pointer">\u00d7</button>' +
      '</div>' +
      '<div style="display:flex;align-items:baseline;gap:9px;margin-bottom:6px">' +
        '<span data-xs style="font-family:\'JetBrains Mono\',monospace;font-size:40px;font-weight:800;letter-spacing:-.03em;color:' + teal + '">0</span>' +
        '<span style="font-size:14px;color:' + muted + '">/ 100</span></div>' +
      '<div style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:' + muted + ';margin-bottom:16px">' +
        probe.nodes.toLocaleString() + ' elements inspected \u00b7 live</div>' +
      '<div data-xf style="display:flex;flex-direction:column;gap:11px"></div>' +
      '<button data-xq2 style="margin-top:18px;width:100%;padding:10px;border:1px solid ' + border + ';background:transparent;color:' + ink +
        ';border-radius:9px;font-size:13.5px;font-weight:700;cursor:pointer">Close X-ray</button>';
    root.appendChild(hud);
    document.body.appendChild(root);

    hud.querySelector("[data-xq]").addEventListener("click", closeXray);
    hud.querySelector("[data-xq2]").addEventListener("click", closeXray);
    onXrayKey = function (e) { if (e.key === "Escape") closeXray(); };
    window.addEventListener("keydown", onXrayKey);

    var list = hud.querySelector("[data-xf]");
    var scoreEl = hud.querySelector("[data-xs]");
    var dur = 2600, t0 = performance.now(), shown = 0, running = true;

    xrayRoot = {
      node: root,
      stop: function () {
        running = false;
        document.documentElement.style.overflow = prevOverflow;
        document.body.style.overflow = prevBody;
      }
    };

    (function step(now) {
      if (!running) return;
      var p = Math.min(1, (now - t0) / dur);
      var e = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
      var y = e * vh;

      scrim.style.opacity = String(Math.min(0.58, p * 2.2));
      line.style.transform = "translateY(" + y.toFixed(1) + "px)";
      hud.style.opacity = String(Math.min(1, p * 4));

      boxes.forEach(function (b) {
        if (!b.lit && b.top <= y) { b.lit = true; b.node.style.opacity = "1"; }
      });

      var want = Math.floor(p * probe.findings.length);
      while (shown < want && shown < probe.findings.length) {
        var f = probe.findings[shown];
        var row = document.createElement("div");
        row.style.cssText = "display:flex;align-items:flex-start;gap:10px";
        row.innerHTML =
          '<span style="width:6px;height:6px;border-radius:50%;flex-shrink:0;margin-top:6px;background:' + TONE[f.t] + '"></span>' +
          '<span style="flex:1;min-width:0"><span style="display:block;font-size:13px;font-weight:600;color:' + ink + ';line-height:1.35"></span>' +
          '<span style="display:block;font-size:11.5px;color:' + muted + ';line-height:1.45;margin-top:2px"></span></span>' +
          '<span style="font-family:\'JetBrains Mono\',monospace;font-size:11.5px;font-weight:700;color:' + TONE[f.t] + '">' +
            (f.d > 0 ? "+" : "\u2212") + Math.abs(f.d) + '</span>';
        var spans = row.querySelectorAll("span > span");
        spans[0].textContent = f.label;
        spans[1].textContent = f.plain;
        list.appendChild(row);
        shown++;
      }

      scoreEl.textContent = String(Math.round(probe.score * e));

      if (p < 1) requestAnimationFrame(step);
      else {
        scoreEl.textContent = String(probe.score);
        line.style.opacity = "0";
        var note = document.createElement("div");
        note.style.cssText = "margin-top:16px;padding-top:14px;border-top:1px solid " + border +
          ";font-size:12px;line-height:1.5;color:" + muted;
        note.textContent = "Measured from this page in your browser, just now. This local X-ray covers page structure only; it is not a full external HIP scan.";
        list.parentNode.insertBefore(note, list.nextSibling);
      }
    })(performance.now());
  }

  function closeXray() {
    if (!xrayRoot) return;
    xrayRoot.stop();
    xrayRoot.node.remove();
    xrayRoot = null;
    if (onXrayKey) { window.removeEventListener("keydown", onXrayKey); onXrayKey = null; }
  }

  window.hip = {
    init: function () {
      initChrome();
      wireCards();
      if (booted) { armEntrances(); return; }
      booted = true;
      initScroll();
      initPointer();
      initGlobe();
    },
    xray: xray,
    printReceipt: function () {
      document.body.classList.add("printing-receipt");
      window.addEventListener("afterprint", function once() {
        document.body.classList.remove("printing-receipt");
        window.removeEventListener("afterprint", once);
      });
      window.print();
    },
    closeXray: closeXray
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", window.hip.init, { once: true });
  } else {
    window.hip.init();
  }
})();
