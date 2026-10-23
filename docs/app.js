(function () {
  "use strict";

  var TOPICS = [
    { id: "malware", label: "Malware", h: 355 },
    { id: "ransomware", label: "Ransomware", h: 22 },
    { id: "threat-hunting", label: "Threat hunting", h: 170 },
    { id: "vulnerabilities", label: "Vulnerabilities", h: 45 },
    { id: "cloud-identity", label: "Cloud and identity", h: 212 },
    { id: "dfir", label: "DFIR", h: 265 },
    { id: "threat-actors", label: "Threat actors", h: 320 },
    { id: "phishing", label: "Phishing", h: 140 }
  ];
  var RANGES = [
    { id: "1", label: "Last 24 hours" },
    { id: "3", label: "Last 3 days" },
    { id: "7", label: "Last 7 days" },
    { id: "14", label: "Last 14 days" }
  ];
  var TYPE_LABELS = {
    "news": "News",
    "vendor-research": "Vendor and research blogs",
    "government": "Government and CERT",
    "community": "Community and OSINT",
    "intel-feed": "Threat intel feeds and APIs"
  };
  var PAGE = 30;
  var PREF_KEY = "cyberpulse.prefs";
  var REDUCE = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  var state = { topics: [], source: "", range: "7", q: "", shown: PAGE };
  var data = { items: [], kev: [], iocs: [], sources: [] };

  // Feed content is untrusted, so everything is built with textContent, never innerHTML.
  function el(tag, props, children) {
    var node = document.createElement(tag);
    props = props || {};
    Object.keys(props).forEach(function (k) {
      if (k === "class") node.className = props[k];
      else if (k === "text") node.textContent = props[k];
      else if (k.indexOf("on") === 0) node.addEventListener(k.slice(2), props[k]);
      else node.setAttribute(k, props[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }
  function $(id) { return document.getElementById(id); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function safeHref(u) { return /^https?:\/\//i.test(u || "") ? u : ""; }
  function setHue(node, h) { node.style.setProperty("--h", String(h)); return node; }

  function ago(iso) {
    var s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 3600) return Math.max(1, Math.round(s / 60)) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function topicById(id) {
    for (var i = 0; i < TOPICS.length; i++) if (TOPICS[i].id === id) return TOPICS[i];
    return null;
  }
  function hashHue(str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) % 360;
    return h;
  }
  function initials(name) {
    var words = name.replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/);
    var out = (words[0] || "?").charAt(0) + (words.length > 1 ? words[1].charAt(0) : (words[0] || "").charAt(1));
    return out.toUpperCase();
  }

  function loadPrefs() {
    try {
      var p = JSON.parse(localStorage.getItem(PREF_KEY) || "{}");
      if (Array.isArray(p.topics)) state.topics = p.topics;
      if (typeof p.source === "string") state.source = p.source;
      if (typeof p.range === "string") state.range = p.range;
    } catch (e) { /* storage unavailable */ }
  }
  function savePrefs() {
    try {
      localStorage.setItem(PREF_KEY, JSON.stringify({ topics: state.topics, source: state.source, range: state.range }));
    } catch (e) { /* storage unavailable */ }
  }

  function inRange(item) {
    return Date.now() - new Date(item.published).getTime() <= Number(state.range) * 86400000;
  }
  function matchesSearch(item) {
    if (!state.q) return true;
    var hay = (item.title + " " + item.summary + " " + item.source).toLowerCase();
    return state.q.toLowerCase().split(/\s+/).every(function (w) { return hay.indexOf(w) !== -1; });
  }
  function matchesTopics(item) {
    if (!state.topics.length) return true;
    return item.tags.some(function (t) { return state.topics.indexOf(t) !== -1; });
  }
  function baseItems() {
    return data.items.filter(function (i) {
      return inRange(i) && matchesSearch(i) && (!state.source || i.source === state.source);
    });
  }
  function filtered() { return baseItems().filter(matchesTopics); }

  function toggleTopic(id) {
    var idx = state.topics.indexOf(id);
    if (idx === -1) state.topics.push(id); else state.topics.splice(idx, 1);
    state.shown = PAGE;
    savePrefs();
    render();
  }

  function countUp(node, to) {
    if (REDUCE || to < 2) { node.textContent = String(to); return; }
    var t0 = performance.now(), dur = 900;
    (function step(t) {
      var p = Math.min(1, (t - t0) / dur);
      node.textContent = String(Math.round(to * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(step);
    })(t0);
  }

  function renderHero(json) {
    var now = Date.now();
    var fresh = data.items.filter(function (i) { return now - new Date(i.published).getTime() <= 86400000; }).length;
    countUp($("st-new"), fresh);
    countUp($("st-total"), data.items.length);
    countUp($("st-kev"), data.kev.length);
    var ok = data.sources.filter(function (s) { return s.status === "ok"; }).length;
    $("st-src").textContent = json.demo ? "Demo" : ok + " / " + data.sources.length;

    var live = $("live");
    var age = (now - new Date(json.generated_at).getTime()) / 3600000;
    if (json.demo) {
      live.className = "live demo";
      $("live-text").textContent = "Demo data";
    } else if (age > 3) {
      live.className = "live stale";
      $("live-text").textContent = "Stale, updated " + ago(json.generated_at);
    } else {
      live.className = "live ok";
      $("live-text").textContent = "Live, updated " + ago(json.generated_at);
    }
  }

  function renderChips() {
    var base = baseItems();
    var box = $("chips");
    clear(box);
    TOPICS.forEach(function (t) {
      var n = base.filter(function (i) { return i.tags.indexOf(t.id) !== -1; }).length;
      var on = state.topics.indexOf(t.id) !== -1;
      var chip = el("button", {
        type: "button", class: "chip", "aria-pressed": on ? "true" : "false",
        onclick: function () { toggleTopic(t.id); }
      }, [
        el("span", { class: "swatch", "aria-hidden": "true" }),
        document.createTextNode(t.label),
        el("span", { class: "n", text: String(n) })
      ]);
      box.appendChild(setHue(chip, t.h));
    });
  }

  function renderPulse() {
    var base = baseItems();
    var counts = TOPICS.map(function (t) {
      return base.filter(function (i) { return i.tags.indexOf(t.id) !== -1; }).length;
    });
    var max = Math.max.apply(null, counts.concat([1]));
    var box = $("pulse");
    clear(box);
    TOPICS.forEach(function (t, idx) {
      var on = state.topics.indexOf(t.id) !== -1;
      var fill = el("span", { class: "fill" });
      fill.style.width = Math.round((counts[idx] / max) * 100) + "%";
      var row = el("button", {
        type: "button", class: "prow", "aria-pressed": on ? "true" : "false",
        onclick: function () { toggleTopic(t.id); }
      }, [
        el("span", { text: t.label }),
        el("span", { class: "track" }, [fill]),
        el("span", { class: "pnum", text: String(counts[idx]) })
      ]);
      box.appendChild(setHue(row, t.h));
    });
  }

  function renderList() {
    var items = filtered();
    var list = $("list");
    list.setAttribute("aria-busy", "false");
    clear(list);
    $("count").textContent = items.length + (items.length === 1 ? " article" : " articles");
    if (!items.length) {
      list.appendChild(el("div", { class: "empty", text: "Nothing matches these filters. Try a wider time range or fewer topics." }));
    }
    var now = Date.now();
    items.slice(0, state.shown).forEach(function (item, idx) {
      var href = safeHref(item.link);
      var primary = null;
      for (var k = 0; k < item.tags.length && !primary; k++) primary = topicById(item.tags[k]);
      var title = href
        ? el("a", { href: href, target: "_blank", rel: "noopener noreferrer", text: item.title })
        : document.createTextNode(item.title);
      var tags = el("div", { class: "tags" }, item.tags.map(function (t) {
        var topic = topicById(t);
        var pill = el("span", { class: "tagpill", text: topic ? topic.label : "General" });
        return setHue(pill, topic ? topic.h : 200);
      }));
      var isNew = now - new Date(item.published).getTime() < 3 * 3600000;
      var avatar = el("div", { class: "avatar", "aria-hidden": "true", text: initials(item.source) });
      avatar.style.setProperty("--a", String(hashHue(item.source)));
      var card = el("article", { class: "card" }, [
        avatar,
        el("div", {}, [
          el("div", { class: "meta" }, [
            el("span", { class: "src", text: item.source }),
            el("time", { datetime: item.published, title: item.published, text: ago(item.published) }),
            isNew ? el("span", { class: "new", text: "NEW" }) : null
          ]),
          el("h3", {}, [title]),
          item.summary ? el("p", { text: item.summary }) : null,
          tags
        ])
      ]);
      card.style.setProperty("--h", String(primary ? primary.h : 200));
      card.style.setProperty("--i", String(Math.min(idx, 12)));
      list.appendChild(card);
    });
    $("more").hidden = items.length <= state.shown;
  }

  function renderPanels() {
    var kev = $("kev");
    clear(kev);
    data.kev.forEach(function (v) {
      kev.appendChild(el("li", {}, [
        el("a", { class: "cve", href: "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(v.cve), target: "_blank", rel: "noopener noreferrer", text: v.cve }),
        el("div", { text: (v.vendor + " " + v.product).trim() }),
        el("div", { class: "sub", text: "Added " + v.added + (v.due ? ", fix due " + v.due : "") }),
        v.ransomware ? el("span", { class: "flag", text: "Used in ransomware campaigns" }) : null
      ]));
    });
    $("kev-panel").hidden = !data.kev.length;

    var iocs = $("iocs");
    clear(iocs);
    data.iocs.forEach(function (i) {
      iocs.appendChild(el("li", {}, [
        el("div", { class: "mono", text: i.indicator }),
        el("div", { class: "sub", text: (i.threat || "unknown") + (i.tags && i.tags.length ? " | " + i.tags.join(", ") : "") + " | " + i.source })
      ]));
    });
    $("ioc-panel").hidden = !data.iocs.length;
  }

  function renderSources() {
    var box = $("source-groups");
    clear(box);
    Object.keys(TYPE_LABELS).forEach(function (type) {
      var group = data.sources.filter(function (s) { return s.type === type; });
      if (!group.length) return;
      var grid = el("div", { class: "src-grid" }, group.map(function (s) {
        var cls = s.status === "ok" ? "ok" : (s.status === "error" ? "error" : "other");
        var label = s.status === "ok" ? s.count + " recent" : s.status;
        var home = safeHref(s.home);
        var name = home ? el("a", { href: home, target: "_blank", rel: "noopener noreferrer", text: s.name }) : document.createTextNode(s.name);
        return el("div", { class: "src-item" }, [name, el("span", { class: "st " + cls, text: label })]);
      }));
      box.appendChild(el("div", { class: "src-group" }, [el("h3", { text: TYPE_LABELS[type] }), grid]));
    });
  }

  function renderControls() {
    var names = {};
    data.items.forEach(function (i) { names[i.source] = true; });
    var sel = $("source");
    clear(sel);
    sel.appendChild(el("option", { value: "", text: "All sources" }));
    Object.keys(names).sort().forEach(function (n) { sel.appendChild(el("option", { value: n, text: n })); });
    sel.value = names[state.source] ? state.source : "";
    state.source = sel.value;
    var rng = $("range");
    clear(rng);
    RANGES.forEach(function (r) { rng.appendChild(el("option", { value: r.id, text: r.label })); });
    rng.value = state.range;
    if (rng.value !== state.range) { rng.value = "7"; state.range = "7"; }
    $("q").value = state.q;
  }

  function hasFilters() {
    return state.topics.length > 0 || state.source !== "" || state.q !== "" || state.range !== "7";
  }

  function render() {
    renderChips();
    renderPulse();
    renderList();
    $("clear").hidden = !hasFilters();
  }

  function bind() {
    var timer = null;
    $("q").addEventListener("input", function (e) {
      clearTimeout(timer);
      timer = setTimeout(function () { state.q = e.target.value.trim(); state.shown = PAGE; render(); }, 150);
    });
    $("source").addEventListener("change", function (e) { state.source = e.target.value; state.shown = PAGE; savePrefs(); render(); });
    $("range").addEventListener("change", function (e) { state.range = e.target.value; state.shown = PAGE; savePrefs(); render(); });
    $("clear").addEventListener("click", function () {
      state.topics = []; state.source = ""; state.q = ""; state.range = "7"; state.shown = PAGE;
      savePrefs(); renderControls(); render();
    });
    $("more").addEventListener("click", function () { state.shown += PAGE; renderList(); });

    var top = $("totop");
    window.addEventListener("scroll", function () { top.hidden = window.scrollY < 700; }, { passive: true });
    top.addEventListener("click", function () { window.scrollTo({ top: 0, behavior: REDUCE ? "auto" : "smooth" }); });
  }

  // Slow-drifting network of nodes behind the hero. Pauses off-screen and for reduced motion.
  function initNetwork() {
    var canvas = $("net");
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext("2d");
    var w = 0, h = 0, nodes = [], raf = 0, running = false, mouse = { x: -999, y: -999 };

    function spawn() {
      return { x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - 0.5) * 0.28, vy: (Math.random() - 0.5) * 0.28, r: 1 + Math.random() * 1.4 };
    }
    function resize() {
      var rect = canvas.parentNode.getBoundingClientRect();
      var dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = rect.width; h = rect.height;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      var n = Math.round(Math.min(72, Math.max(26, (w * h) / 17000)));
      while (nodes.length < n) nodes.push(spawn());
      nodes.length = n;
    }
    function frame() {
      ctx.clearRect(0, 0, w, h);
      var i, j, a, b, dx, dy, d;
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        if (!REDUCE) {
          a.x += a.vx; a.y += a.vy;
          if (a.x < 0 || a.x > w) a.vx *= -1;
          if (a.y < 0 || a.y > h) a.vy *= -1;
        }
        ctx.fillStyle = "rgba(94, 234, 212, 0.75)";
        ctx.beginPath(); ctx.arc(a.x, a.y, a.r, 0, 6.2832); ctx.fill();
        for (j = i + 1; j < nodes.length; j++) {
          b = nodes[j]; dx = a.x - b.x; dy = a.y - b.y; d = Math.sqrt(dx * dx + dy * dy);
          if (d < 125) {
            ctx.strokeStyle = "rgba(45, 212, 191, " + ((1 - d / 125) * 0.28).toFixed(3) + ")";
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
        dx = a.x - mouse.x; dy = a.y - mouse.y; d = Math.sqrt(dx * dx + dy * dy);
        if (d < 170) {
          ctx.strokeStyle = "rgba(96, 165, 250, " + ((1 - d / 170) * 0.5).toFixed(3) + ")";
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
        }
      }
      if (running && !REDUCE) raf = requestAnimationFrame(frame);
    }
    function start() { if (running) return; running = true; raf = requestAnimationFrame(frame); }
    function stop() { running = false; cancelAnimationFrame(raf); }

    resize();
    frame();
    window.addEventListener("resize", function () { resize(); if (REDUCE) frame(); });
    canvas.parentNode.addEventListener("pointermove", function (e) {
      var r = canvas.getBoundingClientRect();
      mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top;
    });
    canvas.parentNode.addEventListener("pointerleave", function () { mouse.x = -999; mouse.y = -999; });
    if (!REDUCE) {
      if ("IntersectionObserver" in window) {
        new IntersectionObserver(function (entries) { entries[0].isIntersecting ? start() : stop(); }).observe(canvas.parentNode);
      } else { start(); }
      document.addEventListener("visibilitychange", function () { document.hidden ? stop() : start(); });
    }
  }

  function start(json) {
    data = {
      items: Array.isArray(json.items) ? json.items : [],
      kev: Array.isArray(json.kev) ? json.kev : [],
      iocs: Array.isArray(json.iocs) ? json.iocs : [],
      sources: Array.isArray(json.sources) ? json.sources : []
    };
    loadPrefs();
    renderHero(json);
    renderControls();
    renderPanels();
    renderSources();
    bind();
    render();
  }

  function fail() {
    $("live-text").textContent = "No data yet";
    var list = $("list");
    list.setAttribute("aria-busy", "false");
    clear(list);
    list.appendChild(el("div", { class: "empty", text: "No data file found yet. Run the collector, then reload this page." }));
  }

  initNetwork();
  if (window.__NEWS__) {
    start(window.__NEWS__);
  } else {
    fetch("data/news.json", { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(start)
      .catch(fail);
  }
})();
