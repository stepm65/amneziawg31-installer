/* Progressive enhancements. No external dependencies; no browser storage or secrets. */
(() => {
  'use strict';
  const byId = (id) => document.getElementById(id);
  byId('refresh-page')?.addEventListener('click', () => window.location.reload());
  // Each navigation item is a separate route; never simulate pages with anchors.
  const navLinks = [...document.querySelectorAll('.side-link')];
  const current = window.location.pathname;
  for (const link of navLinks) {
    const selected = link.getAttribute('href') === current ||
      (current.startsWith('/maintenance') && link.dataset.navKey === 'maintenance') ||
      (current.includes('/clients/') && link.dataset.navKey === 'clients');
    link.classList.toggle('side-active', selected);
    if (selected) link.setAttribute('aria-current','page');
    else link.removeAttribute('aria-current');
  }
  const serverScope = document.body.dataset.serverScope || '';
  const mobileToggle = byId('mobile-nav-toggle');
  const mobileClose = byId('sidebar-mobile-close');
  const scrim = byId('nav-scrim');
  const sidebar = byId('app-sidebar');
  const setDrawer = (open) => {
    document.body.classList.toggle('nav-open', open);
    mobileToggle?.setAttribute('aria-expanded', String(open));
    if (open) mobileClose?.focus();
    else if (document.activeElement === mobileClose) mobileToggle?.focus();
  };
  mobileToggle?.addEventListener('click', () => setDrawer(!document.body.classList.contains('nav-open')));
  mobileClose?.addEventListener('click', () => setDrawer(false));
  scrim?.addEventListener('click', () => setDrawer(false));
  sidebar?.querySelectorAll('.side-link').forEach((link) => {
    link.addEventListener('click', () => setDrawer(false));
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && document.body.classList.contains('nav-open')) setDrawer(false);
  });
  // Server selection is done with real links in the sidebar; no stored global selector.
  document.body.classList.remove("nav-collapsed");
  for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  }
  const search = byId('client-search');
  const filter = byId('client-filter');
  function applyFilter() {
    const text = (search?.value || '').toLowerCase().trim();
    const status = filter?.value || 'all';
    for (const row of document.querySelectorAll('tr.client-row')) {
      const matches = (!text || row.dataset.name?.includes(text) || row.dataset.ip?.includes(text)) &&
        (status !== 'enabled' || row.dataset.enabled === '1');
      row.classList.toggle('hidden-by-filter', !matches);
    }
  }
  search?.addEventListener('input', applyFilter);
  filter?.addEventListener('change', applyFilter);
  byId('generate-obf')?.addEventListener('click', async () => {
    const button = byId('generate-obf');
    button.disabled = true;
    try {
      const reply = await fetch(`${serverScope}/api/obfuscation/generate`, {
        credentials:'same-origin', cache:'no-store'
      });
      if (!reply.ok) throw new Error(`HTTP ${reply.status}`);
      const params = await reply.json();
      const area = byId('obfuscation-fields');
      for (const [key,value] of Object.entries(params)) {
        const field = [...area.querySelectorAll('[name]')].find(x => x.name === key);
        if (field) field.value = String(value);
      }
      byId('obfuscation')?.setAttribute('open','');
    } catch (_) {
      window.alert(document.documentElement.lang === 'en' ?
        'Unable to generate parameters.' : 'Не удалось сгенерировать параметры.');
    } finally {button.disabled = false;}
  });
  if (!byId('traffic-chart')) return;

  const rxSamples = [], txSamples = [];
  let previous = null;
  let priorAt = null;
  const MAX_SAMPLES = 36;
  const formatRate = (n) => {
    if (!Number.isFinite(n) || n < 0) return '—';
    const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s'];
    let count = n;
    let index = 0;
    while (count >= 1024 && index < units.length - 1) { count /= 1024; index++; }
    return `${count.toFixed(index ? 1 : 0)} ${units[index]}`;
  };
  const path = (values, max) => values.map((value, i) => {
    const x = values.length < 2 ? 0 : (i / (values.length - 1)) * 620;
    const y = 181 - Math.min(value / max, 1) * 167;
    return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  function draw() {
    const max = Math.max(1024, ...rxSamples, ...txSamples) * 1.12;
    byId('chart-rx').setAttribute('d', path(rxSamples, max));
    byId('chart-tx').setAttribute('d', path(txSamples, max));
  }
  let busy = false;
  async function poll() {
    if (busy || document.hidden) return;
    busy = true;
    try {
      const response = await fetch(`${serverScope}/api/traffic`, {cache:'no-store', credentials:'same-origin'});
      if (!response.ok) throw Error(`HTTP ${response.status}`);
      const value = await response.json();
      const now = performance.now();
      if (previous && priorAt) {
        const seconds = (now - priorAt) / 1000;
        if (seconds > 0) {
          // Counter resets (e.g. VPN restarted) display zero, not a negative rate.
          const rx = Math.max(0, Number(value.rx) - Number(previous.rx)) / seconds;
          const tx = Math.max(0, Number(value.tx) - Number(previous.tx)) / seconds;
          rxSamples.push(rx); txSamples.push(tx);
          if (rxSamples.length > MAX_SAMPLES) rxSamples.shift();
          if (txSamples.length > MAX_SAMPLES) txSamples.shift();
          byId('rx-rate').textContent = formatRate(rx);
          byId('tx-rate').textContent = formatRate(tx);
          draw();
          byId('traffic-chart-message')?.replaceChildren();
        }
      }
      previous = value; priorAt = now;
      if (byId('live-connected')) byId('live-connected').textContent = String(value.connected);
    } catch (_) {
      // Keep last good measurements; avoid displaying invented traffic.
    } finally { busy = false; }
  }
  poll();
  window.setInterval(poll, 4000);
})();

// Config export tabs and local-only copy controls.
(() => {
  'use strict';
  const tabs = [...document.querySelectorAll('[data-tab-target]')];
  const setTab = (tab) => {
    if (!tab || tab.disabled) return;
    for (const button of tabs) {
      const active = button === tab;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', String(active));
      const panel = document.getElementById(button.dataset.tabTarget);
      if (panel) panel.hidden = !active;
    }
  };
  for (const tab of tabs) {
    tab.addEventListener('click', () => setTab(tab));
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowRight', 'ArrowLeft'].includes(event.key)) return;
      const available = tabs.filter((button) => !button.disabled);
      const i = available.indexOf(tab);
      if (i < 0) return;
      const step = event.key === 'ArrowRight' ? 1 : -1;
      const next = available[(i + step + available.length) % available.length];
      next.focus(); setTab(next); event.preventDefault();
    });
  }
  for (const btn of document.querySelectorAll('[data-copy-target]')) {
    btn.addEventListener('click', async () => {
      const input = document.getElementById(btn.dataset.copyTarget);
      if (!input) return;
      const status = document.getElementById('copy-status');
      try {
        if (!navigator.clipboard?.writeText) throw Error('Clipboard not available');
        await navigator.clipboard.writeText(input.value);
        if (status) status.textContent = status.dataset.copyOk || 'Copied';
      } catch (_) {
        input.focus(); input.select();
        if (status) status.textContent = status.dataset.copyFailed || 'Select and copy manually';
      }
    });
  }
})();

// Persistent history is collected server-side by the systemd sampler.
(() => {
  'use strict';
  const selector=document.getElementById('history-window');
  if (!selector) return;
  const rx=document.getElementById('history-rx');
  const tx=document.getElementById('history-tx');
  const info=document.getElementById('history-info');
  const draw=(items,max)=>items.map((n,i)=>{
    const x=items.length===1?0:i*620/(items.length-1);
    return `${i?'L':'M'}${x.toFixed(1)},${(180-n/max*165).toFixed(1)}`;
  }).join(' ');
  async function load() {
    try {
      const response=await fetch(`${document.body.dataset.serverScope || ''}/api/history?window=`+encodeURIComponent(selector.value),
         {cache:'no-store',credentials:'same-origin'});
      if (!response.ok) throw Error('HTTP '+response.status);
      const data=await response.json();
      const points=data.points||[];
      if (!points.length) {
        rx.setAttribute('d','');tx.setAttribute('d','');
        info.hidden=false;
        return;
      }
      const peak=Math.max(1,...points.map(p=>p.rx),...points.map(p=>p.tx));
      rx.setAttribute('d',draw(points.map(p=>p.rx),peak));
      tx.setAttribute('d',draw(points.map(p=>p.tx),peak));
      info.hidden=true;
    } catch (_) {info.hidden=false;}
  }
  selector.addEventListener('change',load);
  load();
})();
