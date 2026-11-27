/* Progressive enhancements. No external dependencies; no browser storage or secrets. */

// Traffic charts: speeds in bits per second (as the speed limits), a "nice" top of the scale.
const awgChart = {
  units(frame) {
    const d = frame?.dataset || {};
    return [d.unitB || 'bit/s', d.unitK || 'kbit/s', d.unitM || 'Mbit/s', d.unitG || 'Gbit/s'];
  },
  rate(bytesPerSecond, frame) {
    if (!Number.isFinite(bytesPerSecond) || bytesPerSecond < 0) return '—';
    let value = bytesPerSecond * 8, index = 0;
    const units = awgChart.units(frame);
    while (value >= 1000 && index < units.length - 1) { value /= 1000; index++; }
    const digits = value >= 100 || index === 0 ? 0 : value >= 10 ? 1 : 2;
    const locale = document.documentElement.lang === 'en' ? 'en-GB' : 'ru-RU';
    return `${value.toLocaleString(locale, {maximumFractionDigits: digits})} ${units[index]}`;
  },
  // The top of the scale in bytes/s: 1, 2, 2.5 or 5 times a power of ten, in bits.
  niceMax(bytesPerSecond) {
    const bits = Math.max(8000, bytesPerSecond * 8 * 1.1);
    const power = Math.pow(10, Math.floor(Math.log10(bits)));
    const step = [1, 2, 2.5, 5, 10].find(x => x * power >= bits);
    return step * power / 8;
  },
  ticks(frame, max) {
    for (const [key, value] of [['max', max], ['mid', max / 2]]) {
      const tick = frame?.querySelector(`[data-tick="${key}"]`);
      if (tick) tick.textContent = awgChart.rate(value, frame);
    }
  },
  // y in a 190 high view box: the top of the scale at 30, zero at 181 (md3.css puts the axis labels there).
  path(values, max, width = 620) {
    return values.map((value, i) => {
      const x = values.length < 2 ? 0 : (i / (values.length - 1)) * width;
      const y = 181 - Math.min(value / max, 1) * 151;
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  },
};

(() => {
  'use strict';
  const byId = (id) => document.getElementById(id);
  let redirectedForLogin = false;
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await nativeFetch(...args);
    if (response.status === 401 && !redirectedForLogin) {
      redirectedForLogin = true;
      const next = window.location.pathname + window.location.search;
      window.location.assign('/login?next=' + encodeURIComponent(next));
    }
    return response;
  };
  byId('refresh-page')?.addEventListener('click', () => window.location.reload());
  for (const button of document.querySelectorAll('[data-expiry-open]')) {
    const field = byId(button.dataset.expiryOpen);
    const calendar = byId(button.getAttribute('aria-controls'));
    const russian = calendar.lang === 'ru';
    const locale = russian ? 'ru-RU' : 'en-GB';
    const weekdays = russian ? ['Пн','Вт','Ср','Чт','Пт','Сб','Вс'] : ['Mo','Tu','We','Th','Fr','Sa','Su'];
    calendar.innerHTML = '<header><button type="button" data-month="-1">‹</button>' +
      '<strong aria-live="polite"></strong><button type="button" data-month="1">›</button></header>' +
      '<div class="expiry-calendar-days"></div><footer><button type="button" data-today>' +
      (russian ? 'Сегодня' : 'Today') + '</button><button type="button" data-clear>' +
      (russian ? 'Очистить' : 'Clear') + '</button></footer>';
    const previous = calendar.querySelector('[data-month="-1"]');
    const next = calendar.querySelector('[data-month="1"]');
    previous.setAttribute('aria-label', russian ? 'Предыдущий месяц' : 'Previous month');
    next.setAttribute('aria-label', russian ? 'Следующий месяц' : 'Next month');
    const days = calendar.querySelector('.expiry-calendar-days');
    let month;
    function parsedDate() {
      const value = field.value.trim();
      const local = /^(\d{2})\.(\d{2})\.(\d{4})$/.exec(value);
      const iso = /^(\d{4})-(\d{2})-(\d{2})(?:$|[T ])/.exec(value);
      if (!local && !iso) return null;
      const [year, monthNumber, day] = local ?
        [Number(local[3]), Number(local[2]), Number(local[1])] : iso.slice(1, 4).map(Number);
      const date = new Date();
      date.setHours(12, 0, 0, 0);
      date.setFullYear(year, monthNumber - 1, day);
      return year > 0 && date.getFullYear() === year && date.getMonth() === monthNumber - 1 &&
        date.getDate() === day ? date : null;
    }
    function closeCalendar() {
      calendar.hidden = true;
      button.setAttribute('aria-expanded', 'false');
    }
    function selectDate(date) {
      const day = String(date?.getDate()).padStart(2, '0');
      const monthNumber = String(date?.getMonth() + 1).padStart(2, '0');
      const year = String(date?.getFullYear()).padStart(4, '0');
      field.value = date ? (russian ? day + '.' + monthNumber + '.' + year : year + '-' + monthNumber + '-' + day) : '';
      closeCalendar();
      field.dispatchEvent(new Event('input', {bubbles: true}));
      field.dispatchEvent(new Event('change', {bubbles: true}));
      field.focus();
    }
    function renderCalendar() {
      calendar.querySelector('strong').textContent = month.toLocaleDateString(locale, {month:'long', year:'numeric'});
      previous.disabled = month.getFullYear() === 1 && month.getMonth() === 0;
      next.disabled = month.getFullYear() === 9999 && month.getMonth() === 11;
      days.replaceChildren();
      for (const weekday of weekdays) {
        const label = document.createElement('span');
        label.textContent = weekday;
        days.append(label);
      }
      const selected = parsedDate();
      const date = new Date(month);
      while (date.getMonth() === month.getMonth()) {
        const day = document.createElement('button');
        day.type = 'button';
        day.textContent = date.getDate();
        day.dataset.day = date.getDate();
        day.setAttribute('aria-label', date.toLocaleDateString(locale, {day:'numeric', month:'long', year:'numeric'}));
        day.setAttribute('aria-pressed', String(Boolean(selected && selected.toDateString() === date.toDateString())));
        if (date.getDate() === 1) day.style.gridColumnStart = (date.getDay() + 6) % 7 + 1;
        days.append(day);
        date.setDate(date.getDate() + 1);
      }
    }
    function openCalendar() {
      month = parsedDate() || new Date();
      month.setDate(1);
      renderCalendar();
      calendar.hidden = false;
      button.setAttribute('aria-expanded', 'true');
      (days.querySelector('[aria-pressed="true"]') || days.querySelector('button')).focus();
      calendar.scrollIntoView({block: 'nearest'});
    }
    button.addEventListener('click', () => calendar.hidden ? openCalendar() : closeCalendar());
    calendar.addEventListener('click', event => {
      const target = event.target.closest('button');
      if (!target) return;
      if (target.hasAttribute('data-month')) {
        month.setMonth(month.getMonth() + Number(target.dataset.month));
        renderCalendar();
      } else if (target.hasAttribute('data-day')) {
        const date = new Date(month);
        date.setDate(Number(target.dataset.day));
        selectDate(date);
      } else if (target.hasAttribute('data-today')) {
        selectDate(new Date());
      } else if (target.hasAttribute('data-clear')) {
        selectDate(null);
      }
    });
    field.addEventListener('input', () => {
      if (!calendar.hidden) {
        const selected = parsedDate();
        if (selected) { month = selected; month.setDate(1); }
        renderCalendar();
      }
    });
    field.parentElement.addEventListener('keydown', event => {
      const dayOffset = {ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7}[event.key];
      if (dayOffset && event.target.hasAttribute('data-day')) {
        event.preventDefault();
        const date = new Date(month);
        date.setDate(Number(event.target.dataset.day) + dayOffset);
        if (date.getFullYear() < 1 || date.getFullYear() > 9999) return;
        month = new Date(date);
        month.setDate(1);
        renderCalendar();
        days.querySelector('[data-day="' + date.getDate() + '"]').focus();
      }
      if (event.key === 'Escape' && !calendar.hidden) {
        event.preventDefault();
        closeCalendar();
        button.focus();
      }
      if (event.altKey && event.key === 'ArrowDown') {
        event.preventDefault();
        openCalendar();
      }
    });
    document.addEventListener('click', event => {
      if (!field.parentElement.contains(event.target)) closeCalendar();
    });
    field.parentElement.addEventListener('focusout', event => {
      if (event.relatedTarget && !field.parentElement.contains(event.relatedTarget)) closeCalendar();
    });
    button.hidden = false;
  }
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
  // Native dialog is part of the panel, not a browser confirm popup.
  const modal = document.createElement('dialog');
  modal.className = 'awg-confirm-dialog';
  modal.innerHTML = '<div class="awg-confirm-content"><h2></h2><p></p><div class="awg-confirm-actions"><button type="button" class="btn btn-secondary" data-cancel></button><button type="button" class="btn btn-primary" data-accept></button></div></div>';
  document.body.append(modal);
  const isRu = document.documentElement.lang === 'ru';
  modal.querySelector('h2').textContent = isRu ? 'Подтверждение действия' : 'Confirm action';
  modal.querySelector('[data-cancel]').textContent = isRu ? 'Отмена' : 'Cancel';
  modal.querySelector('[data-accept]').textContent = isRu ? 'Подтвердить' : 'Confirm';
  const close = () => modal.close();
  modal.querySelector('[data-cancel]').addEventListener('click', close);
  let confirmedForm = null;
  let confirmedSubmitter = null;
  modal.querySelector('[data-accept]').addEventListener('click', () => {
    const form = confirmedForm, submitter = confirmedSubmitter;
    confirmedForm = null; confirmedSubmitter = null;
    close();
    if (!form) return;
    if (form.dataset.confirm) form.dataset.confirmed = '1';    // lets the form's own confirmation pass once
    submitter ? form.requestSubmit(submitter) : form.requestSubmit();
  });
  modal.addEventListener('close', () => { confirmedForm = null; confirmedSubmitter = null; });
  // A single button that needs confirmation (for example "Clear" next to the Telegram token).
  for (const button of document.querySelectorAll('button[data-confirm-submit]')) {
    button.addEventListener('click', (event) => {
      const form = button.form;
      if (!form) return;
      event.preventDefault();
      confirmedForm = form; confirmedSubmitter = button;
      modal.querySelector('p').textContent = button.dataset.confirmSubmit;
      modal.showModal();
    });
  }
  for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', (event) => {
      if (form.dataset.confirmed === '1') { delete form.dataset.confirmed; return; }
      if (!form.dataset.confirm) return;
      event.preventDefault();
      confirmedForm = form;
      modal.querySelector('p').textContent = form.dataset.confirm;
      modal.showModal();
    });
  }
  const peerCheckboxes = [...document.querySelectorAll('.peer-select')];
  const allPeers = byId('select-all-peers');
  const bulkButton = byId('bulk-delete-button');
  const bulkCount = byId('bulk-selection-count');
  const bulkBar = byId('bulk-toolbar');
  function updatePeerSelection() {
    const selected = peerCheckboxes.filter(x => x.checked).length;
    if (bulkBar) bulkBar.hidden = selected === 0;
    if (bulkButton) bulkButton.disabled = selected === 0;
    for (const button of document.querySelectorAll('[data-needs-selection]')) button.disabled = selected === 0;
    if (bulkCount) bulkCount.textContent = (isRu ? 'Выбрано: ' : 'Selected: ') + selected;
    if (allPeers) {
      allPeers.checked = peerCheckboxes.length > 0 && selected === peerCheckboxes.length;
      allPeers.indeterminate = selected > 0 && selected < peerCheckboxes.length;
    }
  }
  allPeers?.addEventListener('change', () => {
    // "All" means the rows the filter shows: a group can be selected and acted on at once.
    peerCheckboxes.forEach(x => {
      x.checked = allPeers.checked && !x.closest('tr')?.classList.contains('hidden-by-filter');
    });
    updatePeerSelection();
  });
  peerCheckboxes.forEach(x => x.addEventListener('change', updatePeerSelection));
  byId('bulk-clear')?.addEventListener('click', () => {
    peerCheckboxes.forEach(x => { x.checked = false; });
    updatePeerSelection();
    allPeers?.focus();
  });

  const search = byId('client-search');
  const statusFilters = [...document.querySelectorAll('[data-client-status]')];
  const groupFilter = byId('client-group-filter');
  const stateFilter = byId('client-state-filter');
  const chips = [...document.querySelectorAll('[data-client-chip]')];
  const clientCount = byId('client-count');
  let chip = 'all';
  // The four chips are the everyday cut: everyone / online now / enabled but offline / switched off.
  const chipMatch = (row) => chip === 'all' || (chip === 'disabled' ? row.dataset.enabled === '0'
    : row.dataset.enabled === '1' && (row.dataset.presence === 'online') === (chip === 'online'));
  function applyFilter() {
    const text = (search?.value || '').toLowerCase().trim();
    const statuses = statusFilters.filter(input => input.checked).map(input => input.dataset.clientStatus);
    const group = groupFilter ? groupFilter.value : '*';
    const flag = stateFilter ? stateFilter.value : '';
    for (const row of document.querySelectorAll('tr.client-row')) {
      const matches = (!text || row.dataset.name?.includes(text) || row.dataset.ip?.includes(text) || row.dataset.text?.includes(text)) &&
        (!statusFilters.length || statuses.includes(row.dataset.enabled)) &&
        (group === '*' || (row.dataset.group || '') === group) &&
        (!flag || (row.dataset.flags || '').split(' ').includes(flag)) && chipMatch(row);
      row.classList.toggle('hidden-by-filter', !matches);
    }
    if (clientCount) {
      const total = Number(clientCount.dataset.total || 0);
      const shown = document.querySelectorAll('tr.client-row:not(.hidden-by-filter)').length;
      clientCount.textContent = shown === total ? `${total} ${isRu ? 'клиентов' : 'peers'}`
        : (isRu ? `${shown} из ${total} клиентов` : `${shown} of ${total} peers`);
    }
  }
  chips.forEach(button => button.addEventListener('click', () => {
    chip = button.dataset.clientChip;
    chips.forEach(x => x.setAttribute('aria-pressed', String(x === button)));
    applyFilter();
  }));
  search?.addEventListener('input', applyFilter);
  statusFilters.forEach(input => input.addEventListener('change', applyFilter));
  groupFilter?.addEventListener('change', applyFilter);
  stateFilter?.addEventListener('change', applyFilter);
  applyFilter();

  // Row menus: a fixed list, so the table's own scroll area never clips it; it flips up near the bottom edge.
  const rowMenus = () => [...document.querySelectorAll('details.row-menu[open]')];
  const closeRowMenus = (except) => rowMenus().forEach(menu => { if (menu !== except) menu.removeAttribute('open'); });
  const placeRowMenu = (menu) => {
    const list = menu.querySelector('.row-menu-list');
    const anchor = menu.querySelector('summary').getBoundingClientRect();
    // The button scrolled out of sight: the menu goes with it.
    if (anchor.bottom < 0 || anchor.top > window.innerHeight) { menu.removeAttribute('open'); return; }
    const width = list.offsetWidth, height = list.offsetHeight;
    const left = Math.min(window.innerWidth - width - 8, Math.max(8, anchor.right - width));
    const below = anchor.bottom + 6;
    list.style.left = left + 'px';
    list.style.top = (below + height > window.innerHeight - 8 ? Math.max(8, anchor.top - height - 6) : below) + 'px';
  };
  for (const menu of document.querySelectorAll('details.row-menu')) {
    menu.addEventListener('toggle', () => {
      if (!menu.open) return;
      closeRowMenus(menu);
      placeRowMenu(menu);
    });
  }
  document.addEventListener('click', event => {
    for (const menu of rowMenus()) if (!menu.contains(event.target)) menu.removeAttribute('open');
  });
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    for (const menu of rowMenus()) {
      menu.removeAttribute('open');
      menu.querySelector('summary')?.focus();
    }
  });
  // Scrolling (the page, or the table sideways) moves an open menu along instead of closing it:
  // opening a menu near the bottom edge scrolls the page a little, and that must not shut it again.
  window.addEventListener('scroll', () => rowMenus().forEach(placeRowMenu), true);
  window.addEventListener('resize', () => closeRowMenus());

  // "12 s ago" keeps counting while the page stays open.
  const agoUnits = isRu ? ['с', 'мин', 'ч', 'д'] : ['s', 'min', 'h', 'd'];
  function refreshAgo() {
    const now = Math.floor(Date.now() / 1000);
    for (const el of document.querySelectorAll('[data-since]')) {
      const seconds = Math.max(0, now - Number(el.dataset.since));
      const [value, unit] = seconds < 60 ? [seconds, 0] : seconds < 3600 ? [Math.floor(seconds / 60), 1]
        : seconds < 86400 ? [Math.floor(seconds / 3600), 2] : [Math.floor(seconds / 86400), 3];
      el.textContent = isRu ? `${value} ${agoUnits[unit]} назад` : `${value} ${agoUnits[unit]} ago`;
    }
  }
  if (document.querySelector('[data-since]')) window.setInterval(refreshAgo, 15000);
  // I1–I5 helpers: a random value per field and ready-made templates for I1.
  for (const box of document.querySelectorAll('[data-cps]')) {
    const enable = box.querySelector('[data-cps-enabled]');
    const fill = async (button, preset) => {
      const target = byId(button.dataset.cpsGenerate || button.dataset.cpsApply);
      if (!target) return;
      button.disabled = true;
      try {
        const host = box.querySelector('[data-cps-host]')?.value.trim() || '';
        const query = 'preset=' + encodeURIComponent(preset) +
          (preset === 'quictls' ? '&host=' + encodeURIComponent(host) : '');
        const reply = await fetch('/api/cps/generate?' + query, {credentials:'same-origin', cache:'no-store'});
        if (reply.status === 422) {
          const problem = await reply.json().catch(() => ({}));
          window.alert(String(problem.detail || box.dataset.cpsError));
          return;
        }
        if (!reply.ok) throw new Error(`HTTP ${reply.status}`);
        const data = await reply.json();
        target.value = String(data.value || '');
        target.dispatchEvent(new Event('input', {bubbles: true}));
        if (enable && target.value) enable.checked = true;
        box.setAttribute('open', '');
        target.focus();
      } catch (_) {
        window.alert(box.dataset.cpsError || 'Unable to generate a value.');
      } finally {button.disabled = false;}
    };
    box.querySelectorAll('[data-cps-generate]').forEach((button) =>
      button.addEventListener('click', () => fill(button, 'random')));
    box.querySelectorAll('[data-cps-apply]').forEach((button) =>
      button.addEventListener('click', () => fill(button, box.querySelector('[data-cps-preset]')?.value || 'random')));
  }
  byId('generate-obf')?.addEventListener('click', async () => {
    const button = byId('generate-obf');
    button.disabled = true;
    try {
      const timingRanges = Boolean(byId('generate-timings')?.checked);
      const reply = await fetch(`${serverScope}/api/obfuscation/generate?timing_ranges=${timingRanges ? 'true' : 'false'}`, {
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

  const frame = byId('live-frame');
  const rxSamples = [], txSamples = [];
  let previous = null;
  let priorAt = null;
  const MAX_SAMPLES = 36;
  const formatRate = (n) => awgChart.rate(n, frame);
  const SAMPLE_SECONDS = 4;
  function draw() {
    const max = awgChart.niceMax(Math.max(0, ...rxSamples, ...txSamples));
    byId('chart-rx').setAttribute('d', awgChart.path(rxSamples, max));
    byId('chart-tx').setAttribute('d', awgChart.path(txSamples, max));
    awgChart.ticks(frame, max);
    const from = byId('live-from');
    if (from) from.textContent = (from.dataset.ago || '{n} s ago').replace('{n}', String((rxSamples.length - 1) * SAMPLE_SECONDS));
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
  const siblings = (tab) => [...(tab.closest('[role="tablist"]') || document).querySelectorAll('[data-tab-target]')];
  const setTab = (tab) => {
    if (!tab || tab.disabled) return;
    for (const button of siblings(tab)) {
      const active = button === tab;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', String(active));
      const panel = document.getElementById(button.dataset.tabTarget);
      if (panel) panel.hidden = !active;
    }
    // Remember the tab: the form sends it back and a reload opens the same one.
    const memory = tab.closest('form')?.querySelector('[data-tab-memory]');
    if (memory && tab.dataset.tabName) {
      memory.value = tab.dataset.tabName;
      const url = new URL(window.location.href);
      url.searchParams.set('sub', tab.dataset.tabName);
      url.searchParams.delete('done');
      window.history.replaceState(null, '', url);
    }
  };
  for (const tab of tabs) {
    tab.addEventListener('click', () => setTab(tab));
    tab.addEventListener('keydown', (event) => {
      if (!['ArrowRight', 'ArrowLeft'].includes(event.key)) return;
      const available = siblings(tab).filter((button) => !button.disabled);
      const i = available.indexOf(tab);
      if (i < 0) return;
      const step = event.key === 'ArrowRight' ? 1 : -1;
      const next = available[(i + step + available.length) % available.length];
      next.focus(); setTab(next); event.preventDefault();
    });
  }
  // Showing and hiding the .conf text is a native <details>; no script is involved.
  const configDetails = document.getElementById('cfgx-config-details');
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
        if (configDetails && configDetails.contains(input)) configDetails.open = true;
        input.focus(); input.select();
        if (status) status.textContent = status.dataset.copyFailed || 'Select and copy manually';
      }
    });
  }
})();

// Persistent history is collected server-side by the systemd sampler.
// Each point is the traffic of one interval (data.bucket seconds), drawn as its average speed.
(() => {
  'use strict';
  const selector=document.getElementById('history-window');
  if (!selector) return;
  const byId=(id)=>document.getElementById(id);
  const frame=byId('history-frame'), svg=byId('history-chart'), tip=byId('history-tip'), cursor=byId('history-cursor');
  const rx=byId('history-rx'), tx=byId('history-tx'), info=byId('history-info');
  const lang=frame?.dataset.lang==='en' ? 'en-GB' : 'ru-RU';
  let shown=[];
  const when=(ts,win)=>{
    const date=new Date(ts*1000);
    return win==='24h' ? date.toLocaleTimeString(lang,{hour:'2-digit',minute:'2-digit'})
      : date.toLocaleDateString(lang,{day:'2-digit',month:'2-digit'})+(win==='7d' ? ' '+date.toLocaleTimeString(lang,{hour:'2-digit',minute:'2-digit'}) : '');
  };
  const span=(seconds)=>{
    const ru=lang==='ru-RU';
    if (seconds<3600) return `${Math.round(seconds/60)} ${ru?'мин':'min'}`;
    return `${Math.round(seconds/3600)} ${ru?'ч':'h'}`;
  };
  const bytes=(n)=>{
    const units=lang==='ru-RU' ? ['Б','КиБ','МиБ','ГиБ','ТиБ'] : ['B','KiB','MiB','GiB','TiB'];
    let i=0; while(n>=1024 && i<units.length-1){n/=1024;i++;}
    return `${n.toLocaleString(lang,{maximumFractionDigits:i?1:0})} ${units[i]}`;
  };
  async function load() {
    try {
      const response=await fetch(`${document.body.dataset.serverScope || ''}/api/history?window=`+encodeURIComponent(selector.value),
         {cache:'no-store',credentials:'same-origin'});
      if (!response.ok) throw Error('HTTP '+response.status);
      const data=await response.json();
      const points=data.points||[];
      const bucket=Math.max(1, Number(data.bucket)||60);
      if (!points.length) {
        rx.setAttribute('d','');tx.setAttribute('d','');shown=[];
        for (const id of ['history-from','history-mid','history-to','history-note']) byId(id).textContent='';
        for (const tick of frame.querySelectorAll('[data-tick="max"],[data-tick="mid"]')) tick.textContent='';
        info.hidden=false;
        return;
      }
      shown=points.map(p=>({ts:p.ts, rx:p.rx/bucket, tx:p.tx/bucket}));
      const max=awgChart.niceMax(Math.max(0,...shown.map(p=>p.rx),...shown.map(p=>p.tx)));
      rx.setAttribute('d',awgChart.path(shown.map(p=>p.rx),max));
      tx.setAttribute('d',awgChart.path(shown.map(p=>p.tx),max));
      awgChart.ticks(frame,max);
      byId('history-from').textContent=when(shown[0].ts,selector.value);
      byId('history-mid').textContent=shown.length>2 ? when(shown[Math.floor((shown.length-1)/2)].ts,selector.value) : '';
      byId('history-to').textContent=when(shown[shown.length-1].ts,selector.value);
      const total=points.reduce((sum,p)=>({rx:sum.rx+p.rx,tx:sum.tx+p.tx}),{rx:0,tx:0});
      byId('history-note').textContent=(frame.dataset.avg||'').replace('{n}',span(bucket))+' · '
        +(frame.dataset.total||'').replace('{rx}',bytes(total.rx)).replace('{tx}',bytes(total.tx));
      info.hidden=true;
    } catch (_) {info.hidden=false;}
  }
  // Hover: the point under the pointer, its time and both speeds.
  svg?.addEventListener('pointermove', event => {
    if (!shown.length) return;
    const box=svg.getBoundingClientRect();
    const share=Math.min(1,Math.max(0,(event.clientX-box.left)/box.width));
    const index=Math.round(share*(shown.length-1));
    const point=shown[index];
    const x=shown.length<2 ? 0 : index/(shown.length-1)*620;
    cursor.setAttribute('x1',x); cursor.setAttribute('x2',x); cursor.setAttribute('visibility','visible');
    const date=new Date(point.ts*1000);
    tip.replaceChildren();
    const head=document.createElement('strong');
    head.textContent=date.toLocaleString(lang,{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
    const up=document.createElement('span'); up.className='tip-rx'; up.textContent='↑ '+awgChart.rate(point.rx,frame);
    const down=document.createElement('span'); down.className='tip-tx'; down.textContent='↓ '+awgChart.rate(point.tx,frame);
    tip.append(head,up,down);
    tip.hidden=false;
    const left=Math.min(box.width-tip.offsetWidth-4,Math.max(4,event.clientX-box.left+12));
    tip.style.left=left+'px';
  });
  svg?.addEventListener('pointerleave', () => {tip.hidden=true; cursor.setAttribute('visibility','hidden');});
  selector.addEventListener('change',load);
  load();
})();

// Infrastructure dashboard: host resources + real, isolated per-AWG traffic.
(() => {
  'use strict';
  const main = document.querySelector('.infrastructure-dashboard');
  if (!main) return;
  const byId = (id) => document.getElementById(id);
  const translate = document.documentElement.lang === 'en';
  const windowLength = { '5m':300, '15m':900, '1h':3600 };
  const sampleLimit = 720;
  const instances = [...document.querySelectorAll('[data-awg-instance]')].map(node => node.dataset.awgInstance);
  const previous = new Map();
  const live = new Map([['wan', []], ...instances.map(i => [i, []])]);
  const history = new Map();
  const hostHistory = new Map();
  const historyAt = new Map();
  const plots = [...document.querySelectorAll('[data-plot]')];
  const cpu = [], ram = [], swap = [], disk = [], sockets = [];
  let previousHost = null;
  let previousAt = null;
  let updating = false;
  let historyUpdating = false;
  const strip = document.querySelector('.fleet-status');
  const periodButtons = [...document.querySelectorAll('[data-period-switch] [data-period]')];
  let currentWindow = '15m';
  const tilePct = {};
  const running = new Map();
  let failures = 0;

  const formatBytes = (value) => {
    if (value === null || !Number.isFinite(Number(value)) || Number(value) < 0) return '—';
    const units=['B','KiB','MiB','GiB','TiB']; let n=Number(value), i=0;
    while (n >= 1024 && i < units.length - 1) {n/=1024; i++;}
    return `${n.toFixed(i===0?0:1)} ${units[i]}`;
  };
  const formatRate = (value) => value===null ? '—' : `${formatBytes(value)}/s`;
  const formatDuration = (value) => {
    if (!Number.isFinite(value) || value < 0) return '—';
    const d=Math.floor(value/86400),h=Math.floor(value%86400/3600),m=Math.floor(value%3600/60);
    if (d) return `${d}${translate?'d':'д'} ${h}${translate?'h':'ч'}`;
    return `${h}${translate?'h':'ч'} ${m}${translate?'m':'м'}`;
  };
  const text = (id, value) => {const el=byId(id);if(el)el.textContent=String(value);};
  const bounded = (v, fallback=0) => Number.isFinite(v) ? Math.max(0,v) : fallback;
  const safeCounter = (value) => Number.isFinite(Number(value)) && Number(value)>=0 ? Number(value) : null;
  const append = (list, point) => {list.push(point); if(list.length>sampleLimit)list.splice(0,list.length-sampleLimit);};

  // Draw one continuous SVG curve from observed values; no seeded/fake samples.
  function smooth(points) {
    if (!points.length) return '';
    if (points.length===1) return `M${(points[0].x-2).toFixed(1)},${points[0].y.toFixed(1)}h4`;
    let output=`M${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`;
    for(let i=1;i<points.length;i++) {
      const prev=points[i-1],now=points[i],mid=(prev.x+now.x)/2;
      output+=` C${mid.toFixed(1)},${prev.y.toFixed(1)} ${mid.toFixed(1)},${now.y.toFixed(1)} ${now.x.toFixed(1)},${now.y.toFixed(1)}`;
    }
    return output;
  }
  function fillPath(points, baseline) {
    if(points.length < 2) return '';
    return `${smooth(points)} L${points.at(-1).x.toFixed(1)},${baseline} L${points[0].x.toFixed(1)},${baseline} Z`;
  }
  function setPath(root, selector, d) {const el=root.querySelector(selector);if(el)el.setAttribute('d',d);}

  function drawSmall(key, values) {
    if(!values.length) return;
    // A resource card is filled from the bottom to its current share: the chart spans the whole
    // card on a 0-100 % scale. One sample is enough to show the level as a flat fill.
    if(values.length < 2) {
      if(key==='socket') return;
      values=[values[0],values[0]];
    }
    const max=key==='socket' ? Math.max(1,...values) : 100;
    const width=280,base=key==='socket'?111:100,height=key==='socket'?104:100;
    const scaled=values.map((v,i)=>({x:i*width/(values.length-1),y:base-height*Math.min(1,Math.max(0,v/max))}));
    if(key==='socket') {
      setPath(main,'[data-socket-line]',smooth(scaled));
      setPath(main,'[data-socket-area]',fillPath(scaled,base));
    } else {
      setPath(main,`[data-kpi-line="${key}"]`,smooth(scaled));
      setPath(main,`[data-kpi-area="${key}"]`,fillPath(scaled,base));
    }
  }

  function selectedWindow() {return currentWindow;}
  function historyPoints(name,win) {
    const all=name==='wan' ? (hostHistory.get(win)||[]) : (history.get(win)?.get(name)||[]);
    const size=windowLength[win];
    const now=Date.now()/1000;
    const source=live.get(name) || [];
    const visibleLive=source.filter(p=>p.ts >= now-size);
    // A minute-bin reflects the preceding collection interval, not a 5s rate.
    const edge=visibleLive.length?visibleLive[0].ts-60:Infinity;
    const archived=all.filter(p=>p.ts>=now-size && p.ts<edge && p.rx!==null && p.tx!==null)
      .map(p=>({ts:p.ts,rx:name==='wan'?p.rx:p.rx/60,tx:name==='wan'?p.tx:p.tx/60}));
    return [...archived,...visibleLive].sort((a,b)=>a.ts-b.ts);
  }
  function drawPlot(plot) {
    const name=plot.dataset.plot, win=selectedWindow(plot), values=historyPoints(name,win);
    const available=values.length > 0;
    const placeholder=plot.querySelector('[data-chart-empty]');
    if(placeholder)placeholder.hidden=available;
    const width=680,height=Number(plot.querySelector('svg')?.getAttribute('viewBox')?.split(' ')[3]) || 144;
    const baseline=height-11,top=9,now=Date.now()/1000,min=now-windowLength[win];
    const max=Math.max(1,...values.flatMap(x=>[x.rx,x.tx]))*1.16;
    plot.dataset.max=String(max);plot.dataset.minTime=String(min);plot.dataset.maxTime=String(now);
    for (const kind of ['rx','tx']) {
      const coords=values.map(v=>({x:Math.max(0,Math.min(width,(v.ts-min)/windowLength[win]*width)),
         y:baseline-(baseline-top)*Math.min(1,Math.max(0,v[kind])/max)}));
      setPath(plot,`[data-line="${kind}"]`,smooth(coords));
      setPath(plot,`[data-area="${kind}"]`,fillPath(coords,baseline));
    }
    const peak=values.length?Math.max(...values.flatMap(v=>[v.rx,v.tx])):null;
    const p=plot.querySelector('[data-chart-peak]');
    if(p)p.textContent=(translate?'Peak: ':'Пик: ')+formatRate(peak);
    const l=plot.querySelector('[data-time-left]');
    if(l)l.textContent=win==='1h'?(translate?'−1h':'−1ч'):win==='5m'?(translate?'−5m':'−5м'):(translate?'−15m':'−15м');
    plot._values=values;
  }
  function redraw() {for(const plot of plots)drawPlot(plot);}

  async function refreshHistory(win, force=false) {
    if(!windowLength[win])return;
    if(!force && historyAt.has(win) && Date.now()-historyAt.get(win)<55000)return;
    try {
      const response=await fetch('/api/overview/series?window='+encodeURIComponent(win),
        {cache:'no-store',credentials:'same-origin'});
      if(!response.ok)throw Error('history '+response.status);
      const payload=await response.json();
      const mapped=new Map();
      for(const record of payload.series || []) {
        if(!instances.includes(record.interface))continue;
        const samples=(record.points||[]).filter(p=>[p.ts,p.rx,p.tx].every(Number.isFinite))
             .map(p=>({ts:p.ts,rx:bounded(p.rx),tx:bounded(p.tx)}));
        mapped.set(record.interface,samples);
      }
      history.set(win,mapped);
      if(Array.isArray(payload.host)){
        const host=payload.host.filter(p=>Number.isFinite(p.ts));
        hostHistory.set(win,host);
        if(win==='15m'){
          for(const [key,arr] of [['cpu',cpu],['ram',ram],['swap',swap],['disk',disk],['sockets',sockets]]){
            const recorded=host.map(p=>p[key]).filter(Number.isFinite);
            if(recorded.length>1 && arr.length<recorded.length){
              arr.splice(0,arr.length,...recorded);
              drawSmall(key==='sockets'?'socket':key,arr);
            }
          }
        }
      }
      historyAt.set(win,Date.now());redraw();
    } catch(_) { /* Show recorded live values only; never manufacture a curve. */ }
  }
  periodButtons.forEach(button=>button.addEventListener('click',()=>{
    currentWindow=button.dataset.period;
    periodButtons.forEach(x=>{
      x.classList.toggle('is-active',x===button);x.setAttribute('aria-pressed',String(x===button));
    });
    refreshHistory(currentWindow);
    redraw();
  }));
  for(const plot of plots) {
    const svg=plot.querySelector('svg'), tooltip=plot.querySelector('[data-chart-tip]');
    svg?.addEventListener('pointermove',event=>{
      if(!plot._values?.length || !tooltip)return;
      const rect=svg.getBoundingClientRect(),frac=Math.max(0,Math.min(1,(event.clientX-rect.left)/rect.width));
      const target=Number(plot.dataset.minTime)+frac*(Number(plot.dataset.maxTime)-Number(plot.dataset.minTime));
      const sample=plot._values.reduce((best,point)=>!best||Math.abs(point.ts-target)<Math.abs(best.ts-target)?point:best,null);
      if(!sample)return;
      const stamp=new Date(sample.ts*1000).toLocaleTimeString(translate?'en-GB':'ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
      tooltip.textContent=`${stamp} · ↓ ${formatRate(sample.rx)} · ↑ ${formatRate(sample.tx)}`;
      tooltip.hidden=false;tooltip.style.left=(frac*100).toFixed(1)+'%';
      const cursor=plot.querySelector('[data-cursor]');
      if(cursor){cursor.setAttribute('x1',(frac*680).toFixed(1));cursor.setAttribute('x2',(frac*680).toFixed(1));cursor.setAttribute('visibility','visible');}
    });
    svg?.addEventListener('pointerleave',()=>{
      if(tooltip)tooltip.hidden=true;
      plot.querySelector('[data-cursor]')?.setAttribute('visibility','hidden');
    });
  }

  // Load levels. 70 % and 90 % are the points where a person should start to care about a resource.
  const levelOf = (pct) => pct >= 90 ? 'crit' : pct >= 70 ? 'warn' : 'ok';
  const levelLabel = {ok: translate?'Normal':'Норма', warn: translate?'High':'Высокая', crit: translate?'Critical':'Критично'};
  const rank = {ok:0, warn:1, crit:2};
  function setLevel(key, pct) {
    const tile = main.querySelector(`[data-kpi="${key}"]`);
    if (!tile || !Number.isFinite(pct)) return;
    const level = levelOf(pct);
    tile.dataset.level = level;
    const chip = tile.querySelector('[data-kpi-level]');
    if (chip) chip.textContent = levelLabel[level];
    tilePct[key] = pct;
  }
  function setStatus(state, title, sub) {
    if (!strip) return;
    strip.dataset.state = state;
    // Only touch the text when it changed: the block is a live region and must not repeat itself every 5 s.
    for (const [id, value] of [['fleet-title', title], ['fleet-sub', sub]]) {
      const el = byId(id);
      if (el && value !== null && el.textContent !== value) el.textContent = value;
    }
  }
  function updateStatus() {
    if (!strip || failures >= 3) return;
    const total = Number(strip.dataset.serversTotal);
    if (!total) return;
    const down = [...running].filter(([, up]) => !up).map(([name]) => name);
    let worst = null;
    for (const [key, pct] of Object.entries(tilePct)) {
      if (!worst || pct > worst.pct) worst = {key, pct, level: levelOf(pct),
        name: main.querySelector(`[data-kpi="${key}"] .host-kpi-heading span`)?.textContent || key};
    }
    const load = byId('fleet-load');
    if (load && worst) {
      load.dataset.level = worst.level;
      load.textContent = worst.level === 'ok' ? (translate?'Normal':'В норме') : `${worst.name} ${Math.round(worst.pct)}%`;
    }
    if (!worst && !down.length) return;
    const parts = [];
    if (down.length) parts.push((translate?'Stopped: ':'Остановлен: ') + down.join(', ') + '.');
    if (worst && worst.level !== 'ok') parts.push(`${worst.name}: ${Math.round(worst.pct)}%.`);
    const level = worst ? worst.level : 'ok';
    if (level === 'crit') setStatus('crit', translate?'Critical load':'Критическая нагрузка', parts.join(' '));
    else if (level === 'warn' || down.length) setStatus('warn', translate?'Needs attention':'Нужно внимание', parts.join(' '));
    else setStatus('ok', translate?'All good':'Всё работает',
      translate?'All servers are running, load is normal.':'Все серверы запущены, нагрузка в норме.');
  }
  function drawPresence(name, connected, total) {
    const el = byId(name + '-presence');
    if (!el) return;
    if (!Number.isFinite(connected) || !Number.isFinite(total) || total <= 0) {el.hidden = true; return;}
    const shown = Math.min(total, 16);
    const on = total <= 16 ? connected : Math.round(connected / total * shown);
    el.replaceChildren(...Array.from({length: shown}, (_, i) => {
      const mark = document.createElement('i');
      if (i < on) mark.className = 'on';
      return mark;
    }));
    el.setAttribute('aria-label', translate ? `${connected} of ${total} clients online` : `Онлайн ${connected} из ${total} клиентов`);
    el.hidden = false;
  }

  function recordPct(key,used,total,detail) {
    if(!Number.isFinite(total) || total<=0)return;
    const percentage=100*Math.min(1,Math.max(0,used/total));
    text('host-'+key,percentage.toFixed(1)+'%');
    text('host-'+key+'-detail',detail || `${formatBytes(used)} / ${formatBytes(total)}`);
    const buf={ram,swap,disk}[key];append(buf,percentage);drawSmall(key,buf);setLevel(key,percentage);
  }

  async function poll() {
    if(updating || document.hidden)return;
    updating=true;
    try {
      const r=await fetch('/api/overview/telemetry',{cache:'no-store',credentials:'same-origin'});
      if(!r.ok)throw Error('HTTP '+r.status);
      const data=await r.json(),now=Date.now()/1000;
      if(Number.isFinite(data.mem_total)&&Number.isFinite(data.mem_available)&&data.mem_total>0)
        recordPct('ram',data.mem_total-data.mem_available,data.mem_total);
      if(Number.isFinite(data.swap_total)&&data.swap_total>=0&&Number.isFinite(data.swap_free)) {
        if(data.swap_total===0){text('host-swap','0%');text('host-swap-detail',translate?'Not configured':'Не используется');append(swap,0);drawSmall('swap',swap);setLevel('swap',0);}
        else recordPct('swap',data.swap_total-data.swap_free,data.swap_total);
      }
      if(Number.isFinite(data.disk_total)&&data.disk_total>0&&Number.isFinite(data.disk_free))
        recordPct('disk',data.disk_total-data.disk_free,data.disk_total);
      if(Number.isFinite(data.uptime))text('host-uptime',formatDuration(data.uptime));
      if(Number.isFinite(data.panel_rss))text('host-panel-ram',formatBytes(data.panel_rss));
      if(Number.isFinite(data.tcp_established))text('host-tcp',data.tcp_established);
      if(Number.isFinite(data.udp_sockets))text('host-udp',data.udp_sockets);
      if(Number.isFinite(data.tcp_established)&&Number.isFinite(data.udp_sockets)) {
        const value=data.tcp_established+data.udp_sockets;
        text('host-sockets-total',value);append(sockets,value);drawSmall('socket',sockets);
      }
      if(data.uplink){text('wan-interface',data.uplink);}
      if(Number.isFinite(data.wan_rx))text('wan-rx-total',formatBytes(data.wan_rx));
      if(Number.isFinite(data.wan_tx))text('wan-tx-total',formatBytes(data.wan_tx));
      if(previousHost && Number.isFinite(data.cpu_total) && Number.isFinite(data.cpu_idle)) {
        const delta=data.cpu_total-previousHost.cpu_total,idle=data.cpu_idle-previousHost.cpu_idle;
        if(delta>0&&idle>=0){const pct=100*Math.min(1,Math.max(0,1-idle/delta));text('host-cpu',pct.toFixed(1)+'%');
          text('host-cpu-detail',(data.cpu_count||'—')+(translate?' logical CPUs':' логических CPU'));
          append(cpu,pct);drawSmall('cpu',cpu);setLevel('cpu',pct);}
      }
      if(previousHost && previousAt && data.uplink===previousHost.uplink &&
         Number.isFinite(data.wan_rx)&&Number.isFinite(data.wan_tx)) {
        const seconds=now-previousAt;
        if(seconds>0 && data.wan_rx>=previousHost.wan_rx && data.wan_tx>=previousHost.wan_tx) {
          const rx=(data.wan_rx-previousHost.wan_rx)/seconds,tx=(data.wan_tx-previousHost.wan_tx)/seconds;
          text('wan-rx-rate',formatRate(rx));text('wan-tx-rate',formatRate(tx));
          append(live.get('wan'),{ts:now,rx,tx});
        }
      }
      let online=0,known=0,upCount=0;
      for(const value of data.instances || []) {
        const name=value.interface;
        if(!live.has(name))continue;
        running.set(name,Boolean(value.running));
        if(value.running)upCount++;
        if(Number.isFinite(value.connected)){online+=value.connected;known+=value.clients;}
        if(Number.isFinite(value.rx))text(name+'-rx-total',formatBytes(value.rx));
        if(Number.isFinite(value.tx))text(name+'-tx-total',formatBytes(value.tx));
        if(Number.isFinite(value.connected)){text(name+'-connected',`${value.connected} / ${value.clients}`);drawPresence(name,value.connected,value.clients);}
        if(Number.isFinite(value.uptime))text(name+'-uptime',formatDuration(value.uptime));
        const old=previous.get(name);
        if(old && Number.isFinite(value.rx)&&Number.isFinite(value.tx) &&
           Number.isFinite(old.rx)&&Number.isFinite(old.tx)&& now>old.ts &&
           value.rx>=old.rx && value.tx>=old.tx) {
          const seconds=now-old.ts,rx=(value.rx-old.rx)/seconds,tx=(value.tx-old.tx)/seconds;
          text(name+'-rx-rate',formatRate(rx));text(name+'-tx-rate',formatRate(tx));
          append(live.get(name),{ts:now,rx,tx});
        }
        previous.set(name,{rx:value.rx,tx:value.tx,ts:now});
      }
      if(strip && running.size){
        strip.dataset.serversUp=String(upCount);
        text('fleet-servers',`${upCount} ${translate?'of':'из'} ${strip.dataset.serversTotal}`);
        if(known)text('fleet-clients',`${online} ${translate?'of':'из'} ${known}`);
      }
      failures=0;updateStatus();
      previousHost=data;previousAt=now;
      redraw();
    } catch(_) {
      /* Keep last known readings, don't substitute demo data. After three misses say so instead of looking healthy. */
      failures++;
      if(failures>=3){
        setStatus('unknown',translate?'No connection to the panel':'Нет связи с панелью',
          translate?'Readings are not updating. Reload the page.':'Данные не обновляются. Обновите страницу.');
        for(const tile of main.querySelectorAll('.host-kpi[data-level=""]'))tile.dataset.level='na';
      }
    }
    finally{updating=false;}
  }
  refreshHistory('15m');
  poll();window.setInterval(poll,5000);
  window.setInterval(()=>refreshHistory(currentWindow),60000);
})();

// Modal dialogs for adding clients (single and batch)
(function(){
  const modals = {};
  for (const dialog of document.querySelectorAll('dialog.awg-modal')) {
    modals[dialog.id] = dialog;
  }
  // Open buttons
  for (const btn of document.querySelectorAll('[data-modal-open]')) {
    btn.addEventListener('click', () => {
      const id = btn.dataset.modalOpen;
      const dialog = modals[id];
      if (dialog) {
        dialog.showModal();
        const firstInput = dialog.querySelector('input:not([type=hidden]), textarea');
        if (firstInput) firstInput.focus();
      }
    });
  }
  // Close on backdrop click and close button
  for (const dialog of Object.values(modals)) {
    dialog.addEventListener('click', (e) => {
      if (e.target === dialog || e.target.closest('.modal-close')) {
        dialog.close();
      }
    });
  }
})();

// Batch creation answers with a ZIP. A plain form submit would save the file and
// leave the page showing the old client list, so the download is done here and
// the page is reloaded afterwards. Without JavaScript the form still works.
(function(){
  const form=document.querySelector('form[data-batch-download]');
  if(!form||!window.fetch||!window.URL)return;
  form.addEventListener('submit',async event=>{
    if(form.dataset.nativeSubmit==='1') { delete form.dataset.nativeSubmit; return; }
    event.preventDefault();
    const button=form.querySelector('button[type="submit"]');
    if(button)button.disabled=true;
    try{
      const reply=await fetch(form.action,{method:'POST',body:new URLSearchParams(new FormData(form)),credentials:'same-origin'});
      const type=reply.headers.get('content-type')||'';
      if(!reply.ok||!type.startsWith('application/zip')){
        // An error page: show it as it is.
        const text=await reply.text();
        document.open();document.write(text);document.close();
        return;
      }
      const name=((reply.headers.get('content-disposition')||'').match(/filename="([^"]+)"/)||[])[1]||'clients.zip';
      const url=URL.createObjectURL(await reply.blob());
      const link=document.createElement('a');
      link.href=url;link.download=name;document.body.appendChild(link);link.click();link.remove();
      window.setTimeout(()=>{
        URL.revokeObjectURL(url);
        // Reloading the document also destroys the now-inert modal.
        window.location.reload();
      },800);
    }catch(_){
      if(button)button.disabled=false;
      // Keep requestSubmit(): the CSRF/confirmation handlers still run.
      form.dataset.nativeSubmit='1';
      form.requestSubmit();          // network trouble before any answer: plain submit
    }
  });
})();

// Telegram block: token visibility, group switches with counters, custom schedule.
(() => {
  'use strict';
  for (const button of document.querySelectorAll('[data-reveal]')) {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.reveal);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      button.classList.toggle('is-active', input.type === 'text');
    });
  }
  for (const card of document.querySelectorAll('[data-tg-group]')) {
    const all = card.querySelector('[data-tg-all]');
    const items = [...card.querySelectorAll('[data-tg-event]')];
    const count = card.querySelector('[data-tg-count]');
    const update = () => {
      const on = items.filter((item) => item.checked).length;
      if (count) count.textContent = `${on}/${items.length}`;
      if (all) { all.checked = on === items.length; all.indeterminate = on > 0 && on < items.length; }
      card.classList.toggle('is-off', on === 0);
    };
    all?.addEventListener('change', () => { items.forEach((item) => { item.checked = all.checked; }); update(); });
    items.forEach((item) => item.addEventListener('change', update));
    update();
  }
  const schedule = document.querySelector('[data-tg-schedule]');
  const custom = document.querySelector('[data-tg-custom]');
  if (schedule && custom) {
    const field = custom.querySelector('input');
    const sync = () => {
      const on = schedule.value === 'custom';
      custom.hidden = !on;
      if (field) field.required = on;
    };
    schedule.addEventListener('change', () => { sync(); if (schedule.value === 'custom') field?.focus(); });
    sync();
  }
})();

// Maintenance → Logs: refresh the journal every 5 seconds while the box is ticked.
(() => {
  'use strict';
  const form = document.querySelector('[data-logs-form]');
  const view = document.querySelector('[data-log-view]');
  const auto = document.querySelector('[data-logs-auto]');
  const count = document.querySelector('[data-log-count]');
  if (!form || !view || !auto) return;
  let timer = null;
  const pinnedToBottom = () => view.scrollHeight - view.scrollTop - view.clientHeight < 24;
  const load = async () => {
    const params = new URLSearchParams(new FormData(form));
    params.delete('tab');
    view.classList.add('is-loading');
    try {
      const reply = await fetch(`/api/logs?${params}`, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
      const data = await reply.json();
      if (!reply.ok) throw new Error(data.error || reply.statusText);
      const stick = pinnedToBottom();
      view.textContent = data.lines.join('\n') || view.dataset.empty || '';
      if (count) count.textContent = count.textContent.replace(/[0-9]+/, String(data.lines.length));
      if (stick) view.scrollTop = view.scrollHeight;
    } catch (error) {
      auto.checked = false; stop();
    } finally {
      view.classList.remove('is-loading');
    }
  };
  const stop = () => { if (timer) { clearInterval(timer); timer = null; } };
  auto.addEventListener('change', () => { stop(); if (auto.checked) { load(); timer = setInterval(load, 5000); } });
  view.scrollTop = view.scrollHeight;
})();

// Clients table: sort by any column; a second click reverses; the choice is remembered in this browser.
(() => {
  'use strict';
  const body = document.querySelector('[data-sortable-clients]');
  if (!body) return;
  const table = body.closest('table');
  const buttons = [...table.querySelectorAll('[data-sort-key]')];
  const ipValue = (ip) => (ip || '').split('.').reduce((sum, part) => sum * 256 + (Number(part) || 0), 0);
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  const value = {
    name: (row) => row.dataset.name || '',
    ip: (row) => ipValue(row.dataset.ip),
    presence: (row) => Number(row.dataset.handshake || 0),
    // Enabled before disabled, then the most recent handshake first.
    status: (row) => Number(row.dataset.enabled || 0) * 1e12 + Number(row.dataset.handshake || 0),
    traffic: (row) => Number(row.dataset.traffic || 0),
  };
  let saved = null;
  try { saved = JSON.parse(window.localStorage.getItem('awg31.clientSort') || 'null'); } catch (error) { saved = null; }
  const apply = (key, direction, remember) => {
    const read = value[key];
    if (!read) return;
    const rows = [...body.querySelectorAll('tr.client-row')];
    rows.sort((a, b) => {
      const x = read(a), y = read(b);
      const order = typeof x === 'string' ? collator.compare(x, y) : x - y;
      return (direction === 'desc' ? -order : order) || collator.compare(a.dataset.name || '', b.dataset.name || '');
    });
    rows.forEach((row) => body.appendChild(row));
    for (const button of buttons) {
      const cell = button.closest('th');
      const active = button.dataset.sortKey === key;
      cell.setAttribute('aria-sort', active ? (direction === 'asc' ? 'ascending' : 'descending') : 'none');
      cell.classList.toggle('is-sorted', active);
      cell.classList.toggle('is-desc', active && direction === 'desc');
    }
    if (remember) {
      try { window.localStorage.setItem('awg31.clientSort', JSON.stringify({ key, direction })); } catch (error) { /* private mode */ }
    }
  };
  for (const button of buttons) {
    button.addEventListener('click', () => {
      const cell = button.closest('th');
      const key = button.dataset.sortKey;
      // Names and addresses start A→Z; presence, access and traffic start with the busiest.
      const first = key === 'name' || key === 'ip' ? 'asc' : 'desc';
      const direction = cell.classList.contains('is-sorted') ? (cell.classList.contains('is-desc') ? 'asc' : 'desc') : first;
      apply(key, direction, true);
    });
  }
  if (saved && value[saved.key]) apply(saved.key, saved.direction === 'desc' ? 'desc' : 'asc', false);
})();

// Extra [Interface] lines: the «Insert a template ▾» menu and the bulk form.
(() => {
  for (const item of document.querySelectorAll('[data-extra-target]')) {
    item.addEventListener('click', () => {
      const area = document.getElementById(item.dataset.extraTarget);
      if (!area) return;
      const text = item.dataset.extraText || '';
      const current = area.value.replace(/\s+$/, '');
      // Templates overlap (the gateway already has NAT and MSS clamping):
      // only the commands that are not in the field yet are added.
      const norm = line => {
        const at = line.indexOf('=');
        return at < 0 ? line.trim() : line.slice(0, at).trim().toLowerCase() + '=' + line.slice(at + 1).trim();
      };
      const have = new Set(current.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).map(norm));
      // A template is blocks set apart by blank lines, each with its own comment: a block goes in with
      // its comment and only its new commands, and a block whose commands are all there is left out.
      const blocks = text.split(/\n\s*\n/).map(block => {
        const lines = block.split('\n');
        const fresh = lines.filter(l => !l.startsWith('#') && !have.has(norm(l)));
        return fresh.length ? [...lines.filter(l => l.startsWith('#')), ...fresh].join('\n') : '';
      }).filter(Boolean);
      if (blocks.length) {
        const added = blocks.join('\n\n');
        area.value = current ? current + '\n\n' + added : added;
      }
      area.rows = Math.min(14, Math.max(area.rows, area.value.split('\n').length + 1));
      item.closest('details')?.removeAttribute('open');
      area.focus();
      area.setSelectionRange(area.value.length, area.value.length);
      area.scrollLeft = 0;   // long commands: keep the start of the lines in view
      area.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
  document.addEventListener('click', event => {
    for (const menu of document.querySelectorAll('details.extra-menu[open]')) {
      if (!menu.contains(event.target)) menu.removeAttribute('open');
    }
  });
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    for (const menu of document.querySelectorAll('details.extra-menu[open]')) {
      menu.removeAttribute('open');
      menu.querySelector('summary')?.focus();
      event.preventDefault();
      event.stopPropagation();
    }
  }, true);
  const isRu = document.documentElement.lang === 'ru';
  const selected = () => [...document.querySelectorAll('.peer-select:checked')].map(x => x.value);
  for (const form of document.querySelectorAll('form[data-bulk-names]')) {
    const count = form.querySelector('[data-bulk-names-count]');
    const dialog = form.closest('dialog');
    const refresh = () => {
      const names = selected();
      if (count) count.textContent = (isRu ? 'Клиенты: ' : 'Clients: ') + (names.join(', ') || '—');
    };
    dialog?.addEventListener('close', refresh);
    document.querySelector(`[data-modal-open="${dialog?.id}"]`)?.addEventListener('click', refresh);
    form.addEventListener('submit', event => {
      form.querySelectorAll('input[data-bulk-name]').forEach(x => x.remove());
      const names = selected();
      if (!names.length) { event.preventDefault(); return; }
      for (const name of names) {
        const input = document.createElement('input');
        input.type = 'hidden'; input.name = 'names'; input.value = name; input.dataset.bulkName = '1';
        form.append(input);
      }
    });
  }
})();

// Update from the panel: follow the run while the panel itself restarts.
(() => {
  const box = document.getElementById('update-progress');
  if (!box) return;
  const log = document.getElementById('update-log');
  const label = box.querySelector('[data-update-label]');
  const reload = box.querySelector('[data-update-reload]');
  const startVersion = box.dataset.updateVersion || '';
  let active = box.dataset.updateRunning === '1' || box.dataset.updateStatus === 'running';
  let misses = 0;
  const show = (status, text) => {
    label.className = 'update-state is-' + status;
    label.textContent = text;
  };
  const scroll = () => { if (log) log.scrollTop = log.scrollHeight; };
  scroll();
  if (!active) return;
  const tick = async () => {
    try {
      const reply = await fetch('/api/update-status', { headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'same-origin' });
      if (reply.status === 401) { window.location.reload(); return; }
      if (!reply.ok) throw new Error(String(reply.status));
      const data = await reply.json();
      misses = 0;
      if (log && typeof data.log === 'string' && data.log !== log.textContent) { log.textContent = data.log; scroll(); }
      const status = (data.state && data.state.status) || 'running';
      if (data.running || status === 'running') {
        show('running', box.dataset.textRunning);
      } else {
        show(status, status === 'ok' ? box.dataset.textOk : box.dataset.textFailed);
        if (reload) reload.hidden = false;
        // A new version of the panel is serving now: load its page.
        if (status === 'ok' && data.version && data.version !== startVersion) setTimeout(() => window.location.reload(), 2500);
        return;
      }
    } catch (error) {
      misses += 1;
      show('running', box.dataset.textRestarting);         // the panel is restarting: keep asking
      if (misses > 300) return;
    }
    setTimeout(tick, 2000);
  };
  setTimeout(tick, 1500);
})();

// 0.17: save a text field as a file (the router script) and a busy label on long checks.
(() => {
  'use strict';
  for (const btn of document.querySelectorAll('[data-download-from]')) {
    btn.addEventListener('click', () => {
      const source = document.getElementById(btn.dataset.downloadFrom);
      if (!source) return;
      const url = URL.createObjectURL(new Blob([source.value], {type: 'text/x-sh'}));
      const link = document.createElement('a');
      link.href = url; link.download = btn.dataset.downloadName || 'download.txt';
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  for (const btn of document.querySelectorAll('button[data-busy-text]')) {
    const form = btn.form;
    if (!form) continue;
    form.addEventListener('submit', () => {
      // After the submit has started: disabling earlier would drop the button from the request.
      setTimeout(() => { btn.disabled = true; btn.textContent = btn.dataset.busyText; }, 0);
    });
  }
})();

// 0.18: the "random subnet" box (remembered in this browser) and the custom masking profile fields.
(() => {
  'use strict';
  for (const box of document.querySelectorAll('input[data-random-subnet]')) {
    const field = document.getElementById(box.dataset.randomSubnet);
    const sync = () => { if (field) { field.disabled = box.checked; field.required = !box.checked; } };
    try { box.checked = localStorage.getItem('awg31-random-subnet') === '1'; } catch (_) { /* storage blocked */ }
    sync();
    box.addEventListener('change', () => {
      sync();
      try { localStorage.setItem('awg31-random-subnet', box.checked ? '1' : '0'); } catch (_) { /* storage blocked */ }
    });
  }
  for (const select of document.querySelectorAll('select[data-mask-profile]')) {
    const custom = select.form && select.form.querySelector('[data-mask-custom]');
    const sync = () => { if (custom) custom.hidden = select.value !== 'custom'; };
    sync();
    select.addEventListener('change', sync);
  }
})();
