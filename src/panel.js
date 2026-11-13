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
  modal.querySelector('[data-accept]').addEventListener('click', () => {
    const form = confirmedForm;
    confirmedForm = null;
    close();
    if (form) { form.dataset.confirmed = '1'; form.requestSubmit(); }
  });
  modal.addEventListener('close', () => { confirmedForm = null; });
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
  function updatePeerSelection() {
    const selected = peerCheckboxes.filter(x => x.checked).length;
    if (bulkButton) bulkButton.disabled = selected === 0;
    if (bulkCount) bulkCount.textContent = (isRu ? 'Выбрано: ' : 'Selected: ') + selected;
    if (allPeers) {
      allPeers.checked = peerCheckboxes.length > 0 && selected === peerCheckboxes.length;
      allPeers.indeterminate = selected > 0 && selected < peerCheckboxes.length;
    }
  }
  allPeers?.addEventListener('change', () => {
    peerCheckboxes.forEach(x => { x.checked = allPeers.checked; });
    updatePeerSelection();
  });
  peerCheckboxes.forEach(x => x.addEventListener('change', updatePeerSelection));

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
    if(values.length < 2) return;
    const max=key==='socket' ? Math.max(1,...values) : 100;
    const width=key==='socket'?280:280,base=key==='socket'?111:46,height=key==='socket'?104:40;
    const scaled=values.map((v,i)=>({x:i*width/(values.length-1),y:base-height*Math.min(1,Math.max(0,v/max))}));
    if(key==='socket') {
      setPath(main,'[data-socket-line]',smooth(scaled));
      setPath(main,'[data-socket-area]',fillPath(scaled,base));
    } else {
      setPath(main,`[data-kpi-line="${key}"]`,smooth(scaled));
      setPath(main,`[data-kpi-area="${key}"]`,fillPath(scaled,base));
    }
  }

  function selectedWindow(plot) {return plot.querySelector('.dash-periods .is-active')?.dataset.period || '15m';}
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
    if(l)l.textContent=win==='1h'?(translate?'−1h':'−1ч'):win==='5m'?'−5м':'−15м';
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
  for(const plot of plots) {
    plot.querySelectorAll('[data-period]').forEach(button=>button.addEventListener('click',()=>{
      plot.querySelectorAll('[data-period]').forEach(x=>{
        x.classList.toggle('is-active',x===button);x.setAttribute('aria-pressed',String(x===button));
      });
      refreshHistory(button.dataset.period);
      drawPlot(plot);
    }));
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

  function recordPct(key,used,total,detail) {
    if(!Number.isFinite(total) || total<=0)return;
    const percentage=100*Math.min(1,Math.max(0,used/total));
    text('host-'+key,percentage.toFixed(1)+'%');
    text('host-'+key+'-detail',detail || `${formatBytes(used)} / ${formatBytes(total)}`);
    const buf={ram,swap,disk}[key];append(buf,percentage);drawSmall(key,buf);
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
        if(data.swap_total===0){text('host-swap','0%');text('host-swap-detail',translate?'Not configured':'Не используется');append(swap,0);drawSmall('swap',swap);}
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
          append(cpu,pct);drawSmall('cpu',cpu);}
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
      for(const value of data.instances || []) {
        const name=value.interface;
        if(!live.has(name))continue;
        if(Number.isFinite(value.rx))text(name+'-rx-total',formatBytes(value.rx));
        if(Number.isFinite(value.tx))text(name+'-tx-total',formatBytes(value.tx));
        if(Number.isFinite(value.connected))text(name+'-connected',`${value.connected} / ${value.clients}`);
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
      previousHost=data;previousAt=now;
      redraw();
    } catch(_) { /* Keep last known readings, don't substitute demo data. */ }
    finally{updating=false;}
  }
  refreshHistory('15m');
  poll();window.setInterval(poll,5000);
  window.setInterval(()=>{for(const win of new Set(plots.map(selectedWindow)))refreshHistory(win);},60000);
})();
