/* Globe.gl dashboard for the dnsmalik.fail2ban honeypot.
   Pulls data from /api/* endpoints; subscribes to /api/stream for live updates.
   Replace visual layout/styling freely — the data contract is at /api/* and won't change.
*/

const $ = (id) => document.getElementById(id);

// ─── Globe setup ──────────────────────────────────────────────────────────────
const globe = Globe()
  .backgroundColor('#060a14')
  .showAtmosphere(true)
  .atmosphereColor('#4fc3f7')
  .atmosphereAltitude(0.18)
  .arcColor('color')
  .arcAltitudeAutoScale(0.3)
  .arcStroke(0.6)
  .arcDashLength(0.4)
  .arcDashGap(0.2)
  .arcDashAnimateTime(3000)
  .arcLabel((d) => `${d.country || d.country_code} → ${d.server?.label || 'us'}<br/>${d.ip}<br/>${d.count} attempts`)
  .pointColor(() => '#ff5252')
  .pointAltitude(0.01)
  .pointRadius(0.4)
  .pointsMerge(true)
  ($('globe-container'));

// Initial pin for our server (Oracle Cloud us-ashburn-1)
let server = { lat: 33.7, lon: -97.4, label: 'ARM6-AD2' };
globe.pointsData([{ lat: server.lat, lng: server.lon, color: '#4fc3f7', radius: 1.2 }]);

// We track attacks as a Map: ip -> {lat, lon, count, country}
const pointsMap = new Map();
const arcsData = [];

function rerenderGlobe() {
  const points = Array.from(pointsMap.values()).map((p) => ({
    lat: p.lat, lng: p.lon, color: p.count > 100 ? '#ff1744' : p.count > 10 ? '#ff7676' : '#ffa726', radius: Math.min(0.6, 0.2 + Math.log10(p.count + 1) * 0.3),
  }));
  // Always include our server pin
  points.push({ lat: server.lat, lng: server.lon, color: '#4fc3f7', radius: 1.2 });
  globe.pointsData(points);

  // Limit arcs to last 50 to keep render cheap
  globe.arcsData(arcsData.slice(-50).map((a) => ({
    startLat: a.lat, startLng: a.lon, endLat: server.lat, endLng: server.lon,
    color: ['#ff5252', '#4fc3f7'], stroke: 0.4,
  })));
}

// ─── Loaders ──────────────────────────────────────────────────────────────────
async function loadSummary() {
  const r = await fetch('/api/stats/summary');
  const d = await r.json();
  $('stat-total').textContent = d.total_failed_logins;
  $('stat-ips').textContent = d.unique_ips;
  $('stat-countries').textContent = d.unique_countries;
  $('stat-bans').textContent = d.active_bans;
  $('stat-last').textContent = d.last_attack_ts ? d.last_attack_ts.replace('T', ' ').replace('Z', '') : '—';
  if (d.server) server = { lat: d.server.lat, lon: d.server.lon, label: d.server.label || server.label };
}

async function loadTopLists() {
  const [pw, un] = await Promise.all([
    fetch('/api/passwords/top?limit=10').then((r) => r.json()),
    fetch('/api/usernames/top?limit=10').then((r) => r.json()),
  ]);
  $('passwords').innerHTML = pw.map((x) => `<li><span>${escapeHtml(String(x.password).slice(0, 30))}</span><span>${x.count}</span></li>`).join('');
  $('usernames').innerHTML = un.map((x) => `<li><span>${escapeHtml(x.username)}</span><span>${x.count}</span></li>`).join('');
}

async function loadGeo() {
  const r = await fetch('/api/attacks/geo');
  const data = await r.json();
  pointsMap.clear();
  for (const d of data) {
    if (d.lat === 0 && d.lon === 0) continue;
    pointsMap.set(d.ip, { lat: d.lat, lon: d.lon, count: d.count, country: d.country });
  }
  rerenderGlobe();
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function addTicker(item) {
  const div = document.createElement('div');
  div.className = 'item';
  div.innerHTML = `<span class="ip">${escapeHtml(item.ip)}</span> → <span class="cred">${escapeHtml(item.username || '')}</span>:<span class="cred">${escapeHtml(item.password || '')}</span>`;
  const t = $('ticker');
  t.insertBefore(div, t.firstChild);
  while (t.children.length > 30) t.removeChild(t.lastChild);
}

// ─── Live updates via Server-Sent Events ──────────────────────────────────────
function subscribeSSE() {
  const es = new EventSource('/api/stream');
  es.onmessage = (msg) => {
    try {
      const ev = JSON.parse(msg.data);
      if (ev.eventid === 'cowrie.login.failed') {
        addTicker({ ip: ev.src_ip, username: ev.username, password: ev.password });
        // Re-fetch geo (debounced) so points refresh
        clearTimeout(window._geoTimer);
        window._geoTimer = setTimeout(() => loadGeo().then(loadSummary), 3000);
      }
    } catch (e) { /* ignore non-JSON heartbeats */ }
  };
  es.onerror = () => setTimeout(subscribeSSE, 5000);  // reconnect
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
(async function boot() {
  await loadSummary();
  await loadGeo();
  await loadTopLists();
  subscribeSSE();
  // Refresh top lists and summary every 30s
  setInterval(() => { loadSummary(); loadTopLists(); }, 30000);
  setInterval(loadGeo, 60000);
})();
