const BASE_URL = 'http://localhost:3000';

const scanBtn = document.getElementById('scanBtn');
const exportBtn = document.getElementById('exportBtn');
const urlInput = document.getElementById('urlInput');
const loading = document.getElementById('loading');
const results = document.getElementById('results');

scanBtn.addEventListener('click', async () => {
  const input = urlInput.value.trim();
  if (!input) return alert('Please enter a URL or domain first!');

  const domain = input.replace(/^https?:\/\//, '').split('/')[0];
  const url = input.startsWith('http') ? input : `https://${input}`;

  loading.classList.remove('hidden');
  results.classList.add('hidden');
  clearResults();

  try {
    const [headers, ssl, dns, ports, whois, redirects, tech] = await Promise.all([
      fetch(`${BASE_URL}/check/headers?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/ssl?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/dns?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/ports?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/whois?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/redirects?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/tech?url=${encodeURIComponent(url)}`).then(r => r.json()),
    ]);

    renderHeaders(headers);
    renderSSL(ssl);
    renderDNS(dns);
    renderPorts(ports);
    renderWHOIS(whois);
    renderRedirects(redirects);
    renderTech(tech);
    renderScore(headers, ssl);

  } catch (err) {
    alert('Failed to connect to server. Make sure server.js is running!');
  } finally {
    loading.classList.add('hidden');
    results.classList.remove('hidden');
    lucide.createIcons();
  }
});

function clearResults() {
  ['result-headers', 'result-ssl', 'result-dns', 'result-ports',
   'result-whois', 'result-redirects', 'result-tech', 'result-score']
    .forEach(id => document.getElementById(id).innerHTML = '');
}

function renderHeaders(data) {
  const el = document.getElementById('result-headers');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span>${data.message}</span></div>`;
    return;
  }
  el.innerHTML = Object.entries(data.checks).map(([key, found]) => `
    <div class="item">
      <span>${key}</span>
      <span class="badge ${found ? 'aman' : 'rentan'}">${found ? 'Present' : 'Missing'}</span>
    </div>
  `).join('');
}

function renderSSL(data) {
  const el = document.getElementById('result-ssl');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span class="badge rentan">No SSL Found</span></div>`;
    return;
  }
  el.innerHTML = `
    <div class="item"><span>Status</span><span class="badge aman">Valid</span></div>
    <div class="item"><span>Issuer</span><span class="badge info">${data.issuer}</span></div>
    <div class="item"><span>Valid From</span><span class="badge info">${data.validFrom}</span></div>
    <div class="item"><span>Valid Until</span><span class="badge info">${data.validTo}</span></div>
  `;
}

function renderDNS(data) {
  const el = document.getElementById('result-dns');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span class="badge rentan">DNS Lookup Failed</span></div>`;
    return;
  }
  el.innerHTML = data.addresses.map(ip => `
    <div class="item"><span>IP Address</span><span class="badge info">${ip}</span></div>
  `).join('');
}

function renderPorts(data) {
  const el = document.getElementById('result-ports');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span class="badge rentan">Port Scan Failed</span></div>`;
    return;
  }
  el.innerHTML = Object.entries(data.results).map(([port, status]) => {
    const badge = status === 'open' ? 'warning' : 'aman';
    const label = status === 'open' ? 'Open' : 'Closed';
    return `
      <div class="item">
        <span>Port ${port}</span>
        <span class="badge ${badge}">${label}</span>
      </div>
    `;
  }).join('');
}

function renderWHOIS(data) {
  const el = document.getElementById('result-whois');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span class="badge rentan">WHOIS Lookup Failed</span></div>`;
    return;
  }
  el.innerHTML = `
    <div class="item"><span>Registrar</span><span class="badge info">${data.registrar}</span></div>
    <div class="item"><span>Created</span><span class="badge info">${data.createdDate}</span></div>
    <div class="item"><span>Expires</span><span class="badge info">${data.expiresDate}</span></div>
    <div class="item"><span>Updated</span><span class="badge info">${data.updatedDate}</span></div>
    <div class="item"><span>Status</span><span class="badge info">${data.status}</span></div>
  `;
}

function renderRedirects(data) {
  const el = document.getElementById('result-redirects');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span class="badge rentan">Redirect Check Failed</span></div>`;
    return;
  }
  if (data.chain.length === 0) {
    el.innerHTML = `<div class="item"><span class="badge aman">No Redirects Found</span></div>`;
    return;
  }
  el.innerHTML = data.chain.map((step, i) => `
    <div class="item">
      <span>Step ${i + 1} — ${step.status}</span>
      <span class="badge ${step.final ? 'aman' : 'warning'}">${step.url.length > 30 ? step.url.substring(0, 30) + '...' : step.url}</span>
    </div>
  `).join('');
}

function renderTech(data) {
  const el = document.getElementById('result-tech');
  if (!data.success) {
    el.innerHTML = `<div class="item"><span class="badge rentan">Detection Failed</span></div>`;
    return;
  }
  if (data.detected.length === 0) {
    el.innerHTML = `<div class="item"><span class="badge info">No Technologies Detected</span></div>`;
    return;
  }
  el.innerHTML = data.detected.map(tech => `
    <div class="item">
      <span>${tech.category}</span>
      <span class="badge info">${tech.name}</span>
    </div>
  `).join('');
}

function renderScore(headers, ssl) {
  const el = document.getElementById('result-score');
  let score = 0;

  if (headers.success) {
    const passed = Object.values(headers.checks).filter(Boolean).length;
    score += Math.round((passed / 5) * 60);
  }

  if (ssl.success && ssl.valid) score += 40;

  let colorClass = 'score-bad';
  let label = 'Dangerous';
  let desc = 'This website has critical security vulnerabilities that need immediate attention.';

  if (score >= 80) {
    colorClass = 'score-good';
    label = 'Secure';
    desc = 'This website has good security practices. Keep monitoring regularly.';
  } else if (score >= 50) {
    colorClass = 'score-medium';
    label = 'Moderate';
    desc = 'Some security issues were found. Consider fixing them to improve protection.';
  }

  el.innerHTML = `
    <div class="score-wrap">
      <div class="score-number ${colorClass}">${score}</div>
      <div class="score-label ${colorClass}">${label}</div>
      <div class="score-desc">${desc}</div>
    </div>
  `;
}

// Export PDF
exportBtn.addEventListener('click', () => {
  const element = document.getElementById('results');
  const domain = urlInput.value.trim().replace(/^https?:\/\//, '').split('/')[0];
  const opt = {
    margin: 10,
    filename: `fatalscan-${domain}.pdf`,
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: { scale: 2, backgroundColor: '#060b14' },
    jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
  };
  html2pdf().set(opt).from(element).save();
});