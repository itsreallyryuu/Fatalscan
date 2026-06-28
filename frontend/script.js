const BASE_URL = '';

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
    const [
      headers, ssl, dns, ports, whois, redirects, tech,
      methods, cors, cookies, clickjacking, csp, referrer,
      permissions, crossorigin, server, httpversion,
      robots, sitemap, sensitivefiles, configfiles, backupfiles, defaultpages,
      emailleakage, commentleakage, sourcemap, manifest,
      mixedcontent, https, hsts, certexpiry,
      securitytxt, humanstxt, swagger
    ] = (await Promise.allSettled([
      fetch(`${BASE_URL}/check/headers?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/ssl?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/dns?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/ports?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/whois?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/redirects?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/tech?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/methods?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/cors?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/cookies?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/clickjacking?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/csp?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/referrer?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/permissions?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/crossorigin?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/server?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/httpversion?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/robots?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/sitemap?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/sensitivefiles?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/configfiles?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/backupfiles?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/defaultpages?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/emailleakage?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/commentleakage?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/sourcemap?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/manifest?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/mixedcontent?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/https?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/hsts?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/certexpiry?domain=${encodeURIComponent(domain)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/securitytxt?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/humanstxt?url=${encodeURIComponent(url)}`).then(r => r.json()),
      fetch(`${BASE_URL}/check/swagger?url=${encodeURIComponent(url)}`).then(r => r.json()),
    ])).map(r => r.status === 'fulfilled' ? r.value : { success: false, message: 'Timeout or error' });
    renderHeaders(headers); renderSSL(ssl); renderDNS(dns); renderPorts(ports);
    renderWHOIS(whois); renderRedirects(redirects); renderTech(tech);
    renderMethods(methods); renderCORS(cors); renderCookies(cookies);
    renderClickjacking(clickjacking); renderCSP(csp); renderReferrer(referrer);
    renderPermissions(permissions); renderCrossOrigin(crossorigin);
    renderServer(server); renderHTTPVersion(httpversion);
    renderRobots(robots); renderSitemap(sitemap);
    renderSensitiveFiles(sensitivefiles); renderConfigFiles(configfiles);
    renderBackupFiles(backupfiles); renderDefaultPages(defaultpages);
    renderEmailLeakage(emailleakage); renderCommentLeakage(commentleakage);
    renderSourceMap(sourcemap); renderManifest(manifest);
    renderMixedContent(mixedcontent); renderHTTPS(https); renderHSTS(hsts);
    renderCertExpiry(certexpiry); renderSecurityTxt(securitytxt);
    renderHumansTxt(humanstxt); renderSwagger(swagger);
    renderScore(headers, ssl, hsts, cors, clickjacking, referrer, permissions);
    renderGrade(headers, ssl, hsts, cors, clickjacking, referrer, permissions);
  } catch (err) {
    alert('Failed to connect. Please try again.');
  } finally {
    loading.classList.add('hidden');
    results.classList.remove('hidden');
    lucide.createIcons();
  }
});

function clearResults() {
  ['result-headers','result-ssl','result-dns','result-ports',
   'result-whois','result-redirects','result-tech','result-methods',
   'result-cors','result-cookies','result-clickjacking','result-csp',
   'result-referrer','result-permissions','result-crossorigin',
   'result-server','result-httpversion','result-robots','result-sitemap',
   'result-sensitivefiles','result-configfiles','result-backupfiles',
   'result-defaultpages','result-emailleakage','result-commentleakage',
   'result-sourcemap','result-manifest','result-mixedcontent',
   'result-https','result-hsts','result-certexpiry','result-securitytxt',
   'result-humanstxt','result-swagger','result-score','result-grade']
    .forEach(id => document.getElementById(id).innerHTML = '');
}

function item(label, value, badge) {
  return `<div class="item"><span>${label}</span><span class="badge ${badge}">${value}</span></div>`;
}

function renderHeaders(data) {
  const el = document.getElementById('result-headers');
  if (!data.success) { el.innerHTML = item('Error', data.message, 'rentan'); return; }
  el.innerHTML = Object.entries(data.checks).map(([key, found]) =>
    item(key, found ? 'Present' : 'Missing', found ? 'aman' : 'rentan')
  ).join('');
}

function renderSSL(data) {
  const el = document.getElementById('result-ssl');
  if (!data.success) { el.innerHTML = item('Status', 'No SSL Found', 'rentan'); return; }
  el.innerHTML = `
    ${item('Status', 'Valid', 'aman')}
    ${item('Issuer', data.issuer, 'info')}
    ${item('Valid From', data.validFrom, 'info')}
    ${item('Valid Until', data.validTo, 'info')}
  `;
}

function renderDNS(data) {
  const el = document.getElementById('result-dns');
  if (!data.success) { el.innerHTML = item('Error', 'DNS Lookup Failed', 'rentan'); return; }
  el.innerHTML = data.addresses.map(ip => item('IP Address', ip, 'info')).join('');
}

function renderPorts(data) {
  const el = document.getElementById('result-ports');
  if (!data.success) { el.innerHTML = item('Error', 'Port Scan Failed', 'rentan'); return; }
  el.innerHTML = Object.entries(data.results).map(([port, status]) =>
    item(`Port ${port}`, status === 'open' ? 'Open' : 'Closed', status === 'open' ? 'warning' : 'aman')
  ).join('');
}

function renderWHOIS(data) {
  const el = document.getElementById('result-whois');
  if (!data.success) { el.innerHTML = item('Error', 'WHOIS Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('Registrar', data.registrar, 'info')}
    ${item('Created', data.createdDate, 'info')}
    ${item('Expires', data.expiresDate, 'info')}
    ${item('Updated', data.updatedDate, 'info')}
    ${item('Status', data.status, 'info')}
  `;
}

function renderRedirects(data) {
  const el = document.getElementById('result-redirects');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  if (data.chain.length === 0) { el.innerHTML = item('Redirects', 'None Found', 'aman'); return; }
  el.innerHTML = data.chain.map((step, i) =>
    item(`Step ${i+1} — ${step.status}`, step.url.length > 30 ? step.url.substring(0,30)+'...' : step.url, step.final ? 'aman' : 'warning')
  ).join('');
}

function renderTech(data) {
  const el = document.getElementById('result-tech');
  if (!data.success) { el.innerHTML = item('Error', 'Detection Failed', 'rentan'); return; }
  if (data.detected.length === 0) { el.innerHTML = item('Result', 'Nothing Detected', 'info'); return; }
  el.innerHTML = data.detected.map(t => item(t.category, t.name, 'info')).join('');
}

function renderMethods(data) {
  const el = document.getElementById('result-methods');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  el.innerHTML = Object.entries(data.results).map(([method, info]) =>
    item(method, `${info.status}`, info.allowed ? 'warning' : 'aman')
  ).join('');
}

function renderCORS(data) {
  const el = document.getElementById('result-cors');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('Allow-Origin', data.allowOrigin, data.vulnerable ? 'rentan' : 'aman')}
    ${item('Allow-Credentials', data.allowCredentials, 'info')}
    ${item('Wildcard Used', data.wildcardUsed ? 'Yes' : 'No', data.wildcardUsed ? 'rentan' : 'aman')}
    ${item('Vulnerable', data.vulnerable ? 'Yes' : 'No', data.vulnerable ? 'rentan' : 'aman')}
  `;
}

function renderCookies(data) {
  const el = document.getElementById('result-cookies');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  if (data.cookies.length === 0) { el.innerHTML = item('Cookies', 'No Cookies Found', 'info'); return; }
  el.innerHTML = data.cookies.map(c => `
    ${item('Cookie', c.raw.substring(0,20)+'...', 'info')}
    ${item('HttpOnly', c.httpOnly ? 'Yes' : 'No', c.httpOnly ? 'aman' : 'rentan')}
    ${item('Secure', c.secure ? 'Yes' : 'No', c.secure ? 'aman' : 'rentan')}
    ${item('SameSite', c.sameSite, c.sameSite !== 'Not Set' ? 'aman' : 'warning')}
  `).join('<hr style="border-color:#1e3a5f;margin:8px 0">');
}

function renderClickjacking(data) {
  const el = document.getElementById('result-clickjacking');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('X-Frame-Options', data.xFrameOptions, data.xFrameOptions !== 'Not Set' ? 'aman' : 'rentan')}
    ${item('CSP frame-ancestors', data.cspFrameAncestors, data.cspFrameAncestors === 'Present' ? 'aman' : 'rentan')}
    ${item('Protected', data.protected ? 'Yes' : 'No', data.protected ? 'aman' : 'rentan')}
  `;
}

function renderCSP(data) {
  const el = document.getElementById('result-csp');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  if (!data.present) { el.innerHTML = item('CSP', 'Not Set', 'rentan'); return; }
  el.innerHTML = data.directives.map(d => item('Directive', d.substring(0,35), 'info')).join('');
}

function renderReferrer(data) {
  const el = document.getElementById('result-referrer');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('Policy', data.policy, data.safe ? 'aman' : 'warning')}
    ${item('Safe', data.safe ? 'Yes' : 'No', data.safe ? 'aman' : 'rentan')}
  `;
}

function renderPermissions(data) {
  const el = document.getElementById('result-permissions');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('Present', data.present ? 'Yes' : 'No', data.present ? 'aman' : 'warning')}
    ${item('Policy', data.policy.substring(0,30), 'info')}
  `;
}

function renderCrossOrigin(data) {
  const el = document.getElementById('result-crossorigin');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('COEP', data.coep, data.coep !== 'Not Set' ? 'aman' : 'warning')}
    ${item('COOP', data.coop, data.coop !== 'Not Set' ? 'aman' : 'warning')}
    ${item('CORP', data.corp, data.corp !== 'Not Set' ? 'aman' : 'warning')}
  `;
}

function renderServer(data) {
  const el = document.getElementById('result-server');
  if (!data.success) { el.innerHTML = item('Error', 'Detection Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('Server', data.server, data.exposed ? 'warning' : 'aman')}
    ${item('Exposed', data.exposed ? 'Yes' : 'No', data.exposed ? 'warning' : 'aman')}
    ${item('X-Powered-By', data.poweredBy, data.poweredBy !== 'Not Set' ? 'warning' : 'aman')}
  `;
}

function renderHTTPVersion(data) {
  const el = document.getElementById('result-httpversion');
  if (!data.success) { el.innerHTML = item('Error', 'Detection Failed', 'rentan'); return; }
  el.innerHTML = item('HTTP Version', data.version, data.version === 'HTTP/2' || data.version === 'HTTP/3' ? 'aman' : 'warning');
}

function renderRobots(data) {
  const el = document.getElementById('result-robots');
  if (!data.success) { el.innerHTML = item('Status', 'Not Found', 'warning'); return; }
  el.innerHTML = `
    ${item('Status', 'Found', 'aman')}
    ${item('Sitemap Ref', data.hasSitemap ? 'Present' : 'Missing', data.hasSitemap ? 'aman' : 'warning')}
    ${item('Disallow Rules', data.disallowCount, 'info')}
  `;
}

function renderSitemap(data) {
  const el = document.getElementById('result-sitemap');
  if (!data.success) { el.innerHTML = item('Status', 'Not Found', 'warning'); return; }
  el.innerHTML = `
    ${item('Status', 'Found', 'aman')}
    ${item('URLs Found', data.urlCount, 'info')}
  `;
}

function renderSensitiveFiles(data) {
  const el = document.getElementById('result-sensitivefiles');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  if (data.found.length === 0) { el.innerHTML = item('Result', 'None Exposed', 'aman'); return; }
  el.innerHTML = data.found.map(f => item('Exposed', f, 'rentan')).join('');
}

function renderConfigFiles(data) {
  const el = document.getElementById('result-configfiles');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  if (data.found.length === 0) { el.innerHTML = item('Result', 'None Exposed', 'aman'); return; }
  el.innerHTML = data.found.map(f => item('Exposed', f, 'rentan')).join('');
}

function renderBackupFiles(data) {
  const el = document.getElementById('result-backupfiles');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  if (data.found.length === 0) { el.innerHTML = item('Result', 'None Exposed', 'aman'); return; }
  el.innerHTML = data.found.map(f => item('Exposed', f, 'rentan')).join('');
}

function renderDefaultPages(data) {
  const el = document.getElementById('result-defaultpages');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  if (data.found.length === 0) { el.innerHTML = item('Result', 'None Found', 'aman'); return; }
  el.innerHTML = data.found.map(f => item('Found', f, 'warning')).join('');
}

function renderEmailLeakage(data) {
  const el = document.getElementById('result-emailleakage');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  if (data.emails.length === 0) { el.innerHTML = item('Result', 'No Emails Found', 'aman'); return; }
  el.innerHTML = data.emails.map(e => item('Email', e, 'warning')).join('');
}

function renderCommentLeakage(data) {
  const el = document.getElementById('result-commentleakage');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  if (data.comments.length === 0) { el.innerHTML = item('Result', 'No Suspicious Comments', 'aman'); return; }
  el.innerHTML = data.comments.map(c => item('Comment', c.substring(0,30)+'...', 'warning')).join('');
}

function renderSourceMap(data) {
  const el = document.getElementById('result-sourcemap');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  el.innerHTML = item('Source Map', data.exposed ? 'Exposed' : 'Not Exposed', data.exposed ? 'rentan' : 'aman');
}

function renderManifest(data) {
  const el = document.getElementById('result-manifest');
  if (!data.success) { el.innerHTML = item('Status', 'Not Found', 'info'); return; }
  el.innerHTML = `
    ${item('Status', 'Found', 'aman')}
    ${item('App Name', data.name || 'N/A', 'info')}
    ${item('Start URL', data.startUrl || 'N/A', 'info')}
  `;
}

function renderMixedContent(data) {
  const el = document.getElementById('result-mixedcontent');
  if (!data.success) { el.innerHTML = item('Error', 'Scan Failed', 'rentan'); return; }
  el.innerHTML = item('Mixed Content', data.hasMixed ? 'Detected' : 'Not Detected', data.hasMixed ? 'rentan' : 'aman');
}

function renderHTTPS(data) {
  const el = document.getElementById('result-https');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('HTTPS', data.usesHttps ? 'Enabled' : 'Disabled', data.usesHttps ? 'aman' : 'rentan')}
    ${item('HTTP Redirect', data.redirectsToHttps ? 'Yes' : 'No', data.redirectsToHttps ? 'aman' : 'warning')}
  `;
}

function renderHSTS(data) {
  const el = document.getElementById('result-hsts');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('HSTS', data.present ? 'Present' : 'Missing', data.present ? 'aman' : 'rentan')}
    ${item('Max Age', data.maxAge || 'N/A', 'info')}
    ${item('Include Subdomains', data.includeSubdomains ? 'Yes' : 'No', data.includeSubdomains ? 'aman' : 'warning')}
  `;
}

function renderCertExpiry(data) {
  const el = document.getElementById('result-certexpiry');
  if (!data.success) { el.innerHTML = item('Error', 'Check Failed', 'rentan'); return; }
  el.innerHTML = `
    ${item('Expires On', data.validTo, 'info')}
    ${item('Days Left', data.daysLeft, data.daysLeft > 30 ? 'aman' : 'rentan')}
    ${item('Status', data.expired ? 'Expired' : 'Valid', data.expired ? 'rentan' : 'aman')}
  `;
}

function renderSecurityTxt(data) {
  const el = document.getElementById('result-securitytxt');
  if (!data.success) { el.innerHTML = item('Status', 'Not Found', 'warning'); return; }
  el.innerHTML = `
    ${item('Status', 'Found', 'aman')}
    ${item('Contact', data.contact || 'N/A', 'info')}
  `;
}

function renderHumansTxt(data) {
  const el = document.getElementById('result-humanstxt');
  if (!data.success) { el.innerHTML = item('Status', 'Not Found', 'info'); return; }
  el.innerHTML = item('Status', 'Found', 'aman');
}

function renderSwagger(data) {
  const el = document.getElementById('result-swagger');
  if (!data.success) { el.innerHTML = item('Status', 'Not Found', 'info'); return; }
  el.innerHTML = `
    ${item('Status', 'Found', 'warning')}
    ${item('Path', data.path, 'warning')}
  `;
}

function renderScore(headers, ssl, hsts, cors, clickjacking, referrer, permissions) {
  const el = document.getElementById('result-score');
  let score = 0;
  if (headers.success) {
    const passed = Object.values(headers.checks).filter(Boolean).length;
    score += Math.round((passed / 5) * 30);
  }
  if (ssl.success && ssl.valid) score += 20;
  if (hsts.success && hsts.present) score += 15;
  if (cors.success && !cors.vulnerable) score += 15;
  if (clickjacking.success && clickjacking.protected) score += 10;
  if (referrer.success && referrer.safe) score += 5;
  if (permissions.success && permissions.present) score += 5;
  let colorClass = 'score-bad', label = 'Dangerous';
  let desc = 'This website has critical security vulnerabilities that need immediate attention.';
  if (score >= 80) { colorClass = 'score-good'; label = 'Secure'; desc = 'This website has good security practices. Keep monitoring regularly.'; }
  else if (score >= 50) { colorClass = 'score-medium'; label = 'Moderate'; desc = 'Some security issues were found. Consider fixing them to improve protection.'; }
  el.innerHTML = `<div class="score-wrap"><div class="score-number ${colorClass}">${score}</div><div class="score-label ${colorClass}">${label}</div><div class="score-desc">${desc}</div></div>`;
}

function renderGrade(headers, ssl, hsts, cors, clickjacking, referrer, permissions) {
  const el = document.getElementById('result-grade');
  let score = 0;
  if (headers.success) {
    const passed = Object.values(headers.checks).filter(Boolean).length;
    score += Math.round((passed / 5) * 30);
  }
  if (ssl.success && ssl.valid) score += 20;
  if (hsts.success && hsts.present) score += 15;
  if (cors.success && !cors.vulnerable) score += 15;
  if (clickjacking.success && clickjacking.protected) score += 10;
  if (referrer.success && referrer.safe) score += 5;
  if (permissions.success && permissions.present) score += 5;
  let grade, colorClass;
  if (score >= 90) { grade = 'A+'; colorClass = 'score-good'; }
  else if (score >= 80) { grade = 'A'; colorClass = 'score-good'; }
  else if (score >= 70) { grade = 'B'; colorClass = 'score-good'; }
  else if (score >= 60) { grade = 'C'; colorClass = 'score-medium'; }
  else if (score >= 50) { grade = 'D'; colorClass = 'score-medium'; }
  else { grade = 'F'; colorClass = 'score-bad'; }
  el.innerHTML = `<div class="score-wrap"><div class="score-number ${colorClass}">${grade}</div><div class="score-label ${colorClass}">Security Grade</div><div class="score-desc">Based on ${score}/100 security score</div></div>`;
}

exportBtn.addEventListener('click', () => {
  const domain = urlInput.value.trim().replace(/^https?:\/\//, '').split('/')[0];
  const rows = [];

  // Header
  rows.push(['FATALSCAN SECURITY REPORT']);
  rows.push(['Target', domain]);
  rows.push(['URL', `https://${domain}`]);
  rows.push(['Generated', new Date().toLocaleString()]);
  rows.push(['Tool', 'fatalscan.vercel.app']);
  rows.push(['Built by', 'Adann (Akhdan Aryasatya Ramadhani)']);
  rows.push(['']);

  // Ambil score & grade dulu
  const scoreEl = document.querySelector('#result-score .score-number');
  const gradeEl = document.querySelector('#result-grade .score-number');
  const scoreLabelEl = document.querySelector('#result-score .score-label');
  const gradeLabelEl = document.querySelector('#result-grade .score-label');

  rows.push(['=== SECURITY SUMMARY ===']);
  rows.push(['Security Score', scoreEl?.innerText || 'N/A', scoreLabelEl?.innerText || '']);
  rows.push(['Security Grade', gradeEl?.innerText || 'N/A', gradeLabelEl?.innerText || '']);
  rows.push(['']);

  // Semua grup & card
  document.querySelectorAll('.group-label').forEach(group => {
    const groupName = group.innerText;
    rows.push([`=== ${groupName} ===`]);

    let el = group.nextElementSibling;
    while (el && el.classList.contains('results-grid')) {
      el.querySelectorAll('.card').forEach(card => {
        if (card.classList.contains('score-card') || card.classList.contains('export-card')) return;
        const title = card.querySelector('.card-header h2')?.innerText || '';
        rows.push([title]);
        card.querySelectorAll('.item').forEach(item => {
          const label = item.querySelector('span:first-child')?.innerText || '';
          const value = item.querySelector('.badge')?.innerText || '';
          if (label && value) rows.push(['', label, value]);
        });
        rows.push(['']);
      });
      el = el.nextElementSibling;
    }
  });

  // Footer
  rows.push(['=== END OF REPORT ===']);
  rows.push(['For educational and ethical use only']);
  rows.push(['fatalscan.vercel.app']);

  // Buat Excel
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);

  // Lebar kolom
  ws['!cols'] = [{ wch: 35 }, { wch: 35 }, { wch: 25 }];

  XLSX.utils.book_append_sheet(wb, ws, 'Security Report');
  XLSX.writeFile(wb, `fatalscan-${domain}.xlsx`);
});