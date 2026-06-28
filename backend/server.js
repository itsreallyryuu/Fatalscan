const express = require('express');
const axios = require('axios');
const cors = require('cors');
const https = require('https');
const dns = require('dns');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

app.use(cors());
app.use(express.json());
app.use(express.static('../frontend'));

// 1. Cek HTTP Security Headers
app.get('/check/headers', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000 });
    const headers = response.headers;

    const checks = {
      'X-Frame-Options': !!headers['x-frame-options'],
      'X-Content-Type-Options': !!headers['x-content-type-options'],
      'Content-Security-Policy': !!headers['content-security-policy'],
      'Strict-Transport-Security': !!headers['strict-transport-security'],
      'Referrer-Policy': !!headers['referrer-policy'],
    };

    res.json({ success: true, checks });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 2. Cek SSL
app.get('/check/ssl', (req, res) => {
  const { domain } = req.query;
  const options = { host: domain, port: 443, method: 'GET' };

  const request = https.request(options, (response) => {
    const cert = response.socket.getPeerCertificate();
    if (!cert || !cert.subject) {
      return res.json({ success: false, message: 'Tidak ada sertifikat SSL' });
    }
    res.json({
      success: true,
      valid: true,
      issuer: cert.issuer?.O || 'Unknown',
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
    });
  });

  request.on('error', (err) => {
    res.json({ success: false, valid: false, message: err.message });
  });

  request.end();
});

// 3. Cek DNS
app.get('/check/dns', (req, res) => {
  const { domain } = req.query;
  dns.resolve(domain, (err, addresses) => {
    if (err) return res.json({ success: false, message: err.message });
    res.json({ success: true, addresses });
  });
});

// 4. Port Scanning
app.get('/check/ports', (req, res) => {
  const { domain } = req.query;
  const ports = [80, 443, 8080, 8443, 21, 22, 3306];
  const results = {};
  let checked = 0;

  ports.forEach((port) => {
    const socket = new net.Socket();
    socket.setTimeout(2000);

    socket.connect(port, domain, () => {
      results[port] = 'open';
      socket.destroy();
    });

    socket.on('error', () => { results[port] = 'closed'; });
    socket.on('timeout', () => { results[port] = 'timeout'; socket.destroy(); });

    socket.on('close', () => {
      checked++;
      if (checked === ports.length) res.json({ success: true, results });
    });
  });
});

// 5. WHOIS Lookup
const whois = require('whois');

app.get('/check/whois', (req, res) => {
  const { domain } = req.query;
  whois.lookup(domain, (err, data) => {
    if (err) return res.json({ success: false, message: err.message });

    const extract = (pattern) => {
      const match = data.match(pattern);
      return match ? match[1].trim() : 'N/A';
    };

    res.json({
      success: true,
      registrar: extract(/Registrar:\s*(.+)/i),
      createdDate: extract(/Creation Date:\s*(.+)/i),
      expiresDate: extract(/Registry Expiry Date:\s*(.+)/i),
      updatedDate: extract(/Updated Date:\s*(.+)/i),
      status: extract(/Domain Status:\s*(.+)/i),
    });
  });
});

// 6. HTTP Redirect Checker
app.get('/check/redirects', async (req, res) => {
  const { url } = req.query;
  const chain = [];

  const follow = async (currentUrl, count) => {
    if (count > 10) return;
    try {
      const response = await axios.get(currentUrl, {
        maxRedirects: 0,
        validateStatus: (s) => s < 400,
        timeout: 5000,
      });

      chain.push({
        url: currentUrl,
        status: response.status,
        final: !response.headers['location'],
      });

      if (response.headers['location']) {
        const next = response.headers['location'].startsWith('http')
          ? response.headers['location']
          : new URL(response.headers['location'], currentUrl).href;
        await follow(next, count + 1);
      }
    } catch (err) {
      chain.push({ url: currentUrl, status: 'Error', final: true });
    }
  };

  await follow(url, 0);
  res.json({ success: true, chain });
});

// 7. Technology Detector
app.get('/check/tech', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000 });
    const html = response.data;
    const headers = response.headers;
    const detected = [];

    // CMS Detection
    if (html.includes('wp-content') || html.includes('wp-includes')) detected.push({ name: 'WordPress', category: 'CMS' });
    if (html.includes('Joomla') || html.includes('/components/com_')) detected.push({ name: 'Joomla', category: 'CMS' });
    if (html.includes('Drupal') || html.includes('/sites/default/files')) detected.push({ name: 'Drupal', category: 'CMS' });
    if (html.includes('__NEXT_DATA__') || html.includes('/_next/')) detected.push({ name: 'Next.js', category: 'Framework' });
    if (html.includes('nuxt') || html.includes('__NUXT__')) detected.push({ name: 'Nuxt.js', category: 'Framework' });
    if (html.includes('ng-version') || html.includes('ng-app')) detected.push({ name: 'Angular', category: 'Framework' });
    if (html.includes('react') || html.includes('__REACT')) detected.push({ name: 'React', category: 'Library' });
    if (html.includes('vue') || html.includes('Vue.js')) detected.push({ name: 'Vue.js', category: 'Framework' });
    if (html.includes('jQuery') || html.includes('jquery')) detected.push({ name: 'jQuery', category: 'Library' });
    if (html.includes('bootstrap') || html.includes('Bootstrap')) detected.push({ name: 'Bootstrap', category: 'CSS Framework' });
    if (html.includes('tailwind') || html.includes('Tailwind')) detected.push({ name: 'Tailwind CSS', category: 'CSS Framework' });
    if (html.includes('shopify') || html.includes('Shopify')) detected.push({ name: 'Shopify', category: 'E-Commerce' });
    if (html.includes('woocommerce') || html.includes('WooCommerce')) detected.push({ name: 'WooCommerce', category: 'E-Commerce' });

    // Server Detection
    if (headers['server']) detected.push({ name: headers['server'], category: 'Server' });
    if (headers['x-powered-by']) detected.push({ name: headers['x-powered-by'], category: 'Powered By' });

    res.json({ success: true, detected });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 3. HTTP Methods Scanner
app.get('/check/methods', async (req, res) => {
  const { url } = req.query;
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];
  const results = {};

  await Promise.all(methods.map(async (method) => {
    try {
      const response = await axios({ method, url, timeout: 5000, validateStatus: () => true });
      results[method] = { status: response.status, allowed: response.status !== 405 };
    } catch {
      results[method] = { status: 'Error', allowed: false };
    }
  }));

  res.json({ success: true, results });
});

// 4. CORS Configuration Scanner
app.get('/check/cors', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      headers: { 'Origin': 'https://evil.com' },
      validateStatus: () => true
    });
    const headers = response.headers;
    const acao = headers['access-control-allow-origin'];
    const acac = headers['access-control-allow-credentials'];

    res.json({
      success: true,
      allowOrigin: acao || 'Not Set',
      allowCredentials: acac || 'Not Set',
      vulnerable: acao === '*' || acao === 'https://evil.com',
      wildcardUsed: acao === '*',
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 5. Cookie Security Scanner
app.get('/check/cookies', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const rawCookies = response.headers['set-cookie'] || [];

    if (rawCookies.length === 0) {
      return res.json({ success: true, cookies: [], message: 'No cookies found' });
    }

    const cookies = rawCookies.map(cookie => ({
      raw: cookie.split(';')[0],
      httpOnly: /httponly/i.test(cookie),
      secure: /secure/i.test(cookie),
      sameSite: /samesite=(\w+)/i.exec(cookie)?.[1] || 'Not Set',
    }));

    res.json({ success: true, cookies });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 6. Clickjacking Protection Scanner
app.get('/check/clickjacking', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const headers = response.headers;
    const xfo = headers['x-frame-options'];
    const csp = headers['content-security-policy'];
    const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);

    res.json({
      success: true,
      xFrameOptions: xfo || 'Not Set',
      cspFrameAncestors: hasFrameAncestors ? 'Present' : 'Not Set',
      protected: !!(xfo || hasFrameAncestors),
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 7. CSP Analyzer
app.get('/check/csp', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const csp = response.headers['content-security-policy'];

    if (!csp) return res.json({ success: true, present: false, directives: [] });

    const directives = csp.split(';').map(d => d.trim()).filter(Boolean);
    res.json({ success: true, present: true, directives });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 8. Referrer Policy Checker
app.get('/check/referrer', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const policy = response.headers['referrer-policy'];
    const safeValues = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'];

    res.json({
      success: true,
      policy: policy || 'Not Set',
      safe: policy ? safeValues.includes(policy.toLowerCase()) : false,
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 9. Permissions Policy Checker
app.get('/check/permissions', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const policy = response.headers['permissions-policy'] || response.headers['feature-policy'];

    res.json({
      success: true,
      present: !!policy,
      policy: policy || 'Not Set',
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// 10. Cross-Origin Policy Checker
app.get('/check/crossorigin', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const headers = response.headers;

    res.json({
      success: true,
      coep: headers['cross-origin-embedder-policy'] || 'Not Set',
      coop: headers['cross-origin-opener-policy'] || 'Not Set',
      corp: headers['cross-origin-resource-policy'] || 'Not Set',
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Server Detection
app.get('/check/server', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const server = response.headers['server'] || 'Not Set';
    const poweredBy = response.headers['x-powered-by'] || 'Not Set';
    res.json({
      success: true,
      server,
      poweredBy,
      exposed: server !== 'Not Set' || poweredBy !== 'Not Set',
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// HTTP Version Detection
app.get('/check/httpversion', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const version = response.request?.res?.httpVersion || '1.1';
    res.json({ success: true, version: `HTTP/${version}` });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Robots.txt Scanner
app.get('/check/robots', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(`${url}/robots.txt`, { timeout: 5000, validateStatus: () => true });
    if (response.status !== 200) return res.json({ success: false });
    const body = response.data;
    const disallowCount = (body.match(/Disallow:/gi) || []).length;
    const hasSitemap = /sitemap/i.test(body);
    res.json({ success: true, hasSitemap, disallowCount });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Sitemap.xml Scanner
app.get('/check/sitemap', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(`${url}/sitemap.xml`, { timeout: 5000, validateStatus: () => true });
    if (response.status !== 200) return res.json({ success: false });
    const urlCount = (response.data.match(/<url>/gi) || []).length;
    res.json({ success: true, urlCount });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Sensitive Files Scanner
app.get('/check/sensitivefiles', async (req, res) => {
  const { url } = req.query;
  const files = ['.env', '.git/config', '.htaccess', 'wp-config.php', 'config.php'];
  const found = [];
  await Promise.all(files.map(async (file) => {
    try {
      const r = await axios.get(`${url}/${file}`, { timeout: 4000, validateStatus: () => true });
      if (r.status === 200) found.push(file);
    } catch {}
  }));
  res.json({ success: true, found });
});

// Config Files Scanner
app.get('/check/configfiles', async (req, res) => {
  const { url } = req.query;
  const files = ['config.yml', 'config.yaml', 'config.json', 'database.yml', 'settings.py', 'appsettings.json'];
  const found = [];
  await Promise.all(files.map(async (file) => {
    try {
      const r = await axios.get(`${url}/${file}`, { timeout: 4000, validateStatus: () => true });
      if (r.status === 200) found.push(file);
    } catch {}
  }));
  res.json({ success: true, found });
});

// Backup Files Scanner
app.get('/check/backupfiles', async (req, res) => {
  const { url } = req.query;
  const files = ['backup.zip', 'backup.sql', 'db.sql', 'dump.sql', 'site.tar.gz', 'backup.tar.gz'];
  const found = [];
  await Promise.all(files.map(async (file) => {
    try {
      const r = await axios.get(`${url}/${file}`, { timeout: 4000, validateStatus: () => true });
      if (r.status === 200) found.push(file);
    } catch {}
  }));
  res.json({ success: true, found });
});

// Default Pages Scanner
app.get('/check/defaultpages', async (req, res) => {
  const { url } = req.query;
  const pages = ['/admin', '/login', '/phpmyadmin', '/wp-admin', '/administrator', '/cpanel'];
  const found = [];
  await Promise.all(pages.map(async (page) => {
    try {
      const r = await axios.get(`${url}${page}`, { timeout: 4000, validateStatus: () => true });
      if (r.status === 200 || r.status === 401 || r.status === 403) found.push(page);
    } catch {}
  }));
  res.json({ success: true, found });
});

// Email Leakage Scanner
app.get('/check/emailleakage', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const emails = [...new Set(response.data.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/g) || [])];
    res.json({ success: true, emails });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Comment Leakage Scanner
app.get('/check/commentleakage', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const comments = [...(response.data.match(/<!--[\s\S]*?-->/g) || [])]
      .filter(c => /todo|fix|hack|password|secret|key|bug|admin|remove/i.test(c));
    res.json({ success: true, comments });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Source Map Exposure
app.get('/check/sourcemap', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const exposed = /\.map['"]/.test(response.data);
    res.json({ success: true, exposed });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Manifest.json Analyzer
app.get('/check/manifest', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(`${url}/manifest.json`, { timeout: 5000, validateStatus: () => true });
    if (response.status !== 200) return res.json({ success: false });
    const data = response.data;
    res.json({ success: true, name: data.name, startUrl: data.start_url });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Mixed Content Scanner
app.get('/check/mixedcontent', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const hasMixed = /http:\/\/[^"'\s]+\.(js|css|png|jpg|gif|svg)/i.test(response.data);
    res.json({ success: true, hasMixed });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// HTTPS Enforcement
app.get('/check/https', async (req, res) => {
  const { url } = req.query;
  const httpUrl = url.replace('https://', 'http://');
  try {
    const response = await axios.get(httpUrl, { timeout: 5000, maxRedirects: 0, validateStatus: () => true });
    const redirectsToHttps = response.status >= 300 && response.status < 400 &&
      response.headers['location']?.startsWith('https');
    res.json({ success: true, usesHttps: url.startsWith('https'), redirectsToHttps: !!redirectsToHttps });
  } catch (err) {
    res.json({ success: true, usesHttps: url.startsWith('https'), redirectsToHttps: false });
  }
});

// HSTS Checker
app.get('/check/hsts', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const hsts = response.headers['strict-transport-security'];
    const maxAgeMatch = hsts?.match(/max-age=(\d+)/);
    res.json({
      success: true,
      present: !!hsts,
      maxAge: maxAgeMatch ? maxAgeMatch[1] : null,
      includeSubdomains: /includeSubDomains/i.test(hsts || ''),
    });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// Certificate Expiration
app.get('/check/certexpiry', (req, res) => {
  const { domain } = req.query;
  const options = { host: domain, port: 443, method: 'GET' };
  const request = https.request(options, (response) => {
    const cert = response.socket.getPeerCertificate();
    if (!cert || !cert.valid_to) return res.json({ success: false });
    const validTo = new Date(cert.valid_to);
    const daysLeft = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));
    res.json({ success: true, validTo: cert.valid_to, daysLeft, expired: daysLeft < 0 });
  });
  request.on('error', () => res.json({ success: false }));
  request.end();
});

// Security.txt Scanner
app.get('/check/securitytxt', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(`${url}/.well-known/security.txt`, { timeout: 5000, validateStatus: () => true });
    if (response.status !== 200) return res.json({ success: false });
    const contact = response.data.match(/Contact:\s*(.+)/i)?.[1]?.trim();
    res.json({ success: true, contact });
  } catch (err) {
    res.json({ success: false });
  }
});

// Humans.txt Scanner
app.get('/check/humanstxt', async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(`${url}/humans.txt`, { timeout: 5000, validateStatus: () => true });
    res.json({ success: response.status === 200 });
  } catch (err) {
    res.json({ success: false });
  }
});

// Swagger / API Docs Detection
app.get('/check/swagger', async (req, res) => {
  const { url } = req.query;
  const paths = ['/swagger', '/api-docs', '/openapi.json', '/swagger.json', '/api/swagger'];
  for (const path of paths) {
    try {
      const r = await axios.get(`${url}${path}`, { timeout: 4000, validateStatus: () => true });
      if (r.status === 200) return res.json({ success: true, path });
    } catch {}
  }
  res.json({ success: false });
});

app.listen(PORT, HOST, () => {
  console.log(`Server berjalan di ${HOST}:${PORT}`);
});