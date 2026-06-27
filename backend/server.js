const express = require('express');
const axios = require('axios');
const cors = require('cors');
const https = require('https');
const dns = require('dns');
const net = require('net');

const app = express();
const PORT = 3000;

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

app.listen(PORT, () => {
  console.log(`Server jalan di http://localhost:${PORT}`);
});