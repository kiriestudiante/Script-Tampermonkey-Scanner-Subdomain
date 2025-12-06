
  // ==UserScript==
  // @name         Subdomain Scanner
  // @namespace    https://tu-script/
  // @version      10.2
  // @description  Escáner avanzado de subdominios
  // @match        https://www.google.com/search*
  // @grant        GM_xmlhttpRequest
  // @grant        GM_addStyle
  // @connect      google.com
  // @connect      www.google.com
  // @connect      crt.sh
  // @connect      dns.google
  // @connect      ssllabs.com
  // @connect      api.bgpview.io
  // @connect      ipinfo.io
  // @connect      ipapi.co
  // @connect      ip-api.com
  // @connect      whois.com
  // @connect      dns.google
  // @connect      www.iana.org
  // @connect      api.endpoints.sh
  // @connect      *
  // @connect      api.hackertarget.com
  // @require      https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js
  // ==/UserScript==

  (function(){
  'use strict';

  const q = new URL(location.href).searchParams.get("q");
  if (!q) return;
  let targetDomain = "";
  if (q.includes("site:")) targetDomain = (q.match(/site:([^\s]+)/)||[])[1] || "";

  const allSubdomains = new Set();
  const domainPaths = {}; // usado para guardar paths por subdominio

  /* UI */
  const panel = document.createElement('div');
  panel.id = 'subPanel';
  panel.innerHTML = `
    <h2 style="margin-top:0">🔍 Subdomain Scanner </h2>
    <b>Dominio:</b> ${targetDomain || "(ninguno)"}<br><br>
    <button id="btnSubScan">🚀 Escanear Completo</button>
    <button id="btnDocSearch">📄 Docs Sensibles</button>
    <div id="results"></div>
  `;
  document.body.appendChild(panel);

  GM_addStyle(`
    #subPanel{position:fixed;top:20px;right:20px;width:480px;background:#111;color:#0f0;padding:15px;z-index:9999999;border:2px solid #0f0;font-family:monospace;max-height:88vh;overflow-y:auto;box-shadow:0 0 10px #0f0}
    #subPanel button{width:100%;padding:10px;background:#0f0;color:#000;cursor:pointer;margin-bottom:10px;font-weight:bold}
    .subdomain-card{padding:8px;margin-top:8px;border-bottom:1px solid #0f0}
  `);

  /* Helpers using GM_xmlhttpRequest */
  function gmGet(url, timeout=10000) {
    return new Promise((resolve,reject)=>{
      GM_xmlhttpRequest({
        method:'GET', url, timeout,
        onload: res => resolve(res),
        onerror: err => reject(err),
        ontimeout: () => reject(new Error('timeout'))
      });
    });
  }

  function gmGetText(url, timeout=10000){
    return gmGet(url, timeout).then(r => r.responseText);
  }

  function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

 
  function fetchGooglePage(start=0, customQuery=null){
    const query = customQuery || q;
    const url = `https://www.google.com/search?q=${encodeURIComponent(query)}&start=${start}`;
    return gmGetText(url,8000).catch(()=>null);
  }

  /* DNS & WHOIS */
  async function fetchDNSRecordTXT(name){
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`;
    try {
      const res = await gmGet(url,8000);
      const json = JSON.parse(res.responseText);
      if (!json.Answer) return "No encontrado";
      return json.Answer.map(a => a.data.replace(/"/g,"")).join(" | ");
    } catch(e){ return "No encontrado";}
  }

  async function fetchDNSRecords(domain){
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
    const records = {};

    for (const type of types) {
        try {
            const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
            const res = await gmGet(url, 5000);
            const json = JSON.parse(res.responseText);
            if (json.Answer && json.Answer.length) {
                records[type] = json.Answer.map(a => a.data).slice(0, 3); // Max 3 por tipo
            }
        } catch(e) {}
    }
    return records;
}
async function getFirstIP(records) {
    return records.A?.[0] || records.AAAA?.[0] || null;
}


let ianaCache = null;

async function getPortService(port) {
    if (ianaCache) return ianaCache[port] || 'unknown';

    try {
        // CDN público con datos IANA 
        const resp = await fetch('https://raw.githubusercontent.com/npm/service-names-port-numbers/main/numbers.json');
        const data = await resp.json();
        
        ianaCache = {};
        data.forEach(s => {
            const portNum = parseInt(s.PortNumber);
            if (portNum && !ianaCache[portNum]) {
                ianaCache[portNum] = s.ServiceName || 'unknown';
            }
        });
        console.log(`✅ IANA CDN cache: ${Object.keys(ianaCache).length} puertos`);
    } catch(e) {
        console.log('❌ CDN falló, usando fallback completo');
        ianaCache = fallbackIANA();
    }
    
    return ianaCache[port] || 'unknown';
}
function fallbackIANA() {
    return {
        // Del attachment IANA 
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
        80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
        139: 'netbios-ssn', 143: 'imap2', 443: 'https', 993: 'imaps',
        995: 'pop3s', 1433: 'ms-sql-s', 3306: 'mysql', 3389: 'ms-wbt-server',
        5432: 'postgresql', 5900: 'vnc', 8080: 'http-alt', 8443: 'https-alt',
        
        // + Del attachment expandido
        5: 'rje', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime',
        17: 'qotd', 19: 'chargen', 20: 'ftp-data', 37: 'time', 42: 'nameserver',
        43: 'nicname', 79: 'finger', 123: 'ntp', 179: 'bgp', 389: 'ldap'
    };
}
async function scanPorts(input) {
    // Acepta IP o dominio
    let ip = input;
    if (!ip || ip === 'No IP') return [];

    // Detectar si la página actual es HTTPS
    const isPageHTTPS = location.protocol === 'https:';

    // Si es dominio, resuelve a IP primero
    if (!ip.match(/\d+\.\d+\.\d+\.\d+/)) {
        ip = await resolveDomainToIP(ip);
        if (!ip) {
            console.warn(`No se encontró IP para ${input}`);
            return [];
        }
        console.log(`Dominio ${input} resuelto a IP ${ip}`);
    }

    // 1. Primero Shodan
    const shodanPorts = await scanPortsShodan(ip);
    if (shodanPorts.length > 0) return shodanPorts;

    // 2. Fallback solo puertos web seguros
    const webPorts = [80, 443, 8080, 8443, 3000, 5000, 8000];
    const checks = webPorts.map(p => new Promise(resolve => {
        // Usar HTTPS si la página es HTTPS y puerto soporta SSL
        const useHTTPS = isPageHTTPS && (p === 443 || p === 8443);
        const proto = useHTTPS ? 'https' : 'http';
        
        const img = new Image();
        const url = `${proto}://${ip}:${p}/favicon.ico?d=${Date.now()}`;
        let done = false;
        
        img.onload = () => { done = true; resolve(p); };
        img.onerror = () => { done = true; resolve(null); };
        img.src = url;
        
        setTimeout(() => { if (!done) { done = true; resolve(null); } }, 2000);
    }));

    const results = await Promise.all(checks);
    return results.filter(Boolean).sort((a, b) => a - b);
}


async function resolveDomainToIP(domain) {
    try {
        const res = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
        const data = await res.json();
        return data.Answer?.find(a => a.type === 1)?.data || null;
    } catch {
        console.error('IANA falló, usando fallback');
        return null;
    }
}

async function scanPortsShodan(ip) {
    try {
        const res = await fetch(`https://internetdb.shodan.io/${ip}`);
        const data = await res.json();
        return data.ports || [];
    } catch {
        return [];
    }
}
  /* Detect technologias */
const TECHNOLOGIES = [
  // CMS y PHP
  {
    name: "WordPress",
    patterns: { html: [/wp-content/i, /wp-includes/i], script: [/wp-.*\.js/i], header: [/x-powered-by:\s*wordpress/i] },
    version: [{ header: /x-powered-by:\s*wordpress\/([\d\.]+)/i }, { html: /\/wp-includes\/[^"]+ver=([\d\.]+)/i }]
  },
  {
    name: "PHP",
    patterns: { header: [/x-powered-by:\s*php/i] },
    version: [{ header: /x-powered-by:\s*php\/([\d\.]+)/i }]
  },
  {
    name: "Laravel",
    patterns: { html: [/laravel/i], script: [/laravel/i], header: [/x-powered-by:laravel/i], meta: [/csrf-token/i] },
    version: [{ html: /laravel.*version["']?:\s*([\d\.]+)/i }]
  },
  {
    name: "Symfony",
    patterns: { html: [/symfony/i], header: [/x-debug-token/i] },
    version: [{ header: /x-symfony-version:\s*([\d\.]+)/i }]
  },
  {
    name: "Drupal",
    patterns: { html: [/drupal-settings-json/i], meta: [/generator:drupal/i] }
  },
  {
    name: "Joomla",
    patterns: { html: [/com_content/i], meta: [/generator:joomla/i] }
  },
  {
    name: "Magento",
    patterns: { html: [/mage\//i], header: [/x-magento/i] }
  },
  {
    name: "PrestaShop",
    patterns: { html: [/prestashop/i], meta: [/generator:prestashop/i] }
  },
  {
    name: "Shopify",
    patterns: { html: [/shopify/i, /cdn\.shopify\.com/i], header: [/x-shopify/i] }
  },
  {
    name: "Ghost",
    patterns: { html: [/ghost/i], header: [/x-powered-by:ghost/i] }
  },
  {
    name: "Typo3",
    patterns: { meta: [/generator:typo3/i], html: [/typo3/i] }
  },
  // JS Frontend
  {
    name: "jQuery",
    patterns: { script: [/jquery/i] },
    version: [{ script: /jquery-(\d+\.\d+\.\d+)\.js/i }]
  },
  { name: "React", patterns: { script: [/react/i] } },
  {
    name: "Vue.js",
    patterns: { script: [/vue(\.min)?\.js/i] },
    version: [{ script: /vue(?:\.min)?\.js\?ver=([\d\.]+)/i }]
  },
  { name: "Angular", patterns: { script: [/angular/i], html: [/ng-version/i] } },
  { name: "Svelte", patterns: { script: [/svelte/i], html: [/svelte/i] } },
  { name: "Ember.js", patterns: { script: [/ember(\.min)?\.js/i] } },
  { name: "Backbone.js", patterns: { script: [/backbone(\.min)?\.js/i] } },
  // CSS Frameworks
  { name: "Bootstrap", patterns: { html: [/bootstrap/i], script: [/bootstrap/i] }, version: [{ script: /bootstrap(?:\.min)?\.js\?ver=([\d\.]+)/i }] },
  { name: "TailwindCSS", patterns: { html: [/class="w-/, /class="bg-/, /class="text-/] } },
  { name: "Bulma", patterns: { html: [/bulma/i] } },
  { name: "Foundation", patterns: { html: [/foundation/i] } },
  // Servidores Web
  {
    name: "Apache",
    patterns: { header: [/server:\s*apache/i] },
    version: [{ header: /server:\s*apache\/([\d\.]+)/i }]
  },
  {
    name: "Nginx",
    patterns: { header: [/server:\s*nginx/i] },
    version: [{ header: /server:\s*nginx\/([\d\.]+)/i }]
  },
  {
    name: "IIS",
    patterns: { header: [/server:microsoft-iis/i] },
    version: [{ header: /server:microsoft-iis\/([\d\.]+)/i }]
  },
  {
    name: "LiteSpeed",
    patterns: { header: [/server:litespeed/i] },
    version: [{ header: /server:litespeed\/([\d\.]+)/i }]
  },
  { name: "Caddy", patterns: { header: [/server:\s*caddy/i] } },
  { name: "Gunicorn", patterns: { header: [/server:\s*gunicorn/i] } },
  // CDN / WAF
  {
    name: "Cloudflare",
    patterns: { header: [/cf-ray/i, /cf-cache-status/i], html: [/cloudflare/i] }
  },
  { name: "AWS", patterns: { header: [/server:amazon/i], html: [/aws/i] } },
  { name: "Google Cloud", patterns: { header: [/server:gws/i], html: [/google/i] } },
  { name: "Akamai", patterns: { header: [/akamai/i] } },
  { name: "Fastly", patterns: { header: [/fastly/i] } },
  // Node.js Backend
  {
    name: "Node.js",
    patterns: { header: [/x-powered-by:express/i], script: [/express/i] }
  },
  { name: "Express", patterns: { header: [/x-powered-by:express/i] } },
  { name: "NestJS", patterns: { script: [/nestjs/i] } },
  { name: "Koa", patterns: { script: [/koa/i] } },
  // Bases de datos visibles / clientes JS
  { name: "MongoDB", patterns: { script: [/mongodb/i], html: [/mongodb/i] } },
  { name: "MySQL", patterns: { html: [/mysql/i] } },
  { name: "PostgreSQL", patterns: { html: [/postgresql/i] } },
  { name: "Redis", patterns: { html: [/redis/i] } },
  // Otros frameworks backend
  { name: "Django", patterns: { header: [/x-powered-by:django/i], html: [/csrfmiddlewaretoken/i] } },
  { name: "Flask", patterns: { header: [/x-powered-by:flask/i], html: [/flask/i] } },
  // Otros
  { name: "Apache Solr", patterns: { header: [/server:solr/i], html: [/solr/i] } },
  { name: "Elasticsearch", patterns: { html: [/elasticsearch/i] } },
  { name: "Google Analytics", patterns: { script: [/google-analytics\.com/i] } },
  { name: "Matomo", patterns: { script: [/matomo.js/i] } }
];

// ---------------------- DETECTOR Tecnologias ----------------------
function detectTechnologies(fullHTML, scripts, headers) {
  const results = [];
  TECHNOLOGIES.forEach(tech => {
    let found = false;

    if (tech.patterns.html)
      tech.patterns.html.forEach(r => { if (!found && r.test(fullHTML)) found = true; });
    if (tech.patterns.script)
      tech.patterns.script.forEach(r => { if (!found && scripts.some(s => r.test(s))) found = true; });
    if (tech.patterns.header)
      tech.patterns.header.forEach(r => { if (!found && headers.some(h => r.test(h))) found = true; });

    if (found) {
      let version = null;
      if (tech.version) {
        tech.version.forEach(rule => {
          if (!version && rule.header)
            headers.forEach(h => { const m = h.match(rule.header); if (m) version = m[1]; });
          if (!version && rule.script)
            scripts.forEach(s => { const m = s.match(rule.script); if (m) version = m[1]; });
          if (!version && rule.html) {
            const m = fullHTML.match(rule.html);
            if (m) version = m[1];
          }
        });
      }
      results.push({ tech: tech.name, version });
    }
  });
  return results;
}



  function fetchFullSite(domain){
    return new Promise(resolve=>{
      const urls = [`https://${domain}`, `http://${domain}`];
      let i = 0;
      function next(){
        if (i>=urls.length) return resolve({title:"No responde", techs:[], html:"", headers:"", alive:false});
        GM_xmlhttpRequest({
          method:'GET', url: urls[i], timeout:8000,
          onload: res => {
            const status = res.status || 0;
            const html = res.responseText || "";
            const headers = (res.responseHeaders||"").split("\n").map(s=>s.trim());
            const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)/gi)].map(m=>m[1]||"");
            const title = (html.match(/<title>([^<]+)<\/title>/i)||[])[1] || "Sin título";
            const techs = detectTechnologies(html, scripts, headers);
            let alive = true;
            if (status >= 400 || status === 0) alive = false;
            if (html.length < 500) alive = false;
            const badTitles = [/403/i,/forbidden/i,/404/i,/not found/i,/error/i,/500/i,/bad gateway/i,/maintenance/i];
            if (badTitles.some(r=>r.test(title))) alive = false;
            resolve({title, techs, html, headers, alive});
          },
          onerror: ()=>{ i++; next(); }
        });
      }
      next();
    });
  }

  /* Subdomain extraction */
  function normalizeDomain(d){ return d.replace(/^www\./i,''); }

  function extractFromHTML(html){
    try{
      const doc = new DOMParser().parseFromString(html,'text/html');
      doc.querySelectorAll('a[href]').forEach(a=>{
        try{
          const u = new URL(a.href, location.href);
          const host = normalizeDomain(u.hostname);
          if (targetDomain && host.endsWith(targetDomain)) {
            allSubdomains.add(host);
            const path = u.pathname + u.search;
            if (!domainPaths[host]) domainPaths[host] = new Set();
            if (path !== '/' && path.length < 200) domainPaths[host].add(path);
          }
        }catch(e){}
      });
    }catch(e){}
  }

  async function extractFromCRT(domain){
    try{
      const text = await gmGetText(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,8000);
      const data = JSON.parse(text);
      data.forEach(cert=>{
        const names = (cert.name_value||'').split("\n");
        names.forEach(n=>{
          const clean = normalizeDomain(n.replace('*.','').trim());
          if (clean.endsWith(domain)) allSubdomains.add(clean);
        });
      });
    }catch(e){}
  }

  async function extractSubdomainsFromDOM(){
       console.log("🔍 Buscando subdominios…");
    await extractFromCRT(targetDomain);
 
    document.querySelectorAll('a[href]').forEach(a=>{
      try{
        const u = new URL(a.href, location.href);
        const host = normalizeDomain(u.hostname);
        if (host.endsWith(targetDomain)) allSubdomains.add(host);
      }catch(e){}
    });
     console.log("✔ Total encontrados:", allSubdomains.size);
    return [...allSubdomains];
  }



  /* DNS A -> IP */
  function fetchIP(domain){
    return new Promise(resolve=>{
      GM_xmlhttpRequest({
        method:'GET',
        url: `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
        onload: res => {
          try {
            const json = JSON.parse(res.responseText);
            const record = json.Answer?.find(a=>a.type===1);
            resolve(record?.data || "No IP");
          }catch(e){ resolve("No IP"); }
        },
        onerror: ()=>resolve("No IP")
      });
    });
  }

  /* ASN + CIDR (simple chaining of public apis) */
async function getASNandCIDR(ip) {
    if (!ip || ip === "No IP") return { asn: 'N/A', provider: 'N/A', cidr: 'N/A', range: 'N/A' };

    const fetchWithGM = (url, timeout = 5000) =>
        gmGetText(url, timeout)
            .then(t => {
                try {
                    return JSON.parse(t);
                } catch {
                    return null;
                }
            })
            .catch(() => null);

    let asn = 'N/A', provider = 'N/A', cidr = 'N/A', range = 'N/A';

    // 1. ipinfo.io
    try {
        const ipinfo = await fetchWithGM(`https://ipinfo.io/${ip}/json`);
        if (ipinfo) {
            asn = ipinfo.asn || (ipinfo.org?.match(/AS\d+/) || ['N/A'])[0];
            provider = ipinfo.org || 'N/A';
            cidr = ipinfo.network || ipinfo.readable_range || 'N/A';
        }
    } catch {}

    // 2. BGPView  
    if (asn && /^AS\d+/i.test(asn)) {
        const num = asn.replace(/AS/i, '');
        try {
            const bgp = await fetchWithGM(`https://api.bgpview.io/asn/${num}`);
            if (bgp?.status === 'ok' && bgp?.data) {
                const prefixes = bgp.data.ipv4_prefixes?.map(p => p.prefix).filter(Boolean) || [];
                if (prefixes.length) {
                    range = prefixes.slice(0, 5).join(', ');
                } else {
                    const allPrefixes = (bgp.data.prefixes || []).map(p => p.prefix).filter(Boolean);
                    if (allPrefixes.length) range = allPrefixes.slice(0, 5).join(', ');
                }
            }
        } catch {}
    }

    // 3. Hackertarget 
    if (range === 'N/A') {
        try {
            const htText = await gmGetText(`https://api.hackertarget.com/aslookup/?q=${asn}`, 5000);
            const cidrs = [...htText.matchAll(/CIDR[:\s]+([\d\.\/]+)/gi)].map(m => m[1]);
            if (cidrs.length) range = cidrs.slice(0, 5).join(', ');
        } catch {}
    }

    // 4.  cual-es-mi-ip.net 
    if (range === 'N/A' && asn !== 'N/A') {
        try {
            const num = asn.replace(/AS/i, '');
            const cualText = await gmGetText(`https://www.cual-es-mi-ip.net/asn-lookup?asn=${num}`);
            // Extrae contactos y datos WHOIS 
            const ownerMatch = cualText.match(/owner:\s*([^\n]+)/i);
            const contactMatch = cualText.match(/e-mail:\s*([^\s\n]+)/gi);

            if (ownerMatch) provider = ownerMatch[1].trim();
            // Nota: cual-es-mi-ip NO da rangos IP, solo WHOIS
        } catch {}
    }

    // 5. ipapi.co GRATIS 
    if (range === 'N/A' && asn !== 'N/A') {
        try {
            const num = asn.replace('AS', '');
            const ipapico = await fetchWithGM(`https://ipapi.co/${num}/asn/json/`);
            if (ipapico?.prefixes) range = ipapico.prefixes.slice(0, 5).join(', ');
        } catch {}
    }

    // 6. Fallback final
    if (range === 'N/A' && cidr !== 'N/A') range = cidr;

    return { asn, provider, cidr, range };
}

  /* SSL:API pública de SSL Labs (v3) con polling */
  function ssllabsAnalyze(domain){
    return new Promise((resolve,reject)=>{
      GM_xmlhttpRequest({
        method:'GET',
        url: `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&fromCache=on&all=done`,
        timeout: 15000,
        onload: r => {
          try{ resolve(JSON.parse(r.responseText)); }catch(e){ resolve(null); }
        },
        onerror: ()=>resolve(null),
        ontimeout: ()=>resolve(null)
      });
    });
  }

  async function getSSLGrade(domain){
    try{
      let data = await ssllabsAnalyze(domain);
      if (!data) return {final:'T', message:'(No SSL Labs response)'};
      // si está en progreso, hacer polling
      const maxPoll = 12;
      let tries = 0;
      while ((data.status === 'IN_PROGRESS' || data.status === 'DNS') && tries < maxPoll) {
        await sleep(5000);
        data = await ssllabsAnalyze(domain);
        tries++;
      }
      if (!data || data.status !== 'READY') return {final:'T', message:`(Status:${data?.status||'err'})`};
      // seleccionar endpoint con mejor grade disponible
      const endpoints = data.endpoints || [];
      if (!endpoints.length) return {final:'T', message:'(No endpoints)'};
      // encontrar mejor grade A+ > A > B ... 
      const order = { 'A+':0,'A':1,'A-':2,'B':3,'C':4,'D':5,'E':6,'F':7,'T':8 };
      endpoints.sort((a,b)=>{
        const ga = (a.grade||'T'); const gb = (b.grade||'T');
        return (order[ga]||9) - (order[gb]||9);
      });
      const best = endpoints[0];
      const grade = best.grade || 'T';
      return { final: grade, sources: { ssllabs: grade }, message: '(SSL Labs)', details: best };
    }catch(e){
      return { final: 'T', message: '(SSL error)' };
    }
  }
  // 2. WHOIS detallado
  async function fetchWhoisDetails(domain) {
      return new Promise(resolve => {
          GM_xmlhttpRequest({
              method: "GET",
              url: `https://www.whois.com/whois/${domain}`,
              onload: res => {
                  try {
                      const html = res.responseText;
                      const registrar = html.match(/Registrar:\s*([^\n]+)/i)?.[1] || "No disponible";
                      const created = html.match(/Creation Date:\s*([^\n]+)/i)?.[1] || "No disponible";
                      const updated = html.match(/Updated Date:\s*([^\n]+)/i)?.[1] || "No disponible";
                      const expires = html.match(/Registry Expiry Date:\s*([^\n]+)/i)?.[1] || "No disponible";
                      const abuse = html.match(/Abuse (email|mail):?\s*([^\n]+)/i)?.[2] || "No disponible";

                      resolve({
                          registrar,
                          created,
                          updated,
                          expires,
                          abuse: abuse.replace(/mailto:/i, "").trim()
                      });
                  } catch {
                      resolve({ registrar: "No disponible", created: "No disponible", updated: "No disponible", expires: "No disponible", abuse: "No disponible" });
                  }
              },
              onerror: () => resolve({ registrar: "No disponible", created: "No disponible", updated: "No disponible", expires: "No disponible", abuse: "No disponible" })
          });
      });
  }


  /* CRT.SH  */
  async function fetchCRTInfo(domain){
    try{
      const txt = await gmGetText(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,8000);
      const data = JSON.parse(txt);
      if (!data || !data.length) return null;
      const cert = data[0];
      return { issuer: cert.issuer_name || "Desconocido", validFrom: cert.not_before, validTo: cert.not_after };
    }catch(e){ return null; }
  }



  /* Port scan */
  async function getDynamicPortsList(){
    try {
      const res = await gmGetText('https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.json',8000);
      const data = JSON.parse(res);
      const webPorts = data.services.filter(s=>/http|https|ftp|ssh|smtp|dns|mysql|postgres/i.test(s.service_name||s.official_name||'')).map(s=>s.port_number);
      return (webPorts.length?webPorts.slice(0,50):[80,443,8080,8443]);
    }catch(e){ return [80,443,8080,8443]; }
  }
async function fetchSSL(domain) {
    return new Promise(resolve => {
        // 1. Primero intento: wildcard %25.domain 
        const url1 = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
        GM_xmlhttpRequest({
            method: "GET",
            url: url1,
            timeout: 10000,
            onload: checkCertData,
            onerror: () => resolve(null)
        });

        async function checkCertData(res) {
            try {
                const data = JSON.parse(res.responseText);
                if (!data || !data.length) {
                    // 2. Segundo intento: dominio exacto
                    const url2 = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
                    const res2 = await gmGet(url2, 5000);
                    const data2 = JSON.parse(res2.responseText);
                    if (!data2?.length) return resolve(null);
                    processCert(data2[0]);
                } else {
                    processCert(data[0]);
                }
            } catch {
                resolve(null);
            }
        }

        function processCert(cert) {
            const validFrom = new Date(cert.not_before);
            const validTo = new Date(cert.not_after);
            const now = new Date();
            const daysLeft = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

            resolve({
                issuer: cert.issuer_name || "Desconocido",
                validFrom: validFrom.toLocaleDateString(),
                validTo: validTo.toLocaleDateString(),
                daysLeft: daysLeft > 0 ? daysLeft : 0,
                expired: now > validTo
            });
        }
    });
}

async function checkTechVersion(tech, version) {
    if (!version) return { vulnerable: false };
    try {
        const resp = await GM_xmlhttpRequest({
            method: 'GET',
            url: `https://api.endpoints.sh/v1/tech/${tech.toLowerCase()}/latest`,
            timeout: 4000
        });
        const data = JSON.parse(resp.responseText);
        const latest = data?.latest || data?.version;
        const isOld = compareVersions(version, latest) < 0;
        return { vulnerable: isOld, latest };
    } catch(e) {
        return { vulnerable: false };
    }
}
async function fetchDNSAdmin(domain) {
    // 1. SOA primero
    try {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=SOA`;
        const res = await gmGet(url, 5000);
        const json = JSON.parse(res.responseText);

        if (json.Answer?.length) {
            let rname = json.Answer[0].data.split(' ')[0];
            if (rname.includes('.')) {
                return rname.replace(/\./g, '@');
            }
            return rname || 'N/D';
        }
    } catch(e) {}

    // 2. Fallback WHOIS
    try {
        const whois = await gmGetText(`https://api.hackertarget.com/whois/?q=${domain}`, 5000);
        const adminMatch = whois.match(/Admin[^:\n]*:\s*([^\n\r]+)/i) ||
                          whois.match(/contact[^:\n]*:\s*([^\n\r]+)/i);
        return adminMatch ? adminMatch[1].trim() : 'N/D';
    } catch(e) {}

    return 'N/D';
}


function withTimeout(promise, ms, fallback = null) {
    return new Promise(resolve => {
        let done = false;
        const timer = setTimeout(() => {
            if (!done) {
                done = true;
                resolve(fallback);
            }
        }, ms);

        promise
            .then(v => {
                if (!done) {
                    done = true;
                    clearTimeout(timer);
                    resolve(v);
                }
            })
            .catch(() => {
                if (!done) {
                    done = true;
                    clearTimeout(timer);
                    resolve(fallback);
                }
            });
    });
}


  /* Subdomain processing UI  */
  async function processSubdomainGrid(d, dataArray) {
    const out = document.getElementById('results');


    const subDiv = document.createElement('div');
    subDiv.className = 'subdomain-card';
     subDiv.style.cssText = `
        border:2px solid #00ff00;border-radius:6px;padding:12px;margin:5px 0;
        cursor:pointer;background:#111;color:#fff;transition:all 0.3s;
        display:flex;align-items:center;justify-content:space-between;
    `;
    const summary = document.createElement('div'); summary.innerHTML = `<b>${d}</b>`; summary.style.flex = '1';
    const status = document.createElement('span'); status.textContent = '⏳'; status.style.marginLeft = '10px';
    const btn = document.createElement('button'); btn.textContent = '▼'; btn.style.marginLeft = '10px';
    subDiv.appendChild(summary); subDiv.appendChild(status); subDiv.appendChild(btn);
    out.appendChild(subDiv);

    const details = document.createElement('div');
    details.style.display = 'block';  // siempre visible
    btn.textContent = '▲';           // icono fijo
    btn.style.display = "none";      // ocultar el botón porque ya no se necesita
    details.style.background = '#1a1a1a';
    details.style.padding = '12px';
    details.style.margin = '6px 0 12px 12px';
    out.appendChild(details);

    btn.onclick = () => {
        details.style.display = details.style.display === 'none' ? 'block' : 'none';
        btn.textContent = details.style.display === 'none' ? '▼' : '▲';
    };

    try {
        details.innerHTML = `<div style="color:#aaa;text-align:center">🔄 Analizando...</div>`;

        // DNS COMPLETO
        const records = await fetchDNSRecords(d);
        const firstIP = await getFirstIP(records);


        const site     = await withTimeout(fetchFullSite(d), 12000, {title:"N/D", techs:[], alive:false});
        const ports    = await withTimeout(firstIP ? scanPorts(firstIP) : [], 8000, []);
        const sslCert  = await withTimeout(fetchSSL(d), 8000, null);
        const adminName = await withTimeout(fetchDNSAdmin(d), 5000, "N/D");

        // PUERTOS CON SERVICIOS
        const services = await Promise.all(ports.map(p => getPortService(p)));
        const portsWithServices = ports.map((p, i) => ({
            port: p,
            service: services[i]
        }));

        const techStatus = await Promise.all((site.techs||[]).map(t =>
                    t.version ? checkTechVersion(t.tech, t.version) : Promise.resolve({vulnerable:false})
                ));
       const techHTML = (site.techs||[]).map((t,i) => {
            const status = techStatus[i];
            const color = status?.vulnerable ? '#f33' : '#0f0';
            return `<span style="color:${color};font-weight:${status?.vulnerable?'bold':''}">
                ${t.tech}${t.version?` v${t.version}`:''}${status?.vulnerable?' ⚠️':''}
            </span>`;
        }).join(', ');

        //  DNS 
        const dnsHTML = Object.entries(records)
            .filter(([type]) => type !== 'SOA') // SOA muy largo
            .map(([type, data]) =>
                `<small style="color:#0ff;display:block;">${type}: ${data?.join(' | ') || 'N/A'}</small>`
            ).join('');

const sslBoxId = "ssl_dynamic_" + d.replace(/\./g, "_");
       details.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div>
            <b>🌐 IP:</b> <code>${firstIP || 'No IP'}</code><br>
            <b>📊 Estado:</b> ${site.alive ? '<span style="color:#0f0">✅ Activo</span>' : '<span style="color:#f33">❌ Inactivo</span>'}<br>
            <b>🏷️ Título:</b> ${site.title || 'N/D'}<br>
            <b>👤 Admin:</b> ${adminName}<br>
        </div>

        <div>
            <b>🔒 SSL:</b><br>
            <div id="${sslBoxId}" style="color:#aaa;font-weight:bold;font-size:1.1em;">
                🔄 Analizando SSL (hasta 5 min)...
            </div>
            <b>⚙️ Techs:</b> ${techHTML}<br>
        </div>
    </div>

    ${ports.length ? `
        <div style="margin:10px 0;background:#200;padding:10px;border-radius:5px;">
            <b>🔓 Puertos abiertos (${ports.length}):</b><br>
            ${portsWithServices.map(p =>
                `<span style="color:#f90;background:#300;padding:3px 6px;margin:1px;border-radius:3px;font-size:0.85em;">
                    ${p.port}/${p.service}
                </span>`
            ).join('')}
        </div>
    ` : '<div style="color:#0f0;margin:10px 0;">🔒 Todos los puertos cerrados</div>'}

    <div style="margin-top:10px;">
        <b>DNS Records:</b><br>
        ${dnsHTML || '<small style="color:#aaa;">Sin registros DNS</small>'}
    </div>

    <div style="margin-top:10px;">
        🔒 <b>SSL Certificado (CRT.sh):</b><br>
        ${sslCert ? `
            Estado: <span style="color:${sslCert.expired ? "#f33" : "#0f0"}">
                ${sslCert.expired ? "❌ Expirado" : `✅ Vigente (${sslCert.daysLeft} días)`}
            </span><br>
            Emisor: ${sslCert.issuer}<br>
            Desde: ${sslCert.validFrom}<br>
            Hasta: ${sslCert.validTo}
        ` : "<small style='color:#aaa;'>No encontrado en CRT.sh</small>"}
    </div>
`;
(async () => {
    const ssl = await withTimeout(getSSLGrade(d), 300000, {final: "T", message: "Timeout (5 min)"});

    const sslColorMap = {
        "A+":"#0f0","A":"#0f0","A-":"#0f0",
        "B":"#0ff","C":"#ff0","D":"#f90",
        "E":"#f66","F":"#f33","T":"#aaa"
    };
    const sslColor = sslColorMap[ssl.final] || "#aaa";

    const box = document.getElementById(sslBoxId);
    if (!box) return;

    box.innerHTML = `
        <span style="color:${sslColor};font-size:1.3em;font-weight:bold;">
            ${ssl.final}
        </span><br>
        <small>${ssl.message || ''}</small>
    `;

    const item = dataArray.find(x => x.domain === d);
    if (item) item.ssl_grade = ssl.final;
})();

dataArray.push({
    domain: d,
    ip: firstIP,
    ssl_grade: null,     // se actualizará luego
    cert_status: sslCert ? (sslCert.expired ? 'Expirado' : 'Vigente') : 'N/A',
    cert_days: sslCert?.daysLeft || 0,
    cert_issuer: sslCert?.issuer || 'N/A',
    techs: techHTML,
    alive: site.alive,
    ports_open: ports.length
});

    } catch(e) {
        details.innerHTML = `<div style="color:#f66">❌ Error: ${e.message}</div>`;
        status.textContent = '⚠️';
    }
}

  document.getElementById('btnSubScan').onclick = async ()=>{
    if (!targetDomain) return alert('No detecté dominio con site:');
    const out = document.getElementById('results'); out.innerHTML = '🔍 Extrayendo subdominios...<br>';
    // buscar en google pages
    for (let start=10; start<=500; start+=10){
      const html = await fetchGooglePage(start);
      if (!html) break;
      extractFromHTML(html);
    }
    await extractSubdomainsFromDOM();
    const list = [...allSubdomains];
    out.innerHTML += `<br><b>✔ Total subdominios: ${list.length}</b><br><br>`;
    out.innerHTML += `<b>📊 Analizando dominio principal... (puede tardar)</b><br>`;
    // dominio principal OSINT
    const spf = await fetchDNSRecordTXT(targetDomain);
    const dkim = await fetchDNSRecordTXT(`default._domainkey.${targetDomain}`);
    const dmarc = await fetchDNSRecordTXT(`_dmarc.${targetDomain}`);
    //const dnsMain = await fetchDNSRecords(targetDomain);
    const ipMain = await fetchIP(targetDomain);
    const asnInfo = await getASNandCIDR(ipMain);
    out.innerHTML += `🔍 Obteniendo WHOIS...<br>`;
    const whoisData = await fetchWhoisDetails(targetDomain);

    //const whoisMain = await fetchDNSRecords(targetDomain);
    out.innerHTML = `
      <div style="background:#222;padding:12px;border-left:4px solid #0f0;margin:10px 0">
        <b style="color:#ff0">🔍 DOMINIO PRINCIPAL: ${targetDomain}</b>
      </div>
      <div><b>📧 Registros Email:</b><br>SPF: ${spf}<br>DKIM: ${dkim}<br>DMARC: ${dmarc}</div><br>
      <div><b>🛡️ RED:</b><br>IP: <code>${ipMain}</code><br>ASN: ${asnInfo.asn}<br>Proveedor: ${asnInfo.provider}<br>Rangos: ${asnInfo.range}</div><br>
     <div style="background:#1a1a1a; padding:10px; border-left:3px solid #ff0;">
                <b>📅 WHOIS:</b><br>
                Registrar: ${whoisData.registrar}<br>
                Creado: ${whoisData.created}<br>
                Expira: ${whoisData.expires}<br>
                Abuse: <a href="mailto:${whoisData.abuse}" style="color:#0ff;">${whoisData.abuse}</a>
            </div><br>


      `;
    // export button 
    const subdomainData = [];
    const exportBtn = document.createElement('button');
    exportBtn.textContent='⬇️ Exportar Subdominios a XLS';
    exportBtn.id = "exportSubBtn";
    out.appendChild(exportBtn);

    exportBtn.onclick = ()=>{
        
        const ws_data = [['Subdominio','IP','SSL','Techs','Activo','Puertos']];

        subdomainData.forEach(d=> {
            ws_data.push([
                d.domain || '',
                d.ip || '',
                d.ssl_grade || '',
                (d.techs || '').replace(/<[^>]*>/g,''),
                d.alive ? 'Sí' : 'No',
                d.ports_open || 0
            ]);
        });

        const ws = XLSX.utils.aoa_to_sheet(ws_data);
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'Subdominios');
        XLSX.writeFile(wb, 'subdominios.xlsx');
    };

// Máximo de tareas paralelas 
const MAX_PARALLEL = 10;

async function runQueue(items, handler) {
    return new Promise(resolve => {
        let index = 0;
        let active = 0;

        function next() {
            if (index >= items.length && active === 0) {
                resolve();
                return;
            }
            while (active < MAX_PARALLEL && index < items.length) {
                const item = items[index++];
                active++;
                handler(item)
                    .catch(() => {})
                    .finally(() => {
                        active--;
                        next();
                    });
            }
        }
        next();
    });
}

out.innerHTML += `<br><b>🚀 Procesando ${list.length} subdominios...</b><br>`;

// Ejecucion cada subdominio sin bloquear
await runQueue(list, d => processSubdomainGrid(d, subdomainData));

out.innerHTML += '<br><b>✅ Escaneo finalizado.</b>';
  };
document.getElementById('btnDocSearch').onclick = async ()=>{
    const out = document.getElementById('results'); 
    out.innerHTML = '<b>📄 Docs sensibles...</b><br><br>';
    
    // Nombre base del dominio
    const baseName = targetDomain.split('.')[0].toLowerCase();
    
    // ✅ DORKS SIMPLIFICADOS 
    const domainDorks = [
        // Archivos importantes
        `site:${targetDomain} filetype:pdf`,
        `site:${targetDomain} filetype:xlsx`,
        `site:${targetDomain} filetype:doc`,
        `site:${targetDomain} filetype:txt`,
        `site:${targetDomain} filetype:sql`,
        
  

    
    ];
    
    let allPages = [], importantPages = []  = [];
    
    out.innerHTML += '<h4>🔍 DOMINIO</h4>';
    for (let i = 0; i < domainDorks.length; i++) {
        const dork = domainDorks[i];
        out.innerHTML += `📁 ${i+1}/${domainDorks.length}: ${dork}<br>`;
        
        for (let page = 0; page < 10; page++) {
            const html = await fetchGooglePage(page * 10, dork);
            if (!html) break;
            
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const links = [...doc.querySelectorAll('a[href]')]
                .map(a => a.href)
                .filter(url => {
                    if (!url.startsWith('http')) return false;
                    if (!url.includes(targetDomain)) return false;
                    
            
                    const isFile = /\.(pdf|xls|xlsx|doc|txt|sql|bak)$/i.test(url);
                    const isSensitive = /admin|login|panel|dashboard|backup|db|rrhh|nómina|password|clave/i.test(url);
                    
                    return isFile || isSensitive;
                });
            
            links.forEach(url => {
                if (!allPages.includes(url)) allPages.push(url);
                
             
                const isImportant = (
                    /\.(pdf|xlsx?|sql)$/i.test(url) ||
                    /planilla|salarial|nómina|rrhh|backup|clave|password|database/i.test(url) ||
                    /admin|login|panel/i.test(url)
                );
                
                if (isImportant && !importantPages.includes(url)) {
                    importantPages.push(url);
                }
            });
            
            if (links.length === 0) break;
            await new Promise(r => setTimeout(r, 500));
        }
        out.innerHTML += `✅ ${allPages.length} total | 🔥 ${importantPages.length} sensibles<br><br>`;
        await new Promise(r => setTimeout(r, 800));
    }
    
  
    
    // RESULTADOS
    out.innerHTML += `<hr><h2>📊 RESULTADOS FINALES</h2>`;
    out.innerHTML += `<b>🌐 ${targetDomain}:</b> ${allPages.length}<br>`;
    out.innerHTML += `<b style="color:red">🔥 Sensibles:</b> ${importantPages.length}<br>`;

    if (importantPages.length) {
        out.innerHTML += `<h4>🔴 SENSIBLES (${importantPages.length})</h4>`;
        importantPages.slice(0,15).forEach((u,i) => {
            out.innerHTML += `${i+1}. <a href="${u}" target="_blank">${u}</a><br>`;
        });
    }
    
    
    // Botones descarga
    out.innerHTML += `<br>
    <button id="dlSensibles" ${importantPages.length ? '' : 'disabled'}>🔴 Sensibles (${importantPages.length})</button>
    <button id="dlTodos">🌐 Todos (${allPages.length})</button>`;
    
    document.getElementById('dlSensibles').onclick = () => downloadList(importantPages, `sensibles_${targetDomain}`);
    document.getElementById('dlTodos').onclick = () => downloadList(allPages, `paginas_${targetDomain}`);
};

// Helper
function downloadList(list, filename) {
    const blob = new Blob([list.join("\n")], {type:'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename + '.txt';
    a.click();
}
  })(); 