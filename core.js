/* Browser/Node shared protocol and conversion logic. No network or storage here. */
'use strict';
(() => {
  const MAX_BODY = 4 * 1024 * 1024;
  // Public application-wide protocol key, not a user's subscription/identity.
  const SIGNING_KEY = 'Vy8Dpmn3wdMTaemIZiLDN8Knzw2cJaoNkcceOLooB3sPGtGkInMO8vBE1G/4AWKAq1t4BFFRY289aduMNxZr4A==';
  const fail = message => { throw new Error(message); };
  function validateUrl(raw) {
    if (typeof raw !== 'string' || /[\s\x00-\x1f\x7f\\]/u.test(raw)) fail('Нужна HTTPS-ссылка без пробелов и управляющих символов.');
    let url;
    try { url = new URL(raw); } catch { fail('Некорректная ссылка подписки.'); }
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || raw.includes('?') || raw.includes('#')) fail('Нужна HTTPS-ссылка без логина, query-параметров и fragment.');
    if (!url.pathname.split('/').pop()) fail('В ссылке отсутствует токен подписки.');
    return url;
  }
  function validateIdentity(value) {
    if (!value || typeof value !== 'object' || ['app_id', 'hwid', 'device'].some(k => typeof value[k] !== 'string' || !value[k] || /[^\x20-\x7e]/.test(value[k]))) fail('Некорректный файл идентификатора устройства.');
    return {app_id: value.app_id, hwid: value.hwid, device: value.device};
  }
  async function signedHeaders(raw, identity, timestamp = Math.floor(Date.now() / 1000), key = SIGNING_KEY) {
    const url = validateUrl(raw);
    validateIdentity(identity);
    const encoder = new TextEncoder();
    const message = `GET\n/sub/${url.pathname.split('/').pop()}\n${timestamp}\n${identity.app_id}`;
    const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(key), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
    return {'Accept':'application/json', 'device':identity.device, 'X-hwid':identity.hwid, 'X-App-Id':identity.app_id, 'X-Timestamp':String(timestamp), 'X-Signature':Array.from(new Uint8Array(signature), b => b.toString(16).padStart(2,'0')).join('')};
  }
  function parseSubscription(bytes) {
    if (bytes.byteLength > MAX_BODY) fail('Ответ превышает лимит 4 MiB.');
    let text;
    try { text = new TextDecoder('utf-8', {fatal:true}).decode(bytes).trim(); } catch { fail('Ответ не является UTF-8.'); }
    let data;
    try { data = JSON.parse(text); } catch {
      if (!text.startsWith('vless://')) {
        try {
          const raw = text.replace(/\s/g,'').replace(/-/g,'+').replace(/_/g,'/');
          text = new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(atob(raw), c => c.charCodeAt(0)));
        } catch { fail('Ожидался JSON, список VLESS или Base64-подписка.'); }
      }
      const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      if (!lines.length || lines.some(s => !s.startsWith('vless://'))) fail('Ответ содержит не только VLESS-записи.');
      data = {servers:lines.map(key => ({key}))};
    }
    if (!data || Array.isArray(data) || (data.status !== undefined && data.status !== 'success')) fail('Сервис не вернул успешную подписку.');
    if (!Array.isArray(data.servers) || !data.servers.length) fail('В подписке нет серверов.');
    if (data.servers.some(s => !s || typeof s.key !== 'string')) fail('У записи сервера отсутствует VLESS-ключ.');
    return data.servers;
  }
  function makeProfile(server, index) {
    let uri = server.key.trim(), u, userId, host, port, name;
    try {
      u = new URL(uri);
      userId = decodeURIComponent(u.username).toLowerCase();
      host = u.hostname.replace(/^\[|\]$/g,''); port = Number(u.port);
      if (u.protocol !== 'vless:' || !host || !Number.isInteger(port) || port < 1 || port > 65535 || u.password || !/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/.test(userId) || (u.pathname && u.pathname !== '/')) throw new Error();
      name = decodeURIComponent(u.hash.slice(1)) || String(server.country || server.panel_name || `Сервер ${index}`);
    } catch { fail(`Некорректный VLESS URI в записи №${index}.`); }
    if (/^127\./.test(host) || ['localhost','::1','::','0.0.0.0'].includes(host.toLowerCase()) || /^::ffff:(127\.|7f[\da-f]{2}:)/i.test(host)) fail('Получена localhost-заглушка вместо серверов подписки.');
    const allowed = new Set(['type','security','encryption','flow','sni','fp','alpn','pbk','sid','spx','host','path','headerType','serviceName','mode','authority','extra','allowInsecure']);
    const q = Object.create(null);
    for (const [key,value] of u.searchParams) {
      if (!allowed.has(key) || Object.hasOwn(q,key)) fail(`Запись №${index}: неизвестный или повторный параметр VLESS.`);
      q[key] = value;
    }
    const network = q.type ?? 'tcp', security = q.security ?? 'none';
    if (!['tcp','raw','ws','grpc','xhttp','httpupgrade'].includes(network)) fail(`Запись №${index}: неподдерживаемый транспорт.`);
    if (!['none','tls','reality'].includes(security) || (q.encryption ?? 'none') !== 'none') fail(`Запись №${index}: неподдерживаемое шифрование.`);
    const stream = {network, security};
    if (security === 'tls' || security === 'reality') {
      const settings = {};
      if (q.sni) settings.serverName = q.sni;
      if (q.fp) settings.fingerprint = q.fp;
      if (security === 'tls') {
        if (q.alpn) settings.alpn = q.alpn.split(',');
        if (q.allowInsecure) {
          if (!['0','1','true','false'].includes(q.allowInsecure.toLowerCase())) fail(`Запись №${index}: некорректный allowInsecure.`);
          settings.allowInsecure = ['1','true'].includes(q.allowInsecure.toLowerCase());
        }
      } else {
        if (!q.pbk) fail(`Запись №${index}: отсутствует публичный ключ Reality.`);
        settings.publicKey = q.pbk; settings.shortId = q.sid || '';
        if (q.spx) settings.spiderX = q.spx;
      }
      stream[security + 'Settings'] = settings;
    }
    if (network === 'tcp' || network === 'raw') {
      const header = q.headerType || 'none';
      if (header === 'http') {
        const request = {path:(q.path ?? '/').split(',')};
        if (q.host) request.headers = {Host:q.host.split(',')};
        stream[network + 'Settings'] = {header:{type:'http',request}};
      } else if (header !== 'none') fail(`Запись №${index}: неподдерживаемая маскировка TCP.`);
    } else if (network === 'ws' || network === 'httpupgrade') {
      const settings = {path:q.path ?? '/'};
      if (q.host) { if (network === 'ws') settings.headers = {Host:q.host}; else settings.host = q.host; }
      stream[network + 'Settings'] = settings;
    } else if (network === 'grpc') {
      if (!['gun','multi'].includes(q.mode ?? 'gun')) fail(`Запись №${index}: неизвестный режим gRPC.`);
      stream.grpcSettings = {serviceName:q.serviceName ?? '', multiMode:q.mode === 'multi'};
      if (q.authority) stream.grpcSettings.authority = q.authority;
    } else if (network === 'xhttp') {
      const settings = {path:q.path ?? '/',host:q.host ?? '',mode:q.mode ?? 'auto'};
      if (q.extra) {
        try { settings.extra = JSON.parse(q.extra); if (!settings.extra || typeof settings.extra !== 'object' || Array.isArray(settings.extra)) throw new Error(); }
        catch { fail(`Запись №${index}: некорректный XHTTP extra.`); }
      }
      stream.xhttpSettings = settings;
    }
    const labels = [];
    for (const field of ['country','server_class']) {
      const label = String(server[field] || '').trim();
      if (label && !labels.some(s => s.toLowerCase() === label.toLowerCase())) labels.push(label);
    }
    const prefix = `[${labels.join(' · ')}] `;
    if (labels.length && !name.startsWith(prefix) && !(labels.length === 1 && name.toLowerCase() === labels[0].toLowerCase())) name = prefix + name;
    if (labels.length) uri = uri.split('#')[0] + '#' + encodeURIComponent(name);
    const user = {id:userId,encryption:'none'};
    if (q.flow) user.flow = q.flow;
    const profile = {remarks:name,log:{loglevel:'warning'},inbounds:[{tag:'socks',listen:'127.0.0.1',port:10808,protocol:'socks',settings:{auth:'noauth',udp:true}}],outbounds:[{tag:'proxy',protocol:'vless',settings:{vnext:[{address:host,port,users:[user]}]},streamSettings:stream},{tag:'direct',protocol:'freedom'},{tag:'block',protocol:'blackhole'}]};
    return {profile,item:{name,uri,host,port,country:String(server.country || ''),category:String(server.server_class || ''),transport:network,security}};
  }
  const api = {MAX_BODY,validateUrl,validateIdentity,signedHeaders,parseSubscription,makeProfile};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else globalThis.SubscriptionCore = api;
})();
