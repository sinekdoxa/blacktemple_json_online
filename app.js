'use strict';
(() => {
  const core = SubscriptionCore;
  const $ = id => document.getElementById(id);
  let entries = [], controller = null, busy = false;
  function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error',error); }
  function setBusy(value) {
    busy = value;
    for (const id of ['fetch','response-file','identity-file','export-identity']) $(id).disabled = value;
    $('cancel').hidden = !value;
  }
  // IndexedDB read/write transactions serialize first use across tabs. Never rotate on errors.
  function identityStore(candidate = null, replace = false) {
    return new Promise((resolve,reject) => {
      const request = indexedDB.open('blacktemple-subscription-export',1);
      request.onupgradeneeded = () => request.result.createObjectStore('state');
      request.onerror = () => reject(new Error('Недоступно локальное хранилище. Разрешите хранение данных сайта; временный HWID не создаётся.'));
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction('state',candidate ? 'readwrite' : 'readonly');
        const store = tx.objectStore('state'); let result, validationError;
        const get = store.get('identity');
        get.onsuccess = () => {
          try {
            if (get.result !== undefined && !replace) result = core.validateIdentity(get.result);
            else if (candidate) { result = core.validateIdentity(candidate); store.put(result,'identity'); }
          } catch { validationError = true; tx.abort(); }
        };
        tx.oncomplete = () => { db.close(); resolve(result); };
        tx.onabort = tx.onerror = () => { db.close(); reject(new Error(validationError ? 'Сохранённый идентификатор повреждён. Импортируйте резервную копию; новый HWID не создаётся.' : 'Не удалось сохранить идентификатор. Запрос не отправлен.')); };
      };
    });
  }
  async function loadIdentity() {
    const existing = await identityStore();
    if (existing) return existing;
    const digest = await crypto.subtle.digest('SHA-256',crypto.getRandomValues(new Uint8Array(32)));
    const candidate = {app_id:crypto.randomUUID(),hwid:Array.from(new Uint8Array(digest),b => b.toString(16).padStart(2,'0')).join(''),device:'BLACKTEMPLE-Test-Android'};
    return identityStore(candidate);
  }
  async function readBounded(response) {
    if (!response.body) throw new Error('Браузер не поддерживает потоковое чтение ответа.');
    const reader = response.body.getReader(), chunks = []; let size = 0;
    try {
      while (true) {
        const {done,value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > core.MAX_BODY) { await reader.cancel(); throw new Error('Ответ превышает лимит 4 MiB.'); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const result = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { result.set(chunk,offset); offset += chunk.byteLength; }
    return result;
  }
  function download(data, filename) {
    const blob = new Blob([JSON.stringify(data,null,2) + '\n'],{type:'application/json;charset=utf-8'});
    const url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = filename; link.rel = 'noreferrer';
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url),10000);
  }
  function resetResults() {
    entries = []; $('cards').replaceChildren(); $('results').hidden = true; $('search').value = '';
  }
  function button(text, action) { const node = document.createElement('button'); node.type = 'button'; node.textContent = text; node.addEventListener('click',action); return node; }
  function filter() {
    const term = $('search').value.toLocaleLowerCase(); let visible = 0;
    for (const card of $('cards').children) { card.hidden = !card.searchText.includes(term); if (!card.hidden) visible++; }
    $('count').textContent = `Серверов: ${visible} из ${entries.length}`;
  }
  function render(bytes) {
    // Convert the entire response first: no partial/silently degraded export.
    const next = core.parseSubscription(bytes).map((server,index) => core.makeProfile(server,index + 1));
    const fragment = document.createDocumentFragment();
    next.forEach(({profile,item},index) => {
      const card = document.createElement('article'); card.className = 'card';
      const title = document.createElement('h2'); title.textContent = `${index + 1}. ${item.name}`;
      const meta = document.createElement('p'); meta.className = 'meta'; meta.textContent = [item.country,item.category,`${item.transport}/${item.security}`,`${item.host}:${item.port}`].filter(Boolean).join(' · ');
      card.searchText = `${item.name} ${meta.textContent}`.toLocaleLowerCase();
      const text = document.createElement('textarea'); text.value = item.uri; text.readOnly = true; text.spellcheck = false; text.setAttribute('aria-label','VLESS-ключ');
      const actions = document.createElement('div'); actions.className = 'actions';
      const copy = button('Копировать VLESS',async () => {
        try { await navigator.clipboard.writeText(item.uri); status('Ключ скопирован.'); }
        catch { text.focus(); text.select(); status('Ключ выделен. Нажмите Ctrl+C / Cmd+C.'); }
      });
      const qrBox = document.createElement('div'); qrBox.className = 'qr'; qrBox.hidden = true;
      const show = button('Показать QR',() => {
        try {
          if (!qrBox.firstChild) {
            // Encode UTF-8 bytes explicitly; no external generator or innerHTML.
            const qr = qrcode(0,'M');
            const binary = Array.from(new TextEncoder().encode(item.uri),b => String.fromCharCode(b)).join('');
            qr.addData(binary,'Byte'); qr.make();
            const ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns,'svg'), path = document.createElementNS(ns,'path');
            const size = qr.getModuleCount(); svg.setAttribute('viewBox',`0 0 ${size + 8} ${size + 8}`); svg.setAttribute('role','img'); svg.setAttribute('aria-label','QR-код VLESS-ключа');
            let d = '';
            for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (qr.isDark(r,c)) d += `M${c+4},${r+4}h1v1h-1z`;
            path.setAttribute('d',d); path.setAttribute('fill','#000'); svg.append(path); qrBox.append(svg);
          }
          qrBox.hidden = !qrBox.hidden; show.textContent = qrBox.hidden ? 'Показать QR' : 'Скрыть QR'; show.setAttribute('aria-expanded',String(!qrBox.hidden));
        } catch { status('Ключ слишком длинный для QR или QR-модуль недоступен. Скопируйте VLESS либо скачайте JSON.',true); }
      });
      show.setAttribute('aria-expanded','false');
      const open = document.createElement('a'); open.href = item.uri; open.textContent = 'Открыть в клиенте'; open.rel = 'noreferrer noopener';
      actions.append(copy,show,open,button('JSON профиля',() => download(profile,`xray-profile-${index+1}.json`)));
      card.append(title,meta,text,actions,qrBox); fragment.append(card);
    });
    entries = next; $('cards').replaceChildren(fragment); $('results').hidden = false; filter();
    status(`Получено конфигураций: ${entries.length}. Данные обработаны локально. VPN-соединения не проверялись.`);
  }
  $('fetch-form').addEventListener('submit',async event => {
    event.preventDefault(); if (busy) return;
    resetResults();
    let raw = $('url').value;
    try { core.validateUrl(raw); } catch (error) { status(error.message,true); return; }
    if (!isSecureContext || !crypto.subtle) { status('Для подписи необходим HTTPS (GitHub Pages) или localhost.',true); return; }
    setBusy(true); controller = new AbortController(); const signal = controller.signal;
    const timeout = setTimeout(() => controller?.abort(),30000);
    try {
      const identity = await loadIdentity();
      const headers = await core.signedHeaders(raw,identity);
      if (signal.aborted) throw new DOMException('','AbortError');
      status('Ожидание сервера подписки… Браузер может сначала отправить CORS OPTIONS.');
      // User-Agent is controlled by the browser and cannot reliably mimic Python.
      const response = await fetch(raw,{method:'GET',headers,mode:'cors',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal});
      if (response.status !== 200) { await response.body?.cancel(); throw new Error(`Сервер вернул HTTP ${response.status}.`); }
      render(await readBounded(response));
    } catch (error) {
      if (error.name === 'AbortError') status('Запрос отменён или превышен таймаут 30 секунд. Автоматического повтора нет.',true);
      else if (error instanceof TypeError) status('Браузер не смог прочитать ответ: возможны запрет CORS, ошибка сети/TLS или редирект. Сервер должен разрешить Origin этой страницы и заголовки device, X-hwid, X-App-Id, X-Timestamp, X-Signature. Обход через прокси отключён.',true);
      else status(error.message,true);
    } finally { clearTimeout(timeout); controller = null; raw = ''; $('url').value = ''; setBusy(false); }
  });
  $('cancel').addEventListener('click',() => controller?.abort());
  $('response-file').addEventListener('change',async event => {
    const file = event.target.files[0]; if (!file || busy) return;
    resetResults(); setBusy(true);
    try { if (file.size > core.MAX_BODY) throw new Error('Файл превышает лимит 4 MiB.'); render(new Uint8Array(await file.arrayBuffer())); }
    catch (error) { status(error.message,true); }
    finally { event.target.value = ''; setBusy(false); }
  });
  $('identity-file').addEventListener('change',async event => {
    const file = event.target.files[0]; if (!file || busy) return;
    setBusy(true);
    try {
      if (file.size > 16384) throw new Error();
      const identity = core.validateIdentity(JSON.parse(await file.text()));
      if (!confirm('Использовать идентификатор из этого файла? Текущий идентификатор сайта будет заменён. Сохраните его резервную копию заранее.')) return;
      await identityStore(identity,true); status('Идентификатор импортирован локально. Сетевые запросы не выполнялись.');
    } catch { status('Не удалось импортировать идентификатор. Проверьте файл и доступность хранилища.',true); }
    finally { event.target.value = ''; setBusy(false); }
  });
  $('export-identity').addEventListener('click',async () => {
    try { const identity = await identityStore(); if (!identity) { status('Идентификатор ещё не создан. Он появится при первом сетевом запросе.'); return; } download(identity,'identity.private.json'); status('Идентификатор скачан. Храните файл конфиденциально.'); }
    catch (error) { status(error.message,true); }
  });
  $('download').addEventListener('click',() => { if (entries.length) download(entries.map(e => e.profile),'subscription.xray.json'); });
  $('clear').addEventListener('click',() => { resetResults(); $('url').value = ''; status('Результаты удалены со страницы. Постоянный идентификатор сохранён.'); });
  $('search').addEventListener('input',filter);
  addEventListener('pagehide',() => { controller?.abort(); $('url').value = ''; resetResults(); });
})();
