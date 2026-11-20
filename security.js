/* Local account security: captures timing intervals, never plaintext passwords or keys. */
(() => {
  'use strict';
  function b64ToBytes(v) {
    const s = atob(v.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4-v.length%4)%4));
    return Uint8Array.from(s, c => c.charCodeAt(0));
  }
  function bytesToB64(v) {
    const b = new Uint8Array(v);
    let s = ''; b.forEach(x => { s += String.fromCharCode(x); });
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  }
  for (const form of document.querySelectorAll('form[data-typing-form]')) {
    const input = form.querySelector('input[type=password]');
    const hidden = form.querySelector('input[name=timing]');
    if (!input || !hidden) continue;
    let last = null, gaps = [];
    input.addEventListener('focus', () => { last = null; gaps = []; });
    input.addEventListener('paste', () => { last = null; gaps = []; });
    input.addEventListener('keydown', (e) => {
      if (e.repeat || e.ctrlKey || e.metaKey || e.altKey || e.key.length !== 1) return;
      const now = performance.now();
      if (last !== null && gaps.length < 80) gaps.push(Math.round(now-last));
      last = now;
    });
    form.addEventListener('submit', () => {
      hidden.value = JSON.stringify({ gaps });
    });
  }
  const result = document.querySelector('#security-result');
  if (!result) return;
  const write = s => { result.textContent = s; };
  async function post(endpoint, data, csrf) {
    const params = new URLSearchParams({csrf, ...data});
    const response = await fetch(endpoint, { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: params, credentials:'same-origin'});
    const obj = await response.json().catch(() => ({error: 'Server returned an unexpected result'}));
    if (!response.ok) throw Error(obj.error || 'Request denied');
    return obj;
  }
  const reg = document.querySelector('#passkey-register-form');
  if (reg) reg.addEventListener('submit', async e => {
    e.preventDefault();
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) throw Error('Passkeys are not supported in this browser.');
      write('Waiting for passkey device...');
      const csrf = reg.querySelector('[name=csrf]').value;
      const pwd = reg.querySelector('[name=password]').value;
      const opts = await post('/passkey/start', {password:pwd}, csrf);
      reg.querySelector('[name=password]').value = '';
      opts.challenge = b64ToBytes(opts.challenge);
      opts.user.id = b64ToBytes(opts.user.id);
      const cred = await navigator.credentials.create({ publicKey:opts });
      if (!cred) throw Error('Passkey creation cancelled');
      const data = {type:cred.type, rawId:bytesToB64(cred.rawId),response:{clientDataJSON:bytesToB64(cred.response.clientDataJSON),attestationObject:bytesToB64(cred.response.attestationObject)}};
      const answer = await post('/passkey/finish',{credential:JSON.stringify(data)},csrf);
      write(answer.message + '. Refresh page to see count.');
    } catch(err) {write('Not completed: ' + err.message);}
  });
  const check = document.querySelector('#passkey-check-form');
  if (check) check.addEventListener('submit', async e => {
    e.preventDefault();
    try {
      if (!window.PublicKeyCredential || !navigator.geolocation) throw Error('Passkey / geolocation unavailable');
      const csrf = check.querySelector('[name=csrf]').value;
      write('Requesting passkey and location permission...');
      const opts = await post('/passkey/auth/start',{},csrf);
      opts.challenge = b64ToBytes(opts.challenge);
      opts.allowCredentials = opts.allowCredentials.map(k => ({...k,id:b64ToBytes(k.id)}));
      const cred = await navigator.credentials.get({publicKey:opts});
      if (!cred) throw Error('Cancelled');
      const position = await new Promise((resolve,reject) => navigator.geolocation.getCurrentPosition(resolve,reject,{enableHighAccuracy:false,timeout:10000,maximumAge:0}));
      const data = {type:cred.type,rawId:bytesToB64(cred.rawId),response:{clientDataJSON:bytesToB64(cred.response.clientDataJSON),authenticatorData:bytesToB64(cred.response.authenticatorData),signature:bytesToB64(cred.response.signature)}};
      const response = await post('/passkey/auth/finish',{credential:JSON.stringify(data),lat:String(position.coords.latitude),lon:String(position.coords.longitude)},csrf);
      write(response.message + ' ('+response.distance_km+' km from demo home).');
      if (response.login_complete) { window.location.assign('/account'); }
    } catch(err) {write('Not completed: '+err.message);}
  });
})();
