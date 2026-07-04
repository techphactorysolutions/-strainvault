'use strict';

const PLAIN_KEY = 'strainvault.state.v1';
const SECURE_KEY = 'strainvault.secure.v1';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const safeClone = value => {
  if (typeof structuredClone === 'function') return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
};

function getStorage() {
  try {
    const testKey = 'strainvault.storage.test';
    window.localStorage.setItem(testKey, '1');
    window.localStorage.removeItem(testKey);
    return window.localStorage;
  } catch (error) {
    console.warn('LocalStorage unavailable:', error);
    return null;
  }
}

const localStore = getStorage();

const DEFAULT_STATE = {
  version: 3,
  createdAt: new Date().toISOString(),
  strains: [],
  sessions: [],
  stash: [],
  settings: {
    adultNoticeAccepted: true,
    reduceMotion: false
  }
};

let state = safeClone(DEFAULT_STATE);
let currentCryptoKey = null;
let secureEnabled = false;
let lastScanImage = '';
let toastTimer = null;
let editingStrainId = '';
let editingSessionId = '';
let editingStashId = '';
let sharingStrainId = '';
let pendingStrainLabelPhoto = '';


const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function uid(prefix = 'sv') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function clampNumber(value, min = 0, max = 100) {
  const parsed = Number(value);
  if (Number.isNaN(parsed)) return 0;
  return Math.min(max, Math.max(min, parsed));
}

function normalizeName(name) {
  return String(name || '').trim().toLowerCase();
}

function formatDate(iso) {
  if (!iso) return 'Unknown date';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(iso));
}

function formatMoney(value) {
  const number = Number(value || 0);
  return new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(number);
}

function b64FromBytes(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function bytesFromB64(base64) {
  return Uint8Array.from(atob(base64), char => char.charCodeAt(0));
}

async function deriveKey(passcode, salt) {
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(passcode), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 160000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptState() {
  const existing = JSON.parse(localStore?.getItem(SECURE_KEY) || '{}');
  const salt = existing.salt ? bytesFromB64(existing.salt) : crypto.getRandomValues(new Uint8Array(16));
  if (!currentCryptoKey) throw new Error('No encryption key is available.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = encoder.encode(JSON.stringify(state));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, currentCryptoKey, payload);
  localStore?.setItem(SECURE_KEY, JSON.stringify({
    version: 1,
    salt: b64FromBytes(salt),
    iv: b64FromBytes(iv),
    data: b64FromBytes(cipher),
    updatedAt: new Date().toISOString()
  }));
  localStore?.removeItem(PLAIN_KEY);
}

async function decryptState(passcode) {
  const record = JSON.parse(localStore?.getItem(SECURE_KEY) || '{}');
  if (!record.salt || !record.iv || !record.data) throw new Error('Secure vault is missing data.');
  const salt = bytesFromB64(record.salt);
  const iv = bytesFromB64(record.iv);
  const key = await deriveKey(passcode, salt);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytesFromB64(record.data));
  currentCryptoKey = key;
  secureEnabled = true;
  return JSON.parse(decoder.decode(plain));
}

async function saveState() {
  try {
    if (secureEnabled && currentCryptoKey) {
      await encryptState();
    } else {
      if (!localStore) throw new Error('Local storage unavailable');
      localStore.setItem(PLAIN_KEY, JSON.stringify(state));
    }
  } catch (error) {
    console.error(error);
    toast('Could not save the vault. Check browser storage.');
  }
}

function loadPlainState() {
  try {
    const stored = localStore?.getItem(PLAIN_KEY);
    if (!stored) return safeClone(DEFAULT_STATE);
    const parsed = JSON.parse(stored);
    return {
      ...safeClone(DEFAULT_STATE),
      ...parsed,
      settings: { ...DEFAULT_STATE.settings, ...(parsed.settings || {}) },
      strains: Array.isArray(parsed.strains) ? parsed.strains : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      stash: Array.isArray(parsed.stash) ? parsed.stash : []
    };
  } catch (error) {
    console.error(error);
    return safeClone(DEFAULT_STATE);
  }
}

async function boot() {
  try {
    if (!localStore) {
      state = safeClone(DEFAULT_STATE);
      bindGlobalEvents();
      renderAll();
      initRevealObserver();
      toast('Private browser storage is blocked. The app is running in demo mode.');
      return;
    }

    const secureRecord = localStore.getItem(SECURE_KEY);
    if (secureRecord) {
      $('#lockScreen').classList.remove('hidden');
      $('#appShell').classList.add('hidden');
      $('.bottom-nav').classList.add('hidden');
      bindGlobalEvents();
      return;
    }
    state = loadPlainState();
    bindGlobalEvents();
    renderAll();
    initRevealObserver();
    // Service worker intentionally disabled for the Netlify test build to avoid stale-cache problems during iteration.
  } catch (error) {
    console.error('StrainVault boot failed:', error);
    document.body.innerHTML = `
      <main class="app-shell">
        <section class="section-card glass" style="margin-top:32px">
          <p class="eyebrow">startup check</p>
          <h1>StrainVault could not start.</h1>
          <p class="muted">This build caught a browser startup error instead of showing a blank screen.</p>
          <pre style="white-space:pre-wrap;color:#ffd166">${escapeHtml(error?.message || String(error))}</pre>
        </section>
      </main>`;
  }
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 2600);
}

function navigate(viewName) {
  $$('.view').forEach(view => view.classList.toggle('active', view.dataset.view === viewName));
  $$('.nav-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.nav === viewName));
  if (viewName === 'settings') {
    $$('.nav-btn').forEach(btn => btn.classList.remove('active'));
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
  initRevealObserver(true);
}

function openModal(id) {
  $('#modalBackdrop').classList.remove('hidden');
  $(`#${id}`).classList.remove('hidden');
  if (id === 'exportModal') renderProfileCard();
}

function closeModal(id) {
  $(`#${id}`).classList.add('hidden');
  const anyOpen = $$('.sheet').some(sheet => !sheet.classList.contains('hidden'));
  if (!anyOpen) $('#modalBackdrop').classList.add('hidden');
}

function closeAllModals() {
  $$('.sheet').forEach(sheet => sheet.classList.add('hidden'));
  $('#modalBackdrop').classList.add('hidden');
}


function setFormValue(form, name, value = '') {
  const field = form.elements[name];
  if (!field) return;
  field.value = value ?? '';
}

function setSelectValue(form, name, value = '') {
  const field = form.elements[name];
  if (!field) return;
  const option = [...field.options].find(item => normalizeName(item.value || item.textContent) === normalizeName(value));
  field.value = option ? option.value : (field.options[0]?.value || '');
}

function formatPercentInput(value) {
  if (value === '' || value === null || value === undefined) return '';
  const number = Number(value);
  if (Number.isNaN(number)) return String(value || '');
  return number.toFixed(1).replace('.0', '');
}

function openStrainEditor(strainId = '', prefill = {}) {
  editingStrainId = strainId || '';
  const form = $('#strainForm');
  form.reset();
  const strain = state.strains.find(item => item.id === editingStrainId);
  const draft = strain ? {} : (prefill || {});
  pendingStrainLabelPhoto = strain ? '' : (draft.labelPhoto || '');
  $('#strainTitle').textContent = strain ? 'Edit strain' : (draft.strainName || draft.name ? 'Review scanned strain' : 'Add strain');
  $('#strainSaveBtn').textContent = strain ? 'Apply changes' : 'Save strain';
  $('#strainDeleteBtn').classList.toggle('hidden', !strain);
  const status = $('#strainScannerStatus');
  if (status) {
    const hasPhoto = Boolean(pendingStrainLabelPhoto || strain?.labelPhoto);
    status.textContent = hasPhoto
      ? 'Label photo attached locally. Text details will save with this strain card.'
      : 'Optional: use scanner assist to fill this card from package text.';
  }
  setFormValue(form, 'id', strain?.id || '');
  setFormValue(form, 'name', strain?.name || draft.strainName || draft.name || '');
  setFormValue(form, 'brand', strain?.brand || draft.brand || '');
  setSelectValue(form, 'type', strain?.type || draft.type || 'Flower');
  setFormValue(form, 'thc', formatPercentInput(strain?.thc || draft.thc || ''));
  setFormValue(form, 'cbd', formatPercentInput(strain?.cbd || draft.cbd || ''));
  setFormValue(form, 'terpenes', strain ? (strain.terpenes || []).join(', ') : (draft.terpenes || ''));
  setFormValue(form, 'notes', strain?.notes || draft.notes || '');
  openModal('strainModal');
}

function openSessionEditor(sessionId = '', strainName = '') {
  editingSessionId = sessionId || '';
  const form = $('#logForm');
  form.reset();
  const session = state.sessions.find(item => item.id === editingSessionId);
  const sourceStrain = session ? null : getStrainByName(strainName);
  $('#logTitle').textContent = session ? 'Edit session' : 'Track a session';
  const submit = form.querySelector('button[type="submit"]');
  if (submit) submit.textContent = session ? 'Apply changes' : 'Save session';
  setFormValue(form, 'strainName', session?.strainName || sourceStrain?.name || strainName || '');
  setFormValue(form, 'brand', session?.brand || sourceStrain?.brand || '');
  setSelectValue(form, 'type', session?.type || sourceStrain?.type || 'Flower');
  setFormValue(form, 'thc', formatPercentInput(session?.thc || sourceStrain?.thc || ''));
  setFormValue(form, 'cbd', formatPercentInput(session?.cbd || sourceStrain?.cbd || ''));
  setFormValue(form, 'terpenes', session?.terpenes || (sourceStrain?.terpenes || []).join(', ') || '');
  setSelectValue(form, 'mood', session?.mood || 'Neutral');
  setSelectValue(form, 'intent', session?.intent || 'Relax');
  ['calm','energy','clarity','anxiety','sleepiness'].forEach(name => setFormValue(form, name, session?.effects?.[name] ?? form.elements[name]?.defaultValue ?? 0));
  setSelectValue(form, 'rating', session?.rating || '5');
  setFormValue(form, 'price', session?.price || '');
  setFormValue(form, 'notes', session?.notes || '');
  openModal('logModal');
}

function openStashEditor(stashId = '') {
  editingStashId = stashId || '';
  const form = $('#stashForm');
  form.reset();
  const item = state.stash.find(entry => entry.id === editingStashId);
  $('#stashTitle').textContent = item ? 'Edit stash item' : 'Add to stash';
  const submit = form.querySelector('button[type="submit"]');
  if (submit) submit.textContent = item ? 'Apply changes' : 'Save stash item';
  setFormValue(form, 'name', item?.name || '');
  setFormValue(form, 'amount', item?.amount || '');
  setFormValue(form, 'price', item?.price || '');
  setFormValue(form, 'dispensary', item?.dispensary || '');
  openModal('stashModal');
}

function getStrainByName(name) {
  return state.strains.find(strain => normalizeName(strain.name) === normalizeName(name));
}

function upsertStrainFromSession(session) {
  const existing = getStrainByName(session.strainName);
  const sessionTerpenes = parseList(session.terpenes);
  if (existing) {
    existing.brand = session.brand || existing.brand;
    existing.type = session.type || existing.type;
    existing.thc = session.thc || existing.thc;
    existing.cbd = session.cbd || existing.cbd;
    existing.terpenes = uniqueList([...(existing.terpenes || []), ...sessionTerpenes]);
    existing.labelPhoto = session.labelPhoto || existing.labelPhoto;
    existing.updatedAt = new Date().toISOString();
    return existing;
  }
  const strain = {
    id: uid('strain'),
    name: session.strainName,
    brand: session.brand,
    type: session.type,
    thc: session.thc,
    cbd: session.cbd,
    terpenes: sessionTerpenes,
    labelPhoto: session.labelPhoto,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  state.strains.unshift(strain);
  return strain;
}

function parseList(value) {
  if (Array.isArray(value)) return value.filter(Boolean).map(item => String(item).trim()).filter(Boolean);
  return String(value || '')
    .split(/[,.|/]+/)
    .map(item => item.trim())
    .filter(Boolean)
    .slice(0, 8);
}

function uniqueList(items) {
  const seen = new Set();
  return items.filter(item => {
    const key = normalizeName(item);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function sessionsForStrain(name) {
  return state.sessions.filter(session => normalizeName(session.strainName) === normalizeName(name));
}

function average(values) {
  const nums = values.map(Number).filter(value => !Number.isNaN(value));
  if (!nums.length) return 0;
  return nums.reduce((sum, value) => sum + value, 0) / nums.length;
}

function strainScore(strain) {
  const sessions = sessionsForStrain(strain.name);
  if (!sessions.length) return 50;
  const rating = average(sessions.map(session => Number(session.rating || 0))) * 20;
  const anxietyPenalty = average(sessions.map(session => Number(session.effects?.anxiety || 0))) * 2.2;
  const clarityBonus = average(sessions.map(session => Number(session.effects?.clarity || 0))) * 1.5;
  const calmBonus = average(sessions.map(session => Number(session.effects?.calm || 0))) * 1.2;
  return Math.round(clampNumber(rating + clarityBonus + calmBonus - anxietyPenalty, 0, 100));
}

function getTopStrainForIntent(intent) {
  const matching = state.sessions.filter(session => session.intent === intent);
  if (!matching.length) return null;
  const grouped = new Map();
  matching.forEach(session => {
    const key = normalizeName(session.strainName);
    const current = grouped.get(key) || { name: session.strainName, scores: [], sessions: 0 };
    current.scores.push(Number(session.rating || 0) * 20 - Number(session.effects?.anxiety || 0) * 3);
    current.sessions += 1;
    grouped.set(key, current);
  });
  return [...grouped.values()].sort((a, b) => average(b.scores) - average(a.scores))[0] || null;
}

function getProfileStats() {
  const totalSpent = [...state.sessions, ...state.stash].reduce((sum, item) => sum + Number(item.price || 0), 0);
  const allTerpenes = state.strains.flatMap(strain => strain.terpenes || []);
  const terpeneCounts = allTerpenes.reduce((map, terpene) => {
    const key = terpene.trim();
    if (key) map.set(key, (map.get(key) || 0) + 1);
    return map;
  }, new Map());
  const favoriteTerpene = [...terpeneCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || 'Not enough data';
  const best = state.strains.length ? [...state.strains].sort((a, b) => strainScore(b) - strainScore(a))[0] : null;
  const avgThc = average(state.strains.map(strain => Number(strain.thc || 0)).filter(Boolean));
  const avgRating = average(state.sessions.map(session => Number(session.rating || 0)));
  return {
    totalSessions: state.sessions.length,
    totalStrains: state.strains.length,
    totalStash: state.stash.length,
    totalSpent,
    favoriteTerpene,
    bestStrain: best,
    avgThc,
    avgRating,
    sleepPick: getTopStrainForIntent('Sleep'),
    focusPick: getTopStrainForIntent('Focus'),
    creativePick: getTopStrainForIntent('Creativity'),
    relaxPick: getTopStrainForIntent('Relax')
  };
}

function renderAll() {
  renderHome();
  renderVault();
  renderJournal();
  renderInsights();
  renderStash();
  renderSecurity();
  initRevealObserver(true);
}

function renderHome() {
  const stats = getProfileStats();
  $('#todayPanel').innerHTML = `
    <p class="eyebrow">today</p>
    <h2>${stats.totalSessions ? 'Your journal is learning.' : 'Start with one clean log.'}</h2>
    <p class="muted">${stats.totalSessions ? `You have ${stats.totalSessions} session${stats.totalSessions === 1 ? '' : 's'} across ${stats.totalStrains} strain${stats.totalStrains === 1 ? '' : 's'}.` : 'Add your first strain, take a label photo, and rate how it actually felt. The app gets smarter as you log.'}</p>
  `;

  $('#insightStrip').innerHTML = [
    metricCard('Sessions', stats.totalSessions, 'logged experiences'),
    metricCard('Best match', stats.bestStrain ? escapeHtml(stats.bestStrain.name) : '—', stats.bestStrain ? `${strainScore(stats.bestStrain)}/100 body score` : 'needs data'),
    metricCard('Top terpene', escapeHtml(stats.favoriteTerpene), 'from your vault'),
    metricCard('Spend', formatMoney(stats.totalSpent), 'sessions + stash')
  ].join('');

  const recent = state.sessions.slice(0, 3);
  $('#recentTimeline').innerHTML = `
    <p class="eyebrow">recent</p>
    <h3>Latest sessions</h3>
    ${recent.length ? recent.map(renderJournalCard).join('') : emptyState('No sessions yet', 'Tap Quick Session and let the flow guide you from strain to effect rating.')}
  `;
}

function metricCard(label, value, sub) {
  return `
    <div class="metric-card glass">
      <small>${escapeHtml(label)}</small>
      <strong>${value}</strong>
      <small>${escapeHtml(sub)}</small>
    </div>
  `;
}

function emptyState(title, body) {
  return `
    <div class="empty-state glass">
      <h3>${escapeHtml(title)}</h3>
      <p class="muted">${escapeHtml(body)}</p>
    </div>
  `;
}

function renderVault() {
  const query = normalizeName($('#strainSearch')?.value || '');
  const type = $('#typeFilter')?.value || 'all';
  const strains = state.strains.filter(strain => {
    const haystack = normalizeName([
      strain.name,
      strain.brand,
      strain.type,
      ...(strain.terpenes || []),
      ...sessionsForStrain(strain.name).flatMap(session => [session.intent, session.mood, session.notes])
    ].join(' '));
    const matchesQuery = !query || haystack.includes(query);
    const matchesType = type === 'all' || strain.type === type;
    return matchesQuery && matchesType;
  });
  $('#strainVault').innerHTML = strains.length ? strains.map(renderStrainCard).join('') : emptyState('Your strain library is empty', 'Scan a label or add a strain to create your first shareable card.');
}

function renderStrainCard(strain) {
  const score = strainScore(strain);
  const sessions = sessionsForStrain(strain.name);
  const tags = [strain.type, strain.thc ? `${strain.thc}% THC` : '', strain.cbd ? `${strain.cbd}% CBD` : '', ...(strain.terpenes || [])].filter(Boolean);
  const bestEffects = summarizeEffects(sessions);
  return `
    <article class="strain-card glass reveal">
      <div class="card-top">
        <div class="card-title">
          <h3>${escapeHtml(strain.name)}</h3>
          <p>${escapeHtml(strain.brand || 'No brand saved')} · ${sessions.length} session${sessions.length === 1 ? '' : 's'}</p>
        </div>
        ${strain.labelPhoto ? `<img class="photo-thumb" src="${strain.labelPhoto}" alt="${escapeHtml(strain.name)} label" />` : `<span class="score-pill">${score}/100</span>`}
      </div>
      <div class="tag-row">${tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}</div>
      <div class="effect-row">${bestEffects.map(effect => `<span class="effect-chip">${escapeHtml(effect)}</span>`).join('')}</div>
      ${strain.notes ? `<p class="muted">${escapeHtml(strain.notes)}</p>` : ''}
      <div class="card-actions">
        <button class="mini-btn" data-action="edit-strain" data-id="${strain.id}">Edit</button>
        <button class="mini-btn" data-action="share-strain" data-id="${strain.id}">Share card</button>
        <button class="mini-btn accent" data-action="log-strain" data-id="${strain.id}">Log session</button>
      </div>
    </article>
  `;
}

function summarizeEffects(sessions) {
  if (!sessions.length) return ['Ready for first rating'];
  const fields = ['calm', 'energy', 'clarity', 'sleepiness'];
  const effects = fields
    .map(field => ({ field, value: average(sessions.map(session => Number(session.effects?.[field] || 0))) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 3)
    .map(item => `${capitalize(item.field)} ${Math.round(item.value)}/10`);
  const anxiety = average(sessions.map(session => Number(session.effects?.anxiety || 0)));
  effects.push(anxiety <= 3 ? 'Low anxiety' : `Anxiety ${Math.round(anxiety)}/10`);
  return effects;
}

function capitalize(value) {
  return String(value || '').charAt(0).toUpperCase() + String(value || '').slice(1);
}

function renderJournal() {
  $('#journalTimeline').innerHTML = state.sessions.length
    ? state.sessions.map(renderJournalCard).join('')
    : emptyState('No effect timeline yet', 'Each session becomes a journal card with mood, use case, rating, notes, and photos.');
}

function renderJournalCard(session) {
  const effects = session.effects || {};
  return `
    <article class="journal-card glass reveal">
      <div class="card-top">
        <div class="card-title">
          <h3>${escapeHtml(session.strainName)}</h3>
          <p>${formatDate(session.createdAt)} · ${escapeHtml(session.intent || 'Session')}</p>
        </div>
        ${session.labelPhoto ? `<img class="photo-thumb" src="${session.labelPhoto}" alt="label photo" />` : `<span class="score-pill">${'★'.repeat(Number(session.rating || 0))}</span>`}
      </div>
      <div class="effect-row">
        <span class="effect-chip">Calm ${effects.calm ?? 0}/10</span>
        <span class="effect-chip">Energy ${effects.energy ?? 0}/10</span>
        <span class="effect-chip">Clarity ${effects.clarity ?? 0}/10</span>
        <span class="effect-chip">Anxiety ${effects.anxiety ?? 0}/10</span>
      </div>
      ${session.notes ? `<p class="muted">${escapeHtml(session.notes)}</p>` : ''}
      ${session.receiptPhoto ? `<div class="tag-row"><span class="tag">Receipt saved</span>${session.price ? `<span class="tag">${formatMoney(session.price)}</span>` : ''}</div>` : ''}
      <div class="card-actions">
        <button class="mini-btn" data-action="edit-session" data-id="${session.id}">Edit</button>
      </div>
    </article>
  `;
}

function renderInsights() {
  const stats = getProfileStats();
  $('#profileDashboard').innerHTML = [
    metricCard('Body score leader', stats.bestStrain ? escapeHtml(stats.bestStrain.name) : '—', stats.bestStrain ? `${strainScore(stats.bestStrain)}/100 personal score` : 'log more sessions'),
    metricCard('Average THC', stats.avgThc ? `${stats.avgThc.toFixed(1)}%` : '—', 'from saved strains'),
    metricCard('Average rating', stats.avgRating ? `${stats.avgRating.toFixed(1)}/5` : '—', 'your personal ratings'),
    metricCard('Favorite terpene', escapeHtml(stats.favoriteTerpene), 'based on saved labels')
  ].join('');

  const picks = [
    ['Relax', stats.relaxPick],
    ['Sleep', stats.sleepPick],
    ['Focus', stats.focusPick],
    ['Creativity', stats.creativePick]
  ];
  $('#matchEngine').innerHTML = `
    <p class="eyebrow">match engine</p>
    <h3>Personal recommendations from your own history</h3>
    <p class="muted">This is preference tracking, not medical advice. It only uses your local logs.</p>
    <div class="card-stack">
      ${picks.map(([label, pick]) => `
        <div class="tag-row" style="justify-content: space-between; align-items:center;">
          <span class="tag">Best for ${label}</span>
          <strong>${pick ? escapeHtml(pick.name) : 'Needs more logs'}</strong>
        </div>
      `).join('')}
    </div>
  `;
}

function renderStash() {
  $('#stashList').innerHTML = state.stash.length
    ? state.stash.map(item => `
      <article class="stash-card glass reveal">
        <div class="card-top">
          <div class="card-title">
            <h3>${escapeHtml(item.name)}</h3>
            <p>${escapeHtml(item.amount || 'Amount not set')} · ${escapeHtml(item.dispensary || 'No dispensary')}</p>
          </div>
          ${item.photo ? `<img class="photo-thumb" src="${item.photo}" alt="stash photo" />` : `<span class="score-pill">${item.price ? formatMoney(item.price) : 'stash'}</span>`}
        </div>
        <div class="tag-row">
          <span class="tag">${formatDate(item.createdAt)}</span>
          ${item.price ? `<span class="tag">${formatMoney(item.price)}</span>` : ''}
        </div>
        <div class="card-actions">
          <button class="mini-btn" data-action="edit-stash" data-id="${item.id}">Edit</button>
        </div>
      </article>
    `).join('')
    : emptyState('No stash saved', 'Track what you have, where it came from, what it cost, and keep the receipt photo attached.');
}

function renderSecurity() {
  $('#securityStatus').textContent = secureEnabled
    ? 'Vault lock is enabled. Data is encrypted locally with your passcode while stored in this browser.'
    : 'Vault lock is off. Data is stored locally in this browser without a cloud account.';
}

async function imageFileToDataUrl(file, maxSize = 1100, quality = 0.78) {
  if (!file || !(file instanceof Blob) || file.size === 0) return '';
  const img = new Image();
  const objectUrl = URL.createObjectURL(file);
  try {
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = reject;
      img.src = objectUrl;
    });
    const ratio = Math.min(1, maxSize / Math.max(img.width, img.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(img.width * ratio));
    canvas.height = Math.max(1, Math.round(img.height * ratio));
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL('image/jpeg', quality);
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

async function readOptionalImageFile(file, label = 'Photo', maxSize = 1100, quality = 0.78) {
  if (!file || !(file instanceof Blob) || file.size === 0) return '';
  try {
    return await imageFileToDataUrl(file, maxSize, quality);
  } catch (error) {
    console.warn(`${label} could not be attached:`, error);
    toast(`${label} could not be attached, but the text details were kept.`);
    return '';
  }
}


async function handleStrainSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const labelPhoto = await readOptionalImageFile(data.get('labelPhoto'), 'Label photo');
  const name = String(data.get('name') || '').trim();
  if (!name) {
    toast('Add a strain name first.');
    return;
  }

  const existing = state.strains.find(strain => strain.id === editingStrainId);
  const duplicate = state.strains.find(strain => normalizeName(strain.name) === normalizeName(name) && strain.id !== editingStrainId);
  if (duplicate && !existing) {
    editingStrainId = duplicate.id;
  }

  const target = existing || duplicate || {
    id: uid('strain'),
    createdAt: new Date().toISOString()
  };

  target.name = name;
  target.brand = String(data.get('brand') || '').trim();
  target.type = String(data.get('type') || 'Flower');
  target.thc = data.get('thc') ? Number(data.get('thc')).toFixed(1).replace('.0', '') : '';
  target.cbd = data.get('cbd') ? Number(data.get('cbd')).toFixed(1).replace('.0', '') : '';
  target.terpenes = parseList(String(data.get('terpenes') || ''));
  target.notes = String(data.get('notes') || '').trim();
  target.labelPhoto = labelPhoto || pendingStrainLabelPhoto || target.labelPhoto || '';
  target.updatedAt = new Date().toISOString();

  if (!state.strains.some(strain => strain.id === target.id)) {
    state.strains.unshift(target);
  }

  await saveState();
  form.reset();
  editingStrainId = '';
  pendingStrainLabelPhoto = '';
  closeModal('strainModal');
  renderAll();
  navigate('vault');
  toast(existing || duplicate ? 'Strain changes applied.' : 'Strain saved to your vault.');
}

async function deleteEditingStrain() {
  if (!editingStrainId) return;
  const strain = state.strains.find(item => item.id === editingStrainId);
  if (!strain) return;
  const confirmed = confirm(`Delete ${strain.name} from your vault? Sessions already logged will stay in your journal.`);
  if (!confirmed) return;
  state.strains = state.strains.filter(item => item.id !== editingStrainId);
  await saveState();
  editingStrainId = '';
  closeModal('strainModal');
  renderAll();
  toast('Strain card deleted.');
}

async function handleLogSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const existing = state.sessions.find(session => session.id === editingSessionId);
  const labelPhoto = await readOptionalImageFile(data.get('labelPhoto'), 'Label photo');
  const receiptPhoto = await readOptionalImageFile(data.get('receiptPhoto'), 'Receipt photo');
  const session = {
    id: existing?.id || uid('session'),
    strainName: String(data.get('strainName') || '').trim(),
    brand: String(data.get('brand') || '').trim(),
    type: String(data.get('type') || 'Flower'),
    thc: data.get('thc') ? Number(data.get('thc')).toFixed(1).replace('.0', '') : '',
    cbd: data.get('cbd') ? Number(data.get('cbd')).toFixed(1).replace('.0', '') : '',
    terpenes: String(data.get('terpenes') || ''),
    mood: String(data.get('mood') || 'Neutral'),
    intent: String(data.get('intent') || 'Relax'),
    effects: {
      calm: Number(data.get('calm') || 0),
      energy: Number(data.get('energy') || 0),
      clarity: Number(data.get('clarity') || 0),
      anxiety: Number(data.get('anxiety') || 0),
      sleepiness: Number(data.get('sleepiness') || 0)
    },
    rating: Number(data.get('rating') || 0),
    price: data.get('price') ? Number(data.get('price')) : '',
    notes: String(data.get('notes') || '').trim(),
    labelPhoto: labelPhoto || existing?.labelPhoto || '',
    receiptPhoto: receiptPhoto || existing?.receiptPhoto || '',
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  if (!session.strainName) {
    toast('Add a strain name first.');
    return;
  }

  upsertStrainFromSession(session);
  if (existing) {
    state.sessions = state.sessions.map(item => item.id === existing.id ? session : item);
  } else {
    state.sessions.unshift(session);
  }
  await saveState();
  form.reset();
  editingSessionId = '';
  closeModal('logModal');
  renderAll();
  toast(existing ? 'Session changes applied.' : 'Session saved to your journal.');
}

async function handleStashSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const existing = state.stash.find(item => item.id === editingStashId);
  const photo = await readOptionalImageFile(data.get('photo'), 'Stash photo');
  const item = {
    id: existing?.id || uid('stash'),
    name: String(data.get('name') || '').trim(),
    amount: String(data.get('amount') || '').trim(),
    price: data.get('price') ? Number(data.get('price')) : '',
    dispensary: String(data.get('dispensary') || '').trim(),
    photo: photo || existing?.photo || '',
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  if (!item.name) {
    toast('Add an item name first.');
    return;
  }
  if (existing) {
    state.stash = state.stash.map(entry => entry.id === existing.id ? item : entry);
  } else {
    state.stash.unshift(item);
  }
  await saveState();
  form.reset();
  editingStashId = '';
  closeModal('stashModal');
  renderAll();
  toast(existing ? 'Stash changes applied.' : 'Stash item saved.');
}

function cleanLabelValue(value = '') {
  return String(value || '')
    .replace(/^[#:\-\s]+/, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

function extractField(all, labels) {
  const escaped = labels.map(label => label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const match = all.match(new RegExp(`(?:${escaped})\\s*[:#-]?\\s*([^\\n,|]+)`, 'i'));
  return cleanLabelValue(match?.[1] || '');
}

function extractPercent(all, labels) {
  const escaped = labels.map(label => label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const match = all.match(new RegExp(`(?:${escaped})\\s*[:#-]?\\s*(\\d+(?:\\.\\d+)?)\\s*%?`, 'i'));
  return match?.[1] || '';
}

function parseLabelText(text) {
  const raw = String(text || '').trim();
  const all = raw.replace(/\r/g, '\n');
  const lines = all.split(/\n|\|/).map(line => cleanLabelValue(line)).filter(Boolean);
  const segments = all
    .split(/\n|\||,|;|•|·/)
    .map(line => cleanLabelValue(line))
    .filter(Boolean);
  const thc = extractPercent(all, ['Total THC', 'THC', 'Delta 9 THC', 'D9 THC', 'THCA']);
  const cbd = extractPercent(all, ['Total CBD', 'CBD', 'CBDA']);
  const brand = extractField(all, ['Brand', 'Grower', 'Cultivator', 'Producer', 'Manufacturer', 'Made by', 'Grown by']) || '';
  const namedStrain = extractField(all, ['Strain Name', 'Strain', 'Product Name', 'Product', 'Cultivar', 'Name']);
  const typeMatch = all.match(/\b(Flower|Bud|Cart|Cartridge|Vape|Edible|Gummy|Concentrate|Wax|Rosin|Resin|Pre[- ]?roll|Preroll|Tincture)\b/i)?.[1] || 'Flower';
  const commonTerpenes = ['myrcene','limonene','caryophyllene','pinene','linalool','humulene','terpinolene','ocimene','bisabolol','camphene','eucalyptol','nerolidol','terpineol','guaiol'];
  const terpeneLine = all.match(/Terpenes?\s*[:#-]?\s*([^\n]+)/i)?.[1] || '';
  const foundTerpenes = commonTerpenes.filter(terp => new RegExp(`\\b${terp}\\b`, 'i').test(all)).map(capitalize);
  const terpenes = uniqueList([...parseList(terpeneLine), ...foundTerpenes]).join(', ');
  const blocked = /(THC|CBD|CBG|CBN|Terpene|Batch|Package|Warning|Cannabinoid|Total|Net Wt|License|Testing|Harvest|Manufactured|Ingredients|Use by|UID|Item|Adult|Government|Activation|Serving|Dose|MG\b|%|\d+\.\d+)/i;
  const typeOnly = /^(Flower|Bud|Cart|Cartridge|Vape|Edible|Gummy|Concentrate|Wax|Rosin|Resin|Pre[- ]?roll|Preroll|Tincture)$/i;
  const likelyName = [...segments, ...lines].find(line => {
    const cleaned = line.replace(/^(strain|product|cultivar|name)\s*[:#-]?\s*/i, '').trim();
    return cleaned.length >= 3 && cleaned.length <= 60 && !blocked.test(cleaned) && !typeOnly.test(cleaned);
  }) || '';
  const strainCandidate = namedStrain || likelyName;
  const type = /cart|cartridge|vape/i.test(typeMatch) ? 'Cart'
    : /pre/i.test(typeMatch) ? 'Pre-roll'
    : /edible|gummy/i.test(typeMatch) ? 'Edible'
    : /wax|rosin|resin|concentrate/i.test(typeMatch) ? 'Concentrate'
    : /tincture/i.test(typeMatch) ? 'Tincture'
    : 'Flower';
  return {
    strainName: cleanLabelValue(strainCandidate.replace(/^(strain|product|cultivar|name)\s*:?\s*/i, '')).slice(0, 60),
    brand,
    type,
    thc,
    cbd,
    terpenes,
    notes: raw ? 'Created from label scanner assist.' : ''
  };
}

function scanDraftFromForm(form) {
  const data = new FormData(form);
  return {
    strainName: String(data.get('strainName') || '').trim(),
    brand: String(data.get('brand') || '').trim(),
    type: String(data.get('type') || 'Flower'),
    thc: data.get('thc') ? Number(data.get('thc')).toFixed(1).replace('.0', '') : '',
    cbd: data.get('cbd') ? Number(data.get('cbd')).toFixed(1).replace('.0', '') : '',
    terpenes: String(data.get('terpenes') || '').trim(),
    notes: String(data.get('notes') || '').trim(),
    labelPhoto: lastScanImage
  };
}

function renderScanDraft(draft) {
  $('#scanDraft').classList.remove('hidden');
  $('#scanDraft').innerHTML = `
    <p class="eyebrow">scanner draft</p>
    <h3>${escapeHtml(draft.strainName || 'Untitled strain')}</h3>
    <p class="muted">Review the label results. You can save it now, or push it into the full Add/Edit Strain form before saving.</p>
    <form id="scanDraftForm" class="flow-form">
      <div class="form-grid">
        <label>Strain name<input name="strainName" value="${escapeHtml(draft.strainName || '')}" required /></label>
        <label>Brand / grower<input name="brand" value="${escapeHtml(draft.brand || '')}" placeholder="Optional" /></label>
        <label>Product type<select name="type">${['Flower','Cart','Edible','Concentrate','Pre-roll','Tincture'].map(type => `<option ${type === draft.type ? 'selected' : ''}>${type}</option>`).join('')}</select></label>
        <label>THC %<input name="thc" type="number" step="0.1" value="${escapeHtml(draft.thc || '')}" /></label>
        <label>CBD %<input name="cbd" type="number" step="0.1" value="${escapeHtml(draft.cbd || '')}" /></label>
        <label>Top terpenes<input name="terpenes" value="${escapeHtml(draft.terpenes || '')}" placeholder="Myrcene, Limonene" /></label>
      </div>
      <label>Notes<textarea name="notes" placeholder="Batch, flavor, smell, package details...">${escapeHtml(draft.notes || '')}</textarea></label>
      <div class="button-row wrap">
        <button class="primary-btn" type="submit">Save strain card</button>
        <button id="applyScanDraftBtn" class="ghost-btn" type="button">Apply to strain form</button>
      </div>
    </form>
  `;
  $('#scanDraftForm').addEventListener('submit', saveScanDraft);
  $('#applyScanDraftBtn').addEventListener('click', () => applyScanDraftToStrain());
}

async function saveScanDraft(event) {
  event.preventDefault();
  const draft = scanDraftFromForm(event.currentTarget);
  if (!draft.strainName) {
    toast('Add a strain name first.');
    return;
  }
  const sessionLike = {
    strainName: draft.strainName,
    brand: draft.brand,
    type: draft.type,
    thc: draft.thc,
    cbd: draft.cbd,
    terpenes: draft.terpenes,
    labelPhoto: draft.labelPhoto
  };
  const saved = upsertStrainFromSession(sessionLike);
  saved.notes = draft.notes || saved.notes || '';
  saved.updatedAt = new Date().toISOString();
  await saveState();
  $('#scanDraft').classList.add('hidden');
  $('#labelText').value = '';
  lastScanImage = '';
  $('#scanPreview').classList.add('hidden');
  $('#scanImageInput').value = '';
  renderAll();
  toast('Shareable strain card saved to your library.');
  navigate('vault');
}

function applyScanDraftToStrain() {
  const form = $('#scanDraftForm');
  if (!form) return;
  const draft = scanDraftFromForm(form);
  if (!draft.strainName) {
    toast('Add a strain name before applying.');
    return;
  }
  closeAllModals();
  openStrainEditor('', draft);
  toast('Scanner info filled into the strain form. Review and save.');
}

async function handleScanImage(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  lastScanImage = await readOptionalImageFile(file, 'Label photo', 1200, .8);
  if (!lastScanImage) return;
  $('#scanPreview').src = lastScanImage;
  $('#scanPreview').classList.remove('hidden');
  toast('Photo attached locally. Paste label text or use Live Text, then create a draft.');
  renderScanDraft({ strainName: '', brand: '', type: 'Flower', thc: '', cbd: '', terpenes: '', notes: 'Label photo attached.' });
}

function openStrainShare(strainId) {
  sharingStrainId = strainId || '';
  const strain = state.strains.find(item => item.id === sharingStrainId);
  if (!strain) {
    toast('Could not find that strain card.');
    return;
  }
  $('#strainShareTitle').textContent = `${strain.name} card`;
  openModal('strainShareModal');
  renderStrainShareCard();
}

function renderStrainShareCard() {
  const strain = state.strains.find(item => item.id === sharingStrainId);
  if (!strain) return;
  const canvas = $('#strainCanvas');
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  const score = strainScore(strain);
  const sessions = sessionsForStrain(strain.name);
  const effects = summarizeEffects(sessions);
  const tags = [strain.type, strain.thc ? `${strain.thc}% THC` : '', strain.cbd ? `${strain.cbd}% CBD` : '', ...(strain.terpenes || [])].filter(Boolean);

  const gradient = ctx.createLinearGradient(0, 0, w, h);
  gradient.addColorStop(0, '#101620');
  gradient.addColorStop(.42, '#123421');
  gradient.addColorStop(.72, '#32204c');
  gradient.addColorStop(1, '#161a24');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, w, h);

  ctx.globalAlpha = .45;
  for (let i = 0; i < 22; i += 1) {
    ctx.beginPath();
    ctx.fillStyle = ['#52f28b', '#ffd166', '#9d7cff', '#76d9ff', '#ff7ab6'][i % 5];
    ctx.arc((i * 97) % w, (i * 173) % h, 55 + (i % 5) * 24, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;

  roundRect(ctx, 70, 70, w - 140, h - 140, 58, 'rgba(255,255,255,.13)', 'rgba(255,255,255,.28)');
  ctx.fillStyle = '#f7f2e8';
  ctx.font = '900 54px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillText('StrainVault', 120, 155);
  ctx.font = '700 27px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = '#b8ff7a';
  ctx.fillText('SHAREABLE STRAIN CARD', 120, 202);

  ctx.fillStyle = '#f7f2e8';
  ctx.font = '900 86px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  wrapText(ctx, strain.name, 120, 330, 800, 92);

  ctx.font = '700 31px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = 'rgba(247,242,232,.78)';
  const brandLine = `${strain.brand || 'No brand saved'} · ${sessions.length} session${sessions.length === 1 ? '' : 's'} logged`;
  wrapText(ctx, brandLine, 120, 500, 820, 38);

  roundRect(ctx, 120, 590, 300, 160, 34, 'rgba(184,255,122,.16)', 'rgba(184,255,122,.35)');
  ctx.font = '800 26px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = 'rgba(247,242,232,.7)';
  ctx.fillText('BODY SCORE', 150, 645);
  ctx.font = '900 66px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = '#f7f2e8';
  ctx.fillText(`${score}/100`, 150, 715);

  roundRect(ctx, 465, 590, 495, 160, 34, 'rgba(255,255,255,.1)', 'rgba(255,255,255,.22)');
  ctx.font = '800 26px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = 'rgba(247,242,232,.7)';
  ctx.fillText('LABEL INFO', 500, 645);
  ctx.font = '900 34px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = '#f7f2e8';
  wrapText(ctx, tags.slice(0, 4).join(' · ') || 'No label info yet', 500, 704, 410, 38);

  let y = 840;
  ctx.font = '800 28px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = '#b8ff7a';
  ctx.fillText('TOP SIGNALS', 120, y);
  y += 48;
  effects.slice(0, 4).forEach(effect => {
    roundRect(ctx, 120, y, 840, 70, 25, 'rgba(255,255,255,.11)', 'rgba(255,255,255,.18)');
    ctx.font = '800 30px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
    ctx.fillStyle = '#f7f2e8';
    ctx.fillText(effect, 150, y + 45);
    y += 88;
  });

  if (strain.notes) {
    ctx.font = '700 27px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
    ctx.fillStyle = 'rgba(247,242,232,.72)';
    wrapText(ctx, `Notes: ${strain.notes}`.slice(0, 150), 120, 1210, 820, 34);
  }

  ctx.font = '700 25px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = 'rgba(247,242,232,.62)';
  ctx.fillText('Private preference card · not medical advice', 120, h - 120);
  const dataUrl = canvas.toDataURL('image/png');
  $('#downloadStrainCardLink').href = dataUrl;
  $('#downloadStrainCardLink').download = `strainvault-${strain.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'strain'}-card.png`;
}

async function shareCurrentStrainCard() {
  const strain = state.strains.find(item => item.id === sharingStrainId);
  const canvas = $('#strainCanvas');
  if (!strain || !canvas) return;
  renderStrainShareCard();
  canvas.toBlob(async blob => {
    if (!blob) {
      toast('Could not prepare image. Use Download PNG instead.');
      return;
    }
    const file = new File([blob], `strainvault-${strain.name}.png`, { type: 'image/png' });
    try {
      if (navigator.canShare?.({ files: [file] }) && navigator.share) {
        await navigator.share({ files: [file], title: `${strain.name} StrainVault card`, text: 'My StrainVault strain card.' });
        toast('Share sheet opened.');
      } else {
        toast('Share files are not supported here. Use Download PNG.');
      }
    } catch (error) {
      if (error?.name !== 'AbortError') {
        console.error(error);
        toast('Share canceled or unavailable. Use Download PNG.');
      }
    }
  }, 'image/png');
}

function renderProfileCard() {
  const canvas = $('#profileCanvas');
  const ctx = canvas.getContext('2d');
  const stats = getProfileStats();
  const w = canvas.width;
  const h = canvas.height;

  const gradient = ctx.createLinearGradient(0, 0, w, h);
  gradient.addColorStop(0, '#11151f');
  gradient.addColorStop(.45, '#14301f');
  gradient.addColorStop(1, '#25183f');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, w, h);

  ctx.globalAlpha = .55;
  for (let i = 0; i < 18; i += 1) {
    ctx.beginPath();
    ctx.fillStyle = ['#52f28b', '#ffd166', '#9d7cff', '#76d9ff'][i % 4];
    ctx.arc(Math.random() * w, Math.random() * h, 70 + Math.random() * 130, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;

  roundRect(ctx, 70, 70, w - 140, h - 140, 56, 'rgba(255,255,255,.12)', 'rgba(255,255,255,.28)');
  ctx.fillStyle = '#f7f2e8';
  ctx.font = '800 58px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillText('StrainVault', 120, 165);
  ctx.font = '700 28px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = '#b8ff7a';
  ctx.fillText('PERSONAL CANNABIS PROFILE', 120, 216);

  ctx.fillStyle = '#f7f2e8';
  ctx.font = '900 82px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  wrapText(ctx, stats.bestStrain ? stats.bestStrain.name : 'Start tracking', 120, 360, 820, 88);

  ctx.font = '700 32px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = 'rgba(247,242,232,.78)';
  ctx.fillText(stats.bestStrain ? `Best body score: ${strainScore(stats.bestStrain)}/100` : 'Your profile gets smarter with each session.', 120, 520);

  const metrics = [
    ['Sessions', stats.totalSessions || '0'],
    ['Strains', stats.totalStrains || '0'],
    ['Top terpene', stats.favoriteTerpene || '—'],
    ['Avg rating', stats.avgRating ? `${stats.avgRating.toFixed(1)}/5` : '—'],
    ['Best for sleep', stats.sleepPick?.name || 'Needs logs'],
    ['Best for focus', stats.focusPick?.name || 'Needs logs']
  ];

  let x = 120;
  let y = 650;
  metrics.forEach((metric, index) => {
    const col = index % 2;
    const row = Math.floor(index / 2);
    x = 120 + col * 430;
    y = 650 + row * 170;
    roundRect(ctx, x, y, 380, 125, 32, 'rgba(255,255,255,.13)', 'rgba(255,255,255,.22)');
    ctx.font = '700 24px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
    ctx.fillStyle = 'rgba(247,242,232,.66)';
    ctx.fillText(metric[0], x + 28, y + 42);
    ctx.font = '900 34px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
    ctx.fillStyle = '#f7f2e8';
    wrapText(ctx, String(metric[1]), x + 28, y + 88, 320, 38);
  });

  ctx.font = '700 26px system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  ctx.fillStyle = 'rgba(247,242,232,.68)';
  ctx.fillText('Private local journal · preference tracking only', 120, h - 130);

  $('#downloadCardLink').href = canvas.toDataURL('image/png');
}

function roundRect(ctx, x, y, width, height, radius, fill, stroke) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + width - radius, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
  ctx.lineTo(x + width, y + height - radius);
  ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  ctx.lineTo(x + radius, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
  ctx.closePath();
  if (fill) {
    ctx.fillStyle = fill;
    ctx.fill();
  }
  if (stroke) {
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 2;
    ctx.stroke();
  }
}

function wrapText(ctx, text, x, y, maxWidth, lineHeight) {
  const words = String(text).split(' ');
  let line = '';
  words.forEach((word, index) => {
    const testLine = line + word + ' ';
    if (ctx.measureText(testLine).width > maxWidth && index > 0) {
      ctx.fillText(line.trim(), x, y);
      line = word + ' ';
      y += lineHeight;
    } else {
      line = testLine;
    }
  });
  ctx.fillText(line.trim(), x, y);
}

async function enableLock() {
  const passcode = $('#vaultPass').value.trim();
  if (passcode.length < 4) {
    toast('Use at least 4 characters for the vault passcode.');
    return;
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  currentCryptoKey = await deriveKey(passcode, salt);
  secureEnabled = true;
  localStore?.setItem(SECURE_KEY, JSON.stringify({ version: 1, salt: b64FromBytes(salt), iv: '', data: '' }));
  await saveState();
  $('#vaultPass').value = '';
  renderSecurity();
  toast('Vault lock enabled.');
}

async function disableLock() {
  if (!secureEnabled) {
    localStore?.removeItem(SECURE_KEY);
    renderSecurity();
    toast('Vault lock is already off.');
    return;
  }
  localStore?.removeItem(SECURE_KEY);
  currentCryptoKey = null;
  secureEnabled = false;
  await saveState();
  renderSecurity();
  toast('Vault lock disabled.');
}

async function handleUnlock() {
  const passcode = $('#unlockPass').value;
  const status = $('#unlockStatus');
  status.textContent = 'Unlocking...';
  try {
    state = await decryptState(passcode);
    $('#lockScreen').classList.add('hidden');
    $('#appShell').classList.remove('hidden');
    $('.bottom-nav').classList.remove('hidden');
    status.textContent = '';
    renderAll();
    initRevealObserver(true);
    // Service worker disabled in this Netlify-safe build.
  } catch (error) {
    console.error(error);
    status.textContent = 'Wrong passcode or damaged vault data.';
  }
}

function exportJson() {
  const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `strainvault-export-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importJson(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const imported = JSON.parse(text);
    if (!Array.isArray(imported.sessions) || !Array.isArray(imported.strains)) throw new Error('Invalid export');
    state = {
      ...safeClone(DEFAULT_STATE),
      ...imported,
      settings: { ...DEFAULT_STATE.settings, ...(imported.settings || {}) }
    };
    await saveState();
    renderAll();
    toast('Import complete.');
  } catch (error) {
    console.error(error);
    toast('That file does not look like a StrainVault export.');
  } finally {
    event.target.value = '';
  }
}

async function clearAllData() {
  const confirmed = confirm('Clear all StrainVault data on this device? This cannot be undone unless you exported a backup.');
  if (!confirmed) return;
  state = safeClone(DEFAULT_STATE);
  currentCryptoKey = null;
  secureEnabled = false;
  pendingStrainLabelPhoto = '';
  lastScanImage = '';
  localStore?.removeItem(PLAIN_KEY);
  localStore?.removeItem(SECURE_KEY);
  renderAll();
  toast('Local vault cleared.');
}

function initRevealObserver(force = false) {
  const elements = $$('.reveal');
  if (!('IntersectionObserver' in window)) {
    elements.forEach(el => el.classList.add('visible'));
    return;
  }
  if (force) elements.forEach(el => el.classList.remove('visible'));
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });
  elements.forEach(el => observer.observe(el));
}

function bindGlobalEvents() {
  $$('.nav-btn').forEach(btn => btn.addEventListener('click', () => navigate(btn.dataset.nav)));
  $('#profileChip').addEventListener('click', () => navigate('settings'));
  $('#quickAddTop').addEventListener('click', () => openSessionEditor());

  document.addEventListener('click', event => {
    const actionEl = event.target.closest('[data-action]');
    const action = actionEl?.dataset.action;
    if (!action) return;
    if (action === 'open-log') openSessionEditor();
    if (action === 'open-strain') openStrainEditor();
    if (action === 'open-stash') openStashEditor();
    if (action === 'open-scan') navigate('scan');
    if (action === 'open-scan-fill') { closeAllModals(); navigate('scan'); toast('Scan or paste label details, then apply them to the strain form.'); }
    if (action === 'open-export') openModal('exportModal');
    if (action === 'edit-strain') openStrainEditor(actionEl.dataset.id);
    if (action === 'share-strain') openStrainShare(actionEl.dataset.id);
    if (action === 'log-strain') {
      const strain = state.strains.find(item => item.id === actionEl.dataset.id);
      openSessionEditor('', strain?.name || '');
    }
    if (action === 'edit-session') openSessionEditor(actionEl.dataset.id);
    if (action === 'edit-stash') openStashEditor(actionEl.dataset.id);
  });

  $$('.close-btn').forEach(btn => btn.addEventListener('click', () => closeModal(btn.dataset.close)));
  $('#modalBackdrop').addEventListener('click', closeAllModals);
  $('#strainForm').addEventListener('submit', handleStrainSubmit);
  $('#strainDeleteBtn').addEventListener('click', deleteEditingStrain);
  $('#logForm').addEventListener('submit', handleLogSubmit);
  $('#stashForm').addEventListener('submit', handleStashSubmit);
  $('#strainSearch').addEventListener('input', renderVault);
  $('#typeFilter').addEventListener('change', renderVault);

  $('#scanImageBtn').addEventListener('click', () => $('#scanImageInput').click());
  $('#scanImageInput').addEventListener('change', handleScanImage);
  $('#parseLabelBtn').addEventListener('click', () => {
    const text = $('#labelText').value.trim();
    if (!text) {
      renderScanDraft({ strainName: '', type: 'Flower', thc: '', cbd: '', terpenes: '' });
      toast('Manual draft created.');
      return;
    }
    renderScanDraft(parseLabelText(text));
    toast('Draft created from label text.');
  });

  $('#renderCardBtn').addEventListener('click', renderProfileCard);
  $('#renderStrainCardBtn').addEventListener('click', renderStrainShareCard);
  $('#shareStrainCardBtn').addEventListener('click', shareCurrentStrainCard);
  $('#enableLockBtn').addEventListener('click', enableLock);
  $('#disableLockBtn').addEventListener('click', disableLock);
  $('#unlockBtn').addEventListener('click', handleUnlock);
  $('#unlockPass').addEventListener('keydown', event => {
    if (event.key === 'Enter') handleUnlock();
  });

  $('#exportJsonBtn').addEventListener('click', exportJson);
  $('#importJsonInput').addEventListener('change', importJson);
  $('#clearDataBtn').addEventListener('click', clearAllData);

  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeAllModals();
  });
}

function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').catch(error => console.warn('Service worker registration failed:', error));
  }
}

boot();
