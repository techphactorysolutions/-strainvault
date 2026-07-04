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
  version: 35,
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
let ocrBusy = false;
let tesseractLoadPromise = null;
let toastTimer = null;
let editingStrainId = '';
let editingSessionId = '';
let editingStashId = '';
let sharingStrainId = '';
let pendingStrainLabelPhoto = '';
let pendingStrainLabelDetails = null;


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
  pendingStrainLabelDetails = strain ? (strain.labelDetails || null) : (draft.details || null);
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
    existing.labelDetails = session.labelDetails || existing.labelDetails || null;
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
    labelDetails: session.labelDetails || null,
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


function renderLabelDetailSummary(strain = {}) {
  const details = strain.labelDetails || {};
  const items = [
    ['Best by', details.bestUsedBy],
    ['Produced by', details.producedBy],
    ['Testing lic.', details.testingLicense],
    ['Weight', details.totalWeight],
    ['Approval #', details.marijuanaApprovalNumber]
  ].filter(([, value]) => value);
  if (!items.length) return '';
  return `<div class="label-summary">${items.map(([label, value]) => `<span><small>${escapeHtml(label)}</small>${escapeHtml(value)}</span>`).join('')}</div>`;
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
      ${renderLabelDetailSummary(strain)}
      ${strain.notes ? `<p class="muted">${escapeHtml(strain.notes.length > 260 ? `${strain.notes.slice(0, 260)}…` : strain.notes)}</p>` : ''}
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
  target.thc = data.get('thc') ? formatCannabinoidPercent(data.get('thc')) : '';
  target.cbd = data.get('cbd') ? formatCannabinoidPercent(data.get('cbd')) : '';
  target.terpenes = parseList(String(data.get('terpenes') || ''));
  target.notes = String(data.get('notes') || '').trim();
  target.labelPhoto = labelPhoto || pendingStrainLabelPhoto || target.labelPhoto || '';
  target.labelDetails = pendingStrainLabelDetails || target.labelDetails || null;
  target.updatedAt = new Date().toISOString();

  if (!state.strains.some(strain => strain.id === target.id)) {
    state.strains.unshift(target);
  }

  await saveState();
  form.reset();
  editingStrainId = '';
  pendingStrainLabelPhoto = '';
  pendingStrainLabelDetails = null;
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
    thc: data.get('thc') ? formatCannabinoidPercent(data.get('thc')) : '',
    cbd: data.get('cbd') ? formatCannabinoidPercent(data.get('cbd')) : '',
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


function setOcrStatus(message) {
  const status = $('#ocrStatus');
  if (status) status.textContent = message;
}

function setScanButtonsEnabled(hasImage) {
  const readBtn = $('#readLabelPhotoBtn');
  if (readBtn) readBtn.disabled = !hasImage || ocrBusy;
}

function resetScanner() {
  lastScanImage = '';
  const input = $('#scanImageInput');
  const preview = $('#scanPreview');
  const text = $('#labelText');
  const draft = $('#scanDraft');
  if (input) input.value = '';
  if (preview) {
    preview.removeAttribute('src');
    preview.classList.add('hidden');
  }
  if (text) text.value = '';
  if (draft) {
    draft.classList.add('hidden');
    draft.innerHTML = '';
  }
  setScanButtonsEnabled(false);
  setOcrStatus('Upload a label photo to begin.');
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const existing = [...document.scripts].find(script => script.src === src);
    if (existing) {
      if (window.Tesseract) resolve();
      else existing.addEventListener('load', resolve, { once: true });
      return;
    }
    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.crossOrigin = 'anonymous';
    script.onload = resolve;
    script.onerror = () => reject(new Error('OCR library could not load.'));
    document.head.appendChild(script);
  });
}

async function loadOcrEngine() {
  if (window.Tesseract) return window.Tesseract;
  if (!tesseractLoadPromise) {
    tesseractLoadPromise = loadScript('https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js')
      .then(() => {
        if (!window.Tesseract) throw new Error('OCR engine did not initialize.');
        return window.Tesseract;
      });
  }
  return tesseractLoadPromise;
}

async function tryNativeTextDetector() {
  if (!('TextDetector' in window)) return '';
  const preview = $('#scanPreview');
  if (!preview || !preview.src) return '';
  try {
    const detector = new window.TextDetector();
    const results = await detector.detect(preview);
    return (results || []).map(item => item.rawValue || '').join('\n').trim();
  } catch (error) {
    console.info('Native text detector unavailable:', error);
    return '';
  }
}

function scannerDraftMissingFields(draft = {}) {
  return [
    draft.strainName ? '' : 'strain name',
    draft.brand ? '' : 'brand',
    draft.thc ? '' : 'THC',
    draft.cbd ? '' : 'CBD'
  ].filter(Boolean);
}

function scannerDraftHasCoreFields(draft = {}) {
  const missing = scannerDraftMissingFields(draft);
  return !missing.length && (draft.confidence || 0) >= 70;
}

async function runOcrOnScanImage() {
  if (!lastScanImage) {
    toast('Take or upload a label photo first.');
    return;
  }
  if (ocrBusy) return;
  ocrBusy = true;
  setScanButtonsEnabled(true);
  setOcrStatus('Reading label photo… keep this page open. Close, bright label photos work best.');
  try {
    const texts = [];
    let nativeText = await tryNativeTextDetector();
    if (nativeText) texts.push(nativeText);

    let combinedDraft = parseLabelText(combineOcrTexts(texts));
    const variants = await createOcrVariants(lastScanImage);

    setOcrStatus('Loading OCR reader… first scan may take a moment.');
    const Tesseract = await loadOcrEngine();

    for (let index = 0; index < variants.length; index += 1) {
      const variant = variants[index];
      const currentMissing = scannerDraftMissingFields(combinedDraft);
      const missingText = currentMissing.length ? ` Missing: ${currentMissing.join(', ')}.` : '';
      setOcrStatus(`Reading ${variant.name}…${missingText}`);
      const result = await Tesseract.recognize(variant.src, 'eng', {
        logger: progress => {
          if (progress?.status === 'recognizing text' && Number.isFinite(progress.progress)) {
            setOcrStatus(`Reading ${variant.name}… ${Math.round(progress.progress * 100)}%`);
          } else if (progress?.status) {
            setOcrStatus(`${capitalize(progress.status)}…`);
          }
        },
        preserve_interword_spaces: '1',
        tessedit_pageseg_mode: index <= 2 ? '6' : '11'
      });
      const text = result?.data?.text || '';
      if (text) texts.push(text);
      combinedDraft = parseLabelText(combineOcrTexts(texts));

      // Do not stop until the full-photo/top-logo passes have had a chance to capture the brand.
      if (scannerDraftHasCoreFields(combinedDraft) && index >= 2) break;
    }

    const text = combineOcrTexts(texts);
    if (!text) {
      setOcrStatus('Could not read the label. Try a closer, brighter photo of only the white label, or paste text with iPhone Live Text.');
      toast('Could not read the label text.');
      return;
    }
    $('#labelText').value = text;
    const draft = parseLabelText(text);
    renderScanDraft(draft);
    const missing = scannerDraftMissingFields(draft);
    if (missing.length) {
      setOcrStatus(`Label read with ${draft.confidence || 0}% confidence. Review missing: ${missing.join(', ')}. Brand logos may need manual correction.`);
    } else {
      setOcrStatus(`Label read with ${draft.confidence || 0}% confidence. Review and save the strain card.`);
    }
    toast('Label read. Review the auto-filled bud info.');
  } catch (error) {
    console.error(error);
    setOcrStatus('Photo OCR failed. Try a closer crop of the white label, or use iPhone Live Text to copy the label text and paste it here.');
    toast('Scanner could not read the photo. Paste label text instead.');
  } finally {
    ocrBusy = false;
    setScanButtonsEnabled(Boolean(lastScanImage));
  }
}


function cleanLabelValue(value = '') {
  return String(value || '')
    .replace(/^[#:\-\s]+/, '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[¢©]/g, 'C')
    .replace(/\s{2,}/g, ' ')
    .replace(/^[.,;:\-\s]+|[.,;:\-\s]+$/g, '')
    .trim();
}

function normalizeOcrText(text = '') {
  return String(text || '')
    .replace(/\r/g, '\n')
    .replace(/[|¦]/g, '\n')
    .replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[∆△]/g, 'Δ')
    .replace(/[®™]/g, '')
    .replace(/[¢©]/g, 'C')
    .replace(/\bT\s*[H#]\s*C\b/gi, 'THC')
    .replace(/\bT\s*[H#]\s*C\s*A\b/gi, 'THCA')
    .replace(/\bC\s*[B8]\s*D\b/gi, 'CBD')
    .replace(/\bC\s*[B8]\s*D\s*A\b/gi, 'CBDA')
    .replace(/\bC\s*[B8]\s*G\b/gi, 'CBG')
    .replace(/\bC\s*[B8]\s*N\b/gi, 'CBN')
    .replace(/\bT0TAL\b/gi, 'TOTAL')
    .replace(/\bTotaI\b/g, 'Total')
    .replace(/\bTotai\b/g, 'Total')
    .replace(/\bCannabinolds?\b/gi, 'Cannabinoids')
    .replace(/\bCannabinoids?\b/gi, match => match.toLowerCase().startsWith('cannabinoid') ? 'Cannabinoids' : match)
    .replace(/\bD(?:elta)?\s*[- ]?9\b/gi, 'Δ9')
    .replace(/\bD8\b/gi, 'Δ8')
    .replace(/\bDelta\s*[- ]?Nine\b/gi, 'Δ9')
    .replace(/\bBest\s+if\s+U(?:sed|scd|se[dcl])\s+by\s+Date\b/gi, 'Best if Used by Date')
    .replace(/\bProduc(?:ed|cd)\s+By\b/gi, 'Produced By')
    .replace(/\bTest(?:ing|inq)\s+License\b/gi, 'Testing License')
    .replace(/\bTest(?:ing|inq)\s+Tag\b/gi, 'Testing Tag')
    .replace(/\bSource\s+Tag\b/gi, 'Source Tag')
    .replace(/\bTota[lI]\s+Weight\b/gi, 'Total Weight')
    .replace(/\bExact\s+Potenc[yv]\b/gi, 'Exact Potency')
    .replace(/\bTerpene\s+Prof(?:ile|lle|iIe)\b/gi, 'Terpene Profile')
    .replace(/\bM[a-z]{2,10}ana\s+Product\s+Approval\s+Number\b/gi, 'Marijuana Product Approval Number')
    .replace(/\bMarijuana\s+Product\s+Approval\s+Number\b/gi, 'Marijuana Product Approval Number')
    .replace(/\s*%/g, '%')
    .replace(/(THC|CBD|THCA|CBDA|CBG|CBGA|CBN|CBC|THCV|CBDV)(\d)/gi, '$1 $2')
    .replace(/(Total THC|Total CBD|Total Cannabinoids|Total Terpenes)(\d)/gi, '$1 $2')
    .replace(/(\d),(\d)/g, '$1.$2')
    .replace(/\n{3,}/g, '\n\n');
}

function escapeRegex(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getCleanLines(text = '') {
  return normalizeOcrText(text)
    .split(/\n|\r|•|·|;/)
    .map(line => cleanLabelValue(line))
    .filter(Boolean);
}

function getSegments(text = '') {
  return normalizeOcrText(text)
    .split(/\n|\r|,|•|·|;|\t/)
    .map(line => cleanLabelValue(line))
    .filter(Boolean);
}

function compactOcrText(text = '') {
  return normalizeOcrText(text)
    .replace(/\s+/g, ' ')
    .replace(/\bTHC A\b/gi, 'THCA')
    .replace(/\bCBD A\b/gi, 'CBDA')
    .trim();
}

function titleCaseScannedName(value = '') {
  const cleaned = cleanLabelValue(value);
  if (!cleaned) return '';
  if (/^[A-Z0-9\s'\-]+$/.test(cleaned) && /[A-Z]/.test(cleaned)) {
    return cleaned.toLowerCase().replace(/\b[a-z]/g, char => char.toUpperCase()).replace(/\bCbd\b/g, 'CBD').replace(/\bThc\b/g, 'THC');
  }
  return cleaned;
}

function normalizePercent(value) {
  const number = Number(String(value || '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(number) || number < 0) return '';
  const adjusted = number > 100 && number < 1000 ? number / 10 : number;
  if (adjusted > 100) return '';
  return adjusted.toFixed(2).replace(/\.00$/, '').replace(/(\.\d)0$/, '$1');
}

function formatCannabinoidPercent(value) {
  const number = Number(String(value || '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(number) || number < 0 || number > 100) return '';
  if (number === 0) return '0';
  if (number < 1) return number.toFixed(2).replace(/0$/, '').replace(/0$/, '');
  return number.toFixed(1).replace('.0', '');
}

function numberValue(value) {
  const parsed = Number(normalizePercent(value));
  return Number.isFinite(parsed) ? parsed : 0;
}

function extractSection(all, startRegex, endRegexes = []) {
  const source = normalizeOcrText(all);
  const start = source.search(startRegex);
  if (start < 0) return '';
  let end = source.length;
  for (const endRegex of endRegexes) {
    const after = source.slice(start + 1).search(endRegex);
    if (after >= 0) end = Math.min(end, start + 1 + after);
  }
  return source.slice(start, end).trim();
}

function extractField(all, labels, maxLength = 90) {
  const lines = getCleanLines(all);
  for (const label of labels) {
    const escaped = escapeRegex(label);
    const lineRegex = new RegExp(`(?:^|\\b)${escaped}\\s*(?:name)?\\s*[:#\\-]?\\s*(.*)$`, 'i');
    for (const line of lines) {
      const match = line.match(lineRegex);
      const value = cleanLabelValue(match?.[1] || '');
      if (value && !/^[:#\-]+$/.test(value)) return value.slice(0, maxLength).trim();
    }
  }
  const source = normalizeOcrText(all);
  for (const label of labels) {
    const escaped = escapeRegex(label);
    const regex = new RegExp(`(?:^|\\n|\\b)${escaped}\\s*(?:name)?\\s*[:#\\-]?\\s*([^\\n]{1,${maxLength}})`, 'i');
    const match = source.match(regex);
    const value = cleanLabelValue(match?.[1] || '');
    if (value && !/^[:#\-]+$/.test(value)) return value.slice(0, maxLength).trim();
  }
  return '';
}

function extractDetailValue(all, labels, maxLength = 80) {
  const value = extractField(all, labels, maxLength);
  return cleanLabelValue(value)
    .replace(/\s+(THC|CBD|Total|Terpene|Cannabinoid|Warning|Instructions)\b.*$/i, '')
    .slice(0, maxLength)
    .trim();
}

function extractDateLike(all, labels) {
  const raw = extractDetailValue(all, labels, 60);
  const date = raw.match(/\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b/)?.[0];
  return date || raw;
}

function extractTagLike(all, labels, maxLength = 80) {
  const raw = extractDetailValue(all, labels, maxLength);
  const cleaned = cleanLabelValue(raw).replace(/[^A-Za-z0-9#\-]/g, '');
  return cleaned || raw;
}

function extractWeightLike(all, labels) {
  const raw = extractDetailValue(all, labels, 60);
  const weight = raw.match(/\b\d+(?:\.\d+)?\s*\(?\s*(?:g|gram|grams|mg|oz)\s*\)?/i)?.[0];
  if (weight) return cleanLabelValue(weight);
  const leading = raw.match(/\b\d+(?:\.\d+)?\b/)?.[0];
  return leading ? `${leading} g` : cleanLabelValue(raw);
}

function detectProductType(all) {
  const value = normalizeOcrText(all);
  const typeMatch = value.match(/\b(Raw\s+Cannabis\s+Flower|Cannabis\s+Flower|Flower|Bud|Buds|Cart|Cartridge|Vape|Edible|Gummy|Concentrate|Wax|Rosin|Resin|Pre[- ]?roll|Preroll|Tincture)\b/i)?.[1] || 'Flower';
  return /cart|cartridge|vape/i.test(typeMatch) ? 'Cart'
    : /pre/i.test(typeMatch) ? 'Pre-roll'
    : /edible|gummy/i.test(typeMatch) ? 'Edible'
    : /wax|rosin|resin|concentrate/i.test(typeMatch) ? 'Concentrate'
    : /tincture/i.test(typeMatch) ? 'Tincture'
    : 'Flower';
}

function normalizeScannedName(value = '') {
  return cleanLabelValue(value)
    .replace(/\b(cannabis|marijuana|flower|buds?|premium|indica|sativa|hybrid|pre[- ]?roll|preroll|cartridge|vape|concentrate|test(ed)?|label|package|product|strain|cultivar)\b/ig, '')
    .replace(/\b\d+(?:\.\d+)?\s*(?:g|gram|mg|oz|%)\b/ig, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/^[.,;:\-\s]+|[.,;:\-\s]+$/g, '')
    .trim();
}

function extractAfterKeyword(text, keywords) {
  const source = normalizeOcrText(text);
  const lines = getCleanLines(source);
  for (const keyword of keywords) {
    const escaped = escapeRegex(keyword);
    const lineRegex = new RegExp(`(?:^|\\b)${escaped}\\s*[:#\\-]?\\s*(.+)$`, 'i');
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const match = line.match(lineRegex);
      if (match) {
        const value = cleanLabelValue(match[1]).replace(/\s+(THC|CBD|Total|Batch|Lot|Pkg|Package|Harvest|Tested|Approval)\b.*$/i, '');
        if (value) return value;
        const next = lines[i + 1] || '';
        if (next) return cleanLabelValue(next);
      }
    }
  }
  return '';
}

const KNOWN_CANNABIS_BRANDS = [
  'Amaze', 'Blue Arrow', 'C4', 'CAMP', 'Cloud Cover', 'Codes', 'Elevate', 'Flora Farms',
  'Good Day Farm', 'Greenlight', 'Heartland Labs', 'Illicit', 'Local Cannabis Co', 'Proper',
  'Robust', 'Sinse', 'Sundro', 'Vertical', 'Vibe', 'Vivid', 'Bloom', 'Daybreak', 'GOAT',
  'Farmer G', 'Smokey River', 'Sublime', 'Safe Bet', 'Nugz', 'Head Change', 'Revolution',
  'Better Daze', 'Better Buds', 'Better Cannabis'
];

function matchKnownBrand(all) {
  const compact = ` ${compactOcrText(all).replace(/[^A-Za-z0-9]+/g, ' ')} `;
  for (const brand of KNOWN_CANNABIS_BRANDS) {
    const brandRegex = new RegExp(`\\b${brand.split(/\s+/).map(escapeRegex).join('\\s+')}\\b`, 'i');
    if (brandRegex.test(compact)) return brand;
  }
  return '';
}

function isBadBrandCandidate(line = '') {
  return !line
    || line.length < 2
    || line.length > 48
    || /\d{4,}|%|THC|CBD|CBG|CBN|CBC|Batch|Lot|Net|Wt|Weight|Warning|Government|Marijuana|Cannabis|Flower|Indica|Sativa|Hybrid|Adult|Keep|Reach|Children|License|Patient|Dispensary|Package|Serving|UID|QR|Code|Use|Testing|Lab|Ingredients|Terpene|Cannabinoid|Total|Approval|Source|Tag|Exact|Potency/i.test(line);
}

function extractBrand(all, details = {}) {
  const known = matchKnownBrand(all);
  if (known) return known;

  const explicit = extractField(all, [
    'Brand', 'Grower', 'Cultivator', 'Cultivated by', 'Grown by', 'Producer', 'Produced by',
    'Manufacturer', 'Manufactured by', 'Mfg by', 'Processor', 'Processed by', 'Packaged by',
    'Distributed by', 'Licensee', 'Facility', 'Company', 'Vendor', 'Supplier'
  ], 70);
  if (explicit && !isBadBrandCandidate(explicit)) return explicit;

  const lines = getCleanLines(all);
  const byLine = lines.find(line => /\b(?:cultivated|grown|manufactured|processed|packaged|distributed|sold|provided)\s+by\b/i.test(line));
  if (byLine) {
    const value = cleanLabelValue(byLine.replace(/^.*?\bby\b\s*/i, ''));
    if (!isBadBrandCandidate(value)) return value;
  }

  // Missouri-style labels sometimes provide a cultivation license instead of a readable brand logo.
  if (details?.producedBy) return details.producedBy;

  const topCandidates = lines.slice(0, 10)
    .map(line => cleanLabelValue(line.replace(/[^A-Za-z0-9&' .\-]/g, '')))
    .filter(line => !isBadBrandCandidate(line) && /[A-Za-z]{2,}/.test(line));
  return topCandidates[0] || '';
}

function isBadNameCandidate(line = '') {
  return !line
    || line.length < 3
    || line.length > 68
    || /^(Flower|Bud|Buds|Cart|Cartridge|Vape|Edible|Gummy|Concentrate|Wax|Rosin|Resin|Pre[- ]?roll|Preroll|Tincture)$/i.test(line)
    || /THC|CBD|CBG|CBN|CBC|Terpene|Batch|Package|Warning|Cannabinoid|Total|Net Wt|Net Weight|License|Testing|Harvest|Manufactured|Ingredients|Use by|Best if|UID|Item #|Adult|Government|Activation|Serving|Dose|MG\b|%|\d+\.\d+|Lab|Patient|METRC|Lot|Expiration|Exp\b|Date|Weight|Marijuana|Keep out|QR|Instructions|Registry|Facility|Approval Number|Produced By|Source Tag|Testing Tag|Testing License|Exact Potency/i.test(line);
}

function extractStrainName(all) {
  const source = normalizeOcrText(all);
  const lines = getCleanLines(source);
  const approvalIndex = lines.findIndex(line => /Marijuana Product Approval Number|Product Approval Number/i.test(line));
  if (approvalIndex >= 0) {
    for (let i = approvalIndex + 1; i < Math.min(lines.length, approvalIndex + 5); i += 1) {
      const candidate = normalizeScannedName(lines[i]);
      if (candidate && /[A-Za-z]{3,}/.test(candidate) && !isBadNameCandidate(candidate)) return titleCaseScannedName(candidate);
    }
  }

  const explicit = extractAfterKeyword(source, ['Strain Name', 'Strain', 'Product Name', 'Cultivar', 'Item Name']);
  const cleanedExplicit = normalizeScannedName(explicit);
  if (cleanedExplicit && !isBadNameCandidate(cleanedExplicit)) return titleCaseScannedName(cleanedExplicit);

  const productLine = lines.find(line => /\b(cannabis\s+flower|flower|pre[- ]?roll|cartridge|vape|concentrate)\b/i.test(line) && !/%|THC|CBD/i.test(line));
  if (productLine) {
    const beforeType = normalizeScannedName(productLine.replace(/\b(cannabis\s+flower|flower|pre[- ]?roll|cartridge|vape|concentrate).*$/i, ''));
    if (beforeType && !matchKnownBrand(beforeType) && !isBadNameCandidate(beforeType)) return titleCaseScannedName(beforeType);
  }

  const candidates = [...getSegments(source), ...lines]
    .map(line => normalizeScannedName(line.replace(/^(strain|product|cultivar|item name)\s*[:#\-]?\s*/i, '')))
    .filter(line => /[A-Za-z]{3,}/.test(line) && !matchKnownBrand(line) && !isBadNameCandidate(line));

  candidates.sort((a, b) => {
    const aWords = a.split(/\s+/).length;
    const bWords = b.split(/\s+/).length;
    const aScore = (aWords >= 2 ? 2 : 0) + (/^[A-Z][a-z]/.test(a) ? 1 : 0) - (/^[A-Z\s]+$/.test(a) ? 1 : 0);
    const bScore = (bWords >= 2 ? 2 : 0) + (/^[A-Z][a-z]/.test(b) ? 1 : 0) - (/^[A-Z\s]+$/.test(b) ? 1 : 0);
    return bScore - aScore;
  });
  return titleCaseScannedName(candidates[0] || '');
}

const POTENCY_LABELS = [
  ['THC', /\bTHC\b(?!\s*[AV])/i],
  ['THCA', /\bTHC\s*A\b|\bTHCA\b/i],
  ['CBD', /\bCBD\b(?!\s*A|\s*V)/i],
  ['CBDA', /\bCBD\s*A\b|\bCBDA\b/i],
  ['CBN', /\bCBN\b/i],
  ['THCV', /\bTHC\s*V\b|\bTHCV\b/i],
  ['CBDV', /\bCBD\s*V\b|\bCBDV\b/i],
  ['Δ9 THC', /\b(?:Δ9|D9|Delta\s*9)[\s\-]*(?:THC)?\b/i]
];

function extractExactPotency(all) {
  const section = extractSection(all, /Exact\s+Potency/i, [/Terpene\s+Profile/i, /Instructions\s+for\s+Use/i, /Marijuana\s+Product\s+Approval/i, /Warning/i]);
  const profile = {};
  if (!section) return profile;
  const compact = compactOcrText(section).replace(/D\s*9/gi, 'D9');

  for (const [key, labelRegex] of POTENCY_LABELS) {
    const label = labelRegex.source;
    const regexes = [
      new RegExp(`(?:${label})\\s*[:#\\-]?\\s*(\\d{1,4}(?:\\.\\d{1,3})?)\\s*(?:mg|milligram|%)?`, 'i'),
      new RegExp(`(?:${label})[^0-9]{0,16}(\\d{1,4}(?:\\.\\d{1,3})?)\\s*(?:mg|milligram|%)?`, 'i')
    ];
    for (const regex of regexes) {
      const match = compact.match(regex);
      const value = match?.[1] || '';
      const n = Number(value);
      if (value !== '' && Number.isFinite(n) && n >= 0 && n <= 1000) {
        profile[key] = value;
        break;
      }
    }
  }

  const hasMainValues = profile.THC || profile.THCA || profile.CBD || profile.CBDA;
  const headerHits = POTENCY_LABELS.filter(([, regex]) => regex.test(section)).length;
  if (!hasMainValues && headerHits >= 3 && /mg\s*\/\s*serv|serving/i.test(section)) {
    const cleaned = compact.replace(/D9[-\s]?THC/gi, 'D9THC').replace(/\bΔ9\b/gi, 'D9THC');
    const values = [...cleaned.matchAll(/\b(\d{1,4}(?:\.\d{1,3})?)\b/g)]
      .map(match => Number(match[1]))
      .filter(n => Number.isFinite(n) && n >= 0 && n <= 1000);
    const useful = values.filter((n, index) => !(n === 9 && /D9/i.test(cleaned.slice(Math.max(0, index - 12), index + 12))));
    const keys = ['THC', 'THCA', 'CBD', 'CBDA', 'CBN', 'THCV', 'CBDV', 'Δ9 THC'];
    useful.slice(0, keys.length).forEach((value, index) => {
      if (!profile[keys[index]]) profile[keys[index]] = String(value);
    });
  }
  return profile;
}

function potencyMgToPercent(value) {
  const n = Number(String(value || '').replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(n) || n < 0) return '';
  // Cannabis flower labels often list mg/serving where one serving is one gram; mg/g divided by 10 equals percent.
  if (n > 100) return formatCannabinoidPercent(n / 10);
  if (n > 10) return formatCannabinoidPercent(n / 10);
  return formatCannabinoidPercent(n / 10);
}

function exactPotencyPercentProfile(mgProfile = {}) {
  const profile = {};
  Object.entries(mgProfile || {}).forEach(([key, value]) => {
    const percent = potencyMgToPercent(value);
    if (percent) profile[key] = percent;
  });
  return profile;
}

function linePercentValue(line = '', labelRegexes = []) {
  const normalized = compactOcrText(line);
  if (!labelRegexes.some(regex => regex.test(normalized))) return '';
  const matchWithPercent = [...normalized.matchAll(/(\d{1,3}(?:\.\d{1,3})?)\s*(?:%|percent)\b/gi)]
    .map(match => normalizePercent(match[1]))
    .filter(Boolean);
  if (matchWithPercent.length) return matchWithPercent[matchWithPercent.length - 1];

  const tokens = [...normalized.matchAll(/(?<!\d)(\d{1,3}(?:\.\d{1,3})?)(?!\d)/g)]
    .map(match => ({ value: normalizePercent(match[1]), raw: match[1], index: match.index || 0 }))
    .filter(item => item.value);
  if (!tokens.length) return '';
  const percentLike = tokens.filter(item => Number(item.value) <= 100 && !/^(19|20)\d{2}$/.test(item.raw));
  return percentLike.length ? percentLike[percentLike.length - 1].value : '';
}

function labelWindowValue(all, labelRegexes = [], options = {}) {
  const source = compactOcrText(all);
  const windowSize = options.windowSize || 96;
  for (const regex of labelRegexes) {
    const match = source.match(regex);
    if (!match) continue;
    const index = match.index || 0;
    const windowText = source.slice(index, index + windowSize);
    const percentMatch = windowText.match(/(\d{1,3}(?:\.\d{1,3})?)\s*(?:%|percent)\b/i);
    const percent = normalizePercent(percentMatch?.[1]);
    if (percent) return percent;
    const numberMatch = windowText.match(/\b(\d{1,3}(?:\.\d{1,3})?)\b/);
    const number = normalizePercent(numberMatch?.[1]);
    if (number) return number;
  }
  return '';
}

function percentNearLabel(all, labelPatterns, options = {}) {
  const source = normalizeOcrText(all);
  const lines = getCleanLines(source);
  const regexes = labelPatterns.map(pattern => typeof pattern === 'string' ? new RegExp(escapeRegex(pattern), 'i') : pattern);
  if (!regexes.some(regex => regex.test(source))) return '';

  for (const line of lines) {
    const value = linePercentValue(line, regexes);
    if (value) return value;
  }

  const compact = compactOcrText(source);
  const windowSize = options.windowSize || 90;
  for (const regex of regexes) {
    const label = regex.source;
    const forward = new RegExp(`(?:${label})[^0-9%]{0,${windowSize}}(\\d{1,3}(?:\\.\\d{1,3})?)\\s*(?:%|percent)?`, 'i');
    const forwardMatch = compact.match(forward);
    const forwardValue = normalizePercent(forwardMatch?.[1]);
    if (forwardValue) return forwardValue;

    const reverse = new RegExp(`(\\d{1,3}(?:\\.\\d{1,3})?)\\s*(?:%|percent)?[^A-Za-z0-9]{0,${windowSize}}(?:${label})`, 'i');
    const reverseMatch = compact.match(reverse);
    const reverseValue = normalizePercent(reverseMatch?.[1]);
    if (reverseValue) return reverseValue;
  }

  return labelWindowValue(compact, regexes, { windowSize });
}

function extractPercent(all, labels) {
  return percentNearLabel(all, labels.map(label => new RegExp(escapeRegex(label), 'i')));
}

function sumCannabinoids(values = []) {
  const total = values.reduce((sum, value) => sum + numberValue(value), 0);
  if (!total) return '';
  return total.toFixed(2).replace(/\.00$/, '').replace(/(\.\d)0$/, '$1');
}

function deriveTotalThc(profile = {}) {
  if (profile['Total THC']) return profile['Total THC'];
  const thca = numberValue(profile.THCA);
  const d9 = numberValue(profile['Δ9 THC'] || profile.THC);
  if (thca || d9) return normalizePercent((thca * 0.877 + d9).toFixed(2));
  return '';
}

function deriveTotalCbd(profile = {}) {
  if (profile['Total CBD']) return profile['Total CBD'];
  const cbda = numberValue(profile.CBDA);
  const cbd = numberValue(profile.CBD);
  if (cbda || cbd) return normalizePercent((cbda * 0.877 + cbd).toFixed(2));
  return '';
}

function extractCannabinoidProfile(all) {
  const normalized = normalizeOcrText(all);
  const profile = {};
  const patterns = [
    ['Total THC', [/total\s+(?:active\s+|potential\s+)?thc/i, /thc\s+total/i, /total\s+delta\s*9\s*thc/i]],
    ['Δ9 THC', [/(?:delta\s*9|d9|Δ9)[\s\-]*(?:thc|tetrahydrocannabinol)/i]],
    ['THCA', [/thc[\s\-]*a\b/i, /\bthca\b/i]],
    ['Total CBD', [/total\s+cbd/i, /cbd\s+total/i]],
    ['CBD', [/\bcbd\b(?!\s*a|\s*v)/i]],
    ['CBDA', [/cbd[\s\-]*a\b/i, /\bcbda\b/i]],
    ['CBG', [/\bcbg\b(?!\s*a)/i]],
    ['CBGA', [/\bcbga\b/i, /cbg[\s\-]*a\b/i]],
    ['CBN', [/\bcbn\b/i]],
    ['CBC', [/\bcbc\b/i]],
    ['Total Cannabinoids', [/total\s+cannabinoids?/i, /total\s+active\s+cannabinoids?/i, /total\s+cannabinoid\s+content/i, /tac\b/i]]
  ];
  for (const [name, regexes] of patterns) {
    const value = percentNearLabel(normalized, regexes, { windowSize: 110 });
    if (value) profile[name] = value;
  }
  if (!profile['Total THC']) {
    const derived = deriveTotalThc(profile);
    if (derived) profile['Total THC'] = derived;
  }
  if (!profile['Total CBD']) {
    const derived = deriveTotalCbd(profile);
    if (derived) profile['Total CBD'] = derived;
  }
  if (!profile['Total Cannabinoids']) {
    const sum = sumCannabinoids([profile['Total THC'], profile['Total CBD'], profile.CBG, profile.CBN, profile.CBC]);
    if (sum) profile['Total Cannabinoids'] = sum;
  }
  return profile;
}

const TERPENE_ALIASES = [
  ['Limonene', /limonene/i],
  ['Beta Caryophyllene', /(?:beta|b)?\s*[- ]?caryo(?:phyllene|phyl|phyt|phyl\w*)|caryo/i],
  ['Alpha Pinene', /(?:alpha|a)\s*[- ]?pinene/i],
  ['Beta Pinene', /(?:beta|b)\s*[- ]?pinene/i],
  ['Ocimene', /ocimene/i],
  ['Beta Myrcene', /(?:beta|b)\s*[- ]?myrcene|myrcene/i],
  ['Humulene', /humulene/i],
  ['Linalool', /linalool/i],
  ['Bisabolol', /bisabolol/i],
  ['Guaiol', /guaiol/i],
  ['Terpinolene', /terpinolene/i],
  ['Nerolidol', /nerolidol/i],
  ['Terpineol', /terpineol/i]
];

function extractTerpeneProfile(all) {
  const section = extractSection(all, /Terpene\s+Profile/i, [/Instructions\s+for\s+Use/i, /Marijuana\s+Product\s+Approval/i, /Warning/i]);
  const source = compactOcrText(section || all).replace(/Beta\s*Caryo\w*/gi, 'Beta Caryophyllene').replace(/Alpha\s*Pinene/gi, 'Alpha Pinene').replace(/Beta\s*Pinene/gi, 'Beta Pinene').replace(/Beta\s*Myrcene/gi, 'Beta Myrcene');
  const profile = {};
  for (const [name, regex] of TERPENE_ALIASES) {
    const match = source.match(new RegExp(`(?:${regex.source})\\s*[:#\\-]?\\s*(\\d{1,2}(?:\\.\\d{1,3})?)`, 'i'));
    const value = match?.[1] || '';
    if (value && Number(value) >= 0 && Number(value) < 100) profile[name] = value;
  }
  return profile;
}

function extractTerpenes(all) {
  const profile = extractTerpeneProfile(all);
  const withValues = Object.entries(profile)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([name, value]) => `${name} ${value} mg/serving`);
  if (withValues.length) return withValues.slice(0, 6).join(', ');

  const source = normalizeOcrText(all);
  const found = TERPENE_ALIASES
    .filter(([, regex]) => regex.test(source))
    .map(([name]) => name);
  return uniqueList(found).join(', ');
}

function extractInstructions(all) {
  const section = extractSection(all, /Instructions\s+for\s+Use/i, [/Marijuana\s+Product\s+Approval/i, /Warning/i]);
  return cleanLabelValue(section.replace(/^Instructions\s+for\s+Use\s+and\s+Length\s+of\s+Effect\s*:?/i, '')).slice(0, 400);
}

function extractLabelDetails(all) {
  const exactPotencyMg = extractExactPotency(all);
  const exactPotencyPercent = exactPotencyPercentProfile(exactPotencyMg);
  const hasExactPotency = Object.keys(exactPotencyPercent).length > 0;
  const cannabinoidProfile = { ...extractCannabinoidProfile(all), ...exactPotencyPercent };
  if (hasExactPotency) {
    if (!/total\s+cannabinoids?/i.test(all)) delete cannabinoidProfile['Total Cannabinoids'];
    if (exactPotencyPercent.THC) cannabinoidProfile['Total THC'] = exactPotencyPercent.THC;
    if (exactPotencyPercent.CBD) cannabinoidProfile['Total CBD'] = exactPotencyPercent.CBD;
  } else {
    if (!cannabinoidProfile['Total THC']) {
      const derived = deriveTotalThc(cannabinoidProfile);
      if (derived) cannabinoidProfile['Total THC'] = derived;
    }
    if (!cannabinoidProfile['Total CBD']) {
      const derived = deriveTotalCbd(cannabinoidProfile);
      if (derived) cannabinoidProfile['Total CBD'] = derived;
    }
  }
  const details = {
    cannabinoids: cannabinoidProfile,
    exactPotencyMg,
    exactPotencyPercent,
    terpeneProfile: extractTerpeneProfile(all),
    totalTerpenes: percentNearLabel(all, [/total\s+terpenes?/i, /terpenes?\s+total/i]),
    servingsPerPackage: extractWeightLike(all, ['Servings/Doses per package', 'Servings per package', 'Doses per package']),
    bestUsedBy: extractDateLike(all, ['Best if Used by Date', 'Best Used by Date', 'Best if used by', 'Use By', 'Best By']),
    producedBy: extractTagLike(all, ['Produced By', 'Producer', 'Cultivator', 'Cultivated By'], 70),
    testingLicense: extractTagLike(all, ['Testing License #', 'Testing License', 'Test License #', 'Test License'], 70),
    testingTag: extractTagLike(all, ['Testing Tag #', 'Testing Tag', 'Test Tag #', 'Test Tag'], 90),
    sourceTag: extractTagLike(all, ['Source Tag #', 'Source Tag'], 90),
    totalWeight: extractWeightLike(all, ['Total Weight', 'Net Weight', 'Net Wt', 'Net Wt.', 'Weight']),
    marijuanaApprovalNumber: extractTagLike(all, ['Marijuana Product Approval Number', 'Product Approval Number', 'Approval Number'], 90),
    packageDate: extractDateLike(all, ['Package Date', 'Packaged Date', 'Packaged', 'Pkg Date', 'Pkg']),
    harvestDate: extractDateLike(all, ['Harvest Date', 'Harvested', 'Harvest']),
    testDate: extractDateLike(all, ['Test Date', 'Tested Date', 'Tested']),
    expirationDate: extractDateLike(all, ['Expiration Date', 'Expire Date', 'Expires']),
    lab: extractDetailValue(all, ['Lab', 'Testing Lab', 'Tested by', 'Analysis by'], 70),
    license: extractDetailValue(all, ['License', 'License #', 'LIC', 'Facility License'], 70),
    instructions: extractInstructions(all)
  };
  return details;
}

function formatProfile(profile = {}, suffix = '%') {
  return Object.entries(profile || {})
    .filter(([, value]) => value !== '' && value !== null && value !== undefined)
    .map(([key, value]) => `${key}: ${value}${suffix}`)
    .join(', ');
}

function buildLabelNotes(draft, raw) {
  const details = draft.details || {};
  const lines = ['Auto-filled from label scanner. Review values against the physical label before relying on them.'];
  if (details.bestUsedBy) lines.push(`Best if used by: ${details.bestUsedBy}`);
  if (details.producedBy) lines.push(`Produced by: ${details.producedBy}`);
  if (details.testingLicense) lines.push(`Testing license #: ${details.testingLicense}`);
  if (details.testingTag) lines.push(`Testing tag #: ${details.testingTag}`);
  if (details.sourceTag) lines.push(`Source tag #: ${details.sourceTag}`);
  if (details.totalWeight) lines.push(`Total weight: ${details.totalWeight}`);
  if (details.servingsPerPackage) lines.push(`Servings/doses per package: ${details.servingsPerPackage}`);
  if (details.marijuanaApprovalNumber) lines.push(`Marijuana product approval #: ${details.marijuanaApprovalNumber}`);
  if (details.totalTerpenes) lines.push(`Total terpenes: ${details.totalTerpenes}%`);
  if (Object.keys(details.exactPotencyMg || {}).length) lines.push(`Exact potency mg/serving: ${formatProfile(details.exactPotencyMg, ' mg')}`);
  if (Object.keys(details.exactPotencyPercent || {}).length) lines.push(`Estimated potency percent: ${formatProfile(details.exactPotencyPercent, '%')}`);
  if (Object.keys(details.terpeneProfile || {}).length) lines.push(`Terpene profile mg/serving: ${formatProfile(details.terpeneProfile, ' mg')}`);
  if (details.packageDate) lines.push(`Packaged: ${details.packageDate}`);
  if (details.harvestDate) lines.push(`Harvested: ${details.harvestDate}`);
  if (details.testDate) lines.push(`Tested: ${details.testDate}`);
  if (details.expirationDate) lines.push(`Expires: ${details.expirationDate}`);
  if (details.lab) lines.push(`Testing lab: ${details.lab}`);
  if (details.license) lines.push(`License: ${details.license}`);
  if (details.instructions) lines.push(`Instructions: ${details.instructions}`);

  const cannabinoidLines = Object.entries(details.cannabinoids || {})
    .filter(([, value]) => value)
    .map(([key, value]) => `${key}: ${value}%`);
  if (cannabinoidLines.length) lines.push(`Cannabinoids: ${cannabinoidLines.join(', ')}`);

  const shortRaw = String(raw || '').replace(/\s{2,}/g, ' ').trim().slice(0, 900);
  if (shortRaw) lines.push(`OCR text: ${shortRaw}`);
  return lines.join('\n');
}

function scannerConfidence(draft) {
  let score = 0;
  if (draft.strainName) score += 18;
  if (draft.brand) score += 12;
  if (draft.thc) score += 18;
  if (draft.cbd) score += 10;
  if (draft.terpenes) score += 8;
  if (draft.details?.bestUsedBy) score += 6;
  if (draft.details?.producedBy) score += 6;
  if (draft.details?.testingLicense) score += 5;
  if (draft.details?.testingTag) score += 5;
  if (draft.details?.sourceTag) score += 5;
  if (draft.details?.totalWeight) score += 4;
  if (Object.keys(draft.details?.exactPotencyMg || {}).length >= 2) score += 8;
  if (Object.keys(draft.details?.terpeneProfile || {}).length >= 2) score += 8;
  return Math.min(100, score);
}

function parseLabelText(text) {
  const raw = String(text || '').trim();
  const all = normalizeOcrText(raw);
  const details = extractLabelDetails(all);
  const cannabinoids = details.cannabinoids || {};
  const thc = details.exactPotencyPercent?.THC || cannabinoids['Total THC'] || deriveTotalThc(cannabinoids) || percentNearLabel(all, [/total\s+(?:active\s+|potential\s+)?thc/i, /thc\s+total/i, /\bthc\b(?!\s*a)/i]) || '';
  const cbd = details.exactPotencyPercent?.CBD || cannabinoids['Total CBD'] || deriveTotalCbd(cannabinoids) || percentNearLabel(all, [/total\s+cbd/i, /cbd\s+total/i, /\bcbd\b(?!\s*a)/i]) || '';
  const draft = {
    strainName: cleanLabelValue(extractStrainName(all)).slice(0, 60),
    brand: cleanLabelValue(extractBrand(all, details)).slice(0, 70),
    type: detectProductType(all),
    thc,
    cbd,
    terpenes: extractTerpenes(all),
    details
  };
  draft.notes = buildLabelNotes(draft, raw);
  draft.confidence = scannerConfidence(draft);
  return draft;
}

function scoreOcrText(text = '') {
  const value = normalizeOcrText(text);
  const draft = value ? parseLabelText(value) : {};
  let score = Math.min(20, Math.floor(value.length / 35));
  if (draft.strainName) score += 18;
  if (draft.brand || matchKnownBrand(value)) score += 14;
  if (draft.thc || /\bTHCA\b|Total THC|Exact Potency/i.test(value)) score += 20;
  if (draft.cbd || /\bCBDA\b|Total CBD|Exact Potency/i.test(value)) score += 10;
  if (/\d+(?:\.\d+)?\s*%/.test(value) || /mg\s*\/\s*serv/i.test(value)) score += 12;
  if (/Best if|Produced By|Testing License|Testing Tag|Source Tag|Total Weight/i.test(value)) score += 18;
  if (/Terpene|Myrcene|Limonene|Pinene|Linalool|Caryophyllene/i.test(value)) score += 8;
  if (/Flower|Cartridge|Pre[- ]?roll|Concentrate|Edible/i.test(value)) score += 6;
  return Math.min(100, score);
}

function combineOcrTexts(texts = []) {
  const seen = new Set();
  const lines = [];
  for (const text of texts) {
    for (const line of getCleanLines(text)) {
      const key = normalizeName(line.replace(/[^A-Za-z0-9.%]+/g, ' '));
      if (!key || seen.has(key)) continue;
      seen.add(key);
      lines.push(line);
    }
  }
  return lines.join('\n').trim();
}


function loadImageElement(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = src;
  });
}

function makeCanvas(width, height) {
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(width));
  canvas.height = Math.max(1, Math.round(height));
  return canvas;
}

function findBrightLabelBox(canvas) {
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const { width, height } = canvas;
  const step = Math.max(2, Math.floor(Math.min(width, height) / 260));
  const data = ctx.getImageData(0, 0, width, height).data;
  let minX = width, minY = height, maxX = 0, maxY = 0, count = 0;
  for (let y = 0; y < height; y += step) {
    for (let x = 0; x < width; x += step) {
      const idx = (y * width + x) * 4;
      const r = data[idx], g = data[idx + 1], b = data[idx + 2];
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      const bright = (r + g + b) / 3;
      const lowSaturation = max - min < 55;
      if (bright > 145 && lowSaturation) {
        minX = Math.min(minX, x); minY = Math.min(minY, y);
        maxX = Math.max(maxX, x); maxY = Math.max(maxY, y);
        count++;
      }
    }
  }
  const boxW = maxX - minX;
  const boxH = maxY - minY;
  const minHits = Math.max(30, (width * height) / (step * step) * 0.01);
  if (count < minHits || boxW < width * 0.12 || boxH < height * 0.08) {
    return { x: 0, y: 0, w: width, h: height };
  }
  const padX = boxW * 0.12;
  const padY = boxH * 0.2;
  return {
    x: Math.max(0, minX - padX),
    y: Math.max(0, minY - padY),
    w: Math.min(width - Math.max(0, minX - padX), boxW + padX * 2),
    h: Math.min(height - Math.max(0, minY - padY), boxH + padY * 2)
  };
}

function cloneCanvasWithFilter(source, mode = 'contrast') {
  const canvas = makeCanvas(source.width, source.height);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, 0, 0);
  const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const data = image.data;
  for (let i = 0; i < data.length; i += 4) {
    const gray = data[i] * 0.299 + data[i + 1] * 0.587 + data[i + 2] * 0.114;
    let value = gray;
    if (mode === 'contrast') value = Math.max(0, Math.min(255, (gray - 128) * 1.9 + 128));
    if (mode === 'binary') value = gray > 150 ? 255 : 0;
    if (mode === 'soft') value = Math.max(0, Math.min(255, (gray - 128) * 1.35 + 136));
    if (mode === 'invert') value = 255 - Math.max(0, Math.min(255, (gray - 128) * 1.8 + 128));
    data[i] = data[i + 1] = data[i + 2] = value;
  }
  ctx.putImageData(image, 0, 0);
  return canvas;
}

function cropCanvas(source, box) {
  const crop = makeCanvas(box.w, box.h);
  crop.getContext('2d').drawImage(source, box.x, box.y, box.w, box.h, 0, 0, crop.width, crop.height);
  return crop;
}

function upscaleCanvas(source, targetMax = 1900) {
  const scale = Math.max(1.2, Math.min(3.4, targetMax / Math.max(source.width, source.height)));
  const canvas = makeCanvas(source.width * scale, source.height * scale);
  const ctx = canvas.getContext('2d');
  ctx.imageSmoothingEnabled = true;
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  return canvas;
}

async function createOcrVariants(dataUrl) {
  const img = await loadImageElement(dataUrl);
  const maxBase = 2400;
  const scale = Math.min(maxBase / Math.max(img.naturalWidth || img.width, img.naturalHeight || img.height), 2.2);
  const base = makeCanvas((img.naturalWidth || img.width) * scale, (img.naturalHeight || img.height) * scale);
  const baseCtx = base.getContext('2d');
  baseCtx.imageSmoothingEnabled = true;
  baseCtx.drawImage(img, 0, 0, base.width, base.height);

  const box = findBrightLabelBox(base);
  const labelCrop = cropCanvas(base, box);
  const labelUpscale = upscaleCanvas(labelCrop, 2400);
  const band = (name, yRatio, hRatio, filter = 'contrast') => {
    const bandBox = {
      x: Math.max(0, Math.round(labelCrop.width * 0.01)),
      y: Math.max(0, Math.round(labelCrop.height * yRatio)),
      w: Math.max(1, Math.round(labelCrop.width * 0.98)),
      h: Math.max(1, Math.round(labelCrop.height * hRatio))
    };
    return { name, canvas: cloneCanvasWithFilter(upscaleCanvas(cropCanvas(labelCrop, bandBox), 3000), filter) };
  };
  const headerBand = band('label header and dates', 0.00, 0.25, 'binary');
  const potencyBand = band('exact potency table', 0.23, 0.22, 'binary');
  const terpeneBand = band('terpene profile table', 0.37, 0.28, 'binary');
  const approvalBand = band('approval number and strain name', 0.66, 0.22, 'contrast');

  // Brand logos often sit above the white test label, so also scan a taller package crop.
  const logoPad = Math.max(labelCrop.height * 1.15, base.height * 0.18);
  const packageBox = {
    x: Math.max(0, box.x - box.w * 0.22),
    y: Math.max(0, box.y - logoPad),
    w: Math.min(base.width - Math.max(0, box.x - box.w * 0.22), box.w * 1.44),
    h: Math.min(base.height - Math.max(0, box.y - logoPad), box.h + logoPad * 1.15)
  };
  const packageCrop = upscaleCanvas(cropCanvas(base, packageBox), 2200);

  const topBox = {
    x: 0,
    y: 0,
    w: base.width,
    h: Math.max(1, Math.round(base.height * 0.42))
  };
  const topCrop = upscaleCanvas(cropCanvas(base, topBox), 2200);

  const variants = [
    headerBand,
    potencyBand,
    terpeneBand,
    approvalBand,
    { name: 'white test label crop', canvas: cloneCanvasWithFilter(labelUpscale, 'contrast') },
    { name: 'high-contrast full label', canvas: cloneCanvasWithFilter(labelUpscale, 'binary') },
    { name: 'package + logo area', canvas: cloneCanvasWithFilter(packageCrop, 'soft') },
    { name: 'full photo', canvas: cloneCanvasWithFilter(upscaleCanvas(base, 2200), 'soft') },
    { name: 'top brand area', canvas: cloneCanvasWithFilter(topCrop, 'contrast') },
    { name: 'inverted label fallback', canvas: cloneCanvasWithFilter(labelUpscale, 'invert') }
  ];

  const seen = new Set();
  return variants
    .map(item => ({ name: item.name, src: item.canvas.toDataURL('image/png') }))
    .filter(item => {
      const key = item.src.slice(0, 120);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function scanDraftFromForm(form) {
  const data = new FormData(form);
  let details = null;
  try {
    details = data.get('labelDetailsJson') ? JSON.parse(String(data.get('labelDetailsJson'))) : null;
  } catch (error) {
    details = null;
  }
  return {
    strainName: String(data.get('strainName') || '').trim(),
    brand: String(data.get('brand') || '').trim(),
    type: String(data.get('type') || 'Flower'),
    thc: data.get('thc') ? formatCannabinoidPercent(data.get('thc')) : '',
    cbd: data.get('cbd') ? formatCannabinoidPercent(data.get('cbd')) : '',
    terpenes: String(data.get('terpenes') || '').trim(),
    notes: String(data.get('notes') || '').trim(),
    labelPhoto: lastScanImage,
    details
  };
}


function renderScannerDetailGrid(draft = {}) {
  const details = draft.details || {};
  const exactMg = formatProfile(details.exactPotencyMg || {}, ' mg');
  const exactPercent = formatProfile(details.exactPotencyPercent || {}, '%');
  const terpeneProfile = formatProfile(details.terpeneProfile || {}, ' mg');
  const values = [
    ['Confidence', `${draft.confidence || 0}%`],
    ['Strain name', draft.strainName || 'Needs review'],
    ['Brand/grower', draft.brand || 'Needs review'],
    ['Product type', draft.type || '—'],
    ['THC %', draft.thc ? `${draft.thc}%` : 'Needs review'],
    ['CBD %', draft.cbd ? `${draft.cbd}%` : 'Needs review'],
    ['Best if used by', details.bestUsedBy || '—'],
    ['Produced by', details.producedBy || '—'],
    ['Testing license #', details.testingLicense || '—'],
    ['Testing tag #', details.testingTag || '—'],
    ['Source tag #', details.sourceTag || '—'],
    ['Total weight', details.totalWeight || '—'],
    ['Servings/doses', details.servingsPerPackage || '—'],
    ['Approval #', details.marijuanaApprovalNumber || '—'],
    ['Exact potency', exactMg || '—'],
    ['Estimated potency %', exactPercent || '—'],
    ['Terpene profile', terpeneProfile || draft.terpenes || '—']
  ];
  return `<div class="scanner-detail-grid rich">${values.map(([label, value]) => `
    <div class="scanner-detail">
      <small>${escapeHtml(label)}</small>
      <strong>${escapeHtml(value)}</strong>
    </div>`).join('')}</div>`;
}

function renderScanDraft(draft) {
  $('#scanDraft').classList.remove('hidden');
  const quality = draft.confidence >= 80 ? 'strong capture' : draft.confidence >= 55 ? 'review needed' : 'low confidence';
  $('#scanDraft').innerHTML = `
    <p class="eyebrow">scanner draft · ${escapeHtml(quality)}</p>
    <h3>${escapeHtml(draft.strainName || 'Review detected label')}</h3>
    <p class="muted">StrainVault auto-filled the fields it could read. Cannabis labels vary a lot, so compare the name, THC/CBD, exact potency, dates, tags, and license numbers against the package before saving.</p>
    ${renderScannerDetailGrid(draft)}
    <form id="scanDraftForm" class="flow-form">
      <textarea name="labelDetailsJson" hidden>${escapeHtml(JSON.stringify(draft.details || {}))}</textarea>
      <div class="form-grid">
        <label>Strain name<input name="strainName" value="${escapeHtml(draft.strainName || '')}" required placeholder="Type strain name if missed" /></label>
        <label>Brand / grower<input name="brand" value="${escapeHtml(draft.brand || '')}" placeholder="Brand may need manual review if it is only a logo" /></label>
        <label>Product type<select name="type">${['Flower','Cart','Edible','Concentrate','Pre-roll','Tincture'].map(type => `<option ${type === draft.type ? 'selected' : ''}>${type}</option>`).join('')}</select></label>
        <label>THC %<input name="thc" type="number" step="0.1" value="${escapeHtml(draft.thc || '')}" placeholder="Total THC" /></label>
        <label>CBD %<input name="cbd" type="number" step="0.1" value="${escapeHtml(draft.cbd || '')}" placeholder="Total CBD" /></label>
        <label>Top terpenes<input name="terpenes" value="${escapeHtml(draft.terpenes || '')}" placeholder="Myrcene, Limonene" /></label>
      </div>
      <label>Captured label details<textarea name="notes" placeholder="Batch, cannabinoid table, package details...">${escapeHtml(draft.notes || '')}</textarea></label>
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
    labelPhoto: draft.labelPhoto,
    labelDetails: draft.details || null
  };
  const saved = upsertStrainFromSession(sessionLike);
  saved.notes = draft.notes || saved.notes || '';
  saved.labelDetails = draft.details || saved.labelDetails || null;
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
  lastScanImage = await readOptionalImageFile(file, 'Label photo', 1600, .86);
  if (!lastScanImage) return;
  $('#scanPreview').src = lastScanImage;
  $('#scanPreview').classList.remove('hidden');
  const draft = $('#scanDraft');
  if (draft) {
    draft.classList.add('hidden');
    draft.innerHTML = '';
  }
  setScanButtonsEnabled(true);
  setOcrStatus('Photo attached. Tap Read label photo, or paste text copied with iPhone Live Text.');
  toast('Photo attached. Tap Read label photo to fill bud info.');
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
  pendingStrainLabelDetails = null;
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
  $('#readLabelPhotoBtn').addEventListener('click', runOcrOnScanImage);
  $('#clearScanBtn').addEventListener('click', resetScanner);
  $('#parseLabelBtn').addEventListener('click', () => {
    const text = $('#labelText').value.trim();
    if (!text) {
      toast('Paste label text or tap Read label photo first.');
      setOcrStatus(lastScanImage ? 'Tap Read label photo, or paste copied label text.' : 'Upload a label photo or paste label text first.');
      return;
    }
    const draft = parseLabelText(text);
    renderScanDraft(draft);
    setOcrStatus(draft.strainName ? 'Draft created. Review before saving.' : 'Draft created, but strain name needs review.');
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
