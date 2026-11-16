/* St George's encrypted collections client. Report content is encrypted in the
   browser before it is sent to Supabase; the admin decryption key stays local. */
const $ = id => document.getElementById(id);
const toastEl = $('toast');
let projectConfig = null, authSession = null, currentUser = null, currentRole = null;
let keyBundle = null, publicKey = null, privateKey = null, allReports = [], shownRows = [], adminLockTimer = null;
const configKey = 'st-georges-supabase-public-config-v1';
const defaultConfig = {
  url: 'https://vgfmzydepdszahrgcdvh.supabase.co',
  key: 'sb_publishable_ob6d4-U3PhRmXRtb8b7o0g_uxfFusKH',
};
const encoder = new TextEncoder();

function toast(message) { toastEl.textContent = message; toastEl.classList.add('show'); setTimeout(() => toastEl.classList.remove('show'), 2600); }
function b64(buffer) { const bytes = new Uint8Array(buffer); let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary); }
function unb64(value) { const binary = atob(value); return Uint8Array.from(binary, ch => ch.charCodeAt(0)); }
function hex(buffer) { return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join(''); }
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function rupees(value) { return '₹' + Number(value || 0).toLocaleString('en-IN', { maximumFractionDigits: 2 }); }
function dateLocal() { const d = new Date(); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10); }

function showGate(mode, message = '') {
  $('gate').hidden = false;
  $('configForm').classList.toggle('hidden', mode !== 'config');
  $('loginForm').classList.toggle('hidden', mode !== 'login');
  $('cryptoForm').classList.toggle('hidden', !mode.startsWith('crypto'));
  $('gateTitle').textContent = mode === 'config' ? 'Connect your database' : mode === 'login' ? 'Sign in to St George’s' : mode === 'cryptoCreate' ? 'Set your private-key password' : 'Unlock encrypted reports';
  $('gateDesc').textContent = mode === 'config' ? 'Enter the public connection details from your Supabase project.' : mode === 'login' ? 'Sign in with the account created for you by the administrator.' : mode === 'cryptoCreate' ? 'Choose a private password for the encryption key. Drivers will not need to know it.' : 'Enter the private-key password to decrypt the bus reports on this device.';
  $('gateHelp').textContent = mode === 'config' ? 'Use only the project URL and publishable key. Never enter a Supabase secret or service-role key here.' : mode === 'login' ? 'Your account role controls whether you can submit encrypted reports or view the admin ledger.' : mode === 'cryptoCreate' ? 'Use at least 12 characters. This password encrypts the only private key that can read reports. If it is lost, reports cannot be recovered.' : 'The private key is decrypted only in this browser session. The database never receives this password.';
  $('cryptoConfirmWrap').classList.toggle('hidden', mode !== 'cryptoCreate');
  $('cryptoSubmit').textContent = mode === 'cryptoCreate' ? 'Create encryption key' : 'Unlock reports';
  $('cryptoError').textContent = message;
  if (mode === 'login' && message) $('loginError').textContent = message;
}

async function connect(config) {
  if (!window.isSecureContext || !crypto?.subtle) throw new Error('Secure browser cryptography requires HTTPS (or a local secure browser context).');
  projectConfig = config;
  authSession = null; currentUser = null;
  showGate('login');
}

async function authRequest(path, body, bearer = null) {
  const headers = { apikey: projectConfig.key, 'Content-Type': 'application/json' };
  if (bearer) headers.Authorization = 'Bearer ' + bearer;
  const response = await fetch(projectConfig.url + path, { method: 'POST', headers, body: JSON.stringify(body) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(result.msg || result.message || result.error_description || result.error || 'Authentication request failed.'), { code: result.code });
  return result;
}

async function refreshAuthIfNeeded() {
  if (!authSession) throw new Error('Your sign-in session ended. Sign in again.');
  if (authSession.expires_at > Date.now() / 1000 + 60) return;
  const refreshed = await authRequest('/auth/v1/token?grant_type=refresh_token', { refresh_token: authSession.refresh_token });
  authSession = { ...refreshed, expires_at: Date.now() / 1000 + refreshed.expires_in };
  currentUser = refreshed.user || currentUser;
}

async function tableRequest(table, method, query = '', body = null, prefer = '') {
  await refreshAuthIfNeeded();
  const headers = { apikey: projectConfig.key, Authorization: 'Bearer ' + authSession.access_token };
  if (body !== null) headers['Content-Type'] = 'application/json';
  if (prefer) headers.Prefer = prefer;
  const response = await fetch(projectConfig.url + '/rest/v1/' + table + query, { method, headers, body: body === null ? undefined : JSON.stringify(body) });
  if (response.status === 204) return null;
  const text = await response.text(); let result = null;
  try { result = text ? JSON.parse(text) : null; } catch { result = text; }
  if (!response.ok) throw Object.assign(new Error(result?.message || result?.hint || String(result || 'Database request failed.')), { code: result?.code });
  return result;
}

$('configForm').addEventListener('submit', async event => {
  event.preventDefault(); $('configError').textContent = '';
  const config = { url: $('projectUrl').value.trim().replace(/\/$/, ''), key: $('publishableKey').value.trim() };
  try { await connect(config); localStorage.setItem(configKey, JSON.stringify(config)); }
  catch (error) { $('configError').textContent = error.message || 'Could not connect. Check the URL and key.'; }
});

$('loginForm').addEventListener('submit', async event => {
  event.preventDefault(); $('loginError').textContent = '';
  let data;
  try { data = await authRequest('/auth/v1/token?grant_type=password', { email: $('email').value.trim(), password: $('password').value }); }
  catch (error) { $('password').value = ''; $('loginError').textContent = error.message; return; }
  $('password').value = '';
  authSession = { ...data, expires_at: Date.now() / 1000 + data.expires_in };
  currentUser = data.user; await enterApp();
});

async function enterApp() {
  $('identity').textContent = currentUser.email || '';
  $('lock').hidden = false;
  let roles;
  try { roles = await tableRequest('user_roles', 'GET', '?select=role&user_id=eq.' + encodeURIComponent(currentUser.id) + '&limit=1'); }
  catch { showGate('login'); $('loginError').textContent = 'Could not read your account role. Check the database setup.'; return; }
  const data = roles?.[0];
  currentRole = data?.role;
  if (!['admin', 'driver'].includes(currentRole)) {
    currentUser = null; authSession = null; showGate('login'); $('loginError').textContent = 'This account has no assigned role yet. Ask the admin to enable it.'; return;
  }
  if (currentRole === 'admin') { await prepareAdminKey(); return; }
  try { await loadPublicKey(); }
  catch (error) { showGate('login', error.message); return; }
  $('gate').hidden = true; $('welcome').textContent = 'Submit bus collections';
  $('subtitle').textContent = 'Your report is encrypted on this device before it is saved.';
  $('adminView').classList.add('hidden'); $('driverView').classList.remove('hidden'); $('refresh').hidden = true;
  $('serviceDate').value = dateLocal();
}

async function prepareAdminKey() {
  try { keyBundle = (await tableRequest('admin_key_bundle', 'GET', '?select=*&id=eq.1&limit=1'))?.[0] || null; }
  catch { showGate('login'); $('loginError').textContent = 'Could not load the encryption key record. Check the SQL setup.'; return; }
  if (!keyBundle) showGate('cryptoCreate');
  else if (keyBundle.owner_id !== currentUser.id) showGate('login', 'The encryption key belongs to a different admin account.');
  else showGate('cryptoUnlock');
}

async function derivePasswordKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function fingerprint(publicKeyBytes) {
  const digest = hex(await crypto.subtle.digest('SHA-256', publicKeyBytes));
  return digest.match(/.{1,4}/g).join(' ');
}

async function createAdminKey(password) {
  $('cryptoError').textContent = 'Creating your encryption key… keep this page open.';
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const publicBytes = await crypto.subtle.exportKey('spki', pair.publicKey);
  const privateBytes = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await derivePasswordKey(password, salt);
  const encryptedPrivate = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, privateBytes);
  const bundle = { id: 1, owner_id: currentUser.id, public_key: b64(publicBytes), encrypted_private_key: b64(encryptedPrivate), key_iv: b64(iv), key_salt: b64(salt) };
  await tableRequest('admin_key_bundle', 'POST', '?on_conflict=id', bundle, 'resolution=merge-duplicates,return=minimal');
  keyBundle = bundle; publicKey = pair.publicKey; privateKey = pair.privateKey;
}

async function unlockAdminKey(password) {
  const wrappingKey = await derivePasswordKey(password, unb64(keyBundle.key_salt));
  const privateBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(keyBundle.key_iv) }, wrappingKey, unb64(keyBundle.encrypted_private_key));
  privateKey = await crypto.subtle.importKey('pkcs8', privateBytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  publicKey = await crypto.subtle.importKey('spki', unb64(keyBundle.public_key), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

$('cryptoForm').addEventListener('submit', async event => {
  event.preventDefault(); $('cryptoError').textContent = '';
  const password = $('cryptoPassword').value;
  if (password.length < 12) { $('cryptoError').textContent = 'Use at least 12 characters.'; return; }
  if (!keyBundle && password !== $('cryptoConfirm').value) { $('cryptoError').textContent = 'The passwords do not match.'; return; }
  try {
    if (!keyBundle) { await createAdminKey(password); toast('Encryption key created. Download and keep the key backup safe.'); }
    else await unlockAdminKey(password);
    $('cryptoPassword').value = ''; $('cryptoConfirm').value = ''; await finishAdminLogin();
  } catch (error) { privateKey = null; $('cryptoError').textContent = keyBundle ? 'Could not unlock this key. Check the private-key password.' : (error.message || 'Could not create the encryption key.'); }
});

async function loadPublicKey() {
  const data = (await tableRequest('admin_key_bundle', 'GET', '?select=public_key&id=eq.1&limit=1'))?.[0];
  if (!data) throw new Error('The admin has not created the encryption key yet. Ask the admin to sign in first.');
  keyBundle = data;
  publicKey = await crypto.subtle.importKey('spki', unb64(data.public_key), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  $('driverFingerprint').textContent = await fingerprint(unb64(data.public_key));
}

async function finishAdminLogin() {
  $('gate').hidden = true; $('welcome').textContent = 'Admin collections';
  $('subtitle').textContent = 'Decrypted in this browser · ciphertext stored in your account. Share key fingerprint with drivers: ' + await fingerprint(unb64(keyBundle.public_key));
  $('adminView').classList.remove('hidden'); $('driverView').classList.add('hidden'); $('refresh').hidden = false; $('backupKey').hidden = false;
  const today = dateLocal(); $('adminDate').value = today;
  await loadRecords(); loadBuses(); resetAdminLockTimer();
}

function lockAdminData() {
  if (currentRole !== 'admin' || !privateKey) return;
  clearTimeout(adminLockTimer); privateKey = null; publicKey = null; allReports = []; shownRows = [];
  $('adminView').classList.add('hidden'); $('backupKey').hidden = true; showGate('cryptoUnlock');
  toast('Encrypted reports locked');
}
function resetAdminLockTimer() {
  if (currentRole !== 'admin' || !privateKey) return;
  clearTimeout(adminLockTimer); adminLockTimer = setTimeout(lockAdminData, 5 * 60 * 1000);
}
['pointerdown','keydown','touchstart'].forEach(name => document.addEventListener(name, resetAdminLockTimer, { passive: true }));
document.addEventListener('visibilitychange', () => { if (document.hidden) lockAdminData(); });

async function encryptReport(report) {
  if (!publicKey) await loadPublicKey();
  const dataKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, dataKey, encoder.encode(JSON.stringify(report)));
  const rawKey = await crypto.subtle.exportKey('raw', dataKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawKey);
  return { ciphertext: b64(ciphertext), nonce: b64(nonce), wrapped_key: b64(wrappedKey) };
}

async function decryptReport(record) {
  const rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64(record.wrapped_key));
  const dataKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(record.nonce) }, dataKey, unb64(record.ciphertext));
  return { ...JSON.parse(new TextDecoder().decode(plaintext)), id: record.id, submitted_by: record.submitted_by, created_at: record.created_at };
}

async function loadRecords() {
  const records = []; let offset = 0;
  while (true) {
    let data;
    try { data = await tableRequest('encrypted_daily_reports', 'GET', '?select=id,ciphertext,nonce,wrapped_key,submitted_by,created_at&order=created_at.desc&limit=500&offset=' + offset); }
    catch (error) { $('records').innerHTML = '<tr><td colspan="7" class="empty">Unable to load encrypted reports: ' + escapeHtml(error.message) + '</td></tr>'; return; }
    records.push(...(data || [])); if (!data || data.length < 500) break; offset += 500;
  }
  try { allReports = await Promise.all(records.map(decryptReport)); }
  catch { $('records').innerHTML = '<tr><td colspan="7" class="empty">A report could not be decrypted. Check the private-key password and backup.</td></tr>'; return; }
  renderRecords($('adminDate').value);
}

function expenseBreakdownOf(report) { return report.expense_breakdown || { bata: 0, diesel: 0, toll: 0, cleaning: 0, chitty: 0, gap: 0, office: 0, balance: 0 }; }
function expenseCell(report) {
  if (!report.expense_breakdown) return '<td class="money negative"><small class="expense-lines">Breakdown not recorded</small><br><b>Total ' + rupees(report.expense_amount) + '</b></td>';
  const e = expenseBreakdownOf(report);
  return '<td class="money negative"><small class="expense-lines">Bata ' + rupees(e.bata) + ' | Diesel ' + rupees(e.diesel) + ' | Toll ' + rupees(e.toll) + ' | Cleaning ' + rupees(e.cleaning) + '<br>Chitty ' + rupees(e.chitty) + ' | Gap ' + rupees(e.gap) + ' | Office ' + rupees(e.office) + ' | BALANCE ' + rupees(e.balance) + '</small><br><b>Total ' + rupees(report.expense_amount) + '</b></td>';
}

function renderRecords(date) {
  shownRows = allReports.filter(r => r.service_date === date);
  const sumC = shownRows.reduce((a, r) => a + Number(r.collection_amount), 0), sumE = shownRows.reduce((a, r) => a + Number(r.expense_amount), 0);
  $('sumCollections').textContent = rupees(sumC); $('sumExpenses').textContent = rupees(sumE); $('sumNet').textContent = rupees(sumC - sumE); $('sumCount').textContent = shownRows.length; $('sumFleetNet').textContent = rupees(allReports.reduce((sum, r) => sum + Number(r.collection_amount) - Number(r.expense_amount), 0));
  $('records').innerHTML = shownRows.length ? shownRows.map(r => `<tr><td>${escapeHtml(r.service_date)}</td><td><b>${escapeHtml(r.bus_number)}</b><br><small>${escapeHtml(r.route)}</small></td><td>${escapeHtml(r.driver_name)}</td><td class="money positive">${rupees(r.collection_amount)}</td>${expenseCell(r)}<td class="money positive">${rupees(Number(r.collection_amount) - Number(r.expense_amount))}</td><td><button class="details-btn" data-bus="${escapeHtml(r.bus_number)}">Daily details</button></td></tr>`).join('') : '<tr><td colspan="7" class="empty">No bus reports for this date yet.</td></tr>';
}

function loadBuses() {
  const newestFirst = [...allReports].sort((a, b) => b.service_date.localeCompare(a.service_date));
  const map = new Map(); for (const record of newestFirst) if (!map.has(record.bus_number)) map.set(record.bus_number, record);
  const buses = [...map.values()];
  $('busDirectory').innerHTML = buses.length ? buses.map(r => { const net = allReports.filter(x => x.bus_number === r.bus_number).reduce((sum, x) => sum + Number(x.collection_amount) - Number(x.expense_amount), 0); return `<tr><td><b>${escapeHtml(r.bus_number)}</b></td><td>${escapeHtml(r.route)}</td><td>${escapeHtml(r.service_date)}</td><td>${escapeHtml(r.driver_name)}</td><td class="money ${net >= 0 ? 'positive' : 'negative'}">${rupees(net)}</td><td><button class="details-btn" data-bus="${escapeHtml(r.bus_number)}">Open dashboard</button></td></tr>`; }).join('') : '<tr><td colspan="6" class="directory-empty">No buses have submitted a report yet.</td></tr>';
}

function openBusDetails(bus) {
  const rows = allReports.filter(r => r.bus_number === bus).sort((a, b) => b.service_date.localeCompare(a.service_date));
  const totalC = rows.reduce((s, r) => s + Number(r.collection_amount), 0), totalE = rows.reduce((s, r) => s + Number(r.expense_amount), 0);
  const expenseTotals = rows.reduce((sum, r) => { const e = expenseBreakdownOf(r); sum.bata += Number(e.bata || 0); sum.diesel += Number(e.diesel || 0); sum.toll += Number(e.toll || 0); sum.cleaning += Number(e.cleaning || 0); sum.chitty += Number(e.chitty || 0); sum.gap += Number(e.gap || 0); sum.office += Number(e.office || 0); sum.balance += Number(e.balance || 0); return sum; }, { bata: 0, diesel: 0, toll: 0, cleaning: 0, chitty: 0, gap: 0, office: 0, balance: 0 });
  const breakdownSummary = 'Bata ' + rupees(expenseTotals.bata) + ' · Diesel ' + rupees(expenseTotals.diesel) + ' · Toll ' + rupees(expenseTotals.toll) + ' · Cleaning ' + rupees(expenseTotals.cleaning) + ' · Chitty ' + rupees(expenseTotals.chitty) + ' · Gap ' + rupees(expenseTotals.gap) + ' · Office ' + rupees(expenseTotals.office) + ' · BALANCE ' + rupees(expenseTotals.balance);
  const historyRows = rows.length ? rows.map(r => '<tr><td>' + escapeHtml(r.service_date) + '</td><td>' + escapeHtml(r.route) + '</td><td>' + escapeHtml(r.driver_name) + '</td><td class="money positive">' + rupees(r.collection_amount) + '</td>' + expenseCell(r) + '<td class="money positive">' + rupees(Number(r.collection_amount) - Number(r.expense_amount)) + '</td></tr>').join('') : '<tr><td colspan="6" class="empty">No reports for this bus yet.</td></tr>';
  $('busDetails').hidden = false; $('busDetailTitle').textContent = 'Bus ' + bus + ' · daily dashboard'; $('busDetailSubtitle').textContent = rows.length + ' daily reports · all recorded dates';
  $('busDetailBody').innerHTML = '<div class="detail-stats"><div class="detail-stat"><small>All-time collections</small><b>' + rupees(totalC) + '</b></div><div class="detail-stat"><small>All-time expenses</small><b>' + rupees(totalE) + '</b><small class="expense-lines">' + breakdownSummary + '</small></div><div class="detail-stat"><small>All-time net</small><b>' + rupees(totalC - totalE) + '</b></div></div><div class="tablewrap"><table class="table"><thead><tr><th>Service date</th><th>Route</th><th>Driver</th><th>Collections</th><th>Expenses by category · total</th><th>Net</th></tr></thead><tbody>' + historyRows + '</tbody></table></div>';
  $('busDetails').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
$('records').addEventListener('click', event => { const button = event.target.closest('[data-bus]'); if (button) openBusDetails(button.dataset.bus); });
$('busDirectory').addEventListener('click', event => { const button = event.target.closest('[data-bus]'); if (button) openBusDetails(button.dataset.bus); });
$('closeBusDetails').addEventListener('click', () => $('busDetails').hidden = true);
$('adminDate').addEventListener('change', () => renderRecords($('adminDate').value));
$('refresh').addEventListener('click', async () => { await loadRecords(); loadBuses(); });

for (const id of ['expenseBata', 'expenseDiesel', 'expenseToll', 'expenseCleaning', 'expenseChitty', 'expenseGap', 'expenseOffice', 'expenseBalance']) $(id).addEventListener('input', updateExpenseTotal);
function updateExpenseTotal() {
  const total = ['expenseBata', 'expenseDiesel', 'expenseToll', 'expenseCleaning', 'expenseChitty', 'expenseGap', 'expenseOffice', 'expenseBalance'].reduce((sum, id) => sum + Number($(id).value || 0), 0);
  $('expenseTotal').textContent = rupees(total);
}

$('reportForm').addEventListener('submit', async event => {
  event.preventDefault(); $('submitError').textContent = '';
  const expense_breakdown = { bata: Number($('expenseBata').value || 0), diesel: Number($('expenseDiesel').value || 0), toll: Number($('expenseToll').value || 0), cleaning: Number($('expenseCleaning').value || 0), chitty: Number($('expenseChitty').value || 0), gap: Number($('expenseGap').value || 0), office: Number($('expenseOffice').value || 0), balance: Number($('expenseBalance').value || 0) };
  const expense_amount = Object.values(expense_breakdown).reduce((sum, amount) => sum + amount, 0);
  const report = { service_date: $('serviceDate').value, bus_number: $('busNumber').value.trim(), route: $('routeName').value.trim(), driver_name: $('driverName').value.trim(), collection_amount: Number($('collectionAmount').value), expense_breakdown, expense_amount };
  try {
    const encrypted = await encryptReport(report);
    await tableRequest('encrypted_daily_reports', 'POST', '', encrypted, 'return=minimal');
    toast('Encrypted report saved to St George’s'); $('reportForm').reset(); $('serviceDate').value = dateLocal(); updateExpenseTotal();
  } catch (error) { $('submitError').textContent = error.message || 'Could not encrypt or submit this report.'; }
});

$('export').addEventListener('click', () => {
  const columns = ['service_date','bus_number','route','driver_name','collection_amount','expense_bata','expense_diesel','expense_toll','expense_cleaning','expense_chitty','expense_gap','expense_office','expense_balance','expense_total','net_amount'];
  const rows = [columns, ...shownRows.map(r => { const e = expenseBreakdownOf(r); return [r.service_date,r.bus_number,r.route,r.driver_name,r.collection_amount,e.bata,e.diesel,e.toll,e.cleaning,e.chitty,e.gap,e.office,e.balance,r.expense_amount,Number(r.collection_amount)-Number(r.expense_amount)]; })];
  const csv = rows.map(row => row.map(value => '"' + String(value).replaceAll('"', '""') + '"').join(',')).join('\n');
  const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' })); link.download = 'st-georges-bus-collections-' + $('adminDate').value + '.csv'; link.click(); URL.revokeObjectURL(link.href);
});

$('backupKey').addEventListener('click', () => {
  if (!keyBundle) return;
  const backup = { format: 'st-georges-admin-key-backup-v1', note: 'Encrypted private key. Requires the private-key password. Keep this file private.', ...keyBundle };
  const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })); link.download = 'st-georges-encrypted-key-backup.json'; link.click(); URL.revokeObjectURL(link.href);
});

$('lock').addEventListener('click', async () => {
  clearTimeout(adminLockTimer);
  privateKey = null; publicKey = null; allReports = []; shownRows = [];
  try { if (authSession) await authRequest('/auth/v1/logout', {}, authSession.access_token); } catch { /* Local sign-out still completes if offline. */ }
  authSession = null; currentUser = null; currentRole = null; $('adminView').classList.add('hidden'); $('driverView').classList.add('hidden'); $('backupKey').hidden = true; showGate('login');
});

const saved = localStorage.getItem(configKey);
if (saved) {
  try { const config = JSON.parse(saved); $('projectUrl').value = config.url; $('publishableKey').value = config.key; connect(config).catch(error => { showGate('config'); $('configError').textContent = error.message; }); }
  catch { showGate('config'); }
} else {
  localStorage.setItem(configKey, JSON.stringify(defaultConfig));
  $('projectUrl').value = defaultConfig.url; $('publishableKey').value = defaultConfig.key;
  connect(defaultConfig).catch(error => { showGate('config'); $('configError').textContent = error.message; });
}

