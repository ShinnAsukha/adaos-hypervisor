/* OXware Web Installer — Frontend Logic */
'use strict';

const STEPS = 6;
let currentStep = 0;

const stepDescs = [
  'Lütfen lisans sözleşmesini okuyun ve kabul edin.',
  'OXware\'in kurulacağı diski seçin. Tüm veriler silinecektir.',
  'Web arayüzüne erişim için ağ yapılandırmasını yapın.',
  'Sunucu kimliği ve yönetici hesap bilgilerini girin.',
  'Ayarları gözden geçirin ve kurulumu başlatın.',
  'Kurulum devam ediyor…',
];

/* ── Init ──────────────────────────────────────────────────────────────── */
window.addEventListener('DOMContentLoaded', () => {
  loadDisks();
  loadIfaces();
  updateUI();
});

/* ── Navigation ────────────────────────────────────────────────────────── */
function nextStep() {
  if (!validateStep(currentStep)) return;
  if (currentStep === 4) { startInstall(); return; }
  if (currentStep >= STEPS - 1) return;
  if (currentStep === 4) fillSummary();
  currentStep++;
  if (currentStep === 4) fillSummary();
  updateUI();
}

function prevStep() {
  if (currentStep <= 0) return;
  currentStep--;
  updateUI();
}

function updateUI() {
  document.querySelectorAll('.step-page').forEach((p, i) => {
    p.classList.toggle('active', i === currentStep);
  });
  document.querySelectorAll('.step-item').forEach((el, i) => {
    el.classList.remove('active', 'done');
    if (i === currentStep) el.classList.add('active');
    else if (i < currentStep) el.classList.add('done');
  });
  const descEl = document.getElementById('step-desc-text');
  if (descEl) descEl.textContent = stepDescs[currentStep] || '';

  const btnPrev = document.getElementById('btn-prev');
  const btnNext = document.getElementById('btn-next');
  const btnAbort = document.getElementById('btn-abort');

  btnPrev.disabled = currentStep === 0 || currentStep === 5;
  btnNext.textContent = currentStep === 4 ? 'Kur!' : (currentStep === 0 ? 'Kabul Et ve Devam Et' : 'Next');

  if (currentStep === 5) {
    btnNext.disabled = true;
    btnAbort.disabled = true;
  }
}

/* ── Validation ────────────────────────────────────────────────────────── */
function validateStep(step) {
  if (step === 1) {
    const disk = document.getElementById('disk-select').value;
    if (!disk) { alert('Lütfen bir disk seçin.'); return false; }
  }
  if (step === 3) {
    const pw  = document.getElementById('inp-password').value;
    const pw2 = document.getElementById('inp-password2').value;
    const err = document.getElementById('pw-err');
    if (!pw) { alert('Şifre boş bırakılamaz.'); return false; }
    if (pw !== pw2) { err.style.display = 'block'; return false; }
    err.style.display = 'none';
  }
  return true;
}

/* ── API Helpers ───────────────────────────────────────────────────────── */
async function api(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(`http://127.0.0.1:8888${path}`, opts);
  return r.json();
}

/* ── Load disks ────────────────────────────────────────────────────────── */
async function loadDisks() {
  try {
    const disks = await api('/api/disks');
    const sel   = document.getElementById('disk-select');
    const mSel  = document.getElementById('modal-disk-sel');
    sel.innerHTML  = '<option value="">— Disk seçin —</option>';
    mSel.innerHTML = '<option value="">— Disk seçin —</option>';
    disks.forEach(d => {
      const opt = new Option(d.label, d.name);
      sel.appendChild(opt.cloneNode(true));
      mSel.appendChild(opt);
    });
    if (disks.length === 1) {
      sel.value  = disks[0].name;
      mSel.value = disks[0].name;
      updateDiskInfo(disks[0]);
    }
    sel.addEventListener('change', () => {
      const d = disks.find(x => x.name === sel.value);
      if (d) { updateDiskInfo(d); mSel.value = d.name; }
    });
    mSel.addEventListener('change', () => {
      const d = disks.find(x => x.name === mSel.value);
      if (d) { updateDiskInfo(d); sel.value = d.name; }
    });
  } catch (e) { console.warn('loadDisks:', e); }
}

function updateDiskInfo(disk) {
  const bar = document.getElementById('disk-info-bar');
  const txt = document.getElementById('disk-info-text');
  bar.style.display = 'block';
  txt.textContent = `${disk.name}  ·  ${disk.gb} GB  ·  Tüm veriler silinecek`;
}

/* ── Load interfaces ───────────────────────────────────────────────────── */
async function loadIfaces() {
  try {
    const ifaces = await api('/api/ifaces');
    const sel = document.getElementById('iface-select');
    sel.innerHTML = '<option value="">— Arayüz seçin —</option>';
    ifaces.forEach(i => sel.appendChild(new Option(i, i)));
    if (ifaces.length > 0) sel.value = ifaces[0];
  } catch (e) { console.warn('loadIfaces:', e); }
}

/* ── Network toggle ────────────────────────────────────────────────────── */
function toggleNet(val) {
  document.getElementById('static-fields').style.display = val === 'static' ? 'block' : 'none';
}

/* ── Disk options modal ────────────────────────────────────────────────── */
function openDiskOpts() {
  document.getElementById('modal-backdrop').style.display = 'block';
  document.getElementById('modal-disk').style.display     = 'block';
  // Sync fs
  document.getElementById('modal-fs').value = document.getElementById('fs-select').value;
}

function closeDiskOpts() {
  document.getElementById('modal-backdrop').style.display = 'none';
  document.getElementById('modal-disk').style.display     = 'none';
  // Sync back
  document.getElementById('fs-select').value = document.getElementById('modal-fs').value;
  const mDisk = document.getElementById('modal-disk-sel').value;
  if (mDisk) document.getElementById('disk-select').value = mDisk;
}

function modalTab(idx, el) {
  document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(`modal-tab-${idx}`).classList.add('active');
}

/* ── Fill summary ──────────────────────────────────────────────────────── */
function fillSummary() {
  const disk     = document.getElementById('disk-select').value || '—';
  const fs       = document.getElementById('fs-select').value;
  const netMode  = document.querySelector('input[name="net-mode"]:checked').value;
  const hostname = document.getElementById('inp-hostname').value || '—';
  const user     = document.getElementById('inp-username').value || '—';
  const netText  = netMode === 'dhcp'
    ? 'DHCP (Otomatik)'
    : document.getElementById('net-ip').value || 'Statik';

  document.getElementById('sum-disk').textContent     = disk;
  document.getElementById('sum-fs').textContent       = fs;
  document.getElementById('sum-net').textContent      = netText;
  document.getElementById('sum-hostname').textContent = hostname;
  document.getElementById('sum-user').textContent     = user;
}

/* ── Start installation ────────────────────────────────────────────────── */
async function startInstall() {
  const cfg = {
    disk:     document.getElementById('disk-select').value,
    fs:       document.getElementById('fs-select').value,
    hostname: document.getElementById('inp-hostname').value,
    username: document.getElementById('inp-username').value,
    password: document.getElementById('inp-password').value,
    net_mode: document.querySelector('input[name="net-mode"]:checked').value,
    iface:    document.getElementById('iface-select').value,
    net_ip:   document.getElementById('net-ip').value,
    net_gw:   document.getElementById('net-gw').value,
    net_dns:  document.getElementById('net-dns').value,
  };

  currentStep = 5;
  updateUI();

  await api('/api/start', 'POST', cfg);

  // SSE progress
  const es = new EventSource('http://127.0.0.1:8888/api/progress');
  es.onmessage = (e) => {
    const d = JSON.parse(e.data);

    document.getElementById('install-pct-label').textContent = `${d.pct}%`;
    document.getElementById('install-bar').style.width       = `${d.pct}%`;
    document.getElementById('install-msg').textContent       = d.msg;

    if (d.new_logs && d.new_logs.length > 0) {
      const logEl = document.getElementById('install-log');
      d.new_logs.forEach(line => {
        const div = document.createElement('div');
        div.className = 'log-line';
        div.textContent = line;
        logEl.appendChild(div);
      });
      logEl.scrollTop = logEl.scrollHeight;
    }

    if (d.error) {
      es.close();
      document.getElementById('install-status').style.display = 'none';
      document.getElementById('install-err').style.display    = 'block';
      document.getElementById('install-err-msg').textContent  = d.error;
    } else if (d.done) {
      es.close();
      document.getElementById('install-status').style.display = 'none';
      document.getElementById('install-done').style.display   = 'block';
      const btnNext = document.getElementById('btn-next');
      btnNext.textContent = 'Yeniden Başlat';
      btnNext.disabled    = false;
      btnNext.onclick     = doReboot;
    }
  };
}

/* ── Abort / Reboot ────────────────────────────────────────────────────── */
function doAbort() {
  if (confirm('Kurulumu iptal etmek istediğinizden emin misiniz?')) {
    window.location.reload();
  }
}

async function doReboot() {
  try { await api('/api/reboot', 'POST'); } catch (_) {}
}
