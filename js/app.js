// app.js — 页面交互
import {
  PskStore, validateTopology, generateAll, goldenTemplate,
} from './core.js';
import { webCrypto } from './crypto-web.js';
import { buildZip } from './zip.js';

const LS_KEY = 'wg-mesh-web-state-v1';
const $ = (sel, root = document) => root.querySelector(sel);

const state = {
  peers: [],
  psks: new PskStore(),
  results: [],
};

// ---------- 工具 ----------
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function download(name, textOrBlob, mime = 'text/plain') {
  const blob = typeof textOrBlob === 'string' ? new Blob([textOrBlob], { type: mime }) : textOrBlob;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}
let bannerTimer;
function banner(msg, kind = 'error') {
  const el = $('#banner');
  el.className = `banner ${kind}`;
  el.textContent = msg;
  clearTimeout(bannerTimer);
  if (kind === 'ok') bannerTimer = setTimeout(() => el.classList.add('hidden'), 4000);
}

// ---------- 节点编辑 ----------
function blankPeer() {
  return { name: '', address: '', listenPort: '', endpoint: '', allowedIps: [], privateKey: '', publicKey: '' };
}

function derivePublic(sk) {
  try {
    return sk.trim() ? webCrypto.publicFromSecret(sk) : '';
  } catch { return ''; }
}

function renderPeers() {
  const wrap = $('#peers');
  $('#peer-count').textContent = state.peers.length;
  wrap.innerHTML = '';
  state.peers.forEach((p, i) => {
    const card = document.createElement('div');
    card.className = 'peer-card';
    card.dataset.idx = i;
    card.innerHTML = `
      <div class="card-head">
        <input class="f-name" placeholder="节点名（字母数字 ._-）" value="${esc(p.name)}">
        <button class="icon-btn f-del" title="删除节点">🗑</button>
      </div>
      <div class="row"><label>Address</label><input class="f-address mono" placeholder="10.0.0.1/32" value="${esc(p.address)}"></div>
      <div class="row"><label>ListenPort</label><input class="f-port" type="number" min="1" max="65535" placeholder="51820（NAT 客户端可留空）" value="${esc(p.listenPort)}"></div>
      <div class="row"><label>Endpoint</label><input class="f-endpoint mono" placeholder="host 或 DDNS，不带端口！NAT 后留空" value="${esc(p.endpoint)}"></div>
      <div class="row stretch">
        <label>额外 AllowedIPs（每行一条）</label>
        <textarea class="f-allowed mono" rows="2" placeholder="192.168.1.0/24">${esc((p.allowedIps || []).join('\n'))}</textarea>
      </div>
      <div class="row stretch">
        <label>PrivateKey</label>
        <div class="row" style="width:100%">
          <textarea class="f-priv mono" rows="2" placeholder="留空则生成时自动创建；也可粘贴已有私钥">${esc(p.privateKey)}</textarea>
        </div>
        <div class="row" style="width:100%">
          <button class="btn mini f-genkey">${p.privateKey ? '重新生成密钥对' : '生成密钥对'}</button>
        </div>
        <div class="pubkey-box f-pub">${p.publicKey ? '公钥: ' + esc(p.publicKey) : '公钥将在生成或填入私钥后出现'}</div>
      </div>`;
    wrap.appendChild(card);
  });
  persist();
}

// 从 DOM 回读
function collect() {
  state.peers = [...document.querySelectorAll('.peer-card')].map((card) => {
    const sk = $('.f-priv', card).value.trim();
    return {
      name: $('.f-name', card).value.trim(),
      address: $('.f-address', card).value.trim(),
      listenPort: $('.f-port', card).value.trim(),
      endpoint: $('.f-endpoint', card).value.trim(),
      allowedIps: $('.f-allowed', card).value.split('\n').map((s) => s.trim()).filter(Boolean),
      privateKey: sk,
      publicKey: derivePublic(sk),
    };
  });
}

// 事件委托
$('#peers').addEventListener('input', (e) => {
  const card = e.target.closest('.peer-card');
  if (!card) return;
  if (e.target.classList.contains('f-priv')) {
    const pub = derivePublic(e.target.value);
    $('.f-pub', card).textContent = pub ? '公钥: ' + pub : '公钥将在生成或填入私钥后出现';
  }
  persist();
});
$('#peers').addEventListener('change', () => persist());
$('#peers').addEventListener('click', (e) => {
  const card = e.target.closest('.peer-card');
  if (!card) return;
  const idx = +card.dataset.idx;
  if (e.target.classList.contains('f-del')) {
    collect();
    if (!state.peers[idx].name || confirm(`删除节点 ${state.peers[idx].name || idx + 1}？其专属 PSK 也会在下次生成时清理`)) {
      state.peers.splice(idx, 1);
      state.results = [];
      renderPeers(); renderResults();
    }
  } else if (e.target.classList.contains('f-genkey')) {
    const kp = webCrypto.makeKeyPair();
    $('.f-priv', card).value = kp.privateKey;
    $('.f-pub', card).textContent = '公钥: ' + kp.publicKey;
    banner('已生成新密钥对（生成配置时生效）', 'ok');
    persist();
  }
});

// ---------- 生成 ----------
$('#btn-generate').addEventListener('click', () => {
  collect();
  let v;
  try {
    v = validateTopology(state.peers);
  } catch (err) {
    banner(err.message, 'error'); return;
  }
  if (v.errors.length) {
    banner('❌ 校验未通过：\n - ' + v.errors.join('\n - '), 'error');
    return;
  }
  try {
    const out = generateAll(state.peers, webCrypto, { pskStore: state.psks, keepalive: 25 });
    state.peers = out.peers; // 回填自动生成的密钥
    state.results = out.configs;
    renderPeers();
    renderResults();
    const warn = v.warnings.length ? '\n\n⚠️ 提示：\n - ' + v.warnings.join('\n - ') : '';
    banner(`✅ 已为 ${out.configs.length} 个节点生成配置（PSK 对数: ${Object.keys(out.psks.toJSON()).length}）${warn}`, v.warnings.length ? 'warn' : 'ok');
    $('#result-section').scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    banner('❌ ' + err.message, 'error');
  }
});

$('#btn-rotate-psk').addEventListener('click', () => {
  collect();
  const names = state.peers.map((p) => p.name).filter(Boolean);
  if (names.length < 2) return banner('至少 2 个节点才能轮换 PSK', 'error');
  if (!confirm('确认重新生成全部节点对 PSK？换钥后所有节点配置都要重新下发。')) return;
  state.psks = new PskStore(); // 清空：generateAll 会按当前拓扑重建
  banner('PSK 已清空，点击「生成配置」即按现有拓扑全部重建。', 'ok');
  persist();
});

// ---------- 结果 ----------
function qrSvg(text) {
  const qr = qrcode(0, 'M'); // 自动版本，M 容错；单份配置 < 1KB，容量充足
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ scalable: true, margin: 2 });
}

function renderResults() {
  const sec = $('#result-section');
  const wrap = $('#results');
  $('#btn-zip').disabled = state.results.length === 0;
  if (!state.results.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  wrap.innerHTML = '';
  state.results.forEach((r) => {
    const card = document.createElement('div');
    card.className = 'result-card';
    card.innerHTML = `
      <div class="result-head">
        <span class="fname">${esc(r.name)}.conf</span>
        <span class="btns">
          <button class="btn mini f-copy">复制</button>
          <button class="btn mini f-dl">下载</button>
        </span>
      </div>
      <div class="result-body">
        <pre class="conf">${esc(r.text)}</pre>
        <div class="qr-box" title="点击放大">${qrSvg(r.text)}<div class="cap">${esc(r.name)}.conf</div></div>
      </div>`;
    $('.f-dl', card).addEventListener('click', () => download(`${r.name}.conf`, r.text));
    $('.f-copy', card).addEventListener('click', async (ev) => {
      await navigator.clipboard.writeText(r.text);
      ev.target.textContent = '已复制 ✓';
      setTimeout(() => { ev.target.textContent = '复制'; }, 1500);
    });
    $('.qr-box', card).addEventListener('click', () => {
      const mask = document.createElement('div');
      mask.className = 'modal-mask';
      mask.innerHTML = `<div class="modal-box">${qrSvg(r.text)}<div class="cap">${esc(r.name)}.conf — WireGuard App 扫码导入</div></div>`;
      mask.addEventListener('click', () => mask.remove());
      document.body.appendChild(mask);
    });
    wrap.appendChild(card);
  });
}

$('#btn-zip').addEventListener('click', () => {
  if (!state.results.length) return;
  const zip = buildZip(state.results.map((r) => ({ name: `${r.name}.conf`, text: r.text })));
  download('wg-mesh-configs.zip', zip, 'application/zip');
});

// ---------- 顶部按钮 ----------
$('#btn-add').addEventListener('click', () => { collect(); state.peers.push(blankPeer()); state.results = []; renderPeers(); renderResults(); });
$('#btn-template').addEventListener('click', () => {
  collect();
  if (state.peers.length && !confirm('载入现网 4 节点模板将覆盖当前表单（已生成密钥不受影响），继续？')) return;
  state.peers = goldenTemplate();
  state.results = [];
  renderPeers(); renderResults();
  banner('已载入示例拓扑：site-a / site-b（公网网关）+ client-a / client-b（NAT 客户端），隧道 10.0.0.0/24，端口 51820；请替换成你自己的节点后点「生成配置」。', 'ok');
});
$('#btn-clear').addEventListener('click', () => {
  if (!confirm('清空全部节点、密钥与 PSK？此操作不可恢复。')) return;
  state.peers = []; state.psks = new PskStore(); state.results = [];
  renderPeers(); renderResults(); banner('已清空', 'ok');
});
$('#btn-export').addEventListener('click', () => {
  collect();
  const data = { version: 1, exportedAt: new Date().toISOString(), peers: state.peers, psks: state.psks.toJSON() };
  download('wg-mesh-topology.json', JSON.stringify(data, null, 2), 'application/json');
});
$('#file-import').addEventListener('change', (e) => {
  const f = e.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      if (!Array.isArray(data.peers)) throw new Error('JSON 中无 peers 数组');
      state.peers = data.peers.map((p) => ({ ...blankPeer(), ...p, allowedIps: p.allowedIps || [] }));
      state.psks = new PskStore(data.psks || {});
      state.results = [];
      renderPeers(); renderResults();
      banner(`已导入 ${state.peers.length} 个节点${Object.keys(data.psks || {}).length ? ' 与 PSK 表' : ''}（含私钥，请妥善保管）`, 'ok');
    } catch (err) { banner('导入失败: ' + err.message, 'error'); }
    e.target.value = '';
  };
  reader.readAsText(f);
});

// ---------- localStorage（默认不启用） ----------
function persist() {
  if (!$('#chk-persist').checked) { localStorage.removeItem(LS_KEY); return; }
  collect();
  localStorage.setItem(LS_KEY, JSON.stringify({ peers: state.peers, psks: state.psks.toJSON() }));
}
$('#chk-persist').addEventListener('change', (e) => {
  if (e.target.checked) {
    if (!confirm('开启后拓扑、私钥与 PSK 会以明文保存在本浏览器 localStorage。仅在你信任的私人设备上启用，确定？')) {
      e.target.checked = false; return;
    }
    persist();
  } else {
    localStorage.removeItem(LS_KEY);
  }
});

// ---------- 启动 ----------
(function init() {
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch { saved = null; }
  if (saved && Array.isArray(saved.peers) && saved.peers.length) {
    state.peers = saved.peers;
    state.psks = new PskStore(saved.psks || {});
    $('#chk-persist').checked = true;
    banner(`已从本机恢复 ${state.peers.length} 个节点（localStorage）`, 'ok');
  } else {
    state.peers = goldenTemplate(); // 默认载入模板，方便一键体验
  }
  renderPeers();
})();
