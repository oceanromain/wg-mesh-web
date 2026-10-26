// core.js — WireGuard full-mesh 配置生成核心（纯逻辑，无 DOM 依赖）
// 浏览器与 Node 均可 import；加密原语通过 adapter 注入：
//   adapter.makeKeyPair() -> { privateKey: b64, publicKey: b64 }
//   adapter.publicFromSecret(secretB64) -> b64
//   adapter.makePsk() -> b64
//
// 设计上直接规避 wg-meshconf 2.5.1 的两个坑：
//  1) Endpoint 永远只拼一次端口（host 字段不允许带端口）
//  2) PersistentKeepalive 只写在「有 Endpoint 的出站 peer 段」

// ---------- base64（浏览器/Node 通用） ----------
const B64CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function b64encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64CHARS[(n >> 18) & 63] + B64CHARS[(n >> 12) & 63]
      + (i + 1 < bytes.length ? B64CHARS[(n >> 6) & 63] : '=')
      + (i + 2 < bytes.length ? B64CHARS[n & 63] : '=');
  }
  return out;
}

export function b64decode(s) {
  const clean = s.replace(/[^A-Za-z0-9+/=]/g, '');
  const out = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = B64CHARS.indexOf(clean[i]);
    const c1 = B64CHARS.indexOf(clean[i + 1]);
    const c2 = clean[i + 2] === '=' ? -1 : B64CHARS.indexOf(clean[i + 2]);
    const c3 = clean[i + 3] === '=' ? -1 : B64CHARS.indexOf(clean[i + 3]);
    const n = (c0 << 18) | (c1 << 12) | ((c2 < 0 ? 0 : c2) << 6) | (c3 < 0 ? 0 : c3);
    out.push((n >> 16) & 255);
    if (c2 >= 0) out.push((n >> 8) & 255);
    if (c3 >= 0) out.push(n & 255);
  }
  return Uint8Array.from(out);
}

// ---------- PSK 存储（按节点名字典序 pair 索引，对齐 add_psk.py） ----------
export function pairKey(a, b) {
  return [a, b].sort().join('|');
}

export class PskStore {
  constructor(init = {}) {
    this.map = new Map(Object.entries(init));
  }
  get(a, b, makePsk) {
    const k = pairKey(a, b);
    if (!this.map.has(k)) {
      if (!makePsk) throw new Error(`PSK 缺失且无生成器: ${k}`);
      this.map.set(k, makePsk());
    }
    return this.map.get(k);
  }
  has(a, b) { return this.map.has(pairKey(a, b)); }
  rotate(a, b, makePsk) { const v = makePsk(); this.map.set(pairKey(a, b), v); return v; }
  rotateAll(makePsk) {
    for (const k of Array.from(this.map.keys())) this.map.set(k, makePsk());
  }
  // 只为当前拓扑保留仍存在的节点对（删节点后清理）
  pruncate(peerNames, makePsk) {
    const alive = new Set(peerNames);
    for (const k of Array.from(this.map.keys())) {
      const [a, b] = k.split('|');
      if (!alive.has(a) || !alive.has(b)) this.map.delete(k);
    }
  }
  toJSON() {
    return Object.fromEntries([...this.map.entries()].sort(([a], [b]) => a.localeCompare(b)));
  }
}

// ---------- 校验 ----------
const RE_NAME = /^[A-Za-z0-9_.-]{1,32}$/;

export function parseCidr(s) {
  const t = s.trim();
  let m = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (m) {
    const ok = m[1].split('.').every((x) => +x >= 0 && +x <= 255) && +m[2] <= 32;
    return ok ? { version: 4, addr: m[1], mask: +m[2] } : null;
  }
  m = t.match(/^([0-9a-fA-F:]+)\/(\d{1,3})$/);
  if (m && m[1].includes(':') && +m[2] <= 128) {
    const parts = m[1].split('::');
    if (parts.length <= 2 && m[1] !== '::') return { version: 6, addr: m[1], mask: +m[2] };
    if (parts.length === 2) return { version: 6, addr: m[1], mask: +m[2] };
  }
  return null;
}

// 两个同协议族 CIDR 是否存在地址区间重叠（含包含/相等）
function cidrRange(c) {
  if (c.version === 4) {
    const ip = c.addr.split('.').reduce((n, o) => (n * 256 + +o) >>> 0, 0) >>> 0;
    const mask = c.mask === 0 ? 0 : ((0xffffffff << (32 - c.mask)) >>> 0);
    return { v: 4, lo: (ip & mask) >>> 0, hi: ((ip & mask) | (~mask >>> 0)) >>> 0 };
  }
  // IPv6：展开成 128bit BigInt
  let addr = c.addr;
  if (addr.includes('::')) {
    const [h, t] = addr.split('::');
    const hh = h ? h.split(':') : [];
    const tt = t ? t.split(':') : [];
    addr = [...hh, ...Array(8 - hh.length - tt.length).fill('0'), ...tt].join(':');
  }
  const groups = addr.split(':').map((x) => BigInt(parseInt(x || '0', 16)));
  let ip = 0n;
  for (const g of groups) ip = (ip << 16n) + g;
  const bits = 128n;
  const m = BigInt(c.mask);
  const mask = m === 0n ? 0n : ((1n << bits) - 1n) ^ ((1n << (bits - m)) - 1n);
  const allOnes = (1n << bits) - 1n;
  return { v: 6, lo: ip & mask, hi: (ip & mask) | (allOnes ^ mask) };
}

export function cidrsOverlap(aStr, bStr) {
  const a = parseCidr(aStr), b = parseCidr(bStr);
  if (!a || !b || a.version !== b.version) return false;
  const ra = cidrRange(a), rb = cidrRange(b);
  return ra.lo <= rb.hi && rb.lo <= ra.hi;
}

// host:port 误填检测：wg-meshconf 老坑，发现则剥离并告警
export function splitEndpoint(raw) {
  const v = (raw || '').trim();
  if (!v) return { host: '' };
  // host(无冒号):端口 —— 域名/IPv4 误带端口
  let m = v.match(/^([^[\]:]+):(\d{1,5})$/);
  if (m) return { host: m[1], portStripped: +m[2] };
  // [IPv6]:端口
  m = v.match(/^\[([0-9a-fA-F:]+)\]:(\d{1,5})$/);
  if (m) return { host: m[1], portStripped: +m[2] };
  // [IPv6] 裸括号 / 裸 IPv6 / 域名：原样
  return { host: v.replace(/^\[(.+)]$/, '$1') };
}

export function validateTopology(peers) {
  const errors = [];
  const warnings = [];
  if (peers.length < 2) errors.push('至少需要 2 个节点');
  const names = new Set();

  peers.forEach((p, i) => {
    const tag = `节点 ${i + 1}${p.name ? `（${p.name}）` : ''}`;
    if (!p.name || !p.name.trim()) errors.push(`${tag}: name 为空`);
    else if (!RE_NAME.test(p.name)) errors.push(`${tag}: name 仅允许字母数字 ._- 且 ≤32 字符`);
    else if (names.has(p.name)) errors.push(`${tag}: name "${p.name}" 重复`);
    else names.add(p.name);

    if (!p.address || !parseCidr(p.address)) errors.push(`${tag}: 隧道 Address 非法（需 CIDR，如 10.0.0.1/32）`);

    if (p.listenPort !== '' && p.listenPort != null) {
      const port = Number(p.listenPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        errors.push(`${tag}: ListenPort 需为 1-65535`);
      }
    }
    if (p.endpoint && p.endpoint.trim()) {
      const ep = splitEndpoint(p.endpoint, null);
      if (ep.portStripped) {
        warnings.push(`${tag}: Endpoint 不应带端口（${ep.host}:${ep.portStripped}），生成时已自动剥离，端口取该节点 ListenPort`);
      }
    }
    (p.allowedIps || []).forEach((c) => {
      if (!parseCidr(c)) errors.push(`${tag}: AllowedIPs "${c}" 不是合法 CIDR`);
    });
    if (!p.privateKey && !p.publicKey) {
      // 双空为正常路径：生成时自动创建密钥，无需告警
    } else if (!p.privateKey && p.publicKey) {
      errors.push(`${tag}: 只填了公钥无法生成本端 [Interface]，请补私钥或留空公钥自动生成`);
    }
  });

  // 跨节点路由重叠检测（只告警不阻止）：每个节点对外宣告 {address} ∪ allowedIps，
  // 任意两个不同节点的宣告网段若重叠（含相等/包含），full-mesh 会产生二义路由。
  const announced = peers
    .filter((p) => p.name && parseCidr(p.address))
    .map((p) => ({ name: p.name, cidrs: [p.address, ...(p.allowedIps || []).filter(parseCidr)] }));
  for (let i = 0; i < announced.length; i++) {
    for (let j = i + 1; j < announced.length; j++) {
      const A = announced[i], B = announced[j];
      for (const ca of A.cidrs) {
        for (const cb of B.cidrs) {
          if (cidrsOverlap(ca, cb)) {
            const same = ca.trim() === cb.trim();
            warnings.push(same
              ? `路由 ${ca} 被多个节点宣告（${A.name} 与 ${B.name}），同一 AllowedIPs 不应由两节点同时宣告`
              : `路由重叠：${A.name} 的 ${ca} 与 ${B.name} 的 ${cb} 存在地址区间重叠`);
          }
        }
      }
    }
  }

  return { errors, warnings };
}

// ---------- 生成 ----------
export function ensureKeys(peer, crypto) {
  if (!peer.privateKey && peer.publicKey) {
    throw new Error(`节点 ${peer.name}: 只有公钥没有私钥，无法在本端生成 [Interface] 配置`);
  }
  if (!peer.privateKey) {
    const kp = crypto.makeKeyPair();
    peer.privateKey = kp.privateKey;
    peer.publicKey = kp.publicKey;
  } else if (!peer.publicKey) {
    peer.publicKey = crypto.publicFromSecret(peer.privateKey.trim());
  } else {
    peer.privateKey = peer.privateKey.trim();
    peer.publicKey = peer.publicKey.trim();
  }
}

export function renderConfig(local, peers, pskStore, crypto, opts = {}) {
  const keepalive = opts.keepalive ?? 25;
  const lines = [];
  lines.push('[Interface]');
  lines.push(`# Name: ${local.name}`);
  lines.push(`Address = ${local.address.trim()}`);
  lines.push(`PrivateKey = ${local.privateKey}`);
  if (local.listenPort !== '' && local.listenPort != null) {
    lines.push(`ListenPort = ${local.listenPort}`);
  }

  for (const remote of peers) {
    if (remote.name === local.name) continue;
    lines.push('');
    lines.push('[Peer]');
    lines.push(`# Name: ${remote.name}`);
    lines.push(`PublicKey = ${remote.publicKey}`);
    lines.push(`PresharedKey = ${pskStore.get(local.name, remote.name, () => crypto.makePsk())}`);

    // 坑①规避：host 与 remote.listenPort 各取一次，绝不重复拼端口
    const epHost = (remote.endpoint || '').trim();
    const remotePort = remote.listenPort !== '' && remote.listenPort != null ? Number(remote.listenPort) : null;
    if (epHost && remotePort) {
      const host = splitEndpoint(epHost).host;
      lines.push(`Endpoint = ${host.includes(':') ? `[${host}]:${remotePort}` : `${host}:${remotePort}`}`);
    }

    const allowed = [];
    const seen = new Set();
    for (const c of [remote.address, ...(remote.allowedIps || [])]) {
      const v = (c || '').trim();
      if (v && !seen.has(v)) { seen.add(v); allowed.push(v); }
    }
    lines.push(`AllowedIPs = ${allowed.join(', ')}`);

    // 坑②规避：keepalive 只挂在有 Endpoint 的出站段（本端主动拨对端）
    if (epHost && remotePort && keepalive) {
      lines.push(`PersistentKeepalive = ${keepalive}`);
    }
  }
  return lines.join('\n') + '\n';
}

// 原地规整并补全密钥，返回 { configs: [{name, text}], psks: PskStore, peers }
export function generateAll(peers, crypto, opts = {}) {
  peers.forEach((p) => {
    p.allowedIps = (p.allowedIps || []).map((x) => x.trim()).filter(Boolean);
  });
  const { errors } = validateTopology(peers);
  if (errors.length) throw new Error('拓扑校验失败：\n - ' + errors.join('\n - '));

  peers.forEach((p) => ensureKeys(p, crypto));
  const psks = opts.pskStore instanceof PskStore ? opts.pskStore : new PskStore(opts.pskStore || {});
  psks.pruncate(peers.map((p) => p.name));

  const configs = peers.map((local) => ({
    name: local.name,
    text: renderConfig(local, peers, psks, crypto, opts),
  }));
  return { configs, psks, peers };
}

// ---------- 内置示例拓扑（4 节点：2 个公网网关 + 2 个 NAT 客户端） ----------
// 纯演示用途的通用地址/域名，不含任何真实部署信息；上手后请替换成自己的拓扑。
export function goldenTemplate() {
  return [
    { name: 'site-a', address: '10.0.0.1/32', listenPort: 51820, endpoint: 'vpn-a.example.com', allowedIps: ['192.168.1.0/24'], privateKey: '', publicKey: '' },
    { name: 'site-b', address: '10.0.0.2/32', listenPort: 51820, endpoint: 'vpn-b.example.com', allowedIps: ['192.168.2.0/24'], privateKey: '', publicKey: '' },
    { name: 'client-a', address: '10.0.0.3/32', listenPort: '', endpoint: '', allowedIps: [], privateKey: '', publicKey: '' },
    { name: 'client-b', address: '10.0.0.4/32', listenPort: '', endpoint: '', allowedIps: [], privateKey: '', publicKey: '' },
  ];
}
