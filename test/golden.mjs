// golden.mjs — 自包含回归：示例拓扑 + 已知坑规避 + wg pubkey 真实校验
// 运行: node test/golden.mjs （需系统 wg / wireguard-tools）
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import assert from 'node:assert/strict';

import {
  generateAll, validateTopology, PskStore, b64decode, splitEndpoint,
  goldenTemplate, cidrsOverlap,
} from '../js/core.js';

const require = createRequire(import.meta.url);
const nacl = require('../vendor/nacl.min.js');
const qrcodeMod = require('../vendor/qrcode.js');
const { buildZip } = await import('../js/zip.js');

const here = dirname(fileURLToPath(import.meta.url));
void here;

// Node 版加密适配（与浏览器 crypto-web.js 同一套原语）
const b64 = (u8) => Buffer.from(u8).toString('base64');
const nodeCrypto = {
  makeKeyPair() {
    const kp = nacl.box.keyPair();
    // tweetnacl box secretKey 即 32B（防御性截取；nacl.sign 的才是 64B）
    return { privateKey: b64(kp.secretKey.subarray(0, 32)), publicKey: b64(kp.publicKey) };
  },
  publicFromSecret(sk) {
    return b64(nacl.box.keyPair.fromSecretKey(Buffer.from(sk, 'base64')).publicKey);
  },
  makePsk() { return b64(nacl.randomBytes(32)); },
};

let passed = 0;
const ok = async (name, fn) => { await fn(); passed++; console.log(`  ✓ ${name}`); };
const tests = [];
const T = (name, fn) => tests.push([name, fn]);

const blocks = (text) => text.trim().split('\n\n');
const field = (blk, key) => blk.split('\n').find((l) => l.startsWith(key + ' ='))?.split('= ')[1];
const canon = (t) => t.replace(/^(PrivateKey|PublicKey|PresharedKey) = .+$/gm, '$1 = <KEY>').trim();

// ---------- 1. 示例拓扑生成 ----------
const peers = goldenTemplate();
const { configs, psks } = generateAll(peers, nodeCrypto, { keepalive: 25 });
const byName = Object.fromEntries(configs.map((c) => [c.name, c.text]));

T('内置示例为 4 节点（2 公网网关 + 2 NAT 客户端）', () => {
  assert.equal(configs.length, 4);
  assert.deepEqual(peers.map((p) => p.name), ['site-a', 'site-b', 'client-a', 'client-b']);
});

// ---------- 2. wg pubkey 真实校验 ----------
T('每个 PrivateKey 经系统 `wg pubkey` 反推与 PublicKey 一致', () => {
  for (const p of peers) {
    const out = execFileSync('wg', ['pubkey'], { input: p.privateKey + '\n' }).toString().trim();
    assert.equal(out, p.publicKey, `${p.name} 公钥不匹配`);
  }
});

// ---------- 3. PSK ----------
T('PSK 共 C(4,2)=6 对、44 字符 base64 解码 32 字节', () => {
  const json = psks.toJSON();
  assert.equal(Object.keys(json).length, 6);
  for (const v of Object.values(json)) {
    assert.equal(v.length, 44);
    assert.equal(b64decode(v).length, 32);
  }
});

T('每对节点双方配置中的 PSK 相同', () => {
  const pskBetween = (a, b) => {
    const blk = blocks(byName[a]).find((b0) => b0.startsWith('[Peer]') && b0.includes(`# Name: ${b}\n`));
    return field(blk, 'PresharedKey');
  };
  const names = Object.keys(byName);
  for (let i = 0; i < names.length; i++)
    for (let j = i + 1; j < names.length; j++)
      assert.equal(pskBetween(names[i], names[j]), pskBetween(names[j], names[i]));
});

// ---------- 4. 结构快照（密钥规范化后逐行一致） ----------
const SITE_A = `[Interface]
# Name: site-a
Address = 10.0.0.1/32
PrivateKey = <KEY>
ListenPort = 51820

[Peer]
# Name: site-b
PublicKey = <KEY>
PresharedKey = <KEY>
Endpoint = vpn-b.example.com:51820
AllowedIPs = 10.0.0.2/32, 192.168.2.0/24
PersistentKeepalive = 25

[Peer]
# Name: client-a
PublicKey = <KEY>
PresharedKey = <KEY>
AllowedIPs = 10.0.0.3/32

[Peer]
# Name: client-b
PublicKey = <KEY>
PresharedKey = <KEY>
AllowedIPs = 10.0.0.4/32`;

const CLIENT_B = `[Interface]
# Name: client-b
Address = 10.0.0.4/32
PrivateKey = <KEY>

[Peer]
# Name: site-a
PublicKey = <KEY>
PresharedKey = <KEY>
Endpoint = vpn-a.example.com:51820
AllowedIPs = 10.0.0.1/32, 192.168.1.0/24
PersistentKeepalive = 25

[Peer]
# Name: site-b
PublicKey = <KEY>
PresharedKey = <KEY>
Endpoint = vpn-b.example.com:51820
AllowedIPs = 10.0.0.2/32, 192.168.2.0/24
PersistentKeepalive = 25

[Peer]
# Name: client-a
PublicKey = <KEY>
PresharedKey = <KEY>
AllowedIPs = 10.0.0.3/32`;

T('公网网关 site-a 结构快照逐行一致（含对端 LAN、NAT 节点无出站段）', () => {
  assert.equal(canon(byName['site-a']), SITE_A);
});

T('NAT 客户端 client-b 无 ListenPort、仅对两个公网网关有 Endpoint+keepalive', () => {
  assert.equal(canon(byName['client-b']), CLIENT_B);
  assert.ok(!byName['client-b'].includes('ListenPort'));
});

// ---------- 5. 坑①：无 host:port:port ----------
T('无 :51820:51820（endpoint 不重复拼端口）', () => {
  for (const t of configs.map((c) => c.text)) assert.ok(!/:51820:51820/.test(t));
});

// ---------- 6. 坑②：keepalive 方向 ----------
T('PersistentKeepalive 仅出现在含 Endpoint 的出站 peer 段', () => {
  for (const { text } of configs) {
    for (const blk of blocks(text).slice(1)) {
      const hasEp = blk.split('\n').some((l) => l.startsWith('Endpoint ='));
      const hasKa = blk.split('\n').some((l) => l.startsWith('PersistentKeepalive ='));
      assert.equal(hasKa, hasEp, `段方向错误:\n${blk}`);
    }
  }
});

// ---------- 7. Endpoint 误带端口 ----------
T('Endpoint 误带端口被识别并剥离（警告而非双端口）', () => {
  const p = goldenTemplate();
  p[0].endpoint = 'vpn-a.example.com:51820';
  const { warnings } = validateTopology(p);
  assert.ok(warnings.some((w) => w.includes('不应带端口')));
  const out = generateAll(p, nodeCrypto, { pskStore: new PskStore() });
  const seg = out.configs[3].text.split('\n\n').find((b) => b.includes('# Name: site-a\n'));
  assert.equal(field(seg, 'Endpoint'), 'vpn-a.example.com:51820');
  assert.ok(!seg.includes(':51820:51820'));
  assert.equal(splitEndpoint('host.example.com:51820').host, 'host.example.com');
  assert.equal(splitEndpoint('[2001:db8::1]:51820').host, '2001:db8::1');
  assert.equal(splitEndpoint('2001:db8::1').host, '2001:db8::1');
});

// ---------- 8. PSK 复用 ----------
T('PskStore 按字典序复用（再生成不换钥）', () => {
  const before = psks.toJSON();
  const again = generateAll(peers.map((p) => ({ ...p })), nodeCrypto, { pskStore: psks });
  assert.deepEqual(again.psks.toJSON(), before);
});

// ---------- 9. 非法输入 ----------
T('非法端口/地址/重名被拦截', () => {
  const bad = [
    { name: 'a', address: '10.0.0.1/32', listenPort: 70000, endpoint: '', allowedIps: [] },
    { name: 'a', address: 'bad', listenPort: '', endpoint: '', allowedIps: ['not-cidr'] },
  ];
  const { errors } = validateTopology(bad);
  assert.ok(errors.length >= 3, errors.join(';'));
});

// ---------- 10. 路由重叠：只告警不阻止 ----------
T('AllowedIPs 重叠/重复宣告只告警不阻止，示例拓扑不误报', () => {
  const noisy = validateTopology(goldenTemplate()).warnings
    .filter((w) => w.includes('重叠') || w.includes('多节点宣告'));
  assert.equal(noisy.length, 0);
  const dup = [
    { name: 'd1', address: '10.7.0.1/32', listenPort: 51820, endpoint: 'a.example', allowedIps: ['10.11.0.0/24'] },
    { name: 'd2', address: '10.7.0.2/32', listenPort: 51820, endpoint: 'b.example', allowedIps: ['10.11.0.0/24'] },
  ];
  assert.ok(validateTopology(dup).warnings.some((w) => w.includes('被多个节点宣告')));
  assert.doesNotThrow(() => generateAll(dup.map((p) => ({ ...p })), nodeCrypto, { pskStore: new PskStore() }));
  assert.ok(cidrsOverlap('10.9.0.0/24', '10.9.0.1/32'));
  assert.ok(!cidrsOverlap('10.9.0.0/24', '10.9.1.0/24'));
  assert.ok(cidrsOverlap('2001:db8::/32', '2001:db8:1::/48'));
  assert.ok(!cidrsOverlap('fd00::/8', 'fe80::/10'));
});

// ---------- 11. 二维码 ----------
T('二维码可编码最长配置并产出 SVG', () => {
  const qrcode = qrcodeMod.qrcode || qrcodeMod.default?.qrcode || qrcodeMod;
  const longest = Object.values(byName).sort((a, b) => b.length - a.length)[0];
  const qr = qrcode(0, 'M');
  qr.addData(longest);
  qr.make();
  const svg = qr.createSvgTag({ scalable: true, margin: 2 });
  assert.ok(svg.includes('<svg') && svg.includes('path'));
});

// ---------- 12. ZIP ----------
T('ZIP 产物包含全部 4 份 conf（store）', async () => {
  const blob = buildZip(configs.map((c) => ({ name: `${c.name}.conf`, text: c.text })));
  const buf = Buffer.from(await blob.arrayBuffer());
  assert.ok(buf.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06])));
  for (const c of configs) assert.ok(buf.includes(`# Name: ${c.name}`));
});

for (const [name, fn] of tests) await ok(name, fn);
console.log(`\n全部 ${passed} 项通过 ✅`);
