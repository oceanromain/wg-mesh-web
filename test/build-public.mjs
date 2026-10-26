#!/usr/bin/env node
// 构建公网部署副本到 dist-public/：
//  - 不内置任何示例拓扑（goldenTemplate 置空），首启空白
//  - 隐藏「载入示例拓扑」按钮、清掉其 banner
//  - 红线扫描：副本不得包含预置拓扑数据（示例节点名/域名/网段）
import { cpSync, rmSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist-public');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

for (const d of ['css', 'js', 'vendor']) cpSync(join(root, d), join(out, d), { recursive: true });
cpSync(join(root, 'index.html'), join(out, 'index.html'));

// 1) goldenTemplate() 置空（该函数位于 core.js 末尾）
const corePath = join(out, 'js/core.js');
let core = readFileSync(corePath, 'utf8');
const marker = 'export function goldenTemplate()';
const cut = core.indexOf(marker);
if (cut < 0) throw new Error('goldenTemplate 锚点未找到');
core = core.slice(0, cut) + "export function goldenTemplate() {\n  // 公网部署版：不内置任何拓扑，默认空白开始\n  return [];\n}\n";
writeFileSync(corePath, core);

// 2) 隐藏示例拓扑按钮 + 清掉其 banner
const html = readFileSync(join(out, 'index.html'), 'utf8').replace(
  '<button id="btn-template" class="btn">载入示例拓扑</button>',
  '<button id="btn-template" class="btn" hidden>载入示例拓扑</button>',
);
writeFileSync(join(out, 'index.html'), html);
const app = readFileSync(join(out, 'js/app.js'), 'utf8').replace(
  /banner\('已载入示例拓扑：[\s\S]*?', 'ok'\);/,
  "banner('已载入示例拓扑', 'ok');",
);
writeFileSync(join(out, 'js/app.js'), app);

// 3) 红线扫描：公网副本不得预置任何具体拓扑。
//    只扫能唯一标识内置示例拓扑的串；
//    输入框 placeholder 里的通用地址（10.0.0.1/32、192.168.1.0/24、51820）只是格式提示，允许保留。
const FORBIDDEN = /vpn-[ab]\.example\.com|site-[ab]|client-[ab]/;
const walk = (dir) => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});
const hits = walk(out).filter((p) => FORBIDDEN.test(readFileSync(p, 'utf8')));
if (hits.length) throw new Error('公网副本残留拓扑信息: ' + hits.join(', '));
console.log('public build OK at', out);
