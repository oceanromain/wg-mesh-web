# wg-mesh-web — WireGuard Mesh 配置生成器（纯浏览器）

在网页上维护节点（name / address / listenport / endpoint / allowedips），一键生成全网
full-mesh 的 `wg-quick` 配置、自动补齐 X25519 密钥与 PresharedKey，并为每个节点生成
**可被 WireGuard App 直接扫码导入**的二维码。

[wg-meshconf](https://github.com/k4yt3x/wg-meshconf) 思路的 Web 重写：**零后端、零构建、零外网请求**。
所有密钥都在访客浏览器内用 [TweetNaCl](https://github.com/dchest/tweetnacl-js)（X25519）本地生成，
服务器只托管静态文件，私钥/PSK 永远不经过网络。

## 功能

- 节点表单：name、Address（隧道 CIDR）、ListenPort、Endpoint（**只填 host，不带端口**）、
  额外 AllowedIPs（每行一条，节点隧道 /32 自动合并），动态增删
- 密钥：留空自动生成 X25519 keypair；也可粘贴已有私钥，公钥实时推导；支持单节点重建
- PSK：每对节点一把对称 PresharedKey，按 `"名字A|名字B"` 字典序幂等复用；一键「轮换 PSK」
- 输出：每节点配置预览 / 复制 / 下载 `<name>.conf`，或一键打包 ZIP
- 每节点二维码：内容即完整配置文本，手机 WireGuard App 扫码直接导入；点击放大
- 拓扑导入 / 导出 JSON；localStorage 记忆为**默认关闭**的 opt-in
- 校验：CIDR、端口范围、重名、Endpoint 误带端口（自动剥离并告警）
- 路由安全提示：跨节点 AllowedIPs/隧道网段**重叠或同一网段被多节点宣告**（IPv4/IPv6 区间判断）
  时给告警——只提醒不阻止，避免 full-mesh 二义路由
- 内置一个纯演示用示例拓扑（公网网关 ×2 + NAT 客户端 ×2），**不含任何真实环境信息**

## 快速开始（本地）

ES module 不能直接 `file://` 打开，用任意静态服务器：

```bash
python3 -m http.server 8080
# 打开 http://127.0.0.1:8080
```

或 `npx serve .` / `npm run serve`。

## Docker 部署

### docker run

```bash
docker run -d --name wg-mesh-web --restart=always \
  -p 8080:80 \
  -v "$PWD:/usr/share/nginx/html:ro" \
  nginx:alpine
```

### docker compose（含安全响应头）

```bash
docker compose up -d
```

`docker-compose.yml` 把站点以只读方式挂进 `nginx:alpine`，并加载 `deploy/` 下加固配置。
对外端口改 `WG_PORT`（见 compose 文件顶部）。

### 公网部署要点

1. **云安全组/防火墙**放行对应 TCP 端口（最小化：只对你的办公/家宽 IP 放行更佳）。
2. 强烈建议套 HTTPS（Caddy/Traefik 自动证书，或 nginx + certbot）。页面本身不收发敏感数据
   （密钥全程本地），HTTP 下仍可安全生成，但公共 Wi-Fi 里页面内容可被旁观。
3. 若不想让公开站点内置示例拓扑，构建「空白版」：

   ```bash
   node test/build-public.mjs      # 产物在 dist-public/，首启 0 节点
   # 用 nginx 指向 dist-public 即可；脚本内置红线扫描，残留拓扑标识会构建失败
   ```

4. `deploy/security-headers.conf` 提供一套保守安全头（CSP 仅同源、禁 frame/表单/外连）。
   注意 nginx 的坑：**子 location 里只要出现一个 `add_header`，就会覆盖整个 server 级的
   add_header**，因此每个 location 都要重新 `include` 该片段（`deploy/nginx.conf` 已示范）。

## 使用

1. 「＋ 添加节点」逐个录入，或点「载入示例拓扑」后改成自己的节点。
2. 公网可达的网关节点填 ListenPort + Endpoint(host)；NAT 后的客户端两者都可留空，
   会自动对有 Endpoint 的对端生成出站 `PersistentKeepalive = 25`。
3. 点「⚡ 生成配置」→ 预览 / 下载 .conf / ZIP，或用手机 App 扫二维码导入。
4. 配置结构可用官方工具做最终语法检查：`wg-quick strip ./NAME.conf`（**注意要带 `./` 和
   `.conf`**，裸写名字会被当成接口名去找 `/etc/wireguard/`）。

## 已在引擎层规避的 wg-meshconf 2.5.1 两个坑

1. **Endpoint 不重复拼端口**：host 与对端 ListenPort 各取一次，绝不会产出
   `host:51820:51820`；误填端口会被剥离并告警。
2. **PersistentKeepalive 方向正确**：只写在「本端有 Endpoint 指向对端」的出站 peer 段
   （NAT 节点主动拨公网网关方向），无 Endpoint 的被动段不写。

## 安全模型

- 纯离线：`vendor/` 只有本地的 TweetNaCl 与 qrcode-generator，无任何 CDN/统计/上报。
- 私钥/PSK 默认仅存内存，关页即焚；localStorage 是显式 opt-in，开启有二次确认。
- 导出的 JSON 和二维码/`.conf` 含明文私钥与 PSK：走私密通道分发，落盘 `chmod 600`，用后销毁。
- **换钥（私钥或 PSK）后必须所有节点同时更新**，混装会因公钥/PSK 双重不匹配无法握手。

## 测试

```bash
node test/golden.mjs   # 需系统 wg（wireguard-tools）
```

14 项断言，含：

- 每个 PrivateKey 经系统 `wg pubkey` 反推与公钥一致（证明 X25519 与 WireGuard 兼容）
- 两份配置结构快照逐行比对（公网网关含对端 LAN 宣告、NAT 客户端无 ListenPort）
- PSK 共 C(N,2) 对、双向一致、32 字节 base64、同拓扑幂等复用
- 无 `:port:port`、keepalive 只挂出站段、Endpoint 误带端口剥离、非法输入拦截
- IPv4/IPv6 路由重叠检测、二维码 SVG 可生成、ZIP 结构完整

真机链路另验证过：页面二维码经 `rsvg-convert` 光栅化后 `zbarimg` 解码，与配置文本逐字节一致，
手机 WireGuard App 扫码可直接导入。

## 目录

```
index.html / css/style.css      页面
js/core.js        生成引擎（纯逻辑，Node/浏览器通用，无 DOM 依赖）
js/crypto-web.js  TweetNaCl X25519 适配
js/zip.js         无依赖 store-only ZIP
js/app.js         交互
vendor/           nacl.min.js、qrcode.js（离线第三方库）
deploy/           nginx 站点与安全头配置
test/golden.mjs       自包含回归
test/build-public.mjs 公网空白版构建（含拓扑残留红线扫描）
```

## 致谢与许可

MIT。本项目借鉴了 [wg-meshconf](https://github.com/k4yt3x/wg-meshconf) 的集中式 mesh 生成思路。
捆绑的第三方库：TweetNaCl（Public domain / MIT）、qrcode-generator（MIT），版权归原作者。
