// crypto-web.js — 基于 TweetNaCl（Curve25519/X25519，raw 32B base64 即 WireGuard 格式）
import { b64encode, b64decode } from './core.js';

export const webCrypto = {
  makeKeyPair() {
    const kp = nacl.box.keyPair();
    // tweetnacl box.keyPair() 的 secretKey 即 32B X25519 私钥（与 WireGuard 同格式）；
    // 截前 32B 为防御性写法（注意：nacl.sign 的 secretKey 才是 64B，别混用）。
    return { privateKey: b64encode(kp.secretKey.subarray(0, 32)), publicKey: b64encode(kp.publicKey) };
  },
  publicFromSecret(secretB64) {
    const sk = b64decode(secretB64);
    if (sk.length !== 32) throw new Error('私钥必须是 32 字节 base64');
    return b64encode(nacl.box.keyPair.fromSecretKey(sk).publicKey);
  },
  makePsk() {
    return b64encode(nacl.randomBytes(32));
  },
};
