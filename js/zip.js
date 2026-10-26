// zip.js — 极简 store-only ZIP（无压缩，无依赖），用于一键下载全部 .conf
function crcTable() {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
}
const TABLE = crcTable();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const enc = new TextEncoder();

// files: [{name, text}] -> Blob(.zip)
export function buildZip(files) {
  const chunks = [];
  const central = [];
  let offset = 0;

  function push(u8) { chunks.push(u8); offset += u8.length; }
  function u16(n) { return new Uint8Array([n & 255, (n >> 8) & 255]); }
  function u32(n) { return new Uint8Array([n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255]); }

  for (const f of files) {
    const nameB = enc.encode(f.name);
    const dataB = enc.encode(f.text);
    const crc = crc32(dataB);
    const localStart = offset;

    push(u32(0x04034b50)); push(u16(20)); push(u16(0x0800)); // 标志位 bit11: UTF-8 文件名
    push(u16(0)); push(u16(0)); push(u16(0)); // store, DOS time/date
    push(u32(crc)); push(u32(dataB.length)); push(u32(dataB.length));
    push(u16(nameB.length)); push(u16(0));
    push(nameB); push(dataB);

    central.push({ nameB, crc, size: dataB.length, offset: localStart });
  }

  const cdStart = offset;
  for (const c of central) {
    push(u32(0x02014b50));
    push(u16(20)); push(u16(20)); push(u16(0x0800));
    push(u16(0)); push(u16(0)); push(u16(0));
    push(u32(c.crc)); push(u32(c.size)); push(u32(c.size));
    push(u16(c.nameB.length)); push(u16(0)); push(u16(0));
    push(u16(0)); push(u16(0)); push(u32(0)); push(u32(c.offset));
    push(c.nameB);
  }
  const cdSize = offset - cdStart;
  push(u32(0x06054b50)); push(u16(0)); push(u16(0));
  push(u16(central.length)); push(u16(central.length));
  push(u32(cdSize)); push(u32(cdStart)); push(u16(0));

  return new Blob(chunks, { type: 'application/zip' });
}
