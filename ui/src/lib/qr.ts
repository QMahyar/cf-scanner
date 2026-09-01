// QR encoder (byte mode, EC level M, versions 1-25). Zero-dependency TypeScript
// port of the encoder used by Q Proxy's panel.html — renders straight to a
// canvas, no `qrcode` npm dependency.
//
// `render(canvas, text): boolean` returns false when text is too long for v25.

const EC = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28];
const NB = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21];

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 256) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}
const gmul = (a: number, b: number) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

function rsDiv(d: number): number[] {
  const r: number[] = [];
  for (let i = 0; i < d - 1; i++) r.push(0);
  r.push(1);
  let root = 1;
  for (let i = 0; i < d; i++) {
    for (let j = 0; j < r.length; j++) r[j] = gmul(r[j], root);
    root = gmul(root, 2);
  }
  return r;
}

function rsRem(dat: number[], div: number[]): number[] {
  const r = div.map(() => 0);
  for (let bi = 0; bi < dat.length; bi++) {
    const f = dat[bi] ^ r.shift()!;
    r.push(0);
    for (let i = 0; i < div.length; i++) r[i] ^= gmul(div[i], f);
  }
  return r;
}

function rawMods(v: number): number {
  let r = (16 * v + 128) * v + 64;
  if (v >= 2) {
    const n = Math.floor(v / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (v >= 7) r -= 36;
  }
  return r;
}
const dataCw = (v: number) => Math.floor(rawMods(v) / 8) - EC[v - 1] * NB[v - 1];

function alignPos(v: number): number[] {
  if (v === 1) return [];
  const n = Math.floor(v / 7) + 2;
  const step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2;
  const p = [6];
  for (let pos = v * 4 + 10; p.length < n; pos -= step) p.splice(1, 0, pos);
  return p;
}

const MASKF = [
  (x: number, y: number) => (x + y) % 2 === 0,
  (x: number, y: number) => y % 2 === 0,
  (x: number, y: number) => x % 3 === 0,
  (x: number, y: number) => (x + y) % 3 === 0,
  (x: number, y: number) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x: number, y: number) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x: number, y: number) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x: number, y: number) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

const N1 = 3;
const N2 = 3;
const N3 = 40;
const N4 = 10;

function gen(text: string): { size: number; modules: Uint8Array[] } | null {
  const bytes = new TextEncoder().encode(text);
  let ver = 1;
  while (ver <= 25 && dataCw(ver) * 8 - 4 - (ver < 10 ? 8 : 16) < bytes.length * 8) ver++;
  if (ver > 25) return null;
  const size = ver * 4 + 17;
  const bits: number[] = [];
  const ab = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  ab(4, 4);
  ab(bytes.length, ver < 10 ? 8 : 16);
  for (const b of bytes) ab(b, 8);
  const dcw = dataCw(ver);
  const total = dcw * 8;
  const term = Math.min(4, total - bits.length);
  for (let i = 0; i < term; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  for (let p = 236; bits.length < total; p ^= 253) {
    for (let j = 7; j >= 0; j--) bits.push((p >>> j) & 1);
  }
  const cw = new Uint8Array(dcw);
  for (let i = 0; i < dcw; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
    cw[i] = b;
  }
  const nb = NB[ver - 1];
  const ecw = EC[ver - 1];
  const raw = Math.floor(rawMods(ver) / 8);
  const shortN = nb - (raw % nb);
  const shortL = Math.floor(raw / nb) - ecw;
  const div = rsDiv(ecw);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < nb; i++) {
    const dl = shortL + (i < shortN ? 0 : 1);
    const dat = cw.slice(k, k + dl);
    k += dl;
    const ecc = rsRem(Array.from(dat), div);
    const blk = Array.from(dat);
    if (i < shortN) blk.push(0);
    blocks.push(blk.concat(ecc));
  }
  const out: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < nb; j++) {
      if (i !== shortL || j >= shortN) out.push(blocks[j][i]);
    }
  }
  const base: Uint8Array[] = [];
  const fn: Uint8Array[] = [];
  for (let y = 0; y < size; y++) {
    base.push(new Uint8Array(size));
    fn.push(new Uint8Array(size));
  }
  const setFn = (x: number, y: number, d: boolean) => {
    base[y][x] = d ? 1 : 0;
    fn[y][x] = 1;
  };
  for (let i = 0; i < size; i++) {
    setFn(6, i, i % 2 === 0);
    setFn(i, 6, i % 2 === 0);
  }
  const finder = (cx: number, cy: number) => {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < size && y >= 0 && y < size) {
          const d = Math.max(Math.abs(dx), Math.abs(dy));
          setFn(x, y, d !== 2 && d !== 4);
        }
      }
  };
  finder(3, 3);
  finder(size - 4, 3);
  finder(3, size - 4);
  const ap = alignPos(ver);
  const apLast = ap[ap.length - 1];
  for (const ay of ap)
    for (const ax of ap) {
      if ((ax === 6 && ay === 6) || (ax === 6 && ay === apLast) || (ay === 6 && ax === apLast)) continue;
      for (let dy = -2; dy <= 2; dy++)
        for (let dx = -2; dx <= 2; dx++)
          setFn(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  const fmtBits = (m: number): number => {
    let rem = m;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return (((m << 10) | rem) ^ 0x5412) >>> 0;
  };
  const drawFormat = (target: Uint8Array[], m: number) => {
    const b = fmtBits(m);
    for (let i = 0; i <= 5; i++) target[i][8] = (b >>> i) & 1;
    target[7][8] = (b >>> 6) & 1;
    target[8][8] = (b >>> 7) & 1;
    target[8][7] = (b >>> 8) & 1;
    for (let i = 9; i < 15; i++) target[8][14 - i] = (b >>> i) & 1;
    for (let i = 0; i < 8; i++) target[8][size - 1 - i] = (b >>> i) & 1;
    for (let i = 8; i < 15; i++) target[size - 15 + i][8] = (b >>> i) & 1;
    target[size - 8][8] = 1;
  };
  drawFormat(base, 0);
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bv = ((ver << 12) | rem) >>> 0;
    for (let i = 0; i < 18; i++) {
      const bit = (bv >>> i) & 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 6);
      setFn(a, b, bit === 1);
      setFn(b, a, bit === 1);
    }
  }
  let idx = 0;
  const M: Uint8Array[] = [];
  for (let y = 0; y < size; y++) M.push(Uint8Array.from(base[y]));
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vt = 0; vt < size; vt++)
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const up = ((right + 1) & 2) === 0;
        const y = up ? size - 1 - vt : vt;
        if (!fn[y][x] && idx < out.length * 8) {
          M[y][x] = (out[idx >> 3] >> (7 - (idx & 7))) & 1;
          idx++;
        }
      }
  }
  let bestM: Uint8Array[] | null = null;
  let bestScore = Infinity;
  for (let m = 0; m < 8; m++) {
    const W = M.map((row) => Uint8Array.from(row));
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++)
        if (!fn[y][x] && MASKF[m](x, y)) W[y][x] ^= 1;
    drawFormat(W, m);
    const s = score(W, size);
    if (s < bestScore) {
      bestScore = s;
      bestM = W;
    }
  }
  return { size, modules: bestM! };
}

function addHist(len: number, hist: number[], sz: number) {
  if (hist[0] === 0) len += sz;
  hist.pop();
  hist.unshift(len);
}
function countPatterns(hist: number[]): number {
  const n = hist[1];
  const core = n > 0 && hist[2] === n && hist[3] === n * 3 && hist[4] === n * 4 && hist[5] === n * 3 && hist[6] === n;
  return (core ? 1 : 0) + (core && hist[0] >= n * 4 ? 1 : 0);
}
function terminateAndCount(color: boolean, len: number, hist: number[], sz: number): number {
  if (color) {
    addHist(len, hist, sz);
    len = 0;
  }
  len += sz;
  addHist(len, hist, sz);
  return countPatterns(hist);
}
function score(M: Uint8Array[], sz: number): number {
  let result = 0;
  for (let y = 0; y < sz; y++) {
    let runColor = !!M[y][0];
    let runX = 0;
    const hist = [0, 0, 0, 0, 0, 0, 0];
    for (let x = 0; x < sz; x++) {
      if (!!M[y][x] === runColor) {
        runX++;
        if (runX === 5) result += N1;
        else if (runX > 5) result++;
      } else {
        addHist(runX, hist, sz);
        if (!runColor) result += countPatterns(hist) * N3;
        runColor = !!M[y][x];
        runX = 1;
      }
    }
    result += terminateAndCount(runColor, runX, hist, sz) * N3;
  }
  for (let x = 0; x < sz; x++) {
    let runColor = !!M[0][x];
    let runX = 0;
    const hist = [0, 0, 0, 0, 0, 0, 0];
    for (let y = 0; y < sz; y++) {
      if (!!M[y][x] === runColor) {
        runX++;
        if (runX === 5) result += N1;
        else if (runX > 5) result++;
      } else {
        addHist(runX, hist, sz);
        if (!runColor) result += countPatterns(hist) * N3;
        runColor = !!M[y][x];
        runX = 1;
      }
    }
    result += terminateAndCount(runColor, runX, hist, sz) * N3;
  }
  for (let y = 0; y < sz - 1; y++)
    for (let x = 0; x < sz - 1; x++) {
      const c = M[y][x];
      if (c === M[y][x + 1] && c === M[y + 1][x] && c === M[y + 1][x + 1]) result += N2;
    }
  let dark = 0;
  for (let y = 0; y < sz; y++)
    for (let x = 0; x < sz; x++) if (M[y][x]) dark++;
  const total = sz * sz;
  const k = Math.ceil(Math.abs((dark * 20 - total * 10) / total)) - 1;
  return result + k * N4;
}

export function render(canvas: HTMLCanvasElement, text: string): boolean {
  const q = gen(text);
  if (!q) return false;
  const size = q.size;
  const dpr = 2;
  const dim = 280 * dpr;
  canvas.width = dim;
  canvas.height = dim;
  const ctx = canvas.getContext("2d");
  if (!ctx) return false;
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, dim, dim);
  const quiet = 4;
  const tot = size + quiet * 2;
  const scale = Math.max(1, Math.floor(dim / tot));
  const off = Math.floor((dim - tot * scale) / 2);
  ctx.fillStyle = "#0a0e14";
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++)
      if (q.modules[y][x]) ctx.fillRect(off + (x + quiet) * scale, off + (y + quiet) * scale, scale, scale);
  return true;
}
